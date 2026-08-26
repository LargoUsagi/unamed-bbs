//! `Core` — the shared persistent-connection scaffolding behind the concrete
//! link transports (`agwpe.Connection`, `tcp.Connection`,
//! `link/meshcore.Connection`).
//!
//! All links are structured identically: an open byte stream held for the
//! program lifetime (a TCP socket today, a configured serial port for
//! MeshCore), a buffered writer used from the main thread, and a background
//! reader thread that pulls raw bytes, hands them to a link-specific parser,
//! and enqueues decoded `IncomingMessage` packets for FIFO draining. Only
//! three things actually differ per link:
//!
//!   * how raw stream bytes are parsed into packets (`Link.dispatch`),
//!   * how one packet's wire bytes are wrapped on send (`Link.sendWire`),
//!   * an optional post-connect handshake (`Link.postConnect`, e.g. AGWPE's
//!     version request + raw-mode enable).
//!
//! Those three operations hang off a small runtime vtable (`Link`) so the
//! scaffolding here stays non-generic. A link module embeds one `Core`
//! (first field, alongside its own parser state) and resolves `*Core`
//! back to its wrapper with `@fieldParentPtr`.
//!
//! The embedding struct must not be moved after `connect()` /
//! `acceptStream()` because the internal `Stream.Writer` holds a pointer to
//! the `write_buf` field.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

const incoming_mod = @import("incoming.zig");

pub const IncomingMessage = incoming_mod.IncomingMessage;
pub const callsign_len = incoming_mod.callsign_len;

// ---------------------------------------------------------------------------
// Windows serial quirks (character-device reads)
// ---------------------------------------------------------------------------

const COMMTIMEOUTS = extern struct {
    ReadIntervalTimeout: u32,
    ReadTotalTimeoutMultiplier: u32,
    ReadTotalTimeoutConstant: u32,
    WriteTotalTimeoutMultiplier: u32,
    WriteTotalTimeoutConstant: u32,
};

const COMSTAT = extern struct {
    flags: u32,
    cbInQue: u32,
    cbOutQue: u32,
};

extern "kernel32" fn SetCommTimeouts(
    handle: std.os.windows.HANDLE,
    timeouts: *const COMMTIMEOUTS,
) callconv(.winapi) std.os.windows.BOOL;

extern "kernel32" fn ClearCommError(
    handle: std.os.windows.HANDLE,
    errors: *u32,
    stat: ?*COMSTAT,
) callconv(.winapi) std.os.windows.BOOL;

const win32_max_dword: u32 = 0xFFFF_FFFF;

/// Install the classic non-blocking serial read timeouts (return
/// immediately with whatever is buffered). zig-serial configures the DCB
/// but never touches COMMTIMEOUTS, leaving read timing undefined.
/// No-op on other targets. Public so standalone tools (meshcore-probe)
/// that bypass `Core` get identical behavior.
pub fn applyWindowsCommTimeouts(file: std.Io.File) void {
    switch (@import("builtin").os.tag) {
        .windows => {
            const timeouts = COMMTIMEOUTS{
                .ReadIntervalTimeout = win32_max_dword,
                .ReadTotalTimeoutMultiplier = win32_max_dword,
                .ReadTotalTimeoutConstant = 0,
                .WriteTotalTimeoutMultiplier = 0,
                .WriteTotalTimeoutConstant = 0,
            };
            _ = SetCommTimeouts(file.handle, &timeouts);
        },
        else => {},
    }
}

/// Bytes waiting in the serial receive queue, or `null` when this is not a
/// Windows target (or the query failed — the caller then just attempts a
/// normal read). Used to gate reads so the driver never starts an idle IRP:
/// some USB-UART drivers complete those with STATUS_TIMEOUT, which Zig's
/// I/O layer does not handle and which would permanently poison the reader.
pub fn windowsSerialBytesQueued(file: std.Io.File) ?u32 {
    switch (@import("builtin").os.tag) {
        .windows => {
            var err_flags: u32 = 0;
            var stat: COMSTAT = std.mem.zeroes(COMSTAT);
            if (ClearCommError(file.handle, &err_flags, &stat) == .FALSE) return null;
            return stat.cbInQue;
        },
        else => return null,
    }
}

/// Per-link operations invoked by the shared scaffolding.
pub const Link = struct {
    /// Consume one batch of freshly-read stream bytes, dispatching each
    /// complete link frame into `core.enqueueIncoming`.
    dispatch: *const fn (core: *Core, data: []const u8) void,

    /// Wrap one packet's wire bytes in the link's own framing and write
    /// them to the socket.
    sendWire: *const fn (
        core: *Core,
        port: u4,
        call_to: []const u8,
        wire: []const u8,
    ) anyerror!void,

    /// Optional handshake written once after the stream opens but before
    /// the reader thread starts (AGWPE sends its 'R' + 'k' setup here).
    postConnect: ?*const fn (core: *Core) anyerror!void = null,
};

/// Shared connection state and lifecycle. Embed in a link-specific wrapper
/// struct that also owns the parser state.
pub const Core = struct {
    /// Link operations (set at construction time by the wrapper).
    link: *const Link,

    io: Io = undefined,
    allocator: std.mem.Allocator = undefined,

    stream: ?net.Stream = null,
    write_buf: [4096]u8 = undefined,
    writer: ?net.Stream.Writer = null,

    /// Serial-port variant: an opened + configured tty/file and its buffered
    /// writer. Mutually exclusive with `stream`/`writer`; used by links that
    /// attach a character device instead of dialing a socket.
    file: ?std.Io.File = null,
    file_writer: ?std.Io.File.Writer = null,

    reader_thread: ?std.Thread = null,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    is_connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    incoming_mutex: Io.Mutex = .init,
    incoming_queue: std.array_list.Managed(IncomingMessage) = undefined,
    /// Read cursor into `incoming_queue` for FIFO draining. Messages before
    /// this index have been drained; messages at and after are pending. Reset
    /// to 0 (and the backing array cleared) once the queue empties.
    drain_head: usize = 0,
    /// True once `setup()` has run (queue/allocator initialized). Guards
    /// `disconnect` and `deinit` from touching an uninitialized queue.
    initialized: bool = false,

    /// Source callsign for outgoing frames (set by CLI/TUI on the client;
    /// set to the server callsign on the server side).
    callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8),
    callsign_len: u8 = 0,

    /// Default radio port/channel (always 0 for direct TCP).
    port: u4 = 0,

    pub fn isConnected(self: *const Core) bool {
        return self.is_connected.load(.acquire);
    }

    /// Shared pre-connect initialization: queue, allocator, callsign, port.
    pub fn setup(
        self: *Core,
        io: Io,
        allocator: std.mem.Allocator,
        port: u4,
        callsign: []const u8,
    ) void {
        self.io = io;
        self.allocator = allocator;
        self.port = port;
        self.incoming_queue = std.array_list.Managed(IncomingMessage).init(allocator);
        self.initialized = true;

        self.callsign = std.mem.zeroes([callsign_len]u8);
        const cn = @min(callsign.len, callsign_len);
        @memcpy(self.callsign[0..cn], callsign[0..cn]);
        self.callsign_len = @intCast(cn);
    }

    /// Open a TCP connection to `address`: shared setup, dial, optional link
    /// handshake, then start the reader thread.
    pub fn connect(
        self: *Core,
        io: Io,
        address: net.IpAddress,
        allocator: std.mem.Allocator,
        port: u4,
        callsign: []const u8,
    ) !void {
        self.setup(io, allocator, port, callsign);
        const stream = try address.connect(io, .{ .mode = .stream });
        try self.attachStream(stream);
    }

    /// Wrap an already-accepted TCP stream (server side). The caller obtains
    /// the stream from `net.Server.accept()`.
    pub fn acceptStream(
        self: *Core,
        io: Io,
        stream: net.Stream,
        allocator: std.mem.Allocator,
        port: u4,
        callsign: []const u8,
    ) !void {
        self.setup(io, allocator, port, callsign);
        try self.attachStream(stream);
    }

    /// Attach an open stream: buffered writer, connected flag, and the
    /// background reader thread. Runs the optional link handshake first.
    pub fn attachStream(self: *Core, stream: net.Stream) !void {
        self.stream = stream;
        self.writer = stream.writer(self.io, &self.write_buf);
        try self.startReader();
    }

    /// Attach an opened + configured serial port (or any file-backed byte
    /// stream). Mirrors `attachStream` for links whose physical layer is a
    /// character device rather than a socket.
    ///
    /// Applies the Windows serial quirks centrally (comm timeouts + queued-
    /// byte gating below) so every serial-based link inherits them.
    pub fn attachFile(self: *Core, file: std.Io.File) !void {
        self.file = file;
        applyWindowsCommTimeouts(file);
        self.file_writer = file.writerStreaming(self.io, &self.write_buf);
        try self.startReader();
    }

    fn startReader(self: *Core) !void {
        self.stop.store(false, .release);
        self.is_connected.store(true, .release);

        if (self.link.postConnect) |hook| try hook(self);

        self.reader_thread = try std.Thread.spawn(.{}, readerLoop, .{self});
    }

    /// Wrap and transmit one packet's wire bytes via the link operation.
    pub fn sendWire(self: *Core, port: u4, call_to: []const u8, wire: []const u8) !void {
        return self.link.sendWire(self, port, call_to, wire);
    }

    /// The buffered writer interface used by link `sendWire` implementations.
    pub fn writerInterface(self: *Core) ?*std.Io.Writer {
        if (self.file_writer) |*w| return &w.interface;
        if (self.writer) |*w| return &w.interface;
        return null;
    }

    /// Enqueue one decoded incoming message (called from the reader thread).
    pub fn enqueueIncoming(self: *Core, msg: IncomingMessage) void {
        self.incoming_mutex.lockUncancelable(self.io);
        defer self.incoming_mutex.unlock(self.io);
        self.incoming_queue.append(msg) catch {};
    }

    /// Drain up to `dest.len` queued incoming messages into `dest`, in FIFO
    /// order. Returns the number copied. Messages that don't fit in `dest`
    /// are retained for the next drain rather than discarded, so a burst
    /// larger than the caller's buffer is processed across successive drains
    /// instead of being silently dropped.
    pub fn drainIncoming(self: *Core, dest: []IncomingMessage) usize {
        self.incoming_mutex.lockUncancelable(self.io);
        defer self.incoming_mutex.unlock(self.io);
        const items = self.incoming_queue.items;
        const avail = items.len - self.drain_head;
        const n = @min(avail, dest.len);
        @memcpy(dest[0..n], items[self.drain_head..][0..n]);
        self.drain_head += n;
        if (self.drain_head >= items.len) {
            self.drain_head = 0;
            self.incoming_queue.clearRetainingCapacity();
        }
        return n;
    }

    fn readerLoop(self: *Core) void {
        var read_buf: [4096]u8 = undefined;
        if (self.file) |f| {
            var reader = f.readerStreaming(self.io, &read_buf);
            while (!self.stop.load(.acquire)) {
                // Only issue a read when the driver reports queued bytes:
                // idle reads on some Windows USB-UART drivers complete with
                // STATUS_TIMEOUT, which poisons the Io.Reader permanently.
                if (windowsSerialBytesQueued(f)) |queued| {
                    if (queued == 0) {
                        std.Io.sleep(self.io, .fromMilliseconds(5), .real) catch {};
                        continue;
                    }
                }
                var data: [1][]u8 = .{&read_buf};
                const n = reader.interface.readVec(&data) catch {
                    self.is_connected.store(false, .release);
                    return;
                };
                if (n == 0) {
                    // Serial poll with nothing buffered (Windows non-
                    // blocking comm timeouts). Back off briefly instead of
                    // spinning; this is NOT an end-of-stream condition.
                    std.Io.sleep(self.io, .fromMilliseconds(5), .real) catch {};
                    continue;
                }
                self.link.dispatch(self, read_buf[0..n]);
            }
        } else if (self.stream) |stream| {
            var reader = stream.reader(self.io, &read_buf);
            self.readUntilStop(&reader.interface, &read_buf);
        }
    }

    fn readUntilStop(self: *Core, interface: *std.Io.Reader, read_buf: *[4096]u8) void {
        while (!self.stop.load(.acquire)) {
            var data: [1][]u8 = .{read_buf};
            const n = interface.readVec(&data) catch {
                self.is_connected.store(false, .release);
                return;
            };
            if (n == 0) {
                self.is_connected.store(false, .release);
                return;
            }
            self.link.dispatch(self, read_buf[0..n]);
        }
    }

    pub fn disconnect(self: *Core) void {
        self.stop.store(true, .release);
        self.is_connected.store(false, .release);

        // Signal first so a blocked read unblocks on close; then join before
        // touching shared state.
        if (self.stream) |stream| {
            stream.shutdown(self.io, .both) catch {};
            stream.close(self.io);
            self.stream = null;
        }
        if (self.file) |file| {
            file.close(self.io);
            self.file = null;
        }

        if (self.reader_thread) |t| {
            t.join();
            self.reader_thread = null;
        }

        self.writer = null;
        self.file_writer = null;
        if (self.initialized) {
            if (self.incoming_queue.items.len > 0) {
                self.incoming_queue.clearRetainingCapacity();
            }
            self.drain_head = 0;
        }
    }

    pub fn deinit(self: *Core) void {
        self.disconnect();
        if (self.initialized) {
            self.incoming_queue.deinit();
        }
        self.initialized = false;
    }
};

// ---------------------------------------------------------------------------
// Tests — shared FIFO drain semantics (one copy for all links)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn noopDispatch(_: *Core, _: []const u8) void {}
fn noopSendWire(_: *Core, _: u4, _: []const u8, _: []const u8) anyerror!void {}

const noop_link = Link{
    .dispatch = noopDispatch,
    .sendWire = noopSendWire,
};

test "drainIncoming retains messages beyond dest capacity (FIFO)" {
    const allocator = testing.allocator;
    var conn: Core = .{ .link = &noop_link };
    conn.setup(std.testing.io, allocator, 0, "TEST");
    defer conn.deinit();

    // Queue 20 dummy messages whose port encodes their original index (mod 16).
    for (0..20) |i| {
        var msg: IncomingMessage = .{};
        msg.port = @intCast(i & 0x0F);
        try conn.incoming_queue.append(msg);
    }

    // dest holds 8; the other 12 must be retained for the next drain.
    var dest: [8]IncomingMessage = undefined;
    const n1 = conn.drainIncoming(&dest);
    try testing.expectEqual(@as(usize, 8), n1);
    try testing.expectEqual(@as(usize, 20), conn.incoming_queue.items.len);
    try testing.expectEqual(@as(usize, 8), conn.drain_head);
    for (dest[0..8], 0..) |m, i| {
        try testing.expectEqual(@as(u4, @intCast(i & 0x0F)), m.port);
    }

    // Drain the next 8 — order preserved, still not fully drained.
    var dest2: [8]IncomingMessage = undefined;
    const n2 = conn.drainIncoming(&dest2);
    try testing.expectEqual(@as(usize, 8), n2);
    try testing.expectEqual(@as(usize, 16), conn.drain_head);
    for (dest2[0..8], 0..) |m, i| {
        try testing.expectEqual(@as(u4, @intCast((8 + i) & 0x0F)), m.port);
    }

    // Drain the final 4 — queue empties, head resets to 0 and backing clears.
    var dest3: [8]IncomingMessage = undefined;
    const n3 = conn.drainIncoming(&dest3);
    try testing.expectEqual(@as(usize, 4), n3);
    try testing.expectEqual(@as(usize, 0), conn.drain_head);
    try testing.expectEqual(@as(usize, 0), conn.incoming_queue.items.len);
    for (dest3[0..4], 0..) |m, i| {
        try testing.expectEqual(@as(u4, @intCast((16 + i) & 0x0F)), m.port);
    }

    // A further drain returns 0 (and stays empty).
    var dest4: [4]IncomingMessage = undefined;
    try testing.expectEqual(@as(usize, 0), conn.drainIncoming(&dest4));
}

test "drainIncoming drains newly appended messages after a partial drain" {
    const allocator = testing.allocator;
    var conn: Core = .{ .link = &noop_link };
    conn.setup(std.testing.io, allocator, 0, "TEST");
    defer conn.deinit();

    for (0..5) |i| {
        var msg: IncomingMessage = .{};
        msg.port = @intCast(i);
        try conn.incoming_queue.append(msg);
    }
    var dest: [3]IncomingMessage = undefined;
    try testing.expectEqual(@as(usize, 3), conn.drainIncoming(&dest));

    // Reader thread appends more while 2 are still pending.
    for (5..8) |i| {
        var msg: IncomingMessage = .{};
        msg.port = @intCast(i);
        try conn.incoming_queue.append(msg);
    }

    // Pending 2 + newly appended 3 = 5 available, in FIFO order.
    var dest2: [10]IncomingMessage = undefined;
    const n = conn.drainIncoming(&dest2);
    try testing.expectEqual(@as(usize, 5), n);
    for (dest2[0..5], 0..) |m, i| {
        try testing.expectEqual(@as(u4, @intCast(i + 3)), m.port);
    }
    try testing.expectEqual(@as(usize, 0), conn.incoming_queue.items.len);
}
