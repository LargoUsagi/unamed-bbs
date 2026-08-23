//! TCP/IP direct transport — a length-delimited TCP connection that carries
//! message frames between client and server without an AGWPE TNC / AX.25
//! radio layer.
//!
//! The wire format is a simple length-delimited envelope:
//!
//!   [magic: u8 = 0x4B]            — 'K' for kiss-test
//!   [port: u8]                    — radio channel (low 4 bits; kept for
//!                                    compatibility with the AGWPE path)
//!   [src_callsign_len: u8]        — 0..10
//!   [src_callsign: N bytes]       — sender callsign (no null padding)
//!   [dest_callsign_len: u8]       — 0..10
//!   [dest_callsign: N bytes]      — destination callsign ("CQ" = broadcast)
//!   [frame_len: u16 LE]           — message-frame wire bytes length
//!   [frame_bytes: frame_len]      — the `MessageFrame` wire bytes
//!
//! This mirrors the AGWPE transport's data plane: `sendWire` wraps the
//! message-frame bytes in the envelope, and the reader thread parses incoming
//! envelopes and populates `IncomingMessage` with the callsigns + decoded
//! frame. The transport satisfies the shared `transport.Transport` vtable so
//! `sendMultipart` and all inbox/outbox logic works unchanged.
//!
//! Two construction paths:
//!   * `connect()`     — client side: open a TCP connection to a server.
//!   * `acceptStream()` — server side: wrap an already-accepted `net.Stream`
//!     from a `net.Server.accept()` call.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

const message_frame = @import("../message_frame.zig");
const transport = @import("transport.zig");

pub const MessageFrame = message_frame.MessageFrame;
pub const MessageType = message_frame.MessageType;
pub const IncomingMessage = message_frame.IncomingMessage;
pub const callsign_len = message_frame.callsign_len;

/// Re-exported for callers that reference transport types through this module.
pub const Transport = transport.Transport;
pub const SendOptions = transport.SendOptions;
pub const FrameInfo = transport.FrameInfo;
pub const FrameObserver = transport.FrameObserver;

/// Magic byte at the start of every TCP transport envelope.
const magic: u8 = 0x4B;

/// Maximum frame payload the parser will accept (matches AGWPE).
pub const max_frame_payload: usize = 4096;

/// Maximum payload bytes per packet chunk for the TCP transport. Set to
/// `message_frame.max_payload_len` (256) to stay consistent with AGWPE and
/// exercise the multipart path identically.
pub const mtu_payload: usize = 256;

// ---------------------------------------------------------------------------
// Envelope read/write
// ---------------------------------------------------------------------------

/// Maximum size of a complete envelope: magic(1) + port(1) +
/// src_len(1) + src(10) + dest_len(1) + dest(10) + frame_len(2) + frame.
const max_envelope_overhead: usize = 1 + 1 + 1 + callsign_len + 1 + callsign_len + 2;
const max_envelope_size: usize = max_envelope_overhead + max_frame_payload;

/// Write a TCP transport envelope into `buf`. Returns the number of bytes
/// written, or `null` if the frame is too large.
fn writeEnvelope(
    buf: []u8,
    port: u4,
    src_callsign: []const u8,
    dest_callsign: []const u8,
    frame: []const u8,
) ?usize {
    if (src_callsign.len > callsign_len) return null;
    if (dest_callsign.len > callsign_len) return null;
    const total = 1 + 1 + 1 + src_callsign.len + 1 + dest_callsign.len + 2 + frame.len;
    if (buf.len < total) return null;

    var pos: usize = 0;
    buf[pos] = magic;
    pos += 1;
    buf[pos] = @intCast(port & 0x0F);
    pos += 1;
    buf[pos] = @intCast(src_callsign.len);
    pos += 1;
    @memcpy(buf[pos..][0..src_callsign.len], src_callsign);
    pos += src_callsign.len;
    buf[pos] = @intCast(dest_callsign.len);
    pos += 1;
    @memcpy(buf[pos..][0..dest_callsign.len], dest_callsign);
    pos += dest_callsign.len;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(frame.len), .little);
    pos += 2;
    @memcpy(buf[pos..][0..frame.len], frame);
    pos += frame.len;
    return pos;
}

// ---------------------------------------------------------------------------
// Streaming envelope parser
// ---------------------------------------------------------------------------

/// Streaming TCP envelope parser. Feed it raw bytes from the TCP stream and
/// it calls `onEnvelope` for each complete envelope.
pub const EnvelopeParser = struct {
    buf: [max_envelope_size]u8 = undefined,
    pos: usize = 0,
    /// Total bytes needed for the current envelope (0 = not yet known).
    needed: usize = 0,

    pub fn feed(
        self: *EnvelopeParser,
        data: []const u8,
        ctx: anytype,
        comptime onEnvelope: fn (@TypeOf(ctx), u8, []const u8, []const u8, []const u8) void,
    ) void {
        var i: usize = 0;
        while (i < data.len) {
            const available = data.len - i;
            // When needed == 0 we haven't determined the envelope size yet,
            // so copy all available bytes (up to buffer capacity) to
            // accumulate enough header bytes to compute `needed`.
            const to_copy = if (self.needed == 0)
                @min(available, max_envelope_size - self.pos)
            else if (self.needed > self.pos)
                @min(available, self.needed - self.pos)
            else
                0;

            if (to_copy > 0) {
                @memcpy(self.buf[self.pos..][0..to_copy], data[i..][0..to_copy]);
                self.pos += to_copy;
                i += to_copy;
            }

            if (self.needed == 0 and self.pos >= 3 + 1) {
                // We have magic + port + src_len + src_callsign (at least).
                self.computeNeeded() orelse {
                    // Bad magic or overflow — reset and resync.
                    self.pos = 0;
                    self.needed = 0;
                    continue;
                };
            }

            if (self.needed > 0 and self.pos >= self.needed) {
                self.emit(ctx, onEnvelope);
                self.pos = 0;
                self.needed = 0;
            }
        }
    }

    fn computeNeeded(self: *EnvelopeParser) ?void {
        if (self.buf[0] != magic) return null;
        const src_len: usize = self.buf[2];
        // Need at least: magic(1) + port(1) + src_len(1) + src + dest_len(1)
        const dest_len_offset = 3 + src_len;
        if (self.pos < dest_len_offset + 1) {
            // Not enough bytes yet — set a partial needed to pull more.
            self.needed = dest_len_offset + 1;
            return {};
        }
        const dest_len: usize = self.buf[dest_len_offset];
        const frame_len_offset = dest_len_offset + 1 + dest_len;
        if (self.pos < frame_len_offset + 2) {
            self.needed = frame_len_offset + 2;
            return {};
        }
        const frame_len: usize = std.mem.readInt(u16, self.buf[frame_len_offset..][0..2], .little);
        if (frame_len > max_frame_payload) return null;
        self.needed = frame_len_offset + 2 + frame_len;
    }

    fn emit(
        self: *EnvelopeParser,
        ctx: anytype,
        comptime onEnvelope: fn (@TypeOf(ctx), u8, []const u8, []const u8, []const u8) void,
    ) void {
        const port = self.buf[1];
        const src_len: usize = self.buf[2];
        const src = self.buf[3 .. 3 + src_len];
        const dest_len_offset = 3 + src_len;
        const dest_len: usize = self.buf[dest_len_offset];
        const dest = self.buf[dest_len_offset + 1 .. dest_len_offset + 1 + dest_len];
        const frame_len_offset = dest_len_offset + 1 + dest_len;
        const frame_len: usize = std.mem.readInt(u16, self.buf[frame_len_offset..][0..2], .little);
        const frame = self.buf[frame_len_offset + 2 .. frame_len_offset + 2 + frame_len];
        onEnvelope(ctx, port, src, dest, frame);
    }
};

// ---------------------------------------------------------------------------
// Tests for the parser
// ---------------------------------------------------------------------------

test "EnvelopeParser parses a single envelope" {
    const Ctx = struct {
        port: u8 = 0,
        src: []const u8 = "",
        dest: []const u8 = "",
        frame: []const u8 = "",
        called: bool = false,
        fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
            self.called = true;
            self.port = port;
            self.src = src;
            self.dest = dest;
            self.frame = frame;
        }
    };
    var parser: EnvelopeParser = .{};
    var ctx: Ctx = .{};

    var buf: [64]u8 = undefined;
    const n = writeEnvelope(&buf, 3, "KE8WIF", "CQ", "hello") orelse return error.EncodeFailed;
    parser.feed(buf[0..n], &ctx, Ctx.cb);

    try std.testing.expect(ctx.called);
    try std.testing.expectEqual(@as(u8, 3), ctx.port);
    try std.testing.expectEqualStrings("KE8WIF", ctx.src);
    try std.testing.expectEqualStrings("CQ", ctx.dest);
    try std.testing.expectEqualStrings("hello", ctx.frame);
}

test "EnvelopeParser handles split data" {
    const Ctx = struct {
        frame: []const u8 = "",
        called: bool = false,
        fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
            _ = port;
            _ = src;
            _ = dest;
            self.called = true;
            self.frame = frame;
        }
    };
    var parser: EnvelopeParser = .{};
    var ctx: Ctx = .{};

    var buf: [64]u8 = undefined;
    const n = writeEnvelope(&buf, 0, "A", "B", "payload") orelse return error.EncodeFailed;

    // Feed first 3 bytes, then the rest.
    parser.feed(buf[0..3], &ctx, Ctx.cb);
    try std.testing.expect(!ctx.called);
    parser.feed(buf[3..n], &ctx, Ctx.cb);
    try std.testing.expect(ctx.called);
    try std.testing.expectEqualStrings("payload", ctx.frame);
}

test "EnvelopeParser rejects bad magic" {
    const Ctx = struct {
        called: bool = false,
        fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
            _ = self;
            _ = port;
            _ = src;
            _ = dest;
            _ = frame;
        }
    };
    var parser: EnvelopeParser = .{};
    var ctx: Ctx = .{};

    // Bad magic byte.
    var bad = [_]u8{ 0x00, 0, 0, 0, 0, 0, 0 };
    parser.feed(&bad, &ctx, Ctx.cb);
    try std.testing.expect(!ctx.called);
}

// ---------------------------------------------------------------------------
// Connection — persistent TCP connection with background reader
// ---------------------------------------------------------------------------

/// Persistent TCP connection for the direct TCP transport. Mirrors
/// `agwpe.Connection`: keeps the socket open, sends framed envelopes on
/// demand from the main thread, and runs a background reader thread that
/// parses incoming envelopes and decodes their message frames.
///
/// The Connection must be initialised with `connect()` (client) or
/// `acceptStream()` (server) before use and cleaned up with `disconnect()` /
/// `deinit()`. The struct must not be moved after connection because the
/// internal `Stream.Writer` holds a pointer to the `write_buf` field.
pub const Connection = struct {
    io: Io = undefined,
    allocator: std.mem.Allocator = undefined,

    stream: ?net.Stream = null,
    write_buf: [4096]u8 = undefined,
    writer: ?net.Stream.Writer = null,

    reader_thread: ?std.Thread = null,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    is_connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    incoming_mutex: std.Io.Mutex = .init,
    incoming_queue: std.array_list.Managed(IncomingMessage) = undefined,
    /// True once `connect()` or `acceptStream()` has been called (and the
    /// incoming_queue / allocator are initialized). Guards `disconnect` and
    /// `deinit` from touching an uninitialized queue.
    initialized: bool = false,

    /// Source callsign for outgoing frames (set by CLI/TUI on the client;
    /// set to the server callsign on the server side).
    callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8),
    callsign_len: u8 = 0,

    /// Radio port/channel (kept for compatibility; always 0 for direct TCP).
    port: u4 = 0,

    /// Open a TCP connection to `address` (client side).
    pub fn connect(
        self: *Connection,
        io: Io,
        address: net.IpAddress,
        allocator: std.mem.Allocator,
        port: u4,
        callsign: []const u8,
    ) !void {
        self.io = io;
        self.allocator = allocator;
        self.port = port;
        self.incoming_queue = std.array_list.Managed(IncomingMessage).init(allocator);
        self.initialized = true;

        self.callsign = std.mem.zeroes([callsign_len]u8);
        const cn = @min(callsign.len, callsign_len);
        @memcpy(self.callsign[0..cn], callsign[0..cn]);
        self.callsign_len = @intCast(cn);

        const stream = try address.connect(io, .{ .mode = .stream });
        self.stream = stream;
        self.writer = stream.writer(io, &self.write_buf);
        self.stop.store(false, .release);
        self.is_connected.store(true, .release);

        self.reader_thread = try std.Thread.spawn(.{}, readerLoop, .{self});
    }

    /// Wrap an already-accepted TCP stream (server side). The caller obtains
    /// the stream from `net.Server.accept()`.
    pub fn acceptStream(
        self: *Connection,
        io: Io,
        stream: net.Stream,
        allocator: std.mem.Allocator,
        port: u4,
        callsign: []const u8,
    ) !void {
        self.io = io;
        self.allocator = allocator;
        self.port = port;
        self.incoming_queue = std.array_list.Managed(IncomingMessage).init(allocator);
        self.initialized = true;

        self.callsign = std.mem.zeroes([callsign_len]u8);
        const cn = @min(callsign.len, callsign_len);
        @memcpy(self.callsign[0..cn], callsign[0..cn]);
        self.callsign_len = @intCast(cn);

        self.stream = stream;
        self.writer = stream.writer(io, &self.write_buf);
        self.stop.store(false, .release);
        self.is_connected.store(true, .release);

        self.reader_thread = try std.Thread.spawn(.{}, readerLoop, .{self});
    }

    /// Return a `Transport` handle backed by this connection.
    pub fn asTransport(self: *Connection) transport.Transport {
        return .{ .ctx = @ptrCast(self), .vtable = &tcp_transport_vtable };
    }

    /// Low-level: send pre-built wire bytes wrapped in a TCP envelope.
    fn sendWireFrame(self: *Connection, port: u4, call_to: []const u8, payload: []const u8) !void {
        const call_from: []const u8 = self.callsign[0..self.callsign_len];

        var buf: [max_envelope_size]u8 = undefined;
        const n = writeEnvelope(&buf, port, call_from, call_to, payload) orelse return error.PayloadTooLarge;

        const w = &self.writer.?.interface;
        try w.writeAll(buf[0..n]);
        try w.flush();
    }

    /// Drain queued incoming messages into `dest`. Returns the number copied.
    pub fn drainIncoming(self: *Connection, dest: []IncomingMessage) usize {
        self.incoming_mutex.lockUncancelable(self.io);
        defer self.incoming_mutex.unlock(self.io);
        const n = @min(self.incoming_queue.items.len, dest.len);
        @memcpy(dest[0..n], self.incoming_queue.items[0..n]);
        self.incoming_queue.clearRetainingCapacity();
        return n;
    }

    /// Background reader thread: reads bytes, parses envelopes, decodes
    /// message frames, and queues results for the main thread to drain.
    fn readerLoop(self: *Connection) void {
        var read_buf: [4096]u8 = undefined;
        const stream = self.stream orelse return;
        var reader = stream.reader(self.io, &read_buf);
        var parser: EnvelopeParser = .{};

        while (!self.stop.load(.acquire)) {
            var data: [1][]u8 = .{&read_buf};
            const n = reader.interface.readVec(&data) catch {
                self.is_connected.store(false, .release);
                return;
            };
            if (n == 0) {
                self.is_connected.store(false, .release);
                return;
            }
            parser.feed(read_buf[0..n], self, onEnvelope);
        }
    }

    /// EnvelopeParser callback: dispatched for each complete envelope.
    fn onEnvelope(self: *Connection, port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
        var msg: IncomingMessage = .{ .port = @intCast(port & 0x0F) };

        if (src.len > 0) {
            @memcpy(msg.callsign[0..src.len], src);
            msg.callsign_str_len = @intCast(src.len);
            msg.has_callsign = true;
        }
        if (dest.len > 0) {
            @memcpy(msg.dest_callsign[0..dest.len], dest);
            msg.dest_callsign_str_len = @intCast(dest.len);
            msg.has_dest_callsign = true;
        }

        _ = message_frame.decodeIncoming(frame, &msg);

        self.incoming_mutex.lockUncancelable(self.io);
        defer self.incoming_mutex.unlock(self.io);
        self.incoming_queue.append(msg) catch {};
    }

    pub fn disconnect(self: *Connection) void {
        self.stop.store(true, .release);
        self.is_connected.store(false, .release);

        if (self.stream) |stream| {
            stream.shutdown(self.io, .both) catch {};
            stream.close(self.io);
            self.stream = null;
        }

        if (self.reader_thread) |t| {
            t.join();
            self.reader_thread = null;
        }

        self.writer = null;
        if (self.initialized) {
            if (self.incoming_queue.items.len > 0) {
                self.incoming_queue.clearRetainingCapacity();
            }
        }
    }

    pub fn deinit(self: *Connection) void {
        self.disconnect();
        if (self.initialized) {
            self.incoming_queue.deinit();
        }
        self.initialized = false;
    }

    pub fn isConnected(self: *const Connection) bool {
        return self.is_connected.load(.acquire);
    }
};

// ---------------------------------------------------------------------------
// Transport vtable
// ---------------------------------------------------------------------------

const tcp_transport_vtable: transport.Transport.VTable = .{
    .mtu_payload = mtu_payload,
    .isConnected = transportIsConnected,
    .sendWire = transportSendWire,
    .drainIncoming = transportDrainIncoming,
    .disconnect = transportDisconnect,
};

fn transportIsConnected(ctx: *anyopaque) bool {
    const self: *const Connection = @ptrCast(@alignCast(ctx));
    return self.isConnected();
}

fn transportSendWire(ctx: *anyopaque, port: u4, call_to: []const u8, wire: []const u8) anyerror!void {
    const self: *Connection = @ptrCast(@alignCast(ctx));
    return self.sendWireFrame(port, call_to, wire);
}

fn transportDrainIncoming(ctx: *anyopaque, dest: []transport.IncomingMessage) usize {
    const self: *Connection = @ptrCast(@alignCast(ctx));
    return self.drainIncoming(dest);
}

fn transportDisconnect(ctx: *anyopaque) void {
    const self: *Connection = @ptrCast(@alignCast(ctx));
    self.disconnect();
}
