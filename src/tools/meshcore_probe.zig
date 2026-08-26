//! MeshCore companion-port probe — a standalone diagnostic executable.
//!
//! Opens a serial port, sends a properly framed `CMD_APP_START`, then dumps
//! every byte the radio sends back in hex (with parsed-frame annotations)
//! for a configurable number of seconds. Ground truth for "is the radio
//! actually responding over serial", independent of the BBS transport stack.
//!
//! Usage: meshcore-probe <device> [baud] [listen_secs]
//!   meshcore-probe COM13
//!   meshcore-probe /dev/ttyUSB0 115200 10

const std = @import("std");
const Io = std.Io;
const serial = @import("serial");
const conn_mod = @import("bbs").connection;

const tx_marker: u8 = '<';
const rx_marker: u8 = '>';

/// Shared between the main thread and the reader thread.
const Stopper = struct {
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    total_bytes: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    frames: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

/// Streaming '<'/'>' frame parser state (reader-thread local).
const RxState = struct {
    state: enum { idle, got_marker, got_len_lo, payload } = .idle,
    declared: u16 = 0,
    have: u16 = 0,

    fn feed(self: *@This(), byte: u8, st: *Stopper, eo: *Io.Writer) void {
        switch (self.state) {
            .idle => {
                if (byte == rx_marker) self.state = .got_marker;
            },
            .got_marker => {
                self.declared = byte;
                self.state = .got_len_lo;
            },
            .got_len_lo => {
                self.declared |= @as(u16, byte) << 8;
                self.have = 0;
                if (self.declared > 0) self.state = .payload;
            },
            .payload => {
                self.have += 1;
                if (self.have >= self.declared) {
                    _ = st.frames.fetchAdd(1, .monotonic);
                    eo.print("\nprobe: complete frame, len={d} (see hex above)\n", .{self.declared}) catch {};
                    eo.flush() catch {};
                    self.state = .idle;
                }
            },
        }
    }
};

const ThreadArgs = struct {
    file: std.Io.File,
    io: Io,
    st: *Stopper,
    eo: *Io.Writer,

    fn run(a: ThreadArgs) void {
        var rbuf: [4096]u8 = undefined;
        var fr = a.file.readerStreaming(a.io, &rbuf);
        var rx = RxState{};
        while (!a.st.stop.load(.acquire)) {
            // Only read when the driver reports queued bytes (Windows).
            if (conn_mod.windowsSerialBytesQueued(a.file)) |queued| {
                if (queued == 0) {
                    std.Io.sleep(a.io, .fromMilliseconds(5), .real) catch {};
                    continue;
                }
            }
            var tmp: [256]u8 = undefined;
            var vecs: [1][]u8 = .{&tmp};
            const n = fr.interface.readVec(&vecs) catch |e| {
                a.eo.print("probe: read error: {s}\n", .{@errorName(e)}) catch {};
                return;
            };
            if (n == 0) {
                // Non-blocking serial poll came back empty — brief backoff.
                std.Io.sleep(a.io, .fromMilliseconds(5), .real) catch {};
                continue;
            }
            _ = a.st.total_bytes.fetchAdd(n, .monotonic);
            a.eo.print("rx[{d}]:", .{n}) catch {};
            for (tmp[0..n]) |b| a.eo.print(" {X:0>2}", .{b}) catch {};
            a.eo.print("\n", .{}) catch {};
            a.eo.flush() catch {};
            for (tmp[0..n]) |b| rx.feed(b, a.st, a.eo);
        }
    }
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer: Io.File.Writer = .init(.stderr(), io, &stderr_buf);
    const err_out = &stderr_writer.interface;

    const argv = try init.minimal.args.toSlice(arena);
    if (argv.len < 2) {
        try err_out.writeAll("usage: meshcore-probe <device> [baud] [listen_secs]\n");
        try err_out.flush();
        return;
    }
    const raw_device = argv[1];
    const baud: u32 = if (argv.len > 2)
        (std.fmt.parseInt(u32, argv[2], 10) catch 115200)
    else
        115200;
    const listen_secs: u64 = if (argv.len > 3)
        (std.fmt.parseInt(u64, argv[3], 10) catch 8)
    else
        8;

    // Resolve bare Windows COM names against the Win32 device namespace up
    // front so the slice outlives this function (arena-backed).
    const device: []const u8 = blk: {
        const is_com = @import("builtin").os.tag == .windows and
            std.ascii.startsWithIgnoreCase(raw_device, "COM") and raw_device.len > 3 and
            digitsOnly(raw_device[3..]);
        if (!is_com) break :blk raw_device;
        break :blk std.fmt.allocPrint(arena, "\\\\.\\{s}", .{raw_device}) catch raw_device;
    };

    try err_out.print("probe: opening {s} at {d} baud\n", .{ device, baud });
    try err_out.flush();

    const file = if (std.fs.path.isAbsolute(device))
        try std.Io.Dir.openFileAbsolute(io, device, .{ .mode = .read_write })
    else
        try std.Io.Dir.cwd().openFile(io, device, .{ .mode = .read_write });

    try serial.configureSerialPort(file, .{
        .baud_rate = baud,
        .word_size = .eight,
        .parity = .none,
        .stop_bits = .one,
        .handshake = .none,
    });
    // Windows comm timeouts + queued-byte gating come from the same shared
    // serial scaffolding the real link uses.
    conn_mod.applyWindowsCommTimeouts(file);
    try err_out.print("probe: port configured\n", .{});

    var wbuf: [256]u8 = undefined;
    var fw = file.writerStreaming(io, &wbuf);

    // CMD_APP_START (0x01): cmd + 7 reserved zeros + app name.
    const app_name = "meshcore-probe";
    var cmd: [3 + 8 + app_name.len]u8 = undefined;
    cmd[0] = tx_marker;
    std.mem.writeInt(u16, cmd[1..3], @intCast(8 + app_name.len), .little);
    cmd[3] = 0x01; // CMD_APP_START
    @memset(cmd[4..11], 0);
    @memcpy(cmd[11..][0..app_name.len], app_name);

    try fw.interface.writeAll(&cmd);
    try fw.interface.flush();
    try err_out.print("probe: sent APP_START ({d} bytes), listening for {d}s...\n", .{ cmd.len, listen_secs });
    try err_out.flush();

    var stopper = Stopper{};
    const thread_args = ThreadArgs{ .file = file, .io = io, .st = &stopper, .eo = err_out };
    const reader_thread = try std.Thread.spawn(.{}, ThreadArgs.run, .{thread_args});

    std.Io.sleep(io, .fromSeconds(@intCast(listen_secs)), .real) catch {};

    stopper.stop.store(true, .release);
    // Closing the file unblocks the pending read on most platforms.
    file.close(io);
    reader_thread.join();

    try err_out.print(
        "probe: done — {d} bytes received, {d} complete frames\n",
        .{ stopper.total_bytes.load(.monotonic), stopper.frames.load(.monotonic) },
    );
    try err_out.flush();

    // The deferred close would double-close; we already closed explicitly.
    std.process.exit(0);
}

fn digitsOnly(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}
