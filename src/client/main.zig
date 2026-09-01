const std = @import("std");
const Io = std.Io;

const tui = @import("tui.zig");
const kiss = @import("bbs");
const endpoint = kiss.endpoint;

const default_callsign = "NOCALL";

const Options = struct {
    /// Parsed connect endpoint from `--connect <url>`. When null, the client
    /// falls back to the saved `tc_connect_uri` in the SQLite store, or no
    /// auto-connect if none is saved.
    connect: ?endpoint.TransportEndpoint = null,
    /// Set when a duplicate `--connect` is passed. Shown as a startup notice
    /// popup so the user knows only the first was used.
    duplicate_connect_notice: ?[]const u8 = null,
    callsign: []const u8 = default_callsign,
    key_passphrase: ?[]const u8 = null,
    /// Path to an Ed25519 secret key file (PEM PKCS#8, OpenSSH, or raw 64
    /// bytes; auto-detected). Mutually exclusive with `key_passphrase` — the
    /// user either derives a key from a passphrase or brings their own
    /// pre-generated key file.
    key_file: ?[]const u8 = null,
    /// Handle to pre-fill the registration form and/or salt the KDF.
    handle: ?[]const u8 = null,
    /// Hex-encoded Ed25519 public key (64 hex chars) of the BBS to trust for
    /// server-originated messages. When set, the client hard-locks this key
    /// and ignores server public keys received over the air.
    bbs_key_hex: ?[]const u8 = null,
    /// Use an in-memory SQLite database — never read or write
    /// `client_store.sqlite` to disk.
    in_memory: bool = false,
};

const usage =
    \\Usage: bbs [options]
    \\
    \\Launches the interactive terminal UI.
    \\
    \\Options:
    \\  --connect <url>     Transport endpoint (single use).
    \\                      agwpe://host:port[:kport]   — AGWPE TNC (radio)
    \\                      tcp://host:port             — direct TCP
    \\                      meshcore://<device>[:baud]  — MeshCore radio on a
    \\                                                    serial port (/dev/ttyUSB0,
    \\                                                    COM6 on Windows)
    \\                      host:port[:kport]           — bare (defaults to AGWPE)
    \\  --callsign <str>    Source callsign for AX.25 header (default: NOCALL)
    \\  --handle <str>      Handle for registration (salts the KDF with --key)
    \\  --key <passphrase>  Derive Ed25519 signing key from passphrase (HKDF-SHA256)
    \\  --key-file <path>  Load Ed25519 secret key from a file (PEM PKCS#8,
    \\                      OpenSSH, or raw 64 bytes). Mutually exclusive with --key.
    \\  --bbs-key <hex>     Hex Ed25519 public key (64 chars) of the BBS to trust.
    \\                      Hard-locks the server key; if omitted the client
    \\                      trusts the public key advertised by any server.
    \\  --in-memory         Use an in-memory database; never touch disk.
    \\  -h, --help          Show this help
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer: Io.File.Writer = .init(.stderr(), io, &stderr_buf);
    const stderr = &stderr_writer.interface;
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    const argv = try init.minimal.args.toSlice(arena);

    const parsed = parseArgs(arena, argv[1..]) catch |err| {
        try stderr.writeAll(usage);
        try stderr.print("\nerror: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return;
    };
    if (parsed == .help) {
        try stderr.writeAll(usage);
        try stderr.flush();
        return;
    }
    const o = parsed.run;

    // Validate --bbs-key hex (if provided) before launching the TUI.
    if (o.bbs_key_hex) |hex| {
        if (parseBbsKeyHex(hex) == null) {
            try stderr.print("error: --bbs-key must be 64 hex chars (32-byte Ed25519 public key)\n", .{});
            try stderr.flush();
            return;
        }
    }

    // Format the connect URI for the duplicate-notice (if any).
    var startup_notice: ?[]const u8 = null;
    if (o.duplicate_connect_notice) |notice| {
        startup_notice = notice;
    }

    // Pre-fill TUI fields from CLI options.
    try tui.run(init, .{
        .connect = o.connect,
        .startup_notice = startup_notice,
        .callsign = o.callsign,
        .handle = o.handle,
        .key_passphrase = o.key_passphrase,
        .key_file = o.key_file,
        .bbs_key_hex = o.bbs_key_hex,
        .in_memory = o.in_memory,
    });
    try stdout.flush();
}

const ParsedOptions = union(enum) { run: Options, help: void };

fn parseArgs(arena: std.mem.Allocator, args: []const [:0]const u8) !ParsedOptions {
    var opts = Options{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            return .help;
        } else if (std.mem.eql(u8, a, "--connect")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForConnect;
            const url = args[i];
            const ep = endpoint.parseEndpoint(url) catch return error.InvalidConnect;
            if (opts.connect == null) {
                // First --connect: use it.
                opts.connect = ep;
            } else {
                // Duplicate --connect: keep the first, set a notice.
                opts.duplicate_connect_notice = std.fmt.allocPrint(arena, "Only one --connect is supported. Using: {s}", .{url}) catch return error.OutOfMemory;
            }
        } else if (std.mem.eql(u8, a, "--callsign")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForCallsign;
            opts.callsign = args[i];
        } else if (std.mem.eql(u8, a, "--handle")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForHandle;
            opts.handle = args[i];
        } else if (std.mem.eql(u8, a, "--key")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForKey;
            opts.key_passphrase = args[i];
        } else if (std.mem.eql(u8, a, "--key-file")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForKeyFile;
            opts.key_file = args[i];
        } else if (std.mem.eql(u8, a, "--bbs-key")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForBbsKey;
            opts.bbs_key_hex = args[i];
        } else if (std.mem.eql(u8, a, "--in-memory")) {
            opts.in_memory = true;
        } else if (std.mem.startsWith(u8, a, "--")) {
            return error.UnknownOption;
        } else {
            return error.UnexpectedPositionalArg;
        }
    }
    // --key and --key-file are alternatives (derive vs. bring-your-own);
    // passing both is ambiguous and rejected.
    if (opts.key_passphrase != null and opts.key_file != null) {
        return error.KeyAndKeyFileBothGiven;
    }
    return .{ .run = opts };
}

/// Parse 64 hex chars into a 32-byte Ed25519 public key. Returns `null` if the
/// input is not exactly 64 hex characters.
fn parseBbsKeyHex(hex: []const u8) ?[32]u8 {
    if (hex.len != 64) return null;
    var key: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const hi = std.fmt.charToDigit(hex[i * 2], 16) catch return null;
        const lo = std.fmt.charToDigit(hex[i * 2 + 1], 16) catch return null;
        key[i] = (hi << 4) | lo;
    }
    return key;
}

test "parseBbsKeyHex accepts 64 hex chars" {
    const hex = "0123456789abcdef" ** 2 ++ "0123456789ABCDEF" ** 2;
    const key = parseBbsKeyHex(hex) orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(usize, 32), key.len);
    try std.testing.expectEqual(@as(u8, 0x01), key[0]);
    try std.testing.expectEqual(@as(u8, 0xef), key[15]);
    try std.testing.expectEqual(@as(u8, 0x01), key[16]);
    try std.testing.expectEqual(@as(u8, 0xEF), key[31]);
}

test "parseBbsKeyHex rejects bad lengths and bad chars" {
    try std.testing.expect(parseBbsKeyHex("00") == null);
    try std.testing.expect(parseBbsKeyHex("zz" ** 32) == null);
}

test "parseArgs --connect agwpe with kport" {
    const allocator = std.testing.allocator;
    const args = [_][:0]const u8{ "--connect", "agwpe://127.0.0.1:8000:1" };
    const result = try parseArgs(allocator, &args);
    const o = result.run;
    try std.testing.expect(o.connect != null);
    const ep = o.connect.?;
    try std.testing.expectEqual(endpoint.TransportKind.agwpe, ep.kind);
    try std.testing.expectEqualStrings("127.0.0.1", ep.host);
    try std.testing.expectEqual(@as(u16, 8000), ep.port);
    try std.testing.expectEqual(@as(u4, 1), ep.kport);
}

test "parseArgs --connect tcp" {
    const allocator = std.testing.allocator;
    const args = [_][:0]const u8{ "--connect", "tcp://127.0.0.1:9000" };
    const result = try parseArgs(allocator, &args);
    const o = result.run;
    try std.testing.expect(o.connect != null);
    const ep = o.connect.?;
    try std.testing.expectEqual(endpoint.TransportKind.tcp, ep.kind);
    try std.testing.expectEqualStrings("127.0.0.1", ep.host);
    try std.testing.expectEqual(@as(u16, 9000), ep.port);
}

test "parseArgs --connect bare defaults to agwpe" {
    const allocator = std.testing.allocator;
    const args = [_][:0]const u8{ "--connect", "127.0.0.1:8000:0" };
    const result = try parseArgs(allocator, &args);
    const o = result.run;
    try std.testing.expect(o.connect != null);
    const ep = o.connect.?;
    try std.testing.expectEqual(endpoint.TransportKind.agwpe, ep.kind);
    try std.testing.expectEqualStrings("127.0.0.1", ep.host);
    try std.testing.expectEqual(@as(u16, 8000), ep.port);
}

test "parseArgs --connect duplicate keeps first and sets notice" {
    const allocator = std.testing.allocator;
    const args = [_][:0]const u8{ "--connect", "tcp://127.0.0.1:9000", "--connect", "agwpe://10.0.0.1:8000:0" };
    const result = try parseArgs(allocator, &args);
    const o = result.run;
    // First connect is kept.
    try std.testing.expect(o.connect != null);
    const ep = o.connect.?;
    try std.testing.expectEqual(endpoint.TransportKind.tcp, ep.kind);
    try std.testing.expectEqualStrings("127.0.0.1", ep.host);
    // Notice is set.
    try std.testing.expect(o.duplicate_connect_notice != null);
    const notice = o.duplicate_connect_notice.?;
    try std.testing.expect(std.mem.indexOf(u8, notice, "Only one") != null);
    try std.testing.expect(std.mem.indexOf(u8, notice, "agwpe://10.0.0.1:8000:0") != null);
    allocator.free(notice);
}

test "parseArgs --callsign and --handle" {
    const allocator = std.testing.allocator;
    const args = [_][:0]const u8{ "--callsign", "KE8WIF", "--handle", "myhandle" };
    const result = try parseArgs(allocator, &args);
    const o = result.run;
    try std.testing.expectEqualStrings("KE8WIF", o.callsign);
    try std.testing.expect(o.handle != null);
    try std.testing.expectEqualStrings("myhandle", o.handle.?);
}

test "parseArgs --key-file sets key_file and leaves key_passphrase null" {
    const allocator = std.testing.allocator;
    const args = [_][:0]const u8{ "--key-file", "/tmp/my.key" };
    const result = try parseArgs(allocator, &args);
    const o = result.run;
    try std.testing.expect(o.key_file != null);
    try std.testing.expectEqualStrings("/tmp/my.key", o.key_file.?);
    try std.testing.expect(o.key_passphrase == null);
}

test "parseArgs rejects --key and --key-file together" {
    const allocator = std.testing.allocator;
    const args = [_][:0]const u8{ "--key", "mypass", "--key-file", "/tmp/my.key" };
    try std.testing.expectError(error.KeyAndKeyFileBothGiven, parseArgs(allocator, &args));
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test {
    std.testing.refAllDecls(@import("client_store.zig"));
    std.testing.refAllDecls(@import("tui/connection.zig"));
    std.testing.refAllDecls(@import("tui/render.zig"));
    std.testing.refAllDecls(@import("tui/widgets/avatar_preview.zig"));
}

test "fuzz example" {
    try std.testing.fuzz({}, testOne, .{});
}

fn testOne(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    const gpa = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    while (!smith.eos()) switch (smith.value(enum { add_data, dup_data })) {
        .add_data => {
            const slice = try list.addManyAsSlice(gpa, smith.value(u4));
            smith.bytes(slice);
        },
        .dup_data => {
            if (list.items.len == 0) continue;
            if (list.items.len > std.math.maxInt(u32)) return error.SkipZigTest;
            const len = smith.valueRangeAtMost(u32, 1, @min(32, list.items.len));
            const off = smith.valueRangeAtMost(u32, 0, @intCast(list.items.len - len));
            try list.appendSlice(gpa, list.items[off..][0..len]);
            try std.testing.expectEqualSlices(
                u8,
                list.items[off..][0..len],
                list.items[list.items.len - len ..],
            );
        },
    };
}
