//! CLI argument parsing for the bulletin server.
//!
//! Supports multiple outbound transports via repeated `--connect` flags with
//! a protocol prefix (`agwpe://host:port[:kport]` or `tcp://host:port`).
//! A single `--host`/`--port` pair is accepted as backward-compatible
//! shorthand for one AGWPE transport.
//!
//! `--listen` flags create inbound TCP listeners (`tcp://host:port`) that
//! accept direct client connections without a TNC.

const std = @import("std");
const endpoint = @import("bbs").endpoint;

pub const default_host = "127.0.0.1";
pub const default_tcp_port: u16 = 8000;
pub const default_kiss_port: u4 = 0;
pub const default_callsign = "NOCALL";
pub const default_store_path = "bulletins.kblt";

/// One transport endpoint — either outbound (connect) or inbound (listen).
pub const TransportSpec = struct {
    kind: endpoint.TransportKind,
    host: []const u8,
    port: u16,
    kport: u4,
};

pub const Options = struct {
    /// Outbound transport endpoints (AGWPE TNCs or TCP targets). Populated
    /// from `--connect` flags (or the legacy `--host`/`--port`/`--kport`
    /// shorthand).
    connects: std.ArrayList(TransportSpec) = .empty,
    /// Inbound transport endpoints (TCP listeners). Populated from
    /// `--listen` flags.
    listens: std.ArrayList(TransportSpec) = .empty,
    callsign: []const u8 = default_callsign,
    key_passphrase: ?[]const u8 = null,
    /// Path to an Ed25519 secret key file (PEM PKCS#8, OpenSSH, or raw 64
    /// bytes; auto-detected). Mutually exclusive with `key_passphrase`.
    key_file: ?[]const u8 = null,
    store_path: []const u8 = default_store_path,
};

/// Backward-compat: `transports` is now `connects`. Kept as a deprecated
/// alias so `main.zig` references can be updated incrementally.
pub fn transports(opts: *const Options) []const TransportSpec {
    return opts.connects.items;
}

pub const usage =
    \\Usage: kiss_server [options]
    \\
    \\Bulletin server. Connects to one or more outbound transports and/or
    \\listens for inbound TCP connections. Broadcasts are sent to ALL
    \\connected transports; directed responses go to the source transport.
    \\
    \\Options:
    \\  --connect <url>    Outbound transport endpoint (repeatable).
    \\                     agwpe://host:port[:kport] — AGWPE TNC (default)
    \\                     tcp://host:port           — direct TCP
    \\                     host:port[:kport]          — bare (AGWPE)
    \\  --listen <url>     Inbound TCP listener (repeatable).
    \\                     tcp://host:port
    \\  --host <addr>      Single AGWPE transport: host (shorthand)
    \\  --port <n>         Single AGWPE transport: TCP port (default: 8000)
    \\  --kport <0-15>     Single AGWPE transport: radio channel (default: 0)
    \\  --callsign <str>   Server callsign for AX.25 header (default: NOCALL)
    \\  --key <passphrase> Derive Ed25519 signing key from passphrase
    \\  --key-file <path>  Load Ed25519 secret key from a file (PEM PKCS#8,
    \\                      OpenSSH, or raw 64 bytes). Mutually exclusive with --key.
    \\  --store <path>     Bulletin persistence file (default: bulletins.kblt)
    \\  -h, --help         Show this help
    \\
;

pub const ParsedOptions = union(enum) { run: Options, help: void };

pub fn parseArgs(arena: std.mem.Allocator, args: []const [:0]const u8) !ParsedOptions {
    var opts = Options{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            return .help;
        } else if (std.mem.eql(u8, a, "--connect")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForConnect;
            const ep = endpoint.parseEndpoint(args[i]) catch return error.InvalidConnect;
            opts.connects.append(arena, .{ .kind = ep.kind, .host = ep.host, .port = ep.port, .kport = ep.kport }) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, a, "--listen")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForListen;
            const ep = endpoint.parseEndpoint(args[i]) catch return error.InvalidListen;
            if (ep.kind != .tcp) return error.ListenMustBeTcp;
            opts.listens.append(arena, .{ .kind = ep.kind, .host = ep.host, .port = ep.port, .kport = 0 }) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, a, "--host")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForHost;
            const host = args[i];
            const port = if (opts.connects.items.len > 0 and opts.connects.items[opts.connects.items.len - 1].host.len == 0)
                opts.connects.items[opts.connects.items.len - 1].port
            else
                default_tcp_port;
            opts.connects.append(arena, .{ .kind = .agwpe, .host = host, .port = port, .kport = default_kiss_port }) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, a, "--port")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForPort;
            const port = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidPort;
            if (opts.connects.items.len > 0) {
                opts.connects.items[opts.connects.items.len - 1].port = port;
            } else {
                opts.connects.append(arena, .{ .kind = .agwpe, .host = "", .port = port, .kport = default_kiss_port }) catch return error.OutOfMemory;
            }
        } else if (std.mem.eql(u8, a, "--kport")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForKport;
            const kport = std.fmt.parseInt(u4, args[i], 10) catch return error.InvalidKport;
            if (opts.connects.items.len > 0) {
                opts.connects.items[opts.connects.items.len - 1].kport = kport;
            } else {
                return error.KportWithoutHost;
            }
        } else if (std.mem.eql(u8, a, "--callsign")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForCallsign;
            opts.callsign = args[i];
        } else if (std.mem.eql(u8, a, "--key")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForKey;
            opts.key_passphrase = args[i];
        } else if (std.mem.eql(u8, a, "--key-file")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForKeyFile;
            opts.key_file = args[i];
        } else if (std.mem.eql(u8, a, "--store")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForStore;
            opts.store_path = args[i];
        } else if (std.mem.startsWith(u8, a, "--")) {
            return error.UnknownOption;
        } else {
            return error.UnexpectedPositional;
        }
    }

    // --key and --key-file are alternatives (derive vs. bring-your-own);
    // passing both is ambiguous and rejected.
    if (opts.key_passphrase != null and opts.key_file != null) {
        return error.KeyAndKeyFileBothGiven;
    }

    // If no connects or listens specified, add a default AGWPE connect.
    if (opts.connects.items.len == 0 and opts.listens.items.len == 0) {
        opts.connects.append(arena, .{ .kind = .agwpe, .host = default_host, .port = default_tcp_port, .kport = default_kiss_port }) catch return error.OutOfMemory;
    }

    return .{ .run = opts };
}
