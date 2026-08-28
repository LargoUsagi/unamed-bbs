//! CLI argument parsing for the bulletin server.
//!
//! Supports multiple outbound transports via repeated `--connect` flags with
//! a protocol prefix (`agwpe://host:port[:kport]`, `tcp://host:port`, or
//! `meshcore:///dev/ttyUSB0[:baud]`).
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
    /// Network kinds: hostname/IP. Meshcore: serial device path.
    host: []const u8,
    port: u16,
    kport: u4,
    /// Serial baud rate (meshcore only; ignored by network kinds).
    baud: u32 = endpoint.meshcore_default_baud,
};

pub const Options = struct {
    /// Outbound transport endpoints (AGWPE TNCs or TCP targets). Populated
    /// from `--connect` flags.
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

pub const usage =
    \\Usage: kiss_server [options]
    \\
    \\Bulletin server. Connects to one or more outbound transports and/or
    \\listens for inbound TCP connections. Broadcasts are sent to ALL
    \\connected transports; directed responses go to the source transport.
    \\
    \\Options:
    \\  --connect <url>    Outbound transport endpoint (repeatable).
    \\                     agwpe://host:port[:kport]   — AGWPE TNC (default)
    \\                     tcp://host:port             — direct TCP
    \\                     meshcore://<device>[:baud]  — MeshCore radio on a
    \\                                                   serial port (/dev/ttyUSB0,
    \\                                                   COM6 on Windows)
    \\                     host:port[:kport]           — bare (AGWPE)
    \\  --listen <url>     Inbound TCP listener (repeatable).
    \\                     tcp://host:port
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
            opts.connects.append(arena, .{ .kind = ep.kind, .host = ep.host, .port = ep.port, .kport = ep.kport, .baud = ep.baud }) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, a, "--listen")) {
            i += 1;
            if (i >= args.len) return error.MissingValueForListen;
            const ep = endpoint.parseEndpoint(args[i]) catch return error.InvalidListen;
            if (ep.kind != .tcp) return error.ListenMustBeTcp;
            opts.listens.append(arena, .{ .kind = ep.kind, .host = ep.host, .port = ep.port, .kport = 0 }) catch return error.OutOfMemory;
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
