//! Protocol-prefixed endpoint URL parsing for transport addresses.
//!
//! Parses strings like `agwpe://127.0.0.1:8000:0`, `tcp://0.0.0.0:9000`, or
//! `meshcore:///dev/ttyUSB0` into a `TransportEndpoint` that identifies the
//! protocol kind plus its address parameters. Used by both the server
//! (`--connect`, `--listen`) and the client (connection settings) so
//! endpoint strings are parsed identically on both sides.
//!
//! Formats:
//!   `agwpe://host:port[:kport]`      — outbound AGWPE TNC connection
//!   `tcp://host:port`                — direct TCP (outbound connect or inbound listen)
//!   `meshcore:///dev/ttyUSB0[:baud]` — MeshCore companion radio on a local
//!                                       serial port (outbound connect only);
//!                                       baud defaults to 115200. Windows:
//!                                       `meshcore://COM6` — bare COM port
//!                                       names are auto-translated to the
//!                                       Win32 device namespace on open, and
//!                                       explicit `meshcore://\\.\COM6`
//!                                       also works.
//!   `host:port[:kport]`              — bare form (no protocol prefix) defaults to
//!                                      AGWPE for backward compatibility

const std = @import("std");

/// Default serial baud rate for MeshCore companion radios (8N1, no flow
/// control — the firmware standard).
pub const meshcore_default_baud: u32 = 115200;

/// The kind of transport identified by a URL prefix.
pub const TransportKind = enum {
    /// AGWPE TNC over TCP (e.g. Direwolf). Outbound connect only.
    agwpe,
    /// Direct TCP/IP — no AX.25 / radio layer. Can be outbound (client) or
    /// inbound (server listen).
    tcp,
    /// MeshCore companion radio over a local serial port. Outbound connect
    /// only (a serial link has no inbound accept path).
    meshcore,
};

/// A parsed transport endpoint: the protocol kind plus its address
/// parameters (host/port/kport triple for network kinds, device path +
/// baud for serial kinds).
pub const TransportEndpoint = struct {
    kind: TransportKind,
    /// Network kinds: hostname or IP. Serial kinds (meshcore): the OS
    /// device path, e.g. `/dev/ttyUSB0` or `\\\\.\\COM5`.
    host: []const u8,
    port: u16,
    /// Radio channel (AGWPE only; always 0 for TCP).
    kport: u4 = 0,
    /// Serial baud rate (meshcore only; ignored by network kinds).
    baud: u32 = meshcore_default_baud,
};

pub const ParseError = error{
    InvalidFormat,
    InvalidPort,
    InvalidKport,
    UnknownProtocol,
    MissingHost,
};

/// Parse a protocol-prefixed endpoint string.
///
/// Accepts:
///   `agwpe://host:port[:kport]`
///   `tcp://host:port`
///   `meshcore:///dev/ttyUSB0[:baud]`
///   `host:port[:kport]` (bare — defaults to AGWPE)
pub fn parseEndpoint(s: []const u8) ParseError!TransportEndpoint {
    if (std.mem.startsWith(u8, s, "agwpe://")) {
        return parseHostPortKport(s[8..], .agwpe);
    } else if (std.mem.startsWith(u8, s, "tcp://")) {
        return parseHostPortKport(s[6..], .tcp);
    } else if (std.mem.startsWith(u8, s, "meshcore://")) {
        return parseMeshcore(s[11..]);
    } else {
        // Bare form — backward-compatible default to AGWPE.
        return parseHostPortKport(s, .agwpe);
    }
}

/// Parse the body of a `meshcore://` URI: a device path with an optional
/// trailing `:baud` suffix. The path may contain slashes (and on Windows
/// backslashes), so only the LAST colon is treated as a separator, and only
/// when the remainder parses as a positive integer baud rate.
fn parseMeshcore(rest: []const u8) ParseError!TransportEndpoint {
    if (rest.len == 0) return ParseError.MissingHost;

    var device = rest;
    var baud: u32 = meshcore_default_baud;

    if (std.mem.lastIndexOfScalar(u8, rest, ':')) |colon| {
        const parsed = std.fmt.parseInt(u32, rest[colon + 1 ..], 10) catch null;
        if (parsed) |b| {
            if (b == 0) return ParseError.InvalidPort;
            baud = b;
            device = rest[0..colon];
        }
    }
    if (device.len == 0) return ParseError.MissingHost;

    return .{ .kind = .meshcore, .host = device, .port = 0, .baud = baud };
}

fn parseHostPortKport(rest: []const u8, kind: TransportKind) ParseError!TransportEndpoint {
    const first_colon = std.mem.indexOfScalar(u8, rest, ':') orelse return ParseError.InvalidFormat;
    const host = rest[0..first_colon];
    if (host.len == 0) return ParseError.MissingHost;

    const remainder = rest[first_colon + 1 ..];

    // Check for a second colon (separates port from kport — AGWPE only).
    if (std.mem.indexOfScalar(u8, remainder, ':')) |second_colon| {
        const port = std.fmt.parseInt(u16, remainder[0..second_colon], 10) catch return ParseError.InvalidPort;
        const kport = std.fmt.parseInt(u4, remainder[second_colon + 1 ..], 10) catch return ParseError.InvalidKport;
        return .{ .kind = kind, .host = host, .port = port, .kport = kport };
    } else {
        const port = std.fmt.parseInt(u16, remainder, 10) catch return ParseError.InvalidPort;
        return .{ .kind = kind, .host = host, .port = port, .kport = 0 };
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseEndpoint agwpe with kport" {
    const ep = try parseEndpoint("agwpe://127.0.0.1:8000:1");
    try std.testing.expectEqual(TransportKind.agwpe, ep.kind);
    try std.testing.expectEqualStrings("127.0.0.1", ep.host);
    try std.testing.expectEqual(@as(u16, 8000), ep.port);
    try std.testing.expectEqual(@as(u4, 1), ep.kport);
}

test "parseEndpoint agwpe without kport" {
    const ep = try parseEndpoint("agwpe://192.168.1.5:8000");
    try std.testing.expectEqual(TransportKind.agwpe, ep.kind);
    try std.testing.expectEqualStrings("192.168.1.5", ep.host);
    try std.testing.expectEqual(@as(u16, 8000), ep.port);
    try std.testing.expectEqual(@as(u4, 0), ep.kport);
}

test "parseEndpoint tcp" {
    const ep = try parseEndpoint("tcp://0.0.0.0:9000");
    try std.testing.expectEqual(TransportKind.tcp, ep.kind);
    try std.testing.expectEqualStrings("0.0.0.0", ep.host);
    try std.testing.expectEqual(@as(u16, 9000), ep.port);
    try std.testing.expectEqual(@as(u4, 0), ep.kport);
}

test "parseEndpoint bare defaults to agwpe" {
    const ep = try parseEndpoint("127.0.0.1:8000:0");
    try std.testing.expectEqual(TransportKind.agwpe, ep.kind);
    try std.testing.expectEqualStrings("127.0.0.1", ep.host);
    try std.testing.expectEqual(@as(u16, 8000), ep.port);
    try std.testing.expectEqual(@as(u4, 0), ep.kport);
}

test "parseEndpoint bare without kport" {
    const ep = try parseEndpoint("localhost:8000");
    try std.testing.expectEqual(TransportKind.agwpe, ep.kind);
    try std.testing.expectEqualStrings("localhost", ep.host);
    try std.testing.expectEqual(@as(u16, 8000), ep.port);
}

test "parseEndpoint rejects missing host" {
    try std.testing.expectError(ParseError.MissingHost, parseEndpoint("tcp://:9000"));
}

test "parseEndpoint meshcore with default baud" {
    const ep = try parseEndpoint("meshcore:///dev/ttyUSB0");
    try std.testing.expectEqual(TransportKind.meshcore, ep.kind);
    try std.testing.expectEqualStrings("/dev/ttyUSB0", ep.host);
    try std.testing.expectEqual(meshcore_default_baud, ep.baud);
    try std.testing.expectEqual(@as(u16, 0), ep.port);
}

test "parseEndpoint meshcore with explicit baud" {
    const ep = try parseEndpoint("meshcore:///dev/ttyACM0:230400");
    try std.testing.expectEqual(TransportKind.meshcore, ep.kind);
    try std.testing.expectEqualStrings("/dev/ttyACM0", ep.host);
    try std.testing.expectEqual(@as(u32, 230400), ep.baud);
}

test "parseEndpoint meshcore windows device path" {
    const ep = try parseEndpoint("meshcore://COM6");
    try std.testing.expectEqual(TransportKind.meshcore, ep.kind);
    try std.testing.expectEqualStrings("COM6", ep.host);
    try std.testing.expectEqual(meshcore_default_baud, ep.baud);
}

test "parseEndpoint meshcore windows win32 device namespace also accepted" {
    const ep = try parseEndpoint("meshcore://\\\\.\\COM12:115200");
    try std.testing.expectEqual(TransportKind.meshcore, ep.kind);
    try std.testing.expectEqualStrings("\\\\.\\COM12", ep.host);
    try std.testing.expectEqual(@as(u32, 115200), ep.baud);
}

test "parseEndpoint meshcore non-numeric suffix stays in the device path" {
    const ep = try parseEndpoint("meshcore:///dev/serial:odd");
    try std.testing.expectEqualStrings("/dev/serial:odd", ep.host);
    try std.testing.expectEqual(meshcore_default_baud, ep.baud);
}

test "parseEndpoint meshcore rejects empty and zero baud" {
    try std.testing.expectError(ParseError.MissingHost, parseEndpoint("meshcore://"));
    try std.testing.expectError(ParseError.InvalidPort, parseEndpoint("meshcore:///dev/ttyUSB0:0"));
}

test "parseEndpoint rejects missing port" {
    try std.testing.expectError(ParseError.InvalidFormat, parseEndpoint("tcp://127.0.0.1"));
}

test "parseEndpoint rejects bad port" {
    try std.testing.expectError(ParseError.InvalidPort, parseEndpoint("tcp://127.0.0.1:abc"));
}
