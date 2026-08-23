//! Protocol-prefixed endpoint URL parsing for transport addresses.
//!
//! Parses strings like `agwpe://127.0.0.1:8000:0` or `tcp://0.0.0.0:9000` into
//! a `TransportEndpoint` that identifies the protocol kind and the
//! host/port/kport triple. Used by both the server (`--connect`, `--listen`)
//! and the client (connection settings) so endpoint strings are parsed
//! identically on both sides.
//!
//! Formats:
//!   `agwpe://host:port[:kport]` — outbound AGWPE TNC connection
//!   `tcp://host:port`           — direct TCP (outbound connect or inbound listen)
//!   `host:port[:kport]`         — bare form (no protocol prefix) defaults to
//!                                  AGWPE for backward compatibility

const std = @import("std");

/// The kind of transport identified by a URL prefix.
pub const TransportKind = enum {
    /// AGWPE TNC over TCP (e.g. Direwolf). Outbound connect only.
    agwpe,
    /// Direct TCP/IP — no AX.25 / radio layer. Can be outbound (client) or
    /// inbound (server listen).
    tcp,
};

/// A parsed transport endpoint: the protocol kind plus host/port/kport.
pub const TransportEndpoint = struct {
    kind: TransportKind,
    host: []const u8,
    port: u16,
    /// Radio channel (AGWPE only; always 0 for TCP).
    kport: u4 = 0,
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
///   `host:port[:kport]` (bare — defaults to AGWPE)
pub fn parseEndpoint(s: []const u8) ParseError!TransportEndpoint {
    if (std.mem.startsWith(u8, s, "agwpe://")) {
        return parseHostPortKport(s[8..], .agwpe);
    } else if (std.mem.startsWith(u8, s, "tcp://")) {
        return parseHostPortKport(s[6..], .tcp);
    } else {
        // Bare form — backward-compatible default to AGWPE.
        return parseHostPortKport(s, .agwpe);
    }
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

test "parseEndpoint rejects missing port" {
    try std.testing.expectError(ParseError.InvalidFormat, parseEndpoint("tcp://127.0.0.1"));
}

test "parseEndpoint rejects bad port" {
    try std.testing.expectError(ParseError.InvalidPort, parseEndpoint("tcp://127.0.0.1:abc"));
}
