//! `public_key` message type — carries an Ed25519 public key with a role tag
//! distinguishing client keys from the bulletin server's key.
//!
//! Wire layout: 1 role byte (u4 in the low nibble, high nibble zero/reserved)
//! followed by the 32-byte Ed25519 public key (33 bytes total).

const std = @import("std");
const frame = @import("frame.zig");

const max_payload_len = frame.max_payload_len;

/// Role encoded in a `public_key` message (u4, stored in the low nibble of the
/// first payload byte). Clients mark their key with `.client`; a bulletin
/// server marks its key with `.server` so receivers know which key to trust
/// for server-originated messages (bulletin lists, etc.).
pub const PublicKeyRole = enum(u4) {
    client = 0,
    server = 1,
    _,
};

/// Payload of a `public_key` message.
pub const PublicKeyPayload = struct {
    role: PublicKeyRole,
    public_key: [32]u8,

    /// Serialize into `buf`. Always writes exactly 33 bytes. Returns `null`
    /// only if `buf` is smaller than 33 bytes.
    pub fn encode(self: PublicKeyPayload, buf: []u8) ?usize {
        if (buf.len < 33) return null;
        buf[0] = @intCast(@intFromEnum(self.role));
        @memcpy(buf[1..33], &self.public_key);
        return 33;
    }

    /// Deserialize from `data`. Returns `null` if `data` is too short. No
    /// allocation — the result is a value type.
    pub fn decode(data: []const u8) ?PublicKeyPayload {
        if (data.len < 33) return null;
        const role: PublicKeyRole = @enumFromInt(@as(u4, @truncate(data[0])));
        var pk: [32]u8 = undefined;
        @memcpy(&pk, data[1..33]);
        return .{ .role = role, .public_key = pk };
    }
};

test "public_key encode/decode round trip (server role)" {
    const pk = [_]u8{0x42} ** 32;
    const payload: PublicKeyPayload = .{ .role = .server, .public_key = pk };

    var buf: [max_payload_len]u8 = undefined;
    const n = payload.encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 33), n);
    try std.testing.expectEqual(@as(u8, 1), buf[0]);

    const decoded = PublicKeyPayload.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expectEqual(PublicKeyRole.server, decoded.role);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.public_key);
}

test "public_key encode/decode round trip (client role)" {
    const pk = [_]u8{0xAB} ** 32;
    const payload: PublicKeyPayload = .{ .role = .client, .public_key = pk };

    var buf: [max_payload_len]u8 = undefined;
    const n = payload.encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(u8, 0), buf[0]);

    const decoded = PublicKeyPayload.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expectEqual(PublicKeyRole.client, decoded.role);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.public_key);
}

test "public_key decode rejects too-short data" {
    const short = [_]u8{ 0x00, 0x01, 0x02 };
    try std.testing.expect(PublicKeyPayload.decode(&short) == null);
}
