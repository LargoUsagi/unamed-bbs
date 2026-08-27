//! `public_key_request` message type — empty payload used by clients to ask
//! the bulletin server to broadcast its public key. Wire size is 0 bytes.

const std = @import("std");

/// Serialize a `public_key_request` payload. Always returns 0 (empty payload).
pub fn encode(buf: []u8) usize {
    _ = buf;
    return 0;
}

/// Deserialize a `public_key_request` payload. The data is ignored — the
/// payload is always `void`. Returns `void` (never fails).
pub fn decode(data: []const u8) void {
    _ = data;
}

test "public_key_request encode writes zero bytes" {
    var buf: [512]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), encode(&buf));
}

test "public_key_request decode returns void" {
    _ = decode(&.{});
    _ = decode(&.{ 0x01, 0x02 });
}
