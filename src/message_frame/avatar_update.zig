//! `avatar_update` message type — a client requests a change to its own
//! avatar (the 11×7 ASCII art shown alongside its posts and profile).
//!
//! The payload is signed by the client's secret key. The server identifies
//! the sender by verifying the signature against every stored public key
//! (callsigns are not unique, so signature identity is the only secure way),
//! updates that user's `avatar` column, and re-broadcasts the updated
//! `user_info` so all clients refresh their cache.
//!
//! Wire layout:
//!   `avatar_len` (u8, 1B) + `avatar` (up to 255 bytes)

const std = @import("std");
const frame = @import("frame.zig");

const max_payload_len = frame.max_payload_len;

/// A client's request to update its own avatar. The sender is identified by
/// the signature on the payload (verified against stored public keys), not by
/// any field carried in the payload — so a forged callsign cannot be used to
/// impersonate another user.
pub const AvatarUpdate = struct {
    /// New avatar text (7 lines joined by '\n', '█'/' ' cells). Max 255 bytes.
    avatar: []const u8,

    /// Serialize into `buf`. Returns the number of bytes written, or `null` if
    /// the avatar exceeds 255 bytes or `buf` is too small.
    pub fn encode(self: AvatarUpdate, buf: []u8) ?usize {
        if (self.avatar.len > 255) return null;
        const total = 1 + self.avatar.len;
        if (total > max_payload_len) return null;
        if (buf.len < total) return null;

        var pos: usize = 0;
        buf[pos] = @intCast(self.avatar.len);
        pos += 1;
        @memcpy(buf[pos..][0..self.avatar.len], self.avatar);
        pos += self.avatar.len;
        return pos;
    }

    /// Deserialize from `data`. Allocates the `avatar` slice — the caller must
    /// call `deinit` to free. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?AvatarUpdate {
        if (data.len < 1) return null;
        const avatar_len: usize = data[0];
        if (data.len < 1 + avatar_len) return null;
        const avatar = try allocator.dupe(u8, data[1 .. 1 + avatar_len]);
        return .{ .avatar = avatar };
    }

    /// Free the `avatar` slice allocated by `decode`.
    pub fn deinit(self: AvatarUpdate, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.avatar));
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "avatar_update encode/decode round trip" {
    const allocator = std.testing.allocator;
    const avatar_str = "█  █  █\n █ █ █ \n█  █  █";
    const au: AvatarUpdate = .{ .avatar = avatar_str };

    var buf: [max_payload_len]u8 = undefined;
    const n = au.encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 1 + avatar_str.len), n);

    const decoded = (try AvatarUpdate.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings(avatar_str, decoded.avatar);
}

test "avatar_update encode rejects avatar > 255 bytes" {
    const long_avatar = [_]u8{'x'} ** 256;
    var buf: [max_payload_len]u8 = undefined;
    try std.testing.expect((AvatarUpdate{ .avatar = &long_avatar }).encode(&buf) == null);
}

test "avatar_update decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{0x05};
    const result = try AvatarUpdate.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "avatar_update encode/decode with empty avatar" {
    const allocator = std.testing.allocator;
    var buf: [max_payload_len]u8 = undefined;
    const n = (AvatarUpdate{ .avatar = "" }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 1), n);

    const decoded = (try AvatarUpdate.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), decoded.avatar.len);
}
