//! `registration_ack` message type — the server's response to a client
//! `registration` message. Indicates whether the registration succeeded and,
//! if so, the u16 user id the server assigned (and will use to identify the
//! author in subsequent bulletins).
//!
//! Wire layout:
//!   `ok` (u8: 0 = failed, 1 = succeeded) + `user_id` (u16 LE) = 3 bytes

const std = @import("std");
const limits = @import("limits.zig");

const max_chunk_len = limits.max_chunk_len;

/// Server response to a `registration` message.
pub const RegistrationAck = struct {
    /// True if the registration was accepted and stored.
    ok: bool,
    /// The server-assigned user id (valid when `ok` is true).
    user_id: u16,

    /// Serialize into `buf`. Always writes exactly 3 bytes.
    pub fn encode(self: RegistrationAck, buf: []u8) ?usize {
        if (buf.len < 3) return null;
        buf[0] = if (self.ok) 1 else 0;
        std.mem.writeInt(u16, buf[1..3], self.user_id, .little);
        return 3;
    }

    /// Deserialize from `data`. Returns `null` if `data` is too short. No
    /// allocation.
    pub fn decode(data: []const u8) ?RegistrationAck {
        if (data.len < 3) return null;
        return .{
            .ok = data[0] != 0,
            .user_id = std.mem.readInt(u16, data[1..3], .little),
        };
    }
};

test "registration_ack encode/decode round trip (ok)" {
    var buf: [max_chunk_len]u8 = undefined;
    const n = (RegistrationAck{ .ok = true, .user_id = 42 }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, 1), buf[0]);

    const decoded = RegistrationAck.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expect(decoded.ok);
    try std.testing.expectEqual(@as(u16, 42), decoded.user_id);
}

test "registration_ack encode/decode round trip (fail)" {
    var buf: [max_chunk_len]u8 = undefined;
    const n = (RegistrationAck{ .ok = false, .user_id = 0 }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(u8, 0), buf[0]);

    const decoded = RegistrationAck.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expect(!decoded.ok);
    try std.testing.expectEqual(@as(u16, 0), decoded.user_id);
}

test "registration_ack decode rejects too-short data" {
    const short = [_]u8{ 0x01, 0x02 };
    try std.testing.expect(RegistrationAck.decode(&short) == null);
}
