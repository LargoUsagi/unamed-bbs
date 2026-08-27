//! `user_info_list` message type — a batched list of `UserInfo` records,
//! the server's response to a `user_info_request`. Batching into one frame
//! (multipart-split when it exceeds a single packet) replaces the former
//! one-`user_info`-per-id reply so that a request for N users produces one
//! message instead of N — a meaningful saving over slow radio links.
//!
//! Each entry is a full `UserInfo` (id, handle, callsign, public key,
//! registered_datetime, is_sysop, avatar) with its own length prefix so the
//! decoder can slice out one record at a time without relying on
//! `UserInfo.decode`'s consumed length.
//!
//! Wire layout:
//!   `count` (u8) + per entry: `entry_len` (u16 LE) + <UserInfo bytes>

const std = @import("std");
const limits = @import("limits.zig");
const user_info = @import("user_info.zig");

const max_encode_len = limits.max_encode_len;

const UserInfo = user_info.UserInfo;

/// Batched list of `UserInfo` records — the server's response to a
/// `user_info_request`. Replaces N individual `user_info` frames with one
/// (multipart-split when large).
pub const UserInfoList = struct {
    users: []const UserInfo,

    /// Serialize into `buf`. Returns the number of bytes written, or `null` if
    /// there are more than 255 entries, any single entry exceeds 65535 bytes,
    /// or the total exceeds `max_encode_len`. Mirrors `BulletinList.encode`.
    pub fn encode(self: UserInfoList, buf: []u8) ?usize {
        if (self.users.len > 255) return null;

        var pos: usize = 0;
        if (buf.len < 1) return null;
        buf[pos] = @intCast(self.users.len);
        pos += 1;

        var entry_buf: [max_encode_len]u8 = undefined;
        for (self.users) |entry| {
            const n = entry.encode(&entry_buf) orelse return null;
            const needed = pos + 2 + n;
            if (needed > buf.len) return null;
            if (needed > max_encode_len) return null;
            std.mem.writeInt(u16, buf[pos..][0..2], @intCast(n), .little);
            pos += 2;
            @memcpy(buf[pos..][0..n], entry_buf[0..n]);
            pos += n;
        }
        return pos;
    }

    /// Deserialize from `data`. Allocates the `users` slice and each entry's
    /// owned `handle`/`callsign`/`avatar` — the caller must call `deinit` to
    /// free. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?UserInfoList {
        if (data.len < 1) return null;
        const count: usize = data[0];
        var pos: usize = 1;
        var users = try allocator.alloc(UserInfo, count);
        var filled: usize = 0;
        errdefer {
            for (users[0..filled]) |u| u.deinit(allocator);
            allocator.free(users);
        }
        for (0..count) |i| {
            if (data.len < pos + 2) {
                for (users[0..filled]) |u| u.deinit(allocator);
                allocator.free(users);
                return null;
            }
            const entry_len: usize = std.mem.readInt(u16, data[pos..][0..2], .little);
            pos += 2;
            if (data.len < pos + entry_len) {
                for (users[0..filled]) |u| u.deinit(allocator);
                allocator.free(users);
                return null;
            }
            const u = (try UserInfo.decode(allocator, data[pos .. pos + entry_len])) orelse {
                for (users[0..filled]) |entry| entry.deinit(allocator);
                allocator.free(users);
                return null;
            };
            users[i] = u;
            filled = i + 1;
            pos += entry_len;
        }
        return .{ .users = users };
    }

    /// Free heap-allocated slices inside a `UserInfoList` produced by `decode`.
    pub fn deinit(self: UserInfoList, allocator: std.mem.Allocator) void {
        for (self.users) |u| u.deinit(allocator);
        allocator.free(@constCast(self.users));
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "user_info_list encode/decode round trip" {
    const allocator = std.testing.allocator;
    const pk_a = [_]u8{0xAB} ** 32;
    const pk_b = [_]u8{0xCD} ** 32;
    const users = [_]UserInfo{
        .{
            .id = 7,
            .registered_datetime = 1724022400,
            .handle = "brad",
            .callsign = "KE8WIF",
            .public_key = pk_a,
            .is_sysop = true,
            .avatar = "█ █\n █ \n█ █",
        },
        .{
            .id = 42,
            .registered_datetime = 1724022401,
            .handle = "kim",
            .callsign = "K2ABC",
            .public_key = pk_b,
            .is_sysop = false,
            .avatar = &.{},
        },
    };

    var buf: [max_encode_len]u8 = undefined;
    const n = (UserInfoList{ .users = &users }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try UserInfoList.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), decoded.users.len);
    try std.testing.expectEqual(@as(u16, 7), decoded.users[0].id);
    try std.testing.expectEqualStrings("brad", decoded.users[0].handle);
    try std.testing.expectEqualStrings("KE8WIF", decoded.users[0].callsign);
    try std.testing.expectEqualSlices(u8, &pk_a, &decoded.users[0].public_key);
    try std.testing.expect(decoded.users[0].is_sysop);
    try std.testing.expectEqualStrings("█ █\n █ \n█ █", decoded.users[0].avatar);
    try std.testing.expectEqual(@as(u16, 42), decoded.users[1].id);
    try std.testing.expectEqualStrings("kim", decoded.users[1].handle);
    try std.testing.expectEqual(@as(usize, 0), decoded.users[1].avatar.len);
}

test "user_info_list with empty list encode/decode round trip" {
    const allocator = std.testing.allocator;
    var buf: [max_encode_len]u8 = undefined;
    const n = (UserInfoList{ .users = &.{} }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 1), n);

    const decoded = (try UserInfoList.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), decoded.users.len);
}

test "user_info_list encode rejects > 255 entries" {
    var many: [256]UserInfo = undefined;
    for (&many) |*e| e.* = .{
        .id = 0,
        .registered_datetime = 0,
        .handle = "",
        .callsign = "",
        .public_key = [_]u8{0} ** 32,
    };
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect((UserInfoList{ .users = &many }).encode(&buf) == null);
}

test "user_info_list decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{0x01, 0x02};
    const result = try UserInfoList.decode(allocator, &short);
    try std.testing.expect(result == null);
}
