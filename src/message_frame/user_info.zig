//! `user_info` and `user_info_request` message types.
//!
//! `user_info` carries a user's full profile (id, handle, callsign, public
//! key, registered_datetime, avatar). The server broadcasts it to CQ whenever a
//! new user registers (so all clients can cache the new user) and in
//! response to a `user_info_request`.
//!
//! `user_info_request` is sent by a client to request user info for one or
//! more user_ids it doesn't have cached. The server responds with one
//! `user_info` message per requested id (skipping any unknown ids).
//!
//! Wire layout (handle, callsign, and avatar are Unishox2-compressed):
//!   `user_info`:
//!     `id` (u16 LE, 2B) + `registered_datetime` (u64 LE, 8B) +
//!     `handle_len` (u8, compressed byte count) + `handle` (compressed) +
//!     `callsign_len` (u8, compressed byte count) + `callsign` (compressed)
//!     + `public_key` (32B) + `is_sysop` (u8, 1B) +
//!     `avatar_len` (u8, compressed byte count) + `avatar` (compressed)
//!   `user_info_request`:
//!     `count` (u8, 1B) + per entry: `user_id` (u16 LE, 2B)

const std = @import("std");
const limits = @import("limits.zig");
const unishox2 = @import("../unishox2.zig");

const max_chunk_len = limits.max_chunk_len;

pub const public_key_len: usize = 32;

/// A user's full profile as cached from the server.
pub const UserInfo = struct {
    /// Server-assigned user id.
    id: u16,
    /// Server-set registration timestamp (Unix epoch seconds).
    registered_datetime: u64,
    /// Display name (handle). Caller owns this slice after `decode`.
    handle: []const u8,
    /// AX.25 callsign. Caller owns this slice after `decode`.
    callsign: []const u8,
    /// Ed25519 public key (32 bytes).
    public_key: [public_key_len]u8,
    /// True if this user is the system operator (admin). The first registered
    /// user on the server becomes the sysop.
    is_sysop: bool = false,
    /// Server-computed ASCII art avatar (7 lines joined by '\n'). May be empty
    /// for users registered before avatars were supported. Caller owns this
    /// slice after `decode`.
    avatar: []const u8 = &.{},

    /// Serialize into `buf`. Compresses handle, callsign, and avatar with
    /// Unishox2. Returns the number of bytes written, or `null` if any
    /// uncompressed field exceeds its limit, any compressed field exceeds
    /// 255 bytes, or `buf` is too small.
    pub fn encode(self: UserInfo, buf: []u8) ?usize {
        if (self.handle.len > limits.max_handle_len) return null;
        if (self.callsign.len > limits.max_callsign_len) return null;
        if (self.avatar.len > limits.max_avatar_len) return null;

        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const compressed_handle = unishox2.compress(alloc, self.handle) catch return null;
        if (compressed_handle.len > 255) return null;
        const compressed_callsign = unishox2.compress(alloc, self.callsign) catch return null;
        if (compressed_callsign.len > 255) return null;
        const compressed_avatar = unishox2.compress(alloc, self.avatar) catch return null;
        if (compressed_avatar.len > 255) return null;

        const fixed = 2 + 8 + 1 + 1 + public_key_len + 1 + 1;
        const total = fixed + compressed_handle.len + compressed_callsign.len + compressed_avatar.len;
        if (total > max_chunk_len) return null;
        if (buf.len < total) return null;

        var pos: usize = 0;
        std.mem.writeInt(u16, buf[pos..][0..2], self.id, .little);
        pos += 2;
        std.mem.writeInt(u64, buf[pos..][0..8], self.registered_datetime, .little);
        pos += 8;
        buf[pos] = @intCast(compressed_handle.len);
        pos += 1;
        @memcpy(buf[pos..][0..compressed_handle.len], compressed_handle);
        pos += compressed_handle.len;
        buf[pos] = @intCast(compressed_callsign.len);
        pos += 1;
        @memcpy(buf[pos..][0..compressed_callsign.len], compressed_callsign);
        pos += compressed_callsign.len;
        @memcpy(buf[pos..][0..public_key_len], &self.public_key);
        pos += public_key_len;
        buf[pos] = if (self.is_sysop) 1 else 0;
        pos += 1;
        buf[pos] = @intCast(compressed_avatar.len);
        pos += 1;
        @memcpy(buf[pos..][0..compressed_avatar.len], compressed_avatar);
        pos += compressed_avatar.len;
        return pos;
    }

    /// Deserialize from `data`. Decompresses handle, callsign, and avatar.
    /// Allocates each slice — the caller must call `deinit` to free. Returns
    /// `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?UserInfo {
        const min_len = 2 + 8 + 1 + 1 + public_key_len + 1 + 1;
        if (data.len < min_len) return null;
        var pos: usize = 0;
        const id = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;
        const registered_datetime = std.mem.readInt(u64, data[pos..][0..8], .little);
        pos += 8;
        const handle_len: usize = data[pos];
        pos += 1;
        if (data.len < pos + handle_len + 1 + public_key_len + 1 + 1) return null;
        const handle = if (handle_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + handle_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + handle_len]);
        errdefer allocator.free(handle);
        pos += handle_len;
        const callsign_len: usize = data[pos];
        pos += 1;
        if (data.len < pos + callsign_len + public_key_len + 1 + 1) {
            allocator.free(handle);
            return null;
        }
        const callsign = if (callsign_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + callsign_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + callsign_len]);
        errdefer allocator.free(callsign);
        pos += callsign_len;
        var public_key: [public_key_len]u8 = undefined;
        @memcpy(&public_key, data[pos..][0..public_key_len]);
        pos += public_key_len;
        const is_sysop = data[pos] != 0;
        pos += 1;
        const avatar_len: usize = data[pos];
        pos += 1;
        if (data.len < pos + avatar_len) {
            allocator.free(handle);
            allocator.free(callsign);
            return null;
        }
        const avatar = if (avatar_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + avatar_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + avatar_len]);

        return .{
            .id = id,
            .registered_datetime = registered_datetime,
            .handle = handle,
            .callsign = callsign,
            .public_key = public_key,
            .is_sysop = is_sysop,
            .avatar = avatar,
        };
    }

    /// Free heap-allocated slices inside a `UserInfo` produced by `decode`.
    pub fn deinit(self: UserInfo, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.handle));
        allocator.free(@constCast(self.callsign));
        if (self.avatar.len != 0) allocator.free(@constCast(self.avatar));
    }
};

/// A request for user info for a list of user_ids.
pub const UserInfoRequest = struct {
    user_ids: []const u16,

    /// Serialize into `buf`. Returns the number of bytes written, or `null` if
    /// there are more than 255 ids or the buffer is too small.
    pub fn encode(self: UserInfoRequest, buf: []u8) ?usize {
        if (self.user_ids.len > 255) return null;
        const total = 1 + self.user_ids.len * 2;
        if (buf.len < total) return null;
        buf[0] = @intCast(self.user_ids.len);
        var pos: usize = 1;
        for (self.user_ids) |uid| {
            std.mem.writeInt(u16, buf[pos..][0..2], uid, .little);
            pos += 2;
        }
        return pos;
    }

    /// Deserialize from `data`. Allocates the `user_ids` slice — the caller
    /// must call `deinit` to free. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?UserInfoRequest {
        if (data.len < 1) return null;
        const count: usize = data[0];
        if (data.len < 1 + count * 2) return null;
        const ids = try allocator.alloc(u16, count);
        var pos: usize = 1;
        for (0..count) |i| {
            ids[i] = std.mem.readInt(u16, data[pos..][0..2], .little);
            pos += 2;
        }
        return .{ .user_ids = ids };
    }

    /// Free the `user_ids` slice allocated by `decode`.
    pub fn deinit(self: UserInfoRequest, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.user_ids));
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "user_info encode/decode round trip" {
    const allocator = std.testing.allocator;
    const pk = [_]u8{0xAB} ** 32;
    const avatar_str = "█  █  █\n █ █ █ \n█  █  █";
    const ui: UserInfo = .{
        .id = 42,
        .registered_datetime = 1724022400,
        .handle = "brad",
        .callsign = "KE8WIF",
        .public_key = pk,
        .is_sysop = true,
        .avatar = avatar_str,
    };

    var buf: [max_chunk_len]u8 = undefined;
    const n = ui.encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try UserInfo.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 42), decoded.id);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.registered_datetime);
    try std.testing.expectEqualStrings("brad", decoded.handle);
    try std.testing.expectEqualStrings("KE8WIF", decoded.callsign);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.public_key);
    try std.testing.expectEqual(true, decoded.is_sysop);
    try std.testing.expectEqualStrings(avatar_str, decoded.avatar);
}

test "user_info encode rejects handle > max_handle_len bytes" {
    const long_handle = [_]u8{'x'} ** (limits.max_handle_len + 1);
    var buf: [max_chunk_len]u8 = undefined;
    try std.testing.expect((UserInfo{
        .id = 1,
        .registered_datetime = 0,
        .handle = &long_handle,
        .callsign = "CS",
        .public_key = [_]u8{0} ** 32,
    }).encode(&buf) == null);
}

test "user_info encode rejects avatar > max_avatar_len bytes" {
    const long_avatar = [_]u8{'x'} ** (limits.max_avatar_len + 1);
    var buf: [max_chunk_len]u8 = undefined;
    try std.testing.expect((UserInfo{
        .id = 1,
        .registered_datetime = 0,
        .handle = "h",
        .callsign = "CS",
        .public_key = [_]u8{0} ** 32,
        .avatar = &long_avatar,
    }).encode(&buf) == null);
}

test "user_info decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02 };
    const result = try UserInfo.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "user_info encode/decode with empty handle and callsign" {
    const allocator = std.testing.allocator;
    var buf: [max_chunk_len]u8 = undefined;
    const n = (UserInfo{
        .id = 7,
        .registered_datetime = 0,
        .handle = "",
        .callsign = "",
        .public_key = [_]u8{0x55} ** 32,
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try UserInfo.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 7), decoded.id);
    try std.testing.expectEqual(@as(usize, 0), decoded.handle.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.callsign.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.avatar.len);
}

test "user_info_request encode/decode round trip" {
    const allocator = std.testing.allocator;
    const ids = [_]u16{ 3, 7, 42, 100 };
    var buf: [max_chunk_len]u8 = undefined;
    const n = (UserInfoRequest{ .user_ids = &ids }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 1 + 4 * 2), n);

    const decoded = (try UserInfoRequest.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), decoded.user_ids.len);
    try std.testing.expectEqual(@as(u16, 3), decoded.user_ids[0]);
    try std.testing.expectEqual(@as(u16, 7), decoded.user_ids[1]);
    try std.testing.expectEqual(@as(u16, 42), decoded.user_ids[2]);
    try std.testing.expectEqual(@as(u16, 100), decoded.user_ids[3]);
}

test "user_info_request encode rejects > 255 ids" {
    var many: [256]u16 = undefined;
    var buf: [max_chunk_len]u8 = undefined;
    try std.testing.expect((UserInfoRequest{ .user_ids = &many }).encode(&buf) == null);
}

test "user_info_request with empty list" {
    const allocator = std.testing.allocator;
    var buf: [max_chunk_len]u8 = undefined;
    const n = (UserInfoRequest{ .user_ids = &.{} }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 1), n);

    const decoded = (try UserInfoRequest.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), decoded.user_ids.len);
}

test "user_info_request decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x03, 0x01 };
    const result = try UserInfoRequest.decode(allocator, &short);
    try std.testing.expect(result == null);
}
