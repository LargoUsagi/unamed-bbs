//! `bulletin_list` message type — paginated list of bulletin summaries
//! (metadata only, no body) — the server's response to a `bulletin_request`.
//!
//! The title is Unishox2-compressed in the wire format; `encode` compresses
//! and `decode` decompresses so callers always work with plain text.
//!
//! Wire layout:
//!   `page` (u16 LE) + `total_pages` (u16 LE) + `count` (u8) +
//!   per entry: `id` (u32 LE) + `user_id` (u16 LE, 2B) + `title_len` (u8) + `title` (compressed)

const std = @import("std");
const limits = @import("limits.zig");
const unishox2 = @import("unishox2.zig");

const max_encode_len = limits.max_encode_len;

/// Metadata for a single bulletin in a paginated list (no body). The `title`
/// is plain text — the `encode` method compresses it for the wire.
pub const BulletinSummary = struct {
    id: u32,
    /// Server-assigned user id (references the `users` table).
    user_id: u16,
    title: []const u8,
};

/// Paginated list of bulletin summaries — the server's response to a
/// `bulletin_request`.
pub const BulletinList = struct {
    page: u16,
    total_pages: u16,
    bulletins: []const BulletinSummary,

    /// Serialize into `buf`. Compresses each title with Unishox2. Returns the
    /// number of bytes written, or `null` if there are more than 255 entries,
    /// any compressed title exceeds 255 bytes, or the total exceeds
    /// `max_encode_len`.
    pub fn encode(self: BulletinList, buf: []u8) ?usize {
        if (self.bulletins.len > 255) return null;

        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();

        var pos: usize = 0;
        if (buf.len < 5) return null;
        std.mem.writeInt(u16, buf[pos..][0..2], self.page, .little);
        pos += 2;
        std.mem.writeInt(u16, buf[pos..][0..2], self.total_pages, .little);
        pos += 2;
        buf[pos] = @intCast(self.bulletins.len);
        pos += 1;

        for (self.bulletins) |entry| {
            if (entry.title.len > limits.max_title_len) return null;
            const compressed_title = unishox2.compress(arena.allocator(), entry.title) catch return null;
            if (compressed_title.len > 255) return null;
            const needed = pos + 4 + 2 + 1 + compressed_title.len;
            if (needed > buf.len) return null;
            if (needed > max_encode_len) return null;
            std.mem.writeInt(u32, buf[pos..][0..4], entry.id, .little);
            pos += 4;
            std.mem.writeInt(u16, buf[pos..][0..2], entry.user_id, .little);
            pos += 2;
            buf[pos] = @intCast(compressed_title.len);
            pos += 1;
            @memcpy(buf[pos..][0..compressed_title.len], compressed_title);
            pos += compressed_title.len;
        }
        return pos;
    }

    /// Deserialize from `data`. Decompresses each title. Allocates the
    /// `bulletins` slice and each entry's `title` — the caller must call
    /// `deinit` to free. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?BulletinList {
        if (data.len < 5) return null;
        const page = std.mem.readInt(u16, data[0..2], .little);
        const total_pages = std.mem.readInt(u16, data[2..4], .little);
        const count: usize = data[4];
        var pos: usize = 5;
        var summaries = try allocator.alloc(BulletinSummary, count);
        for (0..count) |i| {
            if (data.len < pos + 7) return null;
            const id = std.mem.readInt(u32, data[pos..][0..4], .little);
            pos += 4;
            const user_id = std.mem.readInt(u16, data[pos..][0..2], .little);
            pos += 2;
            const tlen: usize = data[pos];
            pos += 1;
            if (data.len < pos + tlen) return null;
            const title = if (tlen == 0)
                try allocator.dupe(u8, &.{})
            else
                unishox2.decompress(allocator, data[pos .. pos + tlen], 4096) catch
                    try allocator.dupe(u8, data[pos .. pos + tlen]);
            summaries[i] = .{
                .id = id,
                .user_id = user_id,
                .title = title,
            };
            pos += tlen;
        }
        return .{
            .page = page,
            .total_pages = total_pages,
            .bulletins = summaries,
        };
    }

    /// Free heap-allocated slices inside a `BulletinList` produced by `decode`.
    pub fn deinit(self: BulletinList, allocator: std.mem.Allocator) void {
        for (self.bulletins) |entry| allocator.free(@constCast(entry.title));
        allocator.free(@constCast(self.bulletins));
    }
};

test "bulletin_list encode/decode round trip" {
    const allocator = std.testing.allocator;
    const summaries = [_]BulletinSummary{
        .{ .id = 1, .user_id = 10, .title = "Net Minutes" },
        .{ .id = 2, .user_id = 20, .title = "Weather Report" },
    };

    var buf: [max_encode_len]u8 = undefined;
    const n = (BulletinList{
        .page = 0,
        .total_pages = 3,
        .bulletins = &summaries,
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try BulletinList.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 0), decoded.page);
    try std.testing.expectEqual(@as(u16, 3), decoded.total_pages);
    try std.testing.expectEqual(@as(usize, 2), decoded.bulletins.len);
    try std.testing.expectEqual(@as(u32, 1), decoded.bulletins[0].id);
    try std.testing.expectEqual(@as(u16, 10), decoded.bulletins[0].user_id);
    try std.testing.expectEqualStrings("Net Minutes", decoded.bulletins[0].title);
    try std.testing.expectEqual(@as(u32, 2), decoded.bulletins[1].id);
    try std.testing.expectEqual(@as(u16, 20), decoded.bulletins[1].user_id);
    try std.testing.expectEqualStrings("Weather Report", decoded.bulletins[1].title);
}

test "bulletin_list with empty bulletins encode/decode round trip" {
    const allocator = std.testing.allocator;
    var buf: [max_encode_len]u8 = undefined;
    const n = (BulletinList{
        .page = 0,
        .total_pages = 0,
        .bulletins = &.{},
    }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 5), n);

    const decoded = (try BulletinList.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), decoded.bulletins.len);
}

test "bulletin_list encode rejects > 255 entries" {
    var many: [256]BulletinSummary = undefined;
    for (&many) |*e| e.* = .{ .id = 0, .user_id = 0, .title = "" };
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect((BulletinList{
        .page = 0,
        .total_pages = 0,
        .bulletins = &many,
    }).encode(&buf) == null);
}

test "bulletin_list decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02 };
    const result = try BulletinList.decode(allocator, &short);
    try std.testing.expect(result == null);
}
