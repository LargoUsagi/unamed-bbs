//! `bulletin` message type — a single bulletin (persistent message) with
//! compressed body, title, user reference, and creation timestamp.
//!
//! Both the title and body are Unishox2-compressed in the wire format.
//! The `Bulletin` struct holds plain text; `encode` compresses and `decode`
//! decompresses so callers always work with readable text.
//!
//! Wire layout:
//!   `id` (u32 LE) + `user_id` (u16 LE, 2B) + `created_at` (u64 LE, 8B) +
//!   `title_len` (u8) + `title` (compressed) + `body_len` (u16 LE) + `body` (compressed)
//!
//! `user_id` is a u16 reference into the server's `users` table. When a
//! client posts a new bulletin it sends `user_id = 0`; the server fills in
//! the correct id (looked up from the AX.25 callsign) before storing and
//! broadcasting.

const std = @import("std");
const frame = @import("frame.zig");
const unishox2 = @import("../unishox2.zig");

const max_encode_len = frame.max_encode_len;

/// A single bulletin with title, body, user reference, and creation
/// timestamp. Both `title` and `body` are plain (uncompressed) text —
/// the `encode` method compresses them for the wire, and `decode`
/// decompresses them.
pub const Bulletin = struct {
    id: u32,
    /// Server-assigned user id (references the `users` table). Clients
    /// set this to 0 when posting; the server replaces it.
    user_id: u16,
    /// Creation timestamp as a Unix epoch value (seconds since 1970-01-01).
    /// Used for chronological sorting.
    created_at: u64,
    /// Human-readable title (max 255 bytes compressed on the wire).
    title: []const u8,
    /// Plain text body.
    body: []const u8,

    /// Serialize into `buf`. Compresses both the title and body with Unishox2
    /// before writing. Returns the number of bytes written, or `null` if the
    /// compressed title exceeds 255 bytes or the total exceeds `max_encode_len`.
    pub fn encode(self: Bulletin, buf: []u8) ?usize {
        var title_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer title_arena.deinit();
        const compressed_title = unishox2.compress(title_arena.allocator(), self.title) catch return null;
        if (compressed_title.len > 255) return null;

        var body_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer body_arena.deinit();
        const compressed_body = unishox2.compress(body_arena.allocator(), self.body) catch return null;

        const total = 4 + 2 + 8 + 1 + compressed_title.len + 2 + compressed_body.len;
        if (total > max_encode_len) return null;
        if (buf.len < total) return null;

        var pos: usize = 0;
        std.mem.writeInt(u32, buf[pos..][0..4], self.id, .little);
        pos += 4;
        std.mem.writeInt(u16, buf[pos..][0..2], self.user_id, .little);
        pos += 2;
        std.mem.writeInt(u64, buf[pos..][0..8], self.created_at, .little);
        pos += 8;
        buf[pos] = @intCast(compressed_title.len);
        pos += 1;
        @memcpy(buf[pos..][0..compressed_title.len], compressed_title);
        pos += compressed_title.len;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(compressed_body.len), .little);
        pos += 2;
        @memcpy(buf[pos..][0..compressed_body.len], compressed_body);
        pos += compressed_body.len;
        return pos;
    }

    /// Deserialize from `data`. Decompresses the title and body. Allocates
    /// both slices — the caller must call `deinit` to free. Returns `null` for
    /// malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?Bulletin {
        if (data.len < 4 + 2 + 8 + 1 + 2) return null;

        var pos: usize = 0;
        const id = std.mem.readInt(u32, data[pos..][0..4], .little);
        pos += 4;

        const user_id = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;

        const created_at = std.mem.readInt(u64, data[pos..][0..8], .little);
        pos += 8;

        const title_len: usize = data[pos];
        pos += 1;
        if (data.len < pos + title_len + 2) return null;

        const title = if (title_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + title_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + title_len]);
        pos += title_len;

        const body_len: usize = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;
        if (data.len < pos + body_len) return null;

        const body = if (body_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + body_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + body_len]);

        return .{
            .id = id,
            .user_id = user_id,
            .created_at = created_at,
            .title = title,
            .body = body,
        };
    }

    /// Free heap-allocated slices inside a `Bulletin` produced by `decode`.
    pub fn deinit(self: Bulletin, allocator: std.mem.Allocator) void {
        allocator.free(self.title);
        allocator.free(self.body);
    }
};

test "bulletin encode/decode round trip" {
    const allocator = std.testing.allocator;
    const title = "Net Minutes 2026-08-18";
    const body = "This is the body of the bulletin.";

    var buf: [max_encode_len]u8 = undefined;
    const n = (Bulletin{
        .id = 100,
        .user_id = 42,
        .created_at = 1724022400,
        .title = title,
        .body = body,
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Bulletin.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 100), decoded.id);
    try std.testing.expectEqual(@as(u16, 42), decoded.user_id);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.created_at);
    try std.testing.expectEqualStrings(title, decoded.title);
    try std.testing.expectEqualStrings(body, decoded.body);
}

test "bulletin encode accepts title that compresses under 255 bytes" {
    // A 256-byte run of 'x' is highly compressible under Unishox2, so the
    // compressed title fits the 1-byte length field (<= 255) and encode
    // succeeds. The encode returns null only when the *compressed* title
    // exceeds 255 bytes.
    const long_title = [_]u8{'x'} ** 256;
    var buf: [max_encode_len]u8 = undefined;
    const n = (Bulletin{
        .id = 1,
        .user_id = 0,
        .created_at = 0,
        .title = &long_title,
        .body = &.{},
    }).encode(&buf);
    try std.testing.expect(n != null);
}

test "bulletin encode rejects payload exceeding max_encode_len" {
    // High-entropy body Unishox2 cannot compress under the limit, pushing
    // the total over max_encode_len (4096). Cycles 1..251 to avoid NUL bytes.
    var big_body: [8192]u8 = undefined;
    for (&big_body, 0..) |*b, i| b.* = @intCast((i % 251) + 1);
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect((Bulletin{
        .id = 1,
        .user_id = 0,
        .created_at = 0,
        .title = "x",
        .body = &big_body,
    }).encode(&buf) == null);
}

test "bulletin decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02 };
    const result = try Bulletin.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "bulletin encode/decode with empty body" {
    const allocator = std.testing.allocator;

    var buf: [max_encode_len]u8 = undefined;
    const n = (Bulletin{
        .id = 1,
        .user_id = 7,
        .created_at = 0,
        .title = "Empty",
        .body = &.{},
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Bulletin.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), decoded.id);
    try std.testing.expectEqual(@as(u16, 7), decoded.user_id);
    try std.testing.expectEqualStrings("Empty", decoded.title);
    try std.testing.expectEqual(@as(usize, 0), decoded.body.len);
}

test "bulletin created_at preserves epoch value for sorting" {
    const allocator = std.testing.allocator;

    var buf: [max_encode_len]u8 = undefined;
    const n = (Bulletin{
        .id = 1,
        .user_id = 1,
        .created_at = 0,
        .title = "A",
        .body = &.{},
    }).encode(&buf) orelse return error.EncodeFailed;
    const d0 = (try Bulletin.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer d0.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), d0.created_at);

    var buf2: [max_encode_len]u8 = undefined;
    const n2 = (Bulletin{
        .id = 2,
        .user_id = 1,
        .created_at = std.math.maxInt(u64),
        .title = "B",
        .body = &.{},
    }).encode(&buf2) orelse return error.EncodeFailed;
    const dmax = (try Bulletin.decode(allocator, buf2[0..n2])) orelse return error.DecodeFailed;
    defer dmax.deinit(allocator);
    try std.testing.expectEqual(std.math.maxInt(u64), dmax.created_at);
    try std.testing.expect(d0.created_at < dmax.created_at);
}
