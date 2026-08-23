//! `bulletin_list_request` asks for a paginated list of bulletin summaries.
//! `bulletin_request` asks for full bulletin content for a range of ids.
//!
//! `bulletin_request` supports two modes, similar to
//! `bulletin_response_request`:
//!
//!   * `tail_after` — "send all bulletins with id > after_id"
//!   * `range`     — "send all bulletins with start_id <= id <= end_id"
//!
//! The server responds with individual `bulletin` messages for each matching
//! bulletin (broadcast to CQ so all clients can cache them).
//!
//! Wire layout:
//!   `bulletin_list_request`: `page` (u16 LE) + `page_size` (u8) = 3 bytes.
//!   `bulletin_request`:
//!     `mode` (u8, 1B)
//!       if `tail_after` (0): `after_id` (u32 LE, 4B)
//!       if `range` (1):     `start_id` (u32 LE, 4B) + `end_id` (u32 LE, 4B)

const std = @import("std");

/// Request a paginated list of bulletins from a server.
pub const BulletinListRequest = struct {
    page: u16,
    page_size: u8,

    /// Serialize into `buf`. Always writes exactly 3 bytes.
    pub fn encode(self: BulletinListRequest, buf: []u8) ?usize {
        if (buf.len < 3) return null;
        std.mem.writeInt(u16, buf[0..2], self.page, .little);
        buf[2] = self.page_size;
        return 3;
    }

    /// Deserialize from `data`. Returns `null` if too short.
    pub fn decode(data: []const u8) ?BulletinListRequest {
        if (data.len < 3) return null;
        return .{
            .page = std.mem.readInt(u16, data[0..2], .little),
            .page_size = data[2],
        };
    }
};

/// Mode for a `bulletin_request`.
pub const BulletinRequestMode = enum(u8) {
    /// Send all bulletins with `id > after_id`.
    tail_after = 0,
    /// Send all bulletins with `start_id <= id <= end_id`.
    range = 1,
};

/// Request full bulletin content for a range of bulletin ids. The server
/// responds by broadcasting individual `bulletin` messages for each matching
/// id (so any listening client can cache them).
///
/// For `tail_after` mode, only `after_id` is meaningful.
/// For `range` mode, `start_id` and `end_id` are used (inclusive).
pub const BulletinRequest = struct {
    mode: BulletinRequestMode,
    after_id: u32 = 0,
    start_id: u32 = 0,
    end_id: u32 = 0,

    /// Serialize into `buf`.
    pub fn encode(self: BulletinRequest, buf: []u8) ?usize {
        switch (self.mode) {
            .tail_after => {
                if (buf.len < 1 + 4) return null;
                buf[0] = @intFromEnum(BulletinRequestMode.tail_after);
                std.mem.writeInt(u32, buf[1..5], self.after_id, .little);
                return 5;
            },
            .range => {
                if (buf.len < 1 + 4 + 4) return null;
                if (self.end_id < self.start_id) return null;
                buf[0] = @intFromEnum(BulletinRequestMode.range);
                std.mem.writeInt(u32, buf[1..5], self.start_id, .little);
                std.mem.writeInt(u32, buf[5..9], self.end_id, .little);
                return 9;
            },
        }
    }

    /// Deserialize from `data`. Returns `null` for malformed data.
    pub fn decode(data: []const u8) ?BulletinRequest {
        if (data.len < 1) return null;
        const mode_byte = data[0];
        if (mode_byte > @intFromEnum(BulletinRequestMode.range)) return null;
        const mode: BulletinRequestMode = @enumFromInt(mode_byte);
        switch (mode) {
            .tail_after => {
                if (data.len < 1 + 4) return null;
                const after_id = std.mem.readInt(u32, data[1..5], .little);
                return .{ .mode = .tail_after, .after_id = after_id };
            },
            .range => {
                if (data.len < 1 + 4 + 4) return null;
                const start_id = std.mem.readInt(u32, data[1..5], .little);
                const end_id = std.mem.readInt(u32, data[5..9], .little);
                if (end_id < start_id) return null;
                return .{ .mode = .range, .start_id = start_id, .end_id = end_id };
            },
        }
    }
};

test "bulletin_list_request encode/decode round trip" {
    var buf: [512]u8 = undefined;
    const n = (BulletinListRequest{ .page = 3, .page_size = 10 }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 3), n);

    const decoded = BulletinListRequest.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expectEqual(@as(u16, 3), decoded.page);
    try std.testing.expectEqual(@as(u8, 10), decoded.page_size);
}

test "bulletin_request encode/decode round trip (tail_after)" {
    var buf: [16]u8 = undefined;
    const n = (BulletinRequest{ .mode = .tail_after, .after_id = 42 }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 5), n);

    const decoded = BulletinRequest.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expectEqual(BulletinRequestMode.tail_after, decoded.mode);
    try std.testing.expectEqual(@as(u32, 42), decoded.after_id);
}

test "bulletin_request encode/decode round trip (range)" {
    var buf: [16]u8 = undefined;
    const n = (BulletinRequest{ .mode = .range, .start_id = 5, .end_id = 10 }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 9), n);

    const decoded = BulletinRequest.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expectEqual(BulletinRequestMode.range, decoded.mode);
    try std.testing.expectEqual(@as(u32, 5), decoded.start_id);
    try std.testing.expectEqual(@as(u32, 10), decoded.end_id);
}

test "bulletin_request encode rejects inverted range" {
    var buf: [16]u8 = undefined;
    try std.testing.expect((BulletinRequest{ .mode = .range, .start_id = 10, .end_id = 5 }).encode(&buf) == null);
}

test "bulletin_request decode rejects invalid mode" {
    var buf: [16]u8 = undefined;
    buf[0] = 99;
    try std.testing.expect(BulletinRequest.decode(buf[0..5]) == null);
}

test "bulletin_request decode rejects malformed (too short)" {
    try std.testing.expect(BulletinRequest.decode(&[_]u8{0}) == null);
    try std.testing.expect(BulletinRequest.decode(&[_]u8{ 0, 1 }) == null);
    try std.testing.expect(BulletinRequest.decode(&[_]u8{ 1, 1, 2 }) == null);
}
