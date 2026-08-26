//! `bulletin_response` message types — threaded replies to a bulletin.
//!
//! A `bulletin_response` is a single reply to a bulletin. The server assigns
//! a sequential `response_id` (0..1023, a u10 stored as u16 on the wire)
//! unique per `(bulletin_id, response_id)` pair. The body is a Unishox2-
//! compressed string. The server stores each response in its SQLite database
//! and broadcasts it to clients; clients cache responses in their own store.
//!
//! Three message types live here:
//!
//! 1. `bulletin_response`        — a single response. Clients send it to
//!    reply to a bulletin (with `response_id = 0`); the server assigns the
//!    real `response_id`, stores the response, and broadcasts it back. The
//!    server also broadcasts it in response to a `bulletin_response_request`.
//!
//! 2. `bulletin_response_list`   — the server's reply to a
//!    `bulletin_response_request`. Carries a `bulletin_id` and a list of
//!    `BulletinResponse` entries (each with its own compressed body).
//!
//! 3. `bulletin_response_request` — a client request for missing responses
//!    for a single bulletin. Two modes:
//!      * `tail_after` — "I have all of 0..after_id contiguous; send me
//!        everything with response_id > after_id". This is the shorthand
//!        for the common case where the client has caught up to `after_id`.
//!      * `range`     — "send me responses with `start_id <= response_id
//!        <= end_id`". Used when the client has non-contiguous ids and
//!        needs to fill specific gaps.
//!
//! Wire layout:
//!   `bulletin_response`:
//!     `bulletin_id` (u32 LE, 4B) + `response_id` (u16 LE, 2B, value 0..1023) +
//!     `user_id` (u16 LE, 2B) + `create_datetime` (u64 LE, 8B, epoch seconds) +
//!     `body_len` (u16 LE, 2B) + `body`
//!   `bulletin_response_list`:
//!     `bulletin_id` (u32 LE, 4B) + `count` (u8) +
//!     per entry: `response_id` (u16 LE, 2B) + `user_id` (u16 LE, 2B) +
//!                `create_datetime` (u64 LE, 8B) + `body_len` (u16 LE, 2B) + `body`
//!   `bulletin_response_request`:
//!     `bulletin_id` (u32 LE, 4B) + `mode` (u8, 1B) +
//!       if `mode == 0` (tail_after): `after_id` (u16 LE, 2B)
//!       if `mode == 1` (range):     `start_id` (u16 LE, 2B) + `end_id` (u16 LE, 2B)
//!
//! `create_datetime` is set by the server to the current epoch time when it
//! receives the response, making the server the authoritative time source.

const std = @import("std");
const limits = @import("limits.zig");
const unishox2 = @import("../unishox2.zig");

const max_encode_len = limits.max_encode_len;

/// Maximum value of a `response_id` (the id space is 0..1023).
pub const max_response_id: u16 = 1023;

/// A single reply to a bulletin.
pub const BulletinResponse = struct {
    /// The bulletin this response belongs to.
    bulletin_id: u32,
    /// Per-bulletin sequential id assigned by the server. Range 0..1023.
    /// Clients set this to 0 when posting a reply; the server replaces it
    /// with the next id before storing and broadcasting.
    response_id: u16,
    /// Server-assigned user id (references the `users` table). Clients set
    /// this to 0 when posting; the server replaces it.
    user_id: u16,
    /// Server-set creation timestamp (Unix epoch seconds). The server sets
    /// this to the current time when it receives the response; clients send
    /// 0. This is the authoritative posting time.
    create_datetime: u64,
    /// Unishox2-compressed body text.
    body: []const u8,

    /// Serialize into `buf`. Compresses the body with Unishox2. Returns the
    /// number of bytes written, or `null` if the uncompressed body exceeds
    /// `max_body_len`, the compressed form exceeds `max_encode_len - 18`, or
    /// `response_id` exceeds `max_response_id`.
    pub fn encode(self: BulletinResponse, buf: []u8) ?usize {
        if (self.response_id > max_response_id) return null;
        if (self.body.len > limits.max_body_len) return null;

        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const compressed = unishox2.compress(arena.allocator(), self.body) catch return null;

        const fixed = 4 + 2 + 2 + 8 + 2;
        if (compressed.len > max_encode_len - fixed) return null;
        if (buf.len < fixed + compressed.len) return null;

        var pos: usize = 0;
        std.mem.writeInt(u32, buf[pos..][0..4], self.bulletin_id, .little);
        pos += 4;
        std.mem.writeInt(u16, buf[pos..][0..2], self.response_id, .little);
        pos += 2;
        std.mem.writeInt(u16, buf[pos..][0..2], self.user_id, .little);
        pos += 2;
        std.mem.writeInt(u64, buf[pos..][0..8], self.create_datetime, .little);
        pos += 8;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(compressed.len), .little);
        pos += 2;
        @memcpy(buf[pos..][0..compressed.len], compressed);
        pos += compressed.len;
        return pos;
    }

    /// Deserialize from `data`. Decompresses the body. Allocates `body` —
    /// caller must call `deinit`. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?BulletinResponse {
        const fixed = 4 + 2 + 2 + 8 + 2;
        if (data.len < fixed) return null;
        var pos: usize = 0;
        const bulletin_id = std.mem.readInt(u32, data[pos..][0..4], .little);
        pos += 4;
        const response_id = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;
        const user_id = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;
        const create_datetime = std.mem.readInt(u64, data[pos..][0..8], .little);
        pos += 8;
        const body_len: usize = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;
        if (data.len < pos + body_len) return null;
        if (response_id > max_response_id) return null;
        const body = if (body_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + body_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + body_len]);
        return .{
            .bulletin_id = bulletin_id,
            .response_id = response_id,
            .user_id = user_id,
            .create_datetime = create_datetime,
            .body = body,
        };
    }

    /// Free heap-allocated slices inside a `BulletinResponse` produced by `decode`.
    pub fn deinit(self: BulletinResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }
};

/// A list of responses for a single bulletin, returned by the server in
/// reply to a `bulletin_response_request`.
pub const BulletinResponseList = struct {
    bulletin_id: u32,
    responses: []const BulletinResponse,

    /// Serialize into `buf`. Compresses each body. Returns the number of bytes
    /// written, or `null` if there are more than 255 responses, any response has
    /// a `response_id > max_response_id`, or the total exceeds `max_encode_len`.
    pub fn encode(self: BulletinResponseList, buf: []u8) ?usize {
        if (self.responses.len > 255) return null;
        for (self.responses) |r| {
            if (r.response_id > max_response_id) return null;
            if (r.body.len > limits.max_body_len) return null;
        }

        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();

        var pos: usize = 0;
        if (buf.len < 4 + 1) return null;
        std.mem.writeInt(u32, buf[pos..][0..4], self.bulletin_id, .little);
        pos += 4;
        buf[pos] = @intCast(self.responses.len);
        pos += 1;

        for (self.responses) |r| {
            const compressed = unishox2.compress(arena.allocator(), r.body) catch return null;
            const fixed = 2 + 2 + 8 + 2;
            const needed = pos + fixed + compressed.len;
            if (needed > buf.len) return null;
            if (needed > max_encode_len) return null;
            std.mem.writeInt(u16, buf[pos..][0..2], r.response_id, .little);
            pos += 2;
            std.mem.writeInt(u16, buf[pos..][0..2], r.user_id, .little);
            pos += 2;
            std.mem.writeInt(u64, buf[pos..][0..8], r.create_datetime, .little);
            pos += 8;
            std.mem.writeInt(u16, buf[pos..][0..2], @intCast(compressed.len), .little);
            pos += 2;
            @memcpy(buf[pos..][0..compressed.len], compressed);
            pos += compressed.len;
        }
        return pos;
    }

    /// Deserialize from `data`. Allocates the `responses` slice and each
    /// entry's `body`. Caller must call `deinit`. Returns `null` for malformed
    /// data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?BulletinResponseList {
        if (data.len < 4 + 1) return null;
        var pos: usize = 0;
        const bulletin_id = std.mem.readInt(u32, data[pos..][0..4], .little);
        pos += 4;
        const count: usize = data[pos];
        pos += 1;

        var responses = try allocator.alloc(BulletinResponse, count);
        var filled: usize = 0;
        errdefer {
            for (responses[0..filled]) |r| r.deinit(allocator);
            allocator.free(responses);
        }

        for (0..count) |i| {
            const fixed = 2 + 2 + 8 + 2;
            if (data.len < pos + fixed) {
                for (responses[0..filled]) |r| r.deinit(allocator);
                allocator.free(responses);
                return null;
            }
            const response_id = std.mem.readInt(u16, data[pos..][0..2], .little);
            pos += 2;
            const user_id = std.mem.readInt(u16, data[pos..][0..2], .little);
            pos += 2;
            const create_datetime = std.mem.readInt(u64, data[pos..][0..8], .little);
            pos += 8;
            const body_len: usize = std.mem.readInt(u16, data[pos..][0..2], .little);
            pos += 2;
            if (data.len < pos + body_len) {
                for (responses[0..filled]) |r| r.deinit(allocator);
                allocator.free(responses);
                return null;
            }
            if (response_id > max_response_id) {
                for (responses[0..filled]) |r| r.deinit(allocator);
                allocator.free(responses);
                return null;
            }
            const body = if (body_len == 0)
                try allocator.dupe(u8, &.{})
            else
                unishox2.decompress(allocator, data[pos .. pos + body_len], 4096) catch
                    try allocator.dupe(u8, data[pos .. pos + body_len]);
            pos += body_len;
            responses[i] = .{
                .bulletin_id = bulletin_id,
                .response_id = response_id,
                .user_id = user_id,
                .create_datetime = create_datetime,
                .body = body,
            };
            filled += 1;
        }

        return .{ .bulletin_id = bulletin_id, .responses = responses };
    }

    /// Free heap-allocated slices inside a `BulletinResponseList` produced by
    /// `decode`.
    pub fn deinit(self: BulletinResponseList, allocator: std.mem.Allocator) void {
        for (self.responses) |r| r.deinit(allocator);
        allocator.free(@constCast(self.responses));
    }
};

/// Mode for a `bulletin_response_request`.
pub const ResponseRequestMode = enum(u8) {
    /// "I have all of 0..after_id; send everything after after_id."
    tail_after = 0,
    /// "Send responses in the inclusive range [start_id, end_id]."
    range = 1,
};

/// A client request for missing responses for a single bulletin.
///
/// For `tail_after` mode, only `after_id` is meaningful.
/// For `range` mode, `start_id` and `end_id` are used (inclusive).
pub const BulletinResponseRequest = struct {
    bulletin_id: u32,
    mode: ResponseRequestMode,
    after_id: u16 = 0,
    start_id: u16 = 0,
    end_id: u16 = 0,

    /// Serialize into `buf`. Returns the number of bytes written, or `null` if
    /// any id exceeds `max_response_id` or the range is inverted for `range`
    /// mode.
    pub fn encode(self: BulletinResponseRequest, buf: []u8) ?usize {
        switch (self.mode) {
            .tail_after => {
                if (self.after_id > max_response_id) return null;
                if (buf.len < 4 + 1 + 2) return null;
                std.mem.writeInt(u32, buf[0..4], self.bulletin_id, .little);
                buf[4] = @intFromEnum(ResponseRequestMode.tail_after);
                std.mem.writeInt(u16, buf[5..7], self.after_id, .little);
                return 7;
            },
            .range => {
                if (self.start_id > max_response_id) return null;
                if (self.end_id > max_response_id) return null;
                if (self.end_id < self.start_id) return null;
                if (buf.len < 4 + 1 + 2 + 2) return null;
                std.mem.writeInt(u32, buf[0..4], self.bulletin_id, .little);
                buf[4] = @intFromEnum(ResponseRequestMode.range);
                std.mem.writeInt(u16, buf[5..7], self.start_id, .little);
                std.mem.writeInt(u16, buf[7..9], self.end_id, .little);
                return 9;
            },
        }
    }

    /// Deserialize from `data`. Returns `null` for malformed data or invalid
    /// id values.
    pub fn decode(data: []const u8) ?BulletinResponseRequest {
        if (data.len < 4 + 1) return null;
        const bulletin_id = std.mem.readInt(u32, data[0..4], .little);
        const mode_byte = data[4];
        if (mode_byte > @intFromEnum(ResponseRequestMode.range)) return null;
        const mode: ResponseRequestMode = @enumFromInt(mode_byte);
        switch (mode) {
            .tail_after => {
                if (data.len < 4 + 1 + 2) return null;
                const after_id = std.mem.readInt(u16, data[5..7], .little);
                if (after_id > max_response_id) return null;
                return .{
                    .bulletin_id = bulletin_id,
                    .mode = .tail_after,
                    .after_id = after_id,
                };
            },
            .range => {
                if (data.len < 4 + 1 + 2 + 2) return null;
                const start_id = std.mem.readInt(u16, data[5..7], .little);
                const end_id = std.mem.readInt(u16, data[7..9], .little);
                if (start_id > max_response_id) return null;
                if (end_id > max_response_id) return null;
                if (end_id < start_id) return null;
                return .{
                    .bulletin_id = bulletin_id,
                    .mode = .range,
                    .start_id = start_id,
                    .end_id = end_id,
                };
            },
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "bulletin_response encode/decode round trip" {
    const allocator = std.testing.allocator;
    const body = "Hello world response body";

    var buf: [max_encode_len]u8 = undefined;
    const n = (BulletinResponse{
        .bulletin_id = 42,
        .response_id = 7,
        .user_id = 3,
        .create_datetime = 1724022400,
        .body = body,
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try BulletinResponse.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 42), decoded.bulletin_id);
    try std.testing.expectEqual(@as(u16, 7), decoded.response_id);
    try std.testing.expectEqual(@as(u16, 3), decoded.user_id);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.create_datetime);
    try std.testing.expectEqualStrings(body, decoded.body);
}

test "bulletin_response encode rejects response_id > max_response_id" {
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect((BulletinResponse{
        .bulletin_id = 1,
        .response_id = max_response_id + 1,
        .user_id = 0,
        .create_datetime = 0,
        .body = &.{},
    }).encode(&buf) == null);
}

test "bulletin_response decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02 };
    const result = try BulletinResponse.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "bulletin_response encode/decode with empty body" {
    const allocator = std.testing.allocator;
    var buf: [max_encode_len]u8 = undefined;
    const n = (BulletinResponse{
        .bulletin_id = 5,
        .response_id = 0,
        .user_id = 1,
        .create_datetime = 0,
        .body = &.{},
    }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 18), n);

    const decoded = (try BulletinResponse.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 5), decoded.bulletin_id);
    try std.testing.expectEqual(@as(u16, 0), decoded.response_id);
    try std.testing.expectEqual(@as(usize, 0), decoded.body.len);
}

test "bulletin_response_list encode/decode round trip" {
    const allocator = std.testing.allocator;
    const body_a = "First response";
    const body_b = "Second response";
    const responses = [_]BulletinResponse{
        .{ .bulletin_id = 7, .response_id = 0, .user_id = 2, .create_datetime = 1000, .body = body_a },
        .{ .bulletin_id = 7, .response_id = 1, .user_id = 3, .create_datetime = 2000, .body = body_b },
    };

    var buf: [max_encode_len]u8 = undefined;
    const n = (BulletinResponseList{ .bulletin_id = 7, .responses = &responses }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try BulletinResponseList.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 7), decoded.bulletin_id);
    try std.testing.expectEqual(@as(usize, 2), decoded.responses.len);
    try std.testing.expectEqual(@as(u16, 0), decoded.responses[0].response_id);
    try std.testing.expectEqual(@as(u16, 2), decoded.responses[0].user_id);
    try std.testing.expectEqual(@as(u64, 1000), decoded.responses[0].create_datetime);
    try std.testing.expectEqualStrings(body_a, decoded.responses[0].body);
    try std.testing.expectEqual(@as(u16, 1), decoded.responses[1].response_id);
    try std.testing.expectEqual(@as(u16, 3), decoded.responses[1].user_id);
    try std.testing.expectEqual(@as(u64, 2000), decoded.responses[1].create_datetime);
    try std.testing.expectEqualStrings(body_b, decoded.responses[1].body);
}

test "bulletin_response_list with empty responses round trip" {
    const allocator = std.testing.allocator;
    var buf: [max_encode_len]u8 = undefined;
    const n = (BulletinResponseList{ .bulletin_id = 99, .responses = &.{} }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 5), n);

    const decoded = (try BulletinResponseList.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 99), decoded.bulletin_id);
    try std.testing.expectEqual(@as(usize, 0), decoded.responses.len);
}

test "bulletin_response_list encode rejects > 255 responses" {
    var many: [256]BulletinResponse = undefined;
    for (&many) |*r| r.* = .{ .bulletin_id = 1, .response_id = 0, .user_id = 0, .create_datetime = 0, .body = &.{} };
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect((BulletinResponseList{ .bulletin_id = 1, .responses = &many }).encode(&buf) == null);
}

test "bulletin_response_list decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02 };
    const result = try BulletinResponseList.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "bulletin_response_list decode rejects response_id > max_response_id" {
    const allocator = std.testing.allocator;
    var buf: [19]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 1, .little);
    buf[4] = 1;
    std.mem.writeInt(u16, buf[5..7], max_response_id + 1, .little);
    std.mem.writeInt(u16, buf[7..9], 0, .little);
    std.mem.writeInt(u64, buf[9..17], 0, .little);
    std.mem.writeInt(u16, buf[17..19], 0, .little);
    const result = try BulletinResponseList.decode(allocator, buf[0..19]);
    try std.testing.expect(result == null);
}

test "bulletin_response_request encode/decode round trip (tail_after)" {
    var buf: [16]u8 = undefined;
    const n = (BulletinResponseRequest{
        .bulletin_id = 42,
        .mode = .tail_after,
        .after_id = 3,
    }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 7), n);

    const decoded = BulletinResponseRequest.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expectEqual(@as(u32, 42), decoded.bulletin_id);
    try std.testing.expectEqual(ResponseRequestMode.tail_after, decoded.mode);
    try std.testing.expectEqual(@as(u16, 3), decoded.after_id);
}

test "bulletin_response_request encode/decode round trip (range)" {
    var buf: [16]u8 = undefined;
    const n = (BulletinResponseRequest{
        .bulletin_id = 42,
        .mode = .range,
        .start_id = 5,
        .end_id = 10,
    }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 9), n);

    const decoded = BulletinResponseRequest.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expectEqual(@as(u32, 42), decoded.bulletin_id);
    try std.testing.expectEqual(ResponseRequestMode.range, decoded.mode);
    try std.testing.expectEqual(@as(u16, 5), decoded.start_id);
    try std.testing.expectEqual(@as(u16, 10), decoded.end_id);
}

test "bulletin_response_request encode rejects invalid tail_after id" {
    var buf: [16]u8 = undefined;
    try std.testing.expect((BulletinResponseRequest{
        .bulletin_id = 1,
        .mode = .tail_after,
        .after_id = max_response_id + 1,
    }).encode(&buf) == null);
}

test "bulletin_response_request encode rejects invalid range ids" {
    var buf: [16]u8 = undefined;
    try std.testing.expect((BulletinResponseRequest{
        .bulletin_id = 1,
        .mode = .range,
        .start_id = 0,
        .end_id = max_response_id + 1,
    }).encode(&buf) == null);
    try std.testing.expect((BulletinResponseRequest{
        .bulletin_id = 1,
        .mode = .range,
        .start_id = 10,
        .end_id = 5,
    }).encode(&buf) == null);
}

test "bulletin_response_request decode rejects malformed (too short)" {
    const short = [_]u8{ 0x01, 0x02 };
    try std.testing.expect(BulletinResponseRequest.decode(&short) == null);
}

test "bulletin_response_request decode rejects invalid mode" {
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 1, .little);
    buf[4] = 99;
    std.mem.writeInt(u16, buf[5..7], 0, .little);
    try std.testing.expect(BulletinResponseRequest.decode(buf[0..7]) == null);
}
