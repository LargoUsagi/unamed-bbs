//! `request_status` message type — the server informs a client about the
//! outcome of a specific request. Carries a u16 identifying the request,
//! an outcome enum, and an optional Unishox2-compressed detail string.
//!
//! Wire layout:
//!   `request_id` (u16 LE, 2B) + `outcome` (u8, 1B) + `detail_len` (u16 LE, 2B) + `detail` (compressed)

const std = @import("std");
const frame = @import("frame.zig");
const unishox2 = @import("../unishox2.zig");

const max_encode_len = frame.max_encode_len;

/// Outcome of a request. Wire values are stored as a single byte.
/// New values can be appended; existing values must not be renumbered.
pub const Outcome = enum(u8) {
    /// The request was processed successfully.
    success = 1,
    /// The request failed (e.g. malformed, unauthorized, not found).
    failure = 2,
    /// No response data is available for this request (e.g. no bulletins in
    /// the requested range, no responses for a bulletin).
    no_data = 3,
};

/// A status report from the server about a specific client request.
pub const RequestStatus = struct {
    /// Client-supplied request identifier. The client chooses this value when
    /// sending a request and the server echoes it back so the client can
    /// correlate the status with the originating request.
    request_id: u16,
    /// The outcome of the request.
    outcome: Outcome,
    /// Human-readable detail text (plain text; compressed on the wire).
    /// May be empty. Heap-allocated when produced by `decode` — caller must
    /// call `deinit`.
    detail: []const u8 = "",

    /// Serialize into `buf`. Compresses the detail text with Unishox2.
    /// Returns the number of bytes written, or `null` on overflow.
    pub fn encode(self: RequestStatus, buf: []u8) ?usize {
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const compressed = unishox2.compress(arena.allocator(), self.detail) catch return null;

        const fixed = 5; // request_id(2) + outcome(1) + detail_len(2)
        if (compressed.len > max_encode_len - fixed) return null;
        if (buf.len < fixed + compressed.len) return null;

        var pos: usize = 0;
        std.mem.writeInt(u16, buf[pos..][0..2], self.request_id, .little);
        pos += 2;
        buf[pos] = @intFromEnum(self.outcome);
        pos += 1;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(compressed.len), .little);
        pos += 2;
        @memcpy(buf[pos..][0..compressed.len], compressed);
        pos += compressed.len;
        return pos;
    }

    /// Deserialize from `data`. Decompresses the detail text. Allocates
    /// `detail` — the caller must call `deinit`. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?RequestStatus {
        const fixed = 5;
        if (data.len < fixed) return null;
        const outcome: Outcome = switch (data[2]) {
            1 => .success,
            2 => .failure,
            3 => .no_data,
            else => return null,
        };
        const detail_len: usize = std.mem.readInt(u16, data[3..5], .little);
        if (data.len < fixed + detail_len) return null;

        const detail = if (detail_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[fixed .. fixed + detail_len], 4096) catch
                try allocator.dupe(u8, data[fixed .. fixed + detail_len]);

        return .{
            .request_id = std.mem.readInt(u16, data[0..2], .little),
            .outcome = outcome,
            .detail = detail,
        };
    }

    /// Free heap-allocated slices inside a `RequestStatus` produced by `decode`.
    pub fn deinit(self: RequestStatus, allocator: std.mem.Allocator) void {
        allocator.free(self.detail);
    }
};

test "request_status encode/decode round trip (success, no detail)" {
    const allocator = std.testing.allocator;
    var buf: [max_encode_len]u8 = undefined;
    const n = (RequestStatus{ .request_id = 42, .outcome = .success }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try RequestStatus.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 42), decoded.request_id);
    try std.testing.expectEqual(Outcome.success, decoded.outcome);
    try std.testing.expectEqualStrings("", decoded.detail);
}

test "request_status encode/decode round trip (no_data, with detail)" {
    const allocator = std.testing.allocator;
    var buf: [max_encode_len]u8 = undefined;
    const n = (RequestStatus{
        .request_id = 100,
        .outcome = .no_data,
        .detail = "No new responses for bulletin 5.",
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try RequestStatus.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 100), decoded.request_id);
    try std.testing.expectEqual(Outcome.no_data, decoded.outcome);
    try std.testing.expectEqualStrings("No new responses for bulletin 5.", decoded.detail);
}

test "request_status decode rejects too-short data" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02, 0x03 };
    const result = try RequestStatus.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "request_status decode rejects invalid outcome byte" {
    const allocator = std.testing.allocator;
    const bad = [_]u8{ 0x01, 0x02, 0xFF, 0x00, 0x00 };
    const result = try RequestStatus.decode(allocator, &bad);
    try std.testing.expect(result == null);
}
