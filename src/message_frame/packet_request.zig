//! `packet_request` message type — a signed request from a client to the server
//! asking it to retransmit specific missing packets of a multipart message.
//!
//! The request is signed by the requesting station's Ed25519 key so the server
//! can verify identity before responding. The server retransmits the requested
//! packets to CQ so all stations benefit.
//!
//! Wire layout (variable length, 1 + N bytes):
//!   byte 0: count (u8) — number of missing packet numbers
//!   byte 1..1+count: packet_numbers (u8 each)
//!
//! The `group_id` for the missing packets is carried in the MessageFrame header
//! (byte 1, bits [5:2]), not in the payload.

const std = @import("std");
const frame = @import("frame.zig");

const max_payload_len = frame.max_payload_len;

/// A request to retransmit specific missing packets of a multipart message.
/// The `group_id` is carried in the MessageFrame header, not in this struct.
pub const PacketRequest = struct {
    /// The missing packet numbers (0-based indices within the group).
    packet_numbers: []const u8,

    /// Serialize into `buf`. Returns the number of bytes written, or `null` if
    /// the packet list is empty or exceeds `max_payload_len`.
    pub fn encode(self: PacketRequest, buf: []u8) ?usize {
        if (self.packet_numbers.len == 0) return null;
        if (self.packet_numbers.len > 255) return null;
        const needed = 1 + self.packet_numbers.len;
        if (needed > max_payload_len) return null;
        if (buf.len < needed) return null;
        buf[0] = @intCast(self.packet_numbers.len);
        @memcpy(buf[1 .. 1 + self.packet_numbers.len], self.packet_numbers);
        return needed;
    }

    /// Deserialize from `data`. Allocates the `packet_numbers` slice — caller
    /// must call `deinit`. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?PacketRequest {
        if (data.len < 1) return null;
        const count: usize = data[0];
        if (count == 0) return null;
        if (data.len < 1 + count) return null;
        const packet_numbers = try allocator.dupe(u8, data[1 .. 1 + count]);
        return .{ .packet_numbers = packet_numbers };
    }

    /// Free the allocated `packet_numbers` slice.
    pub fn deinit(self: PacketRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.packet_numbers);
    }
};

test "packet_request encode/decode round trip" {
    const allocator = std.testing.allocator;
    const missing = [_]u8{ 2, 5, 7 };
    var buf: [max_payload_len]u8 = undefined;
    const n = (PacketRequest{ .packet_numbers = &missing }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 4), n);

    const decoded = (try PacketRequest.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), decoded.packet_numbers.len);
    try std.testing.expectEqual(@as(u8, 2), decoded.packet_numbers[0]);
    try std.testing.expectEqual(@as(u8, 5), decoded.packet_numbers[1]);
    try std.testing.expectEqual(@as(u8, 7), decoded.packet_numbers[2]);
}

test "packet_request encode rejects empty list" {
    var buf: [max_payload_len]u8 = undefined;
    try std.testing.expect((PacketRequest{ .packet_numbers = &.{} }).encode(&buf) == null);
}

test "packet_request decode rejects too-short data" {
    const allocator = std.testing.allocator;
    const short = [_]u8{};
    try std.testing.expect((try PacketRequest.decode(allocator, &short)) == null);
}

test "packet_request decode rejects count/data mismatch" {
    const allocator = std.testing.allocator;
    const bad = [_]u8{ 3, 0, 1 };
    try std.testing.expect((try PacketRequest.decode(allocator, &bad)) == null);
}
