//! `chat_history_request` message type — a client asks the BBS for the most
//! recent N chat messages. The server responds by broadcasting up to N
//! individual `chat` frames (signed by the server, newest first) so the
//! requester — and any other listening station — can cache them.
//!
//! Wire layout:
//!   `count` (u8, 1B) — number of most recent messages to request.
//!
//! The client uses a count of 20 by default (see
//! `common.chat_history_count`).

const std = @import("std");
const frame = @import("frame.zig");

const max_payload_len = frame.max_payload_len;

/// Default number of chat messages the client requests from the BBS.
pub const default_count: u8 = 20;

/// Request up to `count` most recent chat messages from the BBS.
pub const ChatHistoryRequest = struct {
    /// Number of most recent messages to request (0–255; capped by the
    /// server).
    count: u8,

    /// Serialize into `buf`. Always writes exactly 1 byte. Returns `null`
    /// only if `buf` is empty.
    pub fn encode(self: ChatHistoryRequest, buf: []u8) ?usize {
        if (buf.len < 1) return null;
        buf[0] = self.count;
        return 1;
    }

    /// Deserialize from `data`. Returns `null` if `data` is empty.
    pub fn decode(data: []const u8) ?ChatHistoryRequest {
        if (data.len < 1) return null;
        return .{ .count = data[0] };
    }
};

test "chat_history_request encode/decode round trip" {
    var buf: [max_payload_len]u8 = undefined;
    const n = (ChatHistoryRequest{ .count = 20 }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 1), n);

    const decoded = ChatHistoryRequest.decode(buf[0..n]) orelse return error.DecodeFailed;
    try std.testing.expectEqual(@as(u8, 20), decoded.count);
}

test "chat_history_request decode rejects empty data" {
    try std.testing.expect(ChatHistoryRequest.decode(&.{}) == null);
}
