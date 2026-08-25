//! `chat` message type — a chat line routed through the BBS server.
//!
//! A client posts a `chat` frame (signed by the client) addressed to the
//! BBS. The BBS verifies the sender is a registered user (logged in) and
//! that the signature is valid, then stores the message in its `chat_messages`
//! table with the **epoch time of receipt** as the primary key, and
//! re-broadcasts the chat to CQ signed by the server so everyone in range
//! can hear it.
//!
//! Clients only accept `chat` frames that are signed by the BBS server key.
//! On receipt they cache the message in their local `chat_messages` table
//! and display it ordered by `timestamp`.
//!
//! Wire layout:
//!   `timestamp` (u64 LE, 8B) + `user_id` (u16 LE, 2B) +
//!   `text_len` (u16 LE, 2B) + `text` (Unishox2-compressed)
//!
//! `timestamp` is the server-set epoch time (seconds). A client-originated
//! chat sends `timestamp = 0` and `user_id = 0`; the server fills in the
//! authoritative values before storing and re-broadcasting.
//!
//! The text is limited to 256 characters on the client side before
//! compression (see `common.max_chat_text_len`).

const std = @import("std");
const frame = @import("frame.zig");
const unishox2 = @import("../unishox2.zig");
const limits = @import("limits.zig");

const max_encode_len = frame.max_encode_len;

/// Maximum chat text length in characters (client-side limit, before
/// compression). The TUI input is capped to this value. Re-exported from
/// `limits.max_chat_text_len`.
pub const max_chat_text_len: usize = limits.max_chat_text_len;

/// A single chat message. `text` is plain (uncompressed); `encode`
/// compresses it for the wire and `decode` decompresses it.
pub const Chat = struct {
    /// Server-set epoch timestamp (seconds since 1970-01-01). Clients send 0;
    /// the server stamps the message at receipt time and uses it as the
    /// primary key in its `chat_messages` table.
    timestamp: u64,
    /// Server-assigned user id (references the `users` table). Clients send 0;
    /// the server looks it up from the AX.25 callsign.
    user_id: u16,
    /// Plain text body (≤ 256 chars before compression on the client).
    text: []const u8,

    /// Serialize into `buf`. Compresses the text with Unishox2. Returns the
    /// number of bytes written, or `null` if the uncompressed text exceeds
    /// `max_chat_text_len`, the compressed form exceeds `max_encode_len - 12`,
    /// or `buf` is too small.
    pub fn encode(self: Chat, buf: []u8) ?usize {
        if (self.text.len > limits.max_chat_text_len) return null;

        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const compressed = unishox2.compress(arena.allocator(), self.text) catch return null;

        const fixed = 8 + 2 + 2;
        if (compressed.len > max_encode_len - fixed) return null;
        if (buf.len < fixed + compressed.len) return null;

        var pos: usize = 0;
        std.mem.writeInt(u64, buf[pos..][0..8], self.timestamp, .little);
        pos += 8;
        std.mem.writeInt(u16, buf[pos..][0..2], self.user_id, .little);
        pos += 2;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(compressed.len), .little);
        pos += 2;
        @memcpy(buf[pos..][0..compressed.len], compressed);
        pos += compressed.len;
        return pos;
    }

    /// Deserialize from `data`. Decompresses the text. Allocates `text` —
    /// the caller must call `deinit` to free. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?Chat {
        const fixed = 8 + 2 + 2;
        if (data.len < fixed) return null;
        const timestamp = std.mem.readInt(u64, data[0..8], .little);
        const user_id = std.mem.readInt(u16, data[8..10], .little);
        const text_len: usize = std.mem.readInt(u16, data[10..12], .little);
        if (data.len < fixed + text_len) return null;

        const text = if (text_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[fixed .. fixed + text_len], max_chat_text_len * 4) catch
                try allocator.dupe(u8, data[fixed .. fixed + text_len]);

        return .{
            .timestamp = timestamp,
            .user_id = user_id,
            .text = text,
        };
    }

    /// Free heap-allocated slices inside a `Chat` produced by `decode`.
    pub fn deinit(self: Chat, allocator: std.mem.Allocator) void {
        allocator.free(self.text);
    }
};

test "chat encode/decode round trip" {
    const allocator = std.testing.allocator;
    const text = "Hello from the BBS chat!";

    var buf: [max_encode_len]u8 = undefined;
    const n = (Chat{
        .timestamp = 1724022400,
        .user_id = 42,
        .text = text,
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Chat.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.timestamp);
    try std.testing.expectEqual(@as(u16, 42), decoded.user_id);
    try std.testing.expectEqualStrings(text, decoded.text);
}

test "chat encode/decode with empty text" {
    const allocator = std.testing.allocator;

    var buf: [max_encode_len]u8 = undefined;
    const n = (Chat{
        .timestamp = 0,
        .user_id = 0,
        .text = "",
    }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 12), n);

    const decoded = (try Chat.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), decoded.timestamp);
    try std.testing.expectEqual(@as(u16, 0), decoded.user_id);
    try std.testing.expectEqual(@as(usize, 0), decoded.text.len);
}

test "chat encode/decode with 256-char text" {
    const allocator = std.testing.allocator;
    const long_text = [_]u8{'A'} ** max_chat_text_len;

    var buf: [max_encode_len]u8 = undefined;
    const n = (Chat{
        .timestamp = 999999,
        .user_id = 7,
        .text = &long_text,
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Chat.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 999999), decoded.timestamp);
    try std.testing.expectEqual(@as(u16, 7), decoded.user_id);
    try std.testing.expectEqual(@as(usize, max_chat_text_len), decoded.text.len);
}

test "chat decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02 };
    const result = try Chat.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "chat decode rejects truncated text" {
    const allocator = std.testing.allocator;
    const bad = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01 };
    const result = try Chat.decode(allocator, &bad);
    try std.testing.expect(result == null);
}

test "chat encode rejects text > max_chat_text_len bytes" {
    const long_text = [_]u8{'A'} ** (max_chat_text_len + 1);
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect((Chat{
        .timestamp = 0,
        .user_id = 0,
        .text = &long_text,
    }).encode(&buf) == null);
}
