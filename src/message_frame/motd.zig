//! `motd` message type — the "Message of the Day" sent by the server in
//! response to a `motd_request`. The text is Unishox2-compressed on the wire.
//! The `Motd` struct holds plain text; `encode` compresses and `decode`
//! decompresses.
//!
//! Wire layout:
//!   `text_len` (u16 LE, 2B) + `text` (compressed)

const std = @import("std");
const limits = @import("limits.zig");
const unishox2 = @import("../unishox2.zig");

const max_encode_len = limits.max_encode_len;

/// The Message of the Day — plain text (compressed on the wire).
pub const Motd = struct {
    text: []const u8,

    /// Serialize into `buf`. Compresses the text with Unishox2. Returns the
    /// number of bytes written, or `null` if the uncompressed text exceeds
    /// `max_body_len`, the compressed form exceeds `max_encode_len - 2`, or
    /// `buf` is too small.
    pub fn encode(self: Motd, buf: []u8) ?usize {
        if (self.text.len > limits.max_body_len) return null;

        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const compressed = unishox2.compress(arena.allocator(), self.text) catch return null;

        const fixed = 2;
        if (compressed.len > max_encode_len - fixed) return null;
        if (buf.len < fixed + compressed.len) return null;

        var pos: usize = 0;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(compressed.len), .little);
        pos += 2;
        @memcpy(buf[pos..][0..compressed.len], compressed);
        pos += compressed.len;
        return pos;
    }

    /// Deserialize from `data`. Decompresses the text. Allocates `text` —
    /// the caller must call `deinit` to free. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?Motd {
        const fixed = 2;
        if (data.len < fixed) return null;
        const text_len: usize = std.mem.readInt(u16, data[0..2], .little);
        if (data.len < fixed + text_len) return null;

        const text = if (text_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[fixed .. fixed + text_len], 4096) catch
                try allocator.dupe(u8, data[fixed .. fixed + text_len]);

        return .{ .text = text };
    }

    /// Free heap-allocated slices inside a `Motd` produced by `decode`.
    pub fn deinit(self: Motd, allocator: std.mem.Allocator) void {
        allocator.free(self.text);
    }
};

test "motd encode/decode round trip" {
    const allocator = std.testing.allocator;
    const text = "Welcome to the BBS! Net meets every Thursday at 8pm.";

    var buf: [max_encode_len]u8 = undefined;
    const n = (Motd{ .text = text }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Motd.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings(text, decoded.text);
}

test "motd encode/decode with empty text" {
    const allocator = std.testing.allocator;

    var buf: [max_encode_len]u8 = undefined;
    const n = (Motd{ .text = "" }).encode(&buf) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 2), n);

    const decoded = (try Motd.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), decoded.text.len);
}

test "motd decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01 };
    const result = try Motd.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "motd decode rejects truncated text" {
    const allocator = std.testing.allocator;
    const bad = [_]u8{ 0x10, 0x00, 0x01, 0x02 };
    const result = try Motd.decode(allocator, &bad);
    try std.testing.expect(result == null);
}
