//! `registration` message type — a client registers with the BBS by
//! publishing a Handle (display name) and an Ed25519 public key.
//!
//! The payload is signed by the client's secret key, which proves ownership
//! of the public key. The server stores the (handle, public_key) pair in its
//! `users` table keyed by the AX.25 callsign from the incoming frame header
//! (the callsign is intentionally NOT carried in the payload so it cannot be
//! spoofed by the sender) and replies with a `registration_ack` containing
//! the server-assigned u16 user id.
//!
//! Wire layout (handle is Unishox2-compressed):
//!   `handle_len` (u8, compressed byte count) + `handle` (compressed) + `public_key` (32B)

const std = @import("std");
const frame = @import("frame.zig");
const unishox2 = @import("../unishox2.zig");
const limits = @import("limits.zig");

const max_payload_len = frame.max_payload_len;
pub const public_key_len: usize = 32;

/// A registration request sent by a client to the BBS. The callsign is not
/// included — the server takes it from the AX.25 header of the incoming
/// frame so it cannot be forged by the payload's author.
pub const Registration = struct {
    /// Display name (handle) the author wants to be known by.
    handle: []const u8,
    /// The author's Ed25519 public key (32 bytes).
    public_key: [public_key_len]u8,

    /// Serialize into `buf`. Compresses the handle with Unishox2. Returns the
    /// number of bytes written, or `null` if the uncompressed handle exceeds
    /// `max_handle_len`, the compressed form exceeds 255 bytes, or `buf` is
    /// too small.
    pub fn encode(self: Registration, buf: []u8) ?usize {
        if (self.handle.len > limits.max_handle_len) return null;

        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const compressed = unishox2.compress(arena.allocator(), self.handle) catch return null;
        if (compressed.len > 255) return null;

        const total = 1 + compressed.len + public_key_len;
        if (total > max_payload_len) return null;
        if (buf.len < total) return null;

        var pos: usize = 0;
        buf[pos] = @intCast(compressed.len);
        pos += 1;
        @memcpy(buf[pos..][0..compressed.len], compressed);
        pos += compressed.len;
        @memcpy(buf[pos..][0..public_key_len], &self.public_key);
        pos += public_key_len;
        return pos;
    }

    /// Deserialize from `data`. Decompresses the handle. Allocates the
    /// `handle` slice — the caller must call `deinit` to free. Returns `null`
    /// for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?Registration {
        if (data.len < 1) return null;
        var pos: usize = 0;
        const handle_len: usize = data[pos];
        pos += 1;
        if (data.len < pos + handle_len + public_key_len) return null;
        const handle = if (handle_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + handle_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + handle_len]);
        pos += handle_len;
        var public_key: [public_key_len]u8 = undefined;
        @memcpy(&public_key, data[pos..][0..public_key_len]);
        return .{
            .handle = handle,
            .public_key = public_key,
        };
    }

    /// Free heap-allocated slices inside a `Registration` produced by `decode`.
    pub fn deinit(self: Registration, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.handle));
    }
};

test "registration encode/decode round trip" {
    const allocator = std.testing.allocator;
    const pk = [_]u8{0xAB} ** 32;
    const reg: Registration = .{
        .handle = "brad",
        .public_key = pk,
    };

    var buf: [max_payload_len]u8 = undefined;
    const n = reg.encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Registration.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("brad", decoded.handle);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.public_key);
}

test "registration encode rejects handle > max_handle_len bytes" {
    const long_handle = [_]u8{'x'} ** (limits.max_handle_len + 1);
    var buf: [max_payload_len]u8 = undefined;
    try std.testing.expect((Registration{
        .handle = &long_handle,
        .public_key = [_]u8{0} ** 32,
    }).encode(&buf) == null);
}

test "registration decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{0x05};
    const result = try Registration.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "registration encode/decode with empty handle" {
    const allocator = std.testing.allocator;
    var buf: [max_payload_len]u8 = undefined;
    const n = (Registration{
        .handle = "",
        .public_key = [_]u8{0x55} ** 32,
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Registration.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), decoded.handle.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x55} ** 32, &decoded.public_key);
}
