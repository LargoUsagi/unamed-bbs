//! `registration` message type — a client registers or logs in to the BBS
//! by publishing a Handle (display name), a self-identified callsign, and an
//! Ed25519 public key.
//!
//! The payload is signed by the client's secret key, which proves ownership
//! of the public key. The server stores the (handle, public_key) pair in its
//! `users` table. The **self-identified callsign** is carried in the payload
//! (distinct from the link-layer AX.25 callsign used for radio routing) so
//! it works over any transport (AGWPE, MeshCore, TCP) and is stored in
//! `users.callsign` for display on posts and in the user directory.
//!
//! The `mode` field distinguishes registration (new account) from login
//! (existing account). On `register`, the server verifies the signature
//! against the payload's public key and creates a new user; on `login`, the
//! server verifies the signature against the existing stored key and updates
//! the user's key/datetime.
//!
//! Wire layout (handle and callsign are Unishox2-compressed):
//!   `mode` (u8) + `handle_len` (u8) + `handle` (compressed) +
//!   `callsign_len` (u8) + `callsign` (compressed) + `public_key` (32B)

const std = @import("std");
const limits = @import("limits.zig");
const unishox2 = @import("unishox2.zig");

const max_chunk_len = limits.max_chunk_len;
pub const public_key_len: usize = 32;

/// A registration or login request sent by a client to the BBS. The
/// self-identified callsign is carried in the payload (not the link-layer
/// callsign) so it is stored with the user regardless of transport.
pub const Registration = struct {
    /// Whether this is a new registration or a login to an existing account.
    mode: @import("../../protocol.zig").RegistrationMode = .register,
    /// Display name (handle) the author wants to be known by.
    handle: []const u8,
    /// The author's self-identified HAM radio callsign (uppercase, max 10
    /// bytes uncompressed). Distinct from the link-layer AX.25 callsign
    /// used for radio routing.
    callsign: []const u8,
    /// The author's Ed25519 public key (32 bytes).
    public_key: [public_key_len]u8,

    /// Serialize into `buf`. Compresses the handle and callsign with
    /// Unishox2. Returns the number of bytes written, or `null` if the
    /// uncompressed handle exceeds `max_handle_len`, the uncompressed
    /// callsign exceeds `max_callsign_len`, either compressed form exceeds
    /// 255 bytes, the total exceeds `max_chunk_len`, or `buf` is too small.
    pub fn encode(self: Registration, buf: []u8) ?usize {
        if (self.handle.len > limits.max_handle_len) return null;
        if (self.callsign.len > limits.max_callsign_len) return null;

        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const compressed_handle = unishox2.compress(alloc, self.handle) catch return null;
        if (compressed_handle.len > 255) return null;

        const compressed_callsign = unishox2.compress(alloc, self.callsign) catch return null;
        if (compressed_callsign.len > 255) return null;

        const total = 1 + 1 + compressed_handle.len + 1 + compressed_callsign.len + public_key_len;
        if (total > max_chunk_len) return null;
        if (buf.len < total) return null;

        var pos: usize = 0;
        buf[pos] = @intFromEnum(self.mode);
        pos += 1;
        buf[pos] = @intCast(compressed_handle.len);
        pos += 1;
        @memcpy(buf[pos..][0..compressed_handle.len], compressed_handle);
        pos += compressed_handle.len;
        buf[pos] = @intCast(compressed_callsign.len);
        pos += 1;
        @memcpy(buf[pos..][0..compressed_callsign.len], compressed_callsign);
        pos += compressed_callsign.len;
        @memcpy(buf[pos..][0..public_key_len], &self.public_key);
        pos += public_key_len;
        return pos;
    }

    /// Deserialize from `data`. Decompresses the handle and callsign.
    /// Allocates the `handle` and `callsign` slices — the caller must call
    /// `deinit` to free them. Returns `null` for malformed data.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !?Registration {
        if (data.len < 1) return null;
        var pos: usize = 0;
        const mode_byte = data[pos];
        pos += 1;

        if (pos >= data.len) return null;
        const handle_len: usize = data[pos];
        pos += 1;
        if (data.len < pos + handle_len + 1 + public_key_len) return null;

        const handle = if (handle_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + handle_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + handle_len]);
        pos += handle_len;

        if (pos >= data.len) return null;
        const callsign_len: usize = data[pos];
        pos += 1;
        if (data.len < pos + callsign_len + public_key_len) {
            allocator.free(handle);
            return null;
        }

        const callsign = if (callsign_len == 0)
            try allocator.dupe(u8, &.{})
        else
            unishox2.decompress(allocator, data[pos .. pos + callsign_len], 4096) catch
                try allocator.dupe(u8, data[pos .. pos + callsign_len]);
        pos += callsign_len;

        var public_key: [public_key_len]u8 = undefined;
        @memcpy(&public_key, data[pos..][0..public_key_len]);

        const mode: @import("../../protocol.zig").RegistrationMode = switch (mode_byte) {
            0 => .register,
            1 => .login,
            else => {
                allocator.free(handle);
                allocator.free(callsign);
                return null;
            },
        };

        return .{
            .mode = mode,
            .handle = handle,
            .callsign = callsign,
            .public_key = public_key,
        };
    }

    /// Free heap-allocated slices inside a `Registration` produced by `decode`.
    pub fn deinit(self: Registration, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.handle));
        allocator.free(@constCast(self.callsign));
    }
};

test "registration encode/decode round trip (register)" {
    const allocator = std.testing.allocator;
    const pk = [_]u8{0xAB} ** 32;
    const reg: Registration = .{
        .mode = .register,
        .handle = "brad",
        .callsign = "KE8WIF",
        .public_key = pk,
    };

    var buf: [max_chunk_len]u8 = undefined;
    const n = reg.encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Registration.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@import("../../protocol.zig").RegistrationMode.register, decoded.mode);
    try std.testing.expectEqualStrings("brad", decoded.handle);
    try std.testing.expectEqualStrings("KE8WIF", decoded.callsign);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.public_key);
}

test "registration encode/decode round trip (login)" {
    const allocator = std.testing.allocator;
    const pk = [_]u8{0xCD} ** 32;
    const reg: Registration = .{
        .mode = .login,
        .handle = "alice",
        .callsign = "",
        .public_key = pk,
    };

    var buf: [max_chunk_len]u8 = undefined;
    const n = reg.encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Registration.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@import("../../protocol.zig").RegistrationMode.login, decoded.mode);
    try std.testing.expectEqualStrings("alice", decoded.handle);
    try std.testing.expectEqualStrings("", decoded.callsign);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.public_key);
}

test "registration encode rejects handle > max_handle_len bytes" {
    const long_handle = [_]u8{'x'} ** (limits.max_handle_len + 1);
    var buf: [max_chunk_len]u8 = undefined;
    try std.testing.expect((Registration{
        .mode = .register,
        .handle = &long_handle,
        .callsign = "KE8WIF",
        .public_key = [_]u8{0} ** 32,
    }).encode(&buf) == null);
}

test "registration encode rejects callsign > max_callsign_len bytes" {
    const long_callsign = [_]u8{'x'} ** (limits.max_callsign_len + 1);
    var buf: [max_chunk_len]u8 = undefined;
    try std.testing.expect((Registration{
        .mode = .register,
        .handle = "brad",
        .callsign = &long_callsign,
        .public_key = [_]u8{0} ** 32,
    }).encode(&buf) == null);
}

test "registration decode rejects malformed (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{0x05};
    const result = try Registration.decode(allocator, &short);
    try std.testing.expect(result == null);
}

test "registration encode/decode with empty handle and callsign" {
    const allocator = std.testing.allocator;
    var buf: [max_chunk_len]u8 = undefined;
    const n = (Registration{
        .mode = .register,
        .handle = "",
        .callsign = "",
        .public_key = [_]u8{0x55} ** 32,
    }).encode(&buf) orelse return error.EncodeFailed;

    const decoded = (try Registration.decode(allocator, buf[0..n])) orelse return error.DecodeFailed;
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), decoded.handle.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.callsign.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x55} ** 32, &decoded.public_key);
}
