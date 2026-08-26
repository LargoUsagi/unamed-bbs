//! ASCII art avatar generation — shared by client and server.
//!
//! Produces an 11×7 symmetric bitmap avatar from a 32-byte seed (normally an
//! Ed25519 public key) or, as a deterministic fallback, from a u16 user id.
//! The left 6 columns are derived from seed bits; columns 6-10 mirror
//! columns 4-0 to create a symmetric pattern. Filled cells use '█' and empty
//! cells use ' '. The 7 rows are joined by '\n'.
//!
//! The server computes the avatar once at registration time (from the
//! registered public key) and stores/replicates it as a TEXT column on the
//! `users` table, so clients receive it pre-computed in `user_info` broadcasts
//! and never need to run this logic themselves (except for the uncached-user
//! fallback and the account-screen "reset to default" action).

const std = @import("std");

/// Width of the ASCII art avatar.
pub const avatar_width: usize = 11;
/// Height of the ASCII art avatar.
pub const avatar_height: usize = 7;

/// Total number of cells in one avatar (width × height).
pub const avatar_cell_count: usize = avatar_width * avatar_height;

/// Generate an 11×7 symmetric ASCII art avatar from a 32-byte public key.
/// Returns 7 lines joined by '\n'. Caller owns the result.
pub fn generateFromKey(alloc: std.mem.Allocator, public_key: [32]u8) ![]const u8 {
    return generate(alloc, &public_key);
}

/// Generate an 11×7 avatar from a u16 user id (used when the user is not
/// cached and no public key is available). Derives a pseudo-random 32-byte
/// key from the id so the avatar is deterministic.
pub fn generateFromId(alloc: std.mem.Allocator, user_id: u16) ![]const u8 {
    var key: [32]u8 = std.mem.zeroes([32]u8);
    var rng_state: u32 = user_id;
    for (&key) |*b| {
        rng_state = rng_state *% 1103515245 +% 12345;
        b.* = @truncate(rng_state >> 16);
    }
    return generate(alloc, &key);
}

fn generate(alloc: std.mem.Allocator, seed: []const u8) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    for (0..avatar_height) |row| {
        for (0..6) |col| {
            const bit_idx = row * 6 + col;
            const byte_idx = bit_idx / 8;
            const bit_in_byte: u3 = @intCast(7 - (bit_idx % 8));
            const filled = byte_idx < seed.len and
                (seed[byte_idx] & (@as(u8, 1) << bit_in_byte)) != 0;
            try buf.appendSlice(alloc, if (filled) "█" else " ");
        }
        for (0..5) |col| {
            const src_col = 4 - col;
            const bit_idx = row * 6 + src_col;
            const byte_idx = bit_idx / 8;
            const bit_in_byte: u3 = @intCast(7 - (bit_idx % 8));
            const filled = byte_idx < seed.len and
                (seed[byte_idx] & (@as(u8, 1) << bit_in_byte)) != 0;
            try buf.appendSlice(alloc, if (filled) "█" else " ");
        }
        if (row < avatar_height - 1) try buf.append(alloc, '\n');
    }

    return buf.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "generateFromKey produces avatar_height lines of avatar_width cells" {
    const alloc = std.testing.allocator;
    const pk = [_]u8{0xAA} ** 32;
    const av = try generateFromKey(alloc, pk);
    defer alloc.free(av);

    var line_count: usize = 1;
    for (av) |c| {
        if (c == '\n') line_count += 1;
    }
    try std.testing.expectEqual(avatar_height, line_count);
}

test "generateFromKey is deterministic — same key yields same avatar" {
    const alloc = std.testing.allocator;
    const pk = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 } ++ [_]u8{0} ** 16;
    const a1 = try generateFromKey(alloc, pk);
    defer alloc.free(a1);
    const a2 = try generateFromKey(alloc, pk);
    defer alloc.free(a2);
    try std.testing.expectEqualStrings(a1, a2);
}

test "generateFromKey produces symmetric rows (left mirrors right)" {
    const alloc = std.testing.allocator;
    const pk = [_]u8{0xFF} ** 32;
    const av = try generateFromKey(alloc, pk);
    defer alloc.free(av);

    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(alloc);
    var it = std.mem.splitScalar(u8, av, '\n');
    while (it.next()) |line| try lines.append(alloc, line);
    try std.testing.expectEqual(avatar_height, lines.items.len);

    for (lines.items) |line| {
        // Each cell is a 3-byte UTF-8 codepoint ('█' or ' '), so byte length
        // is avatar_width * 3.
        try std.testing.expectEqual(avatar_width * 3, line.len);
        // Columns 6-10 mirror columns 4-0. Compare cell-by-cell (3 bytes each).
        for (0..5) |col| {
            const left_cell = (4 - col) * 3;
            const right_cell = (6 + col) * 3;
            try std.testing.expectEqualSlices(
                u8,
                line[left_cell .. left_cell + 3],
                line[right_cell .. right_cell + 3],
            );
        }
    }
}

test "generateFromId is deterministic — same id yields same avatar" {
    const alloc = std.testing.allocator;
    const a1 = try generateFromId(alloc, 42);
    defer alloc.free(a1);
    const a2 = try generateFromId(alloc, 42);
    defer alloc.free(a2);
    try std.testing.expectEqualStrings(a1, a2);
}

test "generateFromId differs for different ids" {
    const alloc = std.testing.allocator;
    const a1 = try generateFromId(alloc, 1);
    defer alloc.free(a1);
    const a2 = try generateFromId(alloc, 2);
    defer alloc.free(a2);
    try std.testing.expect(!std.mem.eql(u8, a1, a2));
}

test "different keys yield different avatars" {
    const alloc = std.testing.allocator;
    const pk1 = [_]u8{0xAA} ** 32;
    const pk2 = [_]u8{0x55} ** 32;
    const a1 = try generateFromKey(alloc, pk1);
    defer alloc.free(a1);
    const a2 = try generateFromKey(alloc, pk2);
    defer alloc.free(a2);
    try std.testing.expect(!std.mem.eql(u8, a1, a2));
}
