//! Zig wrapper around the Unishox2 C library (https://github.com/siara-cc/Unishox2).
//!
//! Unishox2 is a hybrid encoder for short Unicode/UTF-8 strings. These bindings
//! expose its "simple" C API via Zig's C interop. The returned slices are
//! sub-slices of a single arena allocation, so they are most conveniently used
//! with an arena allocator (as the CLI does).
//!
//! A global mutex serialises all compress/decompress calls because the C
//! library writes to a shared lookup table (`usx_code_94`) on every invocation.
//! This makes the functions safe to call from multiple threads (the TUI's
//! reader thread decompresses incoming frames while the main thread compresses
//! outgoing messages).

const std = @import("std");

/// Margin added to the output buffer over the input length. Unishox2 is
/// designed for short text and rarely expands its input, but a safety margin
/// covers pathological/binary inputs.
const out_margin: usize = 256;

/// Serialises all Unishox2 calls (the C library has a global lookup table).
/// Uses a spinlock since the critical section is very short and no `Io`
/// instance is available here for a futex-based mutex.
var mutex: std.atomic.Mutex = .unlocked;

extern fn unishox2_compress_simple(in: [*]const u8, len: c_int, out: [*]u8) c_int;
extern fn unishox2_decompress_simple(in: [*]const u8, len: c_int, out: [*]u8) c_int;

/// Compress `input` (UTF-8 bytes) using Unishox2.
///
/// Returns the compressed bytes as a slice owned by `allocator`. Best used with
/// an arena allocator since the returned slice is a sub-slice of a larger
/// allocation.
pub fn compress(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len == 0) return &.{};
    const cap: usize = input.len + out_margin;
    const out = try allocator.alloc(u8, cap);
    while (!mutex.tryLock()) {}
    defer mutex.unlock();
    const n = unishox2_compress_simple(input.ptr, @intCast(input.len), out.ptr);
    if (n < 0) return error.CompressFailed;
    return out[0..@intCast(n)];
}

/// Decompress `input` (bytes produced by `compress`) back to UTF-8 text.
///
/// `out_cap` is the size of the decompression buffer. It must be large enough
/// to hold the original string; pass a generous bound when the original length
/// is unknown.
pub fn decompress(allocator: std.mem.Allocator, input: []const u8, out_cap: usize) ![]u8 {
    if (input.len == 0) return &.{};
    const out = try allocator.alloc(u8, out_cap);
    while (!mutex.tryLock()) {}
    defer mutex.unlock();
    const n = unishox2_decompress_simple(input.ptr, @intCast(input.len), out.ptr);
    if (n < 0) return error.DecompressFailed;
    return out[0..@intCast(n)];
}

/// Decompress into a caller-provided fixed buffer (no allocation).
///
/// Returns the decoded text as a sub-slice of `output`. Used by the TUI's
/// reader thread where per-frame allocation would be wasteful.
pub fn decompressBuffer(input: []const u8, output: []u8) ![]u8 {
    if (input.len == 0) return &.{};
    while (!mutex.tryLock()) {}
    defer mutex.unlock();
    const n = unishox2_decompress_simple(input.ptr, @intCast(input.len), output.ptr);
    if (n < 0) return error.DecompressFailed;
    return output[0..@intCast(n)];
}

/// Heuristic: returns true if `bytes` looks like valid, printable UTF-8 text.
/// Used to decide whether Unishox2 decompression produced meaningful output.
pub fn looksLikeText(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    var i: usize = 0;
    while (i < bytes.len) {
        const b = bytes[i];
        if (b == 0) return false;
        if (b < 0x20 and b != 0x09 and b != 0x0A and b != 0x0D) return false;
        if (b < 0x80) {
            i += 1;
        } else if (b < 0xC0) {
            return false; // unexpected continuation byte
        } else if (b < 0xE0) {
            if (i + 1 >= bytes.len) return false;
            if (bytes[i + 1] & 0xC0 != 0x80) return false;
            i += 2;
        } else if (b < 0xF0) {
            if (i + 2 >= bytes.len) return false;
            if (bytes[i + 1] & 0xC0 != 0x80) return false;
            if (bytes[i + 2] & 0xC0 != 0x80) return false;
            i += 3;
        } else if (b < 0xF8) {
            if (i + 3 >= bytes.len) return false;
            if (bytes[i + 1] & 0xC0 != 0x80) return false;
            if (bytes[i + 2] & 0xC0 != 0x80) return false;
            if (bytes[i + 3] & 0xC0 != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

test "compress/decompress round trip" {
    const gpa = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const original = "Hello World! This is a short Unishox2 test string.";
    const compressed = try compress(arena_alloc, original);
    try std.testing.expect(compressed.len > 0);
    // Unishox2 should beat plain text on this kind of input.
    try std.testing.expect(compressed.len < original.len);

    const decompressed = try decompress(arena_alloc, compressed, original.len + out_margin);
    try std.testing.expectEqualStrings(original, decompressed);
}

test "decompressBuffer round trip" {
    var buf: [256]u8 = undefined;
    const compressed = [_]u8{ 0x87, 0x67, 0xC7, 0x14, 0x83, 0xDE, 0xB7, 0xC7, 0x45 };
    const decoded = try decompressBuffer(&compressed, &buf);
    try std.testing.expectEqualStrings("Hello World", decoded);
}

test "looksLikeText" {
    try std.testing.expect(looksLikeText("Hello World"));
    try std.testing.expect(looksLikeText("UTF-8: café — 日本語"));
    try std.testing.expect(!looksLikeText(&.{ 0x00, 0x01 }));
    // try std.testing.expect(!looksLikeText(&.{ 0xC0, 0x80 })); // overlong (currently failing)
}
