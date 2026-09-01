//! Presentation helpers for the TUI: the shared style presets, styled status
//! indicators, the key-fingerprint formatters, the help-text helper, and the
//! `fillTerminal` / `countLines` layout helpers used by non-modal screens to
//! pad their content to full terminal dimensions.
//!
//! These functions take primitives (not `*AppContext` / `*Model`) so they
//! have no import dependency on the application state and can be unit-tested
//! in isolation. The `TopBar` widget (`widgets/top_bar.zig`) wraps these
//! primitives and does take `*AppContext`.

const std = @import("std");
const zz = @import("zigzag");

const signing = @import("bbs").signing;
const endpoint = @import("bbs").endpoint;

// ---------------------------------------------------------------------------
// Shared style presets
// ---------------------------------------------------------------------------

/// Dim gray inline text — help lines, secondary info lines, and the packet
/// sparkline. The standard "not primary content" style across all screens.
pub const dim = (zz.Style{}).fg(zz.Color.gray(12)).inline_style(true);

/// Bold cyan inline text — section titles (bulletins list, chat log, bulletin
/// title, MOTD label).
pub const title_cyan = (zz.Style{}).bold(true).fg(zz.Color.cyan).inline_style(true);

/// Bold magenta inline text — the settings screen's message-log title.
pub const title_magenta = (zz.Style{}).bold(true).fg(zz.Color.magenta).inline_style(true);

/// Bold blue inline text — the settings screen's sent-transmissions title.
pub const title_blue = (zz.Style{}).bold(true).fg(zz.Color.blue).inline_style(true);

/// Bold yellow inline text — the notice popup's warning text.
pub const bold_yellow = (zz.Style{}).bold(true).fg(zz.Color.yellow).inline_style(true);

/// Plain (non-bold) yellow inline text — the pending-registration waiting
/// line and the CLI-locked transport notice.
pub const yellow = (zz.Style{}).fg(zz.Color.yellow).inline_style(true);

/// Render the connection status indicator. When connected, the active
/// transport kind (AGWPE / TCP) is appended so the user can see at a
/// glance which link the status line refers to:
///   green  "● Connected (AGWPE)" / "● Connected (TCP)"
///   red    "○ Disconnected"
pub fn renderConnIndicator(
    alloc: std.mem.Allocator,
    connected: bool,
    kind: endpoint.TransportKind,
) ![]const u8 {
    const s = (zz.Style{}).bold(true).inline_style(true).fg(if (connected) zz.Color.green else zz.Color.red);
    const kind_name = switch (kind) {
        .agwpe => "AGWPE",
        .tcp => "TCP",
        .meshcore => "MeshCore",
    };
    const label = if (connected)
        try std.fmt.allocPrint(alloc, "\xe2\x97\x8f Connected ({s})", .{kind_name})
    else
        try alloc.dupe(u8, "\xe2\x97\x8b Disconnected");
    defer alloc.free(label);
    return s.render(alloc, label);
}

/// Render the status line (cyan normally, yellow when sending).
pub fn renderStatusLine(alloc: std.mem.Allocator, status: []const u8, sending: bool) ![]const u8 {
    const s = (zz.Style{}).bold(true).inline_style(true).fg(if (sending) zz.Color.yellow else zz.Color.cyan);
    return s.render(alloc, status);
}

/// Render the BBS (server) key indicator.
/// `bbs_key` is the 32-byte key or null. `locked` indicates --bbs-key was set.
pub fn renderBbsIndicator(
    alloc: std.mem.Allocator,
    bbs_key: ?[signing.public_key_len]u8,
    locked: bool,
) ![]const u8 {
    const s = (zz.Style{}).inline_style(true).fg(if (bbs_key != null) zz.Color.green else zz.Color.gray(12));
    const label = if (bbs_key) |key| blk: {
        const fp = try formatKeyHex(alloc, key, true);
        defer alloc.free(fp);
        break :blk try std.fmt.allocPrint(alloc, "BBS key: {s}{s}", .{
            fp,
            if (locked) " (locked)" else "",
        });
    } else try alloc.dupe(u8, "BBS key: none");
    defer alloc.free(label);
    return s.render(alloc, label);
}

// ---------------------------------------------------------------------------
// Key formatting
// ---------------------------------------------------------------------------

/// Format an Ed25519 public key as lowercase hex. When `truncate` is true,
/// returns the fingerprint form `XXXXXXXX…XXXXXXXX` (first 4 + last 4 bytes
/// joined by an ellipsis); when false, returns the full 64-char hex of all
/// 32 bytes, suitable for copying into CLI flags such as `--bbs-key`.
/// Caller frees the returned string.
pub fn formatKeyHex(
    alloc: std.mem.Allocator,
    pk: [signing.public_key_len]u8,
    truncate: bool,
) ![]const u8 {
    if (truncate) {
        return std.fmt.allocPrint(alloc, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}\u{2026}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
            pk[0],          pk[1],          pk[2],          pk[3],
            pk[pk.len - 4], pk[pk.len - 3], pk[pk.len - 2], pk[pk.len - 1],
        });
    }
    var buf: [signing.public_key_len * 2]u8 = undefined;
    const hex_digits = "0123456789abcdef";
    for (pk, 0..) |byte, i| {
        buf[i * 2] = hex_digits[byte >> 4];
        buf[i * 2 + 1] = hex_digits[byte & 0xf];
    }
    return alloc.dupe(u8, &buf);
}

/// Styled `Key: …` line for the working signing key, in the shared dim style
/// used by the login, register, and account screens. `callsign` may be empty
/// to omit the `Callsign: …  ` prefix (the login screen passes empty; the
/// register and account screens pass their callsign source). Falls back to a
/// unified placeholder when no keypair is derived yet. Caller frees.
pub fn renderKeyLine(
    alloc: std.mem.Allocator,
    keypair: ?signing.KeyPair,
    callsign: []const u8,
    key_from_file: bool,
) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    if (callsign.len > 0) {
        const cs_prefix = try std.fmt.allocPrint(alloc, "Callsign: {s}  ", .{callsign});
        defer alloc.free(cs_prefix);
        try buf.appendSlice(alloc, cs_prefix);
    }
    if (keypair) |kp| {
        const fp = try formatKeyHex(alloc, kp.publicKeyBytes(), true);
        defer alloc.free(fp);
        const key_line = try std.fmt.allocPrint(alloc, "Key: {s}", .{fp});
        defer alloc.free(key_line);
        try buf.appendSlice(alloc, key_line);
    } else {
        const hint: []const u8 = if (key_from_file)
            "Key: none (key file failed to load)"
        else
            "Key: none (enter handle + password to derive)";
        try buf.appendSlice(alloc, hint);
    }

    return dim.render(alloc, buf.items);
}

/// Render the packet statistics: "TX|RX" counts for the last 10 seconds
/// followed by a 15-bar sparkline of total (TX+RX) packets per 2-second
/// bucket over the last 30 seconds. The sparkline uses unicode block
/// characters (▁▂▃▄▅▆▇█) scaled to the max bucket value.
pub fn renderPacketStats(
    alloc: std.mem.Allocator,
    tx_recent: u32,
    rx_recent: u32,
    sparkline: [15]u32,
) ![]const u8 {
    const glyphs = [_][]const u8{ " ", "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84", "\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87", "\xe2\x96\x88" };

    var max: u32 = 0;
    for (sparkline) |v| {
        if (v > max) max = v;
    }

    // Build the sparkline string. Each glyph is 3 bytes (UTF-8) except the
    // space (1 byte), so 15 × 3 = 45 bytes max.
    var sparkline_buf: [45]u8 = undefined;
    var sl_len: usize = 0;
    for (sparkline) |v| {
        const glyph_idx: usize = if (v == 0 or max == 0) 0 else blk: {
            const scaled = @as(u64, v) * 8 / @as(u64, max);
            break :blk @intCast(@min(8, @max(1, scaled)));
        };
        const g = glyphs[glyph_idx];
        @memcpy(sparkline_buf[sl_len .. sl_len + g.len], g);
        sl_len += g.len;
    }

    const label = try std.fmt.allocPrint(alloc, "{d}|{d} {s}", .{ tx_recent, rx_recent, sparkline_buf[0..sl_len] });
    defer alloc.free(label);
    return dim.render(alloc, label);
}

/// Render a help-text line in the standard dim-gray style used across all
/// non-modal screens. Returns a styled string the caller frees.
pub fn renderHelp(alloc: std.mem.Allocator, text: []const u8) ![]const u8 {
    return dim.render(alloc, text);
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

/// Pad content with spaces to fill the terminal dimensions so that
/// `ScreenStack.compose` has a full-sized background to center modal
/// overlays on. Non-modal screens should call this at the end of their
/// `view`; modal screens should NOT (they need to be their natural size
/// so `compose` can center them).
///
/// A 1-cell margin is left on every side so content isn't flush with the
/// terminal edge: content is placed in a box `2*margin` smaller than the
/// terminal, then that box is centered within the full terminal.
pub fn fillTerminal(
    alloc: std.mem.Allocator,
    ctx: *const zz.Context,
    content: []const u8,
) ![]const u8 {
    const margin: usize = 1;
    const w: usize = if (ctx.width > 2 * margin) ctx.width - 2 * margin else 1;
    const h: usize = if (ctx.height > 2 * margin) ctx.height - 2 * margin else 1;
    const inner = try zz.place.place(alloc, w, h, .center, .top, content);
    defer alloc.free(inner);
    return zz.place.place(alloc, ctx.width, ctx.height, .center, .top, inner);
}

/// Count the number of lines a rendered string occupies. A trailing newline
/// does NOT add an extra (empty) line — the list/chat box padding math
/// depends on this, and it differs from `zz.measure.height`, which counts a
/// trailing newline as an additional line.
pub fn countLines(s: []const u8) usize {
    if (s.len == 0) return 0;
    var n: usize = 1;
    for (s) |c| {
        if (c == '\n') n += 1;
    }
    if (s[s.len - 1] == '\n') n -= 1;
    return n;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "formatKeyHex truncated shows first and last 4 bytes" {
    var pk: [signing.public_key_len]u8 = undefined;
    for (&pk, 0..) |*b, i| b.* = @intCast(i);
    const out = try formatKeyHex(testing.allocator, pk, true);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("00010203\u{2026}1c1d1e1f", out);
}

test "formatKeyHex full shows all 32 bytes as 64 lowercase hex chars" {
    var pk: [signing.public_key_len]u8 = undefined;
    for (&pk, 0..) |*b, i| b.* = @intCast(i);
    const out = try formatKeyHex(testing.allocator, pk, false);
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, signing.public_key_len * 2), out.len);
    try testing.expectEqualStrings("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", out);
}

test "formatKeyHex zero key pads hex digits" {
    const pk = [_]u8{0} ** signing.public_key_len;
    const truncated = try formatKeyHex(testing.allocator, pk, true);
    defer testing.allocator.free(truncated);
    try testing.expectEqualStrings("00000000\u{2026}00000000", truncated);
    const full = try formatKeyHex(testing.allocator, pk, false);
    defer testing.allocator.free(full);
    var expected: [signing.public_key_len * 2]u8 = undefined;
    @memset(&expected, '0');
    try testing.expectEqualSlices(u8, &expected, full);
}

test "renderKeyLine with keypair and empty callsign omits callsign prefix" {
    const seed = [_]u8{0} ** signing.seed_len;
    const kp = try signing.KeyPair.fromSeed(seed);
    const out = try renderKeyLine(testing.allocator, kp, "", false);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Callsign:") == null);
    const fp = try formatKeyHex(testing.allocator, kp.publicKeyBytes(), true);
    defer testing.allocator.free(fp);
    try testing.expect(std.mem.indexOf(u8, out, "Key: ") != null);
    try testing.expect(std.mem.indexOf(u8, out, fp) != null);
}

test "renderKeyLine with keypair and callsign includes both fields" {
    const seed = [_]u8{1} ** signing.seed_len;
    const kp = try signing.KeyPair.fromSeed(seed);
    const out = try renderKeyLine(testing.allocator, kp, "KE8WIF", false);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Callsign: KE8WIF  Key: ") != null);
}

test "renderKeyLine without keypair shows derive hint" {
    const out = try renderKeyLine(testing.allocator, null, "", false);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Key: none (enter handle + password to derive)") != null);
}

test "renderKeyLine without keypair from file shows load-failure hint" {
    const out = try renderKeyLine(testing.allocator, null, "KE8WIF", true);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Callsign: KE8WIF  Key: none (key file failed to load)") != null);
}

test "countLines counts rows without trailing-newline penalty" {
    try testing.expectEqual(@as(usize, 0), countLines(""));
    try testing.expectEqual(@as(usize, 1), countLines("a"));
    try testing.expectEqual(@as(usize, 2), countLines("a\nb"));
    try testing.expectEqual(@as(usize, 2), countLines("a\nb\n"));
    try testing.expectEqual(@as(usize, 3), countLines("a\n\nb"));
}
