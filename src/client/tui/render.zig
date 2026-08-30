//! Presentation helpers for the TUI: styled status indicators and the
//! `fillTerminal` layout helper used by non-modal screens to pad their
//! content to full terminal dimensions.
//!
//! These functions take primitives (not `*AppContext` / `*Model`) so they
//! have no import dependency on the application state and can be unit-tested
//! in isolation.

const std = @import("std");
const zz = @import("zigzag");

const signing = @import("bbs").signing;
const endpoint = @import("bbs").endpoint;

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
    var s = zz.Style{};
    s = s.bold(true);
    s = s.inline_style(true);
    s = s.fg(if (connected) zz.Color.green else zz.Color.red);
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
    var s = zz.Style{};
    s = s.bold(true);
    s = s.inline_style(true);
    s = s.fg(if (sending) zz.Color.yellow else zz.Color.cyan);
    return s.render(alloc, status);
}

/// Render the BBS (server) key indicator.
/// `bbs_key` is the 32-byte key or null. `locked` indicates --bbs-key was set.
pub fn renderBbsIndicator(
    alloc: std.mem.Allocator,
    bbs_key: ?[signing.public_key_len]u8,
    locked: bool,
) ![]const u8 {
    var s = zz.Style{};
    s = s.inline_style(true);
    s = s.fg(if (bbs_key != null) zz.Color.green else zz.Color.gray(12));
    const label = if (bbs_key) |key| blk: {
        const hex = try std.fmt.allocPrint(alloc, "BBS key: {x:0>2}{x:0>2}{x:0>2}{x:0>2}\u{2026}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{s}", .{
            key[0], key[1], key[2], key[3],
            key[28], key[29], key[30], key[31],
            if (locked) " (locked)" else "",
        });
        break :blk hex;
    } else try alloc.dupe(u8, "BBS key: none");
    defer alloc.free(label);
    return s.render(alloc, label);
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
        @memcpy(sparkline_buf[sl_len..sl_len + g.len], g);
        sl_len += g.len;
    }

    var s = zz.Style{};
    s = s.fg(zz.Color.gray(12));
    s = s.inline_style(true);

    const label = try std.fmt.allocPrint(alloc, "{d}|{d} {s}", .{ tx_recent, rx_recent, sparkline_buf[0..sl_len] });
    defer alloc.free(label);
    return s.render(alloc, label);
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
