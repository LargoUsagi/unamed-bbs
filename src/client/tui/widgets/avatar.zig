//! Avatar display widget — renders a stored avatar string for the TUI.
//!
//! Display-only: the server computes avatars once at registration and
//! replicates the resulting string via `user_info`, so this widget never
//! generates anything itself. It just renders the stored text (7 lines of
//! '█'/' ' cells joined by '\n') for embedding in a sidebar or info block.
//! When the avatar is empty (user not yet cached, or a legacy row predating
//! the column), a blank 7-line placeholder is returned so the surrounding
//! layout doesn't collapse.

const std = @import("std");

const zz = @import("zigzag");

const bbs = @import("bbs");

const avatar_height = bbs.avatar.avatar_height;
const avatar_width = bbs.avatar.avatar_width;

/// Render `avatar_text` for display. Caller owns the returned slice. If
/// `avatar_text` is empty, returns a blank 7-line grid of spaces.
pub fn render(alloc: std.mem.Allocator, avatar_text: []const u8) ![]const u8 {
    if (avatar_text.len != 0) return try alloc.dupe(u8, avatar_text);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    const blank_row = " " ** (avatar_width * 3);
    for (0..avatar_height) |row| {
        try buf.appendSlice(alloc, blank_row);
        if (row < avatar_height - 1) try buf.append(alloc, '\n');
    }
    return buf.toOwnedSlice(alloc);
}

/// Enforce the avatar grid dimensions on a `TextArea` used as an avatar
/// editor: at most `avatar_height` lines (7) and at most `avatar_width`
/// (11) display cells per line. The TextArea enforces `max_lines` on
/// newline insertion but does not enforce `max_cols`, so oversize lines
/// are truncated here. Call this after each key press to keep the editor
/// within the 11×7 grid so there is no wrapping.
pub fn clamp(text_area: *zz.TextArea) void {
    const max_w = avatar_width;
    const max_h = avatar_height;
    const lines = &text_area.lines;
    var row: usize = 0;
    while (row < lines.items.len) : (row += 1) {
        const line = &lines.items[row];
        var display_w: usize = 0;
        var byte_idx: usize = 0;
        var truncate_at: usize = line.items.len;
        while (byte_idx < line.items.len) {
            const byte_len = std.unicode.utf8ByteSequenceLength(line.items[byte_idx]) catch 1;
            if (byte_idx + byte_len > line.items.len) break;
            const cp = std.unicode.utf8Decode(line.items[byte_idx..][0..byte_len]) catch {
                display_w += 1;
                byte_idx += 1;
                continue;
            };
            const cw = zz.unicode.charWidth(cp);
            if (display_w + cw > max_w) {
                truncate_at = byte_idx;
                break;
            }
            display_w += cw;
            byte_idx += byte_len;
        }
        if (truncate_at < line.items.len) {
            line.shrinkRetainingCapacity(truncate_at);
        }
    }
    if (lines.items.len > max_h) {
        var i: usize = max_h;
        while (i < lines.items.len) : (i += 1) {
            lines.items[i].deinit();
        }
        lines.shrinkRetainingCapacity(max_h);
    }
    if (text_area.cursor_row >= lines.items.len) {
        text_area.cursor_row = if (lines.items.len > 0) lines.items.len - 1 else 0;
    }
    const cur_line = &lines.items[text_area.cursor_row];
    if (text_area.cursor_col > cur_line.items.len) {
        text_area.cursor_col = cur_line.items.len;
    }
}
