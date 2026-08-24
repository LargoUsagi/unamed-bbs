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
