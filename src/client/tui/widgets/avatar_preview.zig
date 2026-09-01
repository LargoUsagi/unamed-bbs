//! Avatar preview widget — a focusable, display-only rendering of the
//! stored avatar text, used on the Account screen in place of an inline
//! TextArea editor. Pressing Enter while focused opens the avatar editor
//! modal (`screens/avatar_edit.zig`).
//!
//! Satisfies the zigzag focusable protocol (`focused: bool` + `focus()` /
//! `blur()`) so it can be added to a `zz.Form` like any other field, and the
//! form-field protocol (`view()` / `handleKey()`) so the form can render and
//! route key events to it. The avatar text itself is *borrowed* for the
//! duration of `view()` — the caller assigns `avatar_text` from the cached
//! user row immediately before the form is rendered and frees it after, so
//! the widget owns no allocation.

const std = @import("std");
const zz = @import("zigzag");

const avatar_widget = @import("avatar.zig");

pub const AvatarPreview = struct {
    /// Borrowed avatar text (7 lines joined by '\n'). Assigned by the host
    /// screen from its cached user row just before `view()` is called; may
    /// be empty when the user is not yet cached.
    avatar_text: []const u8 = "",
    focused: bool = false,
    pressed: bool = false,

    pub fn focus(self: *AvatarPreview) void {
        self.focused = true;
    }

    pub fn blur(self: *AvatarPreview) void {
        self.focused = false;
    }

    pub fn view(self: *const AvatarPreview, allocator: std.mem.Allocator) anyerror![]const u8 {
        const avatar = try avatar_widget.render(allocator, self.avatar_text);
        defer allocator.free(avatar);

        const box_style = (zz.Style{}).borderAll(zz.Border.rounded).borderForeground(if (self.focused) zz.Color.cyan else zz.Color.gray(12)).paddingAll(1);
        const boxed = try box_style.render(allocator, avatar);
        defer allocator.free(boxed);

        const hint_style = (zz.Style{}).fg(if (self.focused) zz.Color.cyan else zz.Color.gray(12)).inline_style(true);
        const hint = try hint_style.render(allocator, if (self.focused) "Enter: edit" else "");
        defer allocator.free(hint);

        return std.fmt.allocPrint(allocator, "{s}\n{s}", .{ boxed, hint });
    }

    pub fn handleKey(self: *AvatarPreview, key: zz.KeyEvent) void {
        if (key.key == .enter and !key.modifiers.ctrl) {
            self.pressed = true;
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "AvatarPreview focus/blur toggles focused flag" {
    var p = AvatarPreview{};
    try std.testing.expect(!p.focused);
    p.focus();
    try std.testing.expect(p.focused);
    p.blur();
    try std.testing.expect(!p.focused);
}

test "AvatarPreview Enter sets pressed; other keys do not" {
    var p = AvatarPreview{};
    p.handleKey(.{ .key = .enter });
    try std.testing.expect(p.pressed);
    p.pressed = false;

    p.handleKey(.{ .key = .{ .char = 'a' } });
    try std.testing.expect(!p.pressed);

    p.handleKey(.{ .key = .tab });
    try std.testing.expect(!p.pressed);

    p.handleKey(.{ .key = .enter, .modifiers = .{ .ctrl = true } });
    try std.testing.expect(!p.pressed);
}

test "AvatarPreview view renders a bordered box for empty avatar" {
    const alloc = std.testing.allocator;
    var p = AvatarPreview{ .avatar_text = "" };
    const out = try p.view(alloc);
    defer alloc.free(out);
    try std.testing.expect(out.len > 0);
}
