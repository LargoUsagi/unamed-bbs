//! Simple button widget compatible with `zz.Form`. Renders as `[ Label ]`
//! and sets `pressed = true` when Enter is pressed while focused.

const std = @import("std");
const zz = @import("zigzag");

pub const Button = struct {
    label: []const u8,
    pressed: bool = false,
    focused: bool = false,

    pub fn init(label: []const u8) Button {
        return .{ .label = label };
    }

    pub fn focus(self: *Button) void {
        self.focused = true;
    }

    pub fn blur(self: *Button) void {
        self.focused = false;
    }

    pub fn view(self: *const Button, allocator: std.mem.Allocator) ![]const u8 {
        if (self.focused) {
            const s = (zz.Style{}).reverse(true).bold(true).inline_style(true);
            const label = try std.fmt.allocPrint(allocator, "[ {s} ]", .{self.label});
            defer allocator.free(label);
            return s.render(allocator, label);
        }
        return std.fmt.allocPrint(allocator, "[ {s} ]", .{self.label});
    }

    pub fn handleKey(self: *Button, key: zz.KeyEvent) void {
        if (key.key == .enter and !key.modifiers.ctrl) {
            self.pressed = true;
        }
    }
};
