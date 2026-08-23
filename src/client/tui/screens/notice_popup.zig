//! Notice popup modal — displays a one-time informational message (e.g.
//! a duplicate `--connect` warning). Pushed by the model on the first tick
//! when `ctx.startup_notice` is non-null. Auto-pops on Enter/Escape/OK.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(1) = undefined,
    ok_button: Button = .{ .label = "OK" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.form = zz.Form(1).init();
    state.form.title = "Notice";
    state.form.addField("", &state.ok_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent{ .key = .enter }};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "";
    state.form.initFocus();
}

pub fn deinit() void {}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    if (k.key == .escape or k.key == .enter) {
        // Clear the notice so it doesn't re-appear. The string is owned by
        // the process arena allocator and is freed when the process exits.
        state.ctx.startup_notice = null;
        return .pop;
    }
    _ = state.form.handleKey(k);
    if (state.ok_button.pressed) {
        state.ok_button.pressed = false;
        state.ctx.startup_notice = null;
        return .pop;
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;

    const notice = ctx.startup_notice orelse {
        return render.fillTerminal(alloc, zz_ctx, "");
    };

    var notice_style = zz.Style{};
    notice_style = notice_style.bold(true);
    notice_style = notice_style.inline_style(true);
    notice_style = notice_style.fg(zz.Color.yellow);
    const styled_notice = try notice_style.render(alloc, notice);

    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const content = try std.fmt.allocPrint(alloc, "{s}\n\n{s}", .{ styled_notice, form_view });
    defer alloc.free(styled_notice);
    defer alloc.free(content);

    var box_style = zz.Style{};
    box_style = box_style.borderAll(zz.Border.rounded);
    box_style = box_style.borderForeground(zz.Color.yellow);
    box_style = box_style.paddingAll(1);
    box_style = box_style.width(70);
    const boxed = try box_style.render(alloc, content);

    return render.fillTerminal(alloc, zz_ctx, boxed);
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.form.initFocus();
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "Notice",
    .modal = true,
};
