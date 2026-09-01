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

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.form.initFocus();
}

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

    const styled_notice = try render.bold_yellow.render(alloc, notice);

    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const content = try std.fmt.allocPrint(alloc, "{s}\n\n{s}", .{ styled_notice, form_view });
    defer alloc.free(styled_notice);
    defer alloc.free(content);

    const box = (zz.Style{}).borderAll(zz.Border.rounded).borderForeground(zz.Color.yellow).paddingAll(1).width(70);
    const boxed = try box.render(alloc, content);

    return render.fillTerminal(alloc, zz_ctx, boxed);
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
