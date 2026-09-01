//! Logout confirmation modal — asks the user to confirm before deleting
//! the local SQLite database and exiting the application.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(2) = undefined,
    confirm_button: Button = .{ .label = "Confirm Logout" },
    cancel_button: Button = .{ .label = "Cancel" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.form = zz.Form(2).init();
    state.form.title = "Confirm Logout";
    state.form.addField("", &state.cancel_button, .{ .required = false });
    state.form.addField("", &state.confirm_button, .{ .required = false });
    state.form.submit_keys = &.{};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "This will delete all local data and exit.";
    state.form.initFocus();
}

pub fn deinit() void {}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.form.initFocus();
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    if (k.key == .escape) return .pop;
    _ = state.form.handleKey(k);

    if (state.confirm_button.pressed) {
        state.confirm_button.pressed = false;
        // Delete the SQLite file and reset state.
        state.ctx.logout();
        return .quit;
    }
    if (state.cancel_button.pressed) {
        state.cancel_button.pressed = false;
        return .pop;
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const warn_style = (zz.Style{}).fg(zz.Color.red).inline_style(true);
    const warning = try warn_style.render(
        alloc,
        "Logout will delete local data and exit.\nAll cached bulletins, responses, and info will be lost.",
    );
    defer alloc.free(warning);

    const content = try std.fmt.allocPrint(alloc, "{s}\n\n{s}", .{ warning, form_view });

    const box = (zz.Style{}).borderAll(zz.Border.rounded).borderForeground(zz.Color.yellow).paddingAll(1).width(60);
    const boxed = try box.render(alloc, content);
    defer alloc.free(boxed);

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
    .title = "Confirm Logout",
    .modal = true,
};
