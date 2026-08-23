//! Status popup modal — displays a `request_status` message from the server.
//! Pushed by the model when `ctx.pending_status` is non-null. Auto-pops on
//! Enter/Escape/OK button.

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
    state.form.title = "Server Status";
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
        state.ctx.pending_status = null;
        return .pop;
    }
    _ = state.form.handleKey(k);
    if (state.ok_button.pressed) {
        state.ok_button.pressed = false;
        state.ctx.pending_status = null;
        return .pop;
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;

    const ps = ctx.pending_status orelse {
        return render.fillTerminal(alloc, zz_ctx, "");
    };

    const outcome_label: []const u8 = switch (ps.outcome) {
        .success => "Success",
        .failure => "Failure",
        .no_data => "No Data",
    };

    var outcome_style = zz.Style{};
    outcome_style = outcome_style.bold(true);
    outcome_style = outcome_style.inline_style(true);
    outcome_style = outcome_style.fg(switch (ps.outcome) {
        .success => zz.Color.green,
        .failure => zz.Color.red,
        .no_data => zz.Color.yellow,
    });
    const styled_outcome = try outcome_style.render(alloc, outcome_label);
    defer alloc.free(styled_outcome);

    const detail = ps.detail[0..ps.detail_len];
    const detail_line = if (detail.len > 0)
        try std.fmt.allocPrint(alloc, "{s}", .{detail})
    else
        try alloc.dupe(u8, "(no detail provided)");
    defer alloc.free(detail_line);

    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const content = try std.fmt.allocPrint(alloc, "Server status: {s}\n\n{s}\n\n{s}", .{ styled_outcome, detail_line, form_view });
    defer alloc.free(content);

    var box_style = zz.Style{};
    box_style = box_style.borderAll(zz.Border.rounded);
    box_style = box_style.borderForeground(zz.Color.cyan);
    box_style = box_style.paddingAll(1);
    box_style = box_style.width(60);
    const boxed = try box_style.render(alloc, content);
    defer alloc.free(boxed);

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
    .title = "Server Status",
    .modal = true,
};
