//! Request by ID modal — enter a bulletin ID range and request it from the
//! server. Pushed from the Bulletins screen when "Request by ID" is pressed.
//! Pops on successful submission or cancel.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(3) = undefined,
    from_id_input: zz.TextInput = undefined,
    to_id_input: zz.TextInput = undefined,
    request_button: Button = .{ .label = "Request" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.from_id_input = zz.TextInput.init(std.heap.page_allocator);
    state.from_id_input.placeholder = "From ID";

    state.to_id_input = zz.TextInput.init(std.heap.page_allocator);
    state.to_id_input.placeholder = "To ID (blank for single)";

    state.form = zz.Form(3).init();
    state.form.title = "Request Bulletins by ID";
    state.form.addField("From ID", &state.from_id_input, .{ .required = true });
    state.form.addField("To ID", &state.to_id_input, .{ .required = false });
    state.form.addField("", &state.request_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "Leave To ID blank to request a single bulletin. Max range: 50.";
    state.form.initFocus();
}

pub fn deinit() void {
    state.from_id_input.deinit();
    state.to_id_input.deinit();
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.form.initFocus();
    state.ctx.status = "Enter bulletin ID(s) and press Ctrl+S or Request.";
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    if (k.key == .escape) return .pop;
    _ = state.form.handleKey(k);

    if (state.form.isSubmitted()) {
        state.form.reset();
        if (tryRequest()) return .pop;
        return .none;
    }
    if (state.request_button.pressed) {
        state.request_button.pressed = false;
        if (tryRequest()) return .pop;
        return .none;
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    var info_style = zz.Style{};
    info_style = info_style.fg(zz.Color.gray(12));
    info_style = info_style.inline_style(true);
    const hint = try info_style.render(
        alloc,
        "Leave To ID blank for a single bulletin.  Max range: 50.",
    );
    defer alloc.free(hint);

    const content = try std.fmt.allocPrint(alloc, "{s}\n\n{s}", .{ form_view, hint });
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

fn tryRequest() bool {
    const ctx = state.ctx;
    const from_str = state.from_id_input.value.items;
    const to_str = state.to_id_input.value.items;

    if (from_str.len == 0) {
        ctx.status = "Enter a From ID.";
        return false;
    }

    const from_id = std.fmt.parseInt(u32, from_str, 10) catch {
        ctx.status = "From ID is not a valid number.";
        return false;
    };

    if (to_str.len == 0) {
        outbox.sendSingleBulletinRequest(ctx, from_id);
        if (ctx.outbox.busy) {
            state.from_id_input.setValue("") catch {};
            state.to_id_input.setValue("") catch {};
            return true;
        }
        return false;
    }

    const to_id = std.fmt.parseInt(u32, to_str, 10) catch {
        ctx.status = "To ID is not a valid number.";
        return false;
    };

    if (to_id < from_id) {
        ctx.status = "To ID must be >= From ID.";
        return false;
    }

    const range = to_id - from_id + 1;
    if (range > 50) {
        ctx.status = "Range exceeds 50 bulletins maximum.";
        return false;
    }

    outbox.sendBulletinRequestRange(ctx, from_id, to_id);
    if (ctx.outbox.busy) {
        state.from_id_input.setValue("") catch {};
        state.to_id_input.setValue("") catch {};
        return true;
    }
    return false;
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "Request by ID",
    .modal = true,
};
