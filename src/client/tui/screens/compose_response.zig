//! Compose response screen — body input for replying to a bulletin.
//!
//! Pushed from the bulletin detail screen when the user presses the
//! compose-reply key. The parent `bulletin_id` is passed in via `state`
//! before the screen is pushed. The body is the only input (the title is
//! inherited from the parent bulletin). Ctrl+S posts the response; the
//! server assigns the next `response_id` and broadcasts it.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const TopBar = @import("../widgets/top_bar.zig").TopBar;
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const settings_screen = @import("settings.zig");

pub const State = struct {
    top_bar: TopBar = TopBar.init(true),
    ctx: *app.AppContext = undefined,
    /// Set by the bulletin detail screen before pushing this screen.
    bulletin_id: u32 = 0,
    form: zz.Form(2) = undefined,
    body_input: zz.TextArea = undefined,
    post_button: Button = .{ .label = "Post Response" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.body_input = zz.TextArea.init(std.heap.page_allocator);
    state.body_input.placeholder = "Response body...  (Ctrl+S to post, Enter for newline)";
    state.body_input.word_wrap = true;
    state.body_input.width = 80;
    state.body_input.height = 8;

    state.form = zz.Form(2).init();
    state.form.title = "Compose Response";
    state.form.addField("Body", &state.body_input, .{ .required = true });
    state.form.addField("", &state.post_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "";
    state.form.initFocus();
}

pub fn deinit() void {
    state.body_input.deinit();
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.form.initFocus();
    const ctx = state.ctx;
    ctx.status = if (ctx.connection.isConnected())
        "Compose response — Ctrl+S to post."
    else
        "Not connected — Ctrl+R for settings to reconnect.";
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    _ = state.form.handleKey(k);

    if (state.form.isSubmitted()) {
        state.form.reset();
        if (postResponse()) return .pop;
    }

    if (state.post_button.pressed) {
        state.post_button.pressed = false;
        if (postResponse()) return .pop;
    }
    return .none;
}

fn view(ptr: *anyopaque, _: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;

    // Flex the body input width to the modal panel (width 80, minus padding+border = 76).
    state.body_input.width = 76;

    const top_bar = try state.top_bar.view(alloc, ctx);
    defer alloc.free(top_bar);
    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const help = try render.renderHelp(
        alloc,
        "Ctrl+S: post  Tab/Up/Down: navigate  Esc: back",
    );

    const inner = try std.fmt.allocPrint(
        alloc,
        "{s}\n\n{s}\n\n{s}",
        .{ top_bar, form_view, help },
    );
    defer alloc.free(inner);

    const panel = (zz.Style{}).borderAll(zz.Border.rounded).borderForeground(zz.Color.cyan).paddingAll(1).width(80);
    return panel.render(alloc, inner);
}

fn postResponse() bool {
    const ctx = state.ctx;
    const body = state.body_input.getValue(std.heap.page_allocator) catch {
        ctx.status = "Out of memory.";
        return false;
    };
    defer std.heap.page_allocator.free(body);

    outbox.sendBulletinResponse(ctx, state.bulletin_id, body);
    if (ctx.outbox.busy) {
        state.body_input.setValue("") catch {};
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
    .title = "Compose Response",
    .modal = true,
};
