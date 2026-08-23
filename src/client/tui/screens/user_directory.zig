//! User Directory screen — list the users in the local cache and request
//! more by their server-assigned id.
//!
//! Lists every cached `users` row (sorted by id ascending) in a bordered,
//! scrollable list. The current user is marked with `*`. Below the list is a
//! form with a "User ID" text input and a "Request" button: typing an id and
//! pressing Request (or Ctrl+S) sends a `user_info_request` to the BBS for
//! that single id. Selecting a list row currently does nothing — the list is
//! display-only.
//!
//! Tab toggles focus between the form and the list; Up/Down navigates the
//! focused region; Esc pops back to the landing screen.

const std = @import("std");
const zz = @import("zigzag");

const types = @import("../types.zig");
const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const settings_screen = @import("settings.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(2) = undefined,
    user_id_input: zz.TextInput = undefined,
    request_button: Button = .{ .label = "Request" },
    selected_index: usize = 0,
    list_focused: bool = false,
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.user_id_input = zz.TextInput.init(std.heap.page_allocator);
    state.user_id_input.placeholder = "User ID";

    state.form = zz.Form(2).init();
    state.form.title = "Request User by ID";
    state.form.addField("User ID", &state.user_id_input, .{ .required = true });
    state.form.addField("", &state.request_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "Enter a user id, then Request (or Ctrl+S).";
    state.form.initFocus();
}

pub fn deinit() void {
    state.user_id_input.deinit();
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    const ctx = state.ctx;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    const users = ctx.store.listUsers() catch &.{};
    defer if (users.len > 0) ctx.store.freeUserList(users);
    const count = users.len;

    if (state.list_focused) {
        if (k.key == .tab) {
            state.list_focused = false;
            state.form.initFocus();
            return .none;
        }
        if (k.key == .up) {
            if (state.selected_index == 0) {
                state.list_focused = false;
                state.request_button.focus();
            } else {
                state.selected_index -= 1;
            }
            return .none;
        }
        if (k.key == .down) {
            if (state.selected_index < count - 1) {
                state.selected_index += 1;
            }
            return .none;
        }
    } else {
        if ((k.key == .down or k.key == .tab) and state.request_button.focused and count > 0) {
            state.request_button.blur();
            state.list_focused = true;
            state.selected_index = 0;
            return .none;
        }
        _ = state.form.handleKey(k);
    }

    if (state.form.isSubmitted()) {
        state.form.reset();
        if (tryRequest()) {
            state.user_id_input.setValue("") catch {};
        }
        return .none;
    }
    if (state.request_button.pressed) {
        state.request_button.pressed = false;
        if (tryRequest()) {
            state.user_id_input.setValue("") catch {};
        }
        return .none;
    }
    return .none;
}

/// Parse the User ID input and send a `user_info_request` for that id.
/// Returns true on success (so the caller can clear the input field).
fn tryRequest() bool {
    const ctx = state.ctx;
    const id_str = state.user_id_input.value.items;
    if (id_str.len == 0) {
        ctx.status = "Enter a User ID.";
        return false;
    }
    const uid = std.fmt.parseInt(u16, id_str, 10) catch {
        ctx.status = "User ID is not a valid number.";
        return false;
    };
    const ids = [_]u16{uid};
    outbox.sendUserInfoRequest(ctx, &ids);
    return ctx.outbox.busy;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected());
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);
    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    // Cap content width at 80 columns.
    const max_width: u16 = 80;
    const content_width: u16 = if (zz_ctx.width > 4) @min(zz_ctx.width - 4, max_width) else 40;

    const users = ctx.store.listUsers() catch &.{};
    defer if (users.len > 0) ctx.store.freeUserList(users);
    const count = users.len;

    var title_style = zz.Style{};
    title_style = title_style.bold(true);
    title_style = title_style.fg(zz.Color.cyan);
    title_style = title_style.inline_style(true);
    const dir_title = try title_style.render(
        alloc,
        try std.fmt.allocPrint(alloc, "User Directory  ({d} cached)", .{count}),
    );

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    if (count == 0) {
        try buf.appendSlice(alloc, "(no users cached — request one by id below)");
    } else {
        const inner_width: usize = if (content_width > 4) content_width - 4 else 36;
        const my_uid = ctx.identity.my_user_id;
        for (users, 0..) |u, i| {
            const is_selected = state.list_focused and i == state.selected_index;
            const cursor: []const u8 = if (is_selected) ">" else " ";
            const me_mark: []const u8 = if (my_uid != null and my_uid.? == u.id) "*" else " ";
            const sysop_tag: []const u8 = if (u.is_sysop) " (sysop)" else "";
            const line = try std.fmt.allocPrint(
                alloc,
                "{s}{s} #{d:<5} {s:<20} {s:<10}{s}\n",
                .{ cursor, me_mark, u.id, u.handle, u.callsign, sysop_tag },
            );
            defer alloc.free(line);
            if (line.len > inner_width) {
                try buf.appendSlice(alloc, line[0..@min(inner_width, line.len)]);
                try buf.appendSlice(alloc, "\n");
            } else {
                try buf.appendSlice(alloc, line);
            }
        }
        if (buf.items.len > 0 and buf.items[buf.items.len - 1] == '\n')
            buf.items.len -= 1;
    }

    var box_style = zz.Style{};
    box_style = box_style.borderAll(zz.Border.rounded);
    box_style = box_style.borderForeground(if (state.list_focused) zz.Color.yellow else zz.Color.cyan);
    box_style = box_style.paddingAll(1);
    box_style = box_style.width(content_width);
    const dir_box = try box_style.render(alloc, buf.items);

    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);
    const help = try help_style.render(
        alloc,
        "Tab/Up/Down: navigate  Ctrl+S/Request: fetch by id  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}  {s}\n{s}\n\n{s}\n{s}\n\n{s}\n\n{s}",
        .{ styled_conn, styled_status, styled_bbs, dir_title, dir_box, form_view, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    if (!state.list_focused) {
        state.form.initFocus();
    }
    state.ctx.status = "User Directory — request a user by id, or refresh a cached row.";
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{ .ptr = @ptrCast(&state), .vtable = &vtable, .title = "User Directory" };
