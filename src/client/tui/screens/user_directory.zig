//! User Directory screen — list the users in the local cache and request
//! more by their server-assigned id.
//!
//! Lists every cached `users` row (sorted by id ascending) in a bordered,
//! scrollable list. The current user is marked with `*`. The list scrolls
//! with Up/Down/PgUp/PgDn/Home/End when it overflows the visible area, and
//! the focused row is kept in view. Pressing Enter on a selected row opens
//! the user detail screen for that user.
//!
//! Below the list is a form with a "User ID" text input and a "Request"
//! button: typing an id and pressing Request (or Ctrl+S) sends a
//! `user_info_request` to the BBS for that single id.
//!
//! Tab toggles focus between the form and the list; Up/Down navigates the
//! focused region; Esc pops back to the landing screen.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const TopBar = @import("../widgets/top_bar.zig").TopBar;
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const client_store = @import("../../client_store.zig");
const settings_screen = @import("settings.zig");
const user_detail_screen = @import("user_detail.zig");

/// Minimum number of list rows to render when the terminal is too short
/// for a comfortable viewport. Keeps the box useful on tiny terminals.
const min_visible_items: usize = 3;

pub const State = struct {
    top_bar: TopBar = TopBar.init(true),
    ctx: *app.AppContext = undefined,
    form: zz.Form(2) = undefined,
    user_id_input: zz.TextInput = undefined,
    request_button: Button = .{ .label = "Request" },
    selected_index: usize = 0,
    list_focused: bool = false,
    /// Top row of the list currently scrolled into view (an index into the
    /// full cached list). Clamped and adjusted in `view` so the focused
    /// row is always visible.
    scroll_offset: usize = 0,
    /// Number of list rows visible in the box on the last render. Used by
    /// `update` to make PgUp/PgDn move by exactly one viewport window.
    visible_count: usize = min_visible_items,
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
    state.form.focus_group.wrap = false;
    state.form.hint_text = "Enter a user id, then Request (or Ctrl+S).";
    state.form.initFocus();
}

pub fn deinit() void {
    state.user_id_input.deinit();
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    if (!state.list_focused) {
        state.form.initFocus();
    }
    state.ctx.status = "User Directory — request a user by id, or open a cached row.";
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
        return handleListNavKey(k, users, count);
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

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const top_bar = try state.top_bar.view(alloc, ctx);
    defer alloc.free(top_bar);
    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    // Cap content width at 80 columns.
    const max_width: u16 = 80;
    const content_width: u16 = if (zz_ctx.width > 4) @min(zz_ctx.width - 4, max_width) else 40;

    const users = ctx.store.listUsers() catch &.{};
    defer if (users.len > 0) ctx.store.freeUserList(users);
    const count = users.len;

    // Layout accounting (matches the format string at the bottom):
    //   conn+status (1) + bbs (1) + blank (1) = 3 header lines
    //   dir_title (1) + dir_box (box_h) + blank (1) + form (form_h) + blank (1) + help (1)
    // fillTerminal reserves a 1-cell margin on every side, so the usable
    // height is `term_height - 2`. The box has a 1-cell border and 1-cell
    // padding on top and bottom (4 rows of overhead).
    const term_height: usize = zz_ctx.height;
    const margin_h: usize = 2;
    const header_h: usize = 3;
    const form_h: usize = countLines(form_view);
    const title_h: usize = 1;
    const footer_h: usize = 2; // blank line + help line
    const gaps: usize = 1; // blank line between box and form
    const box_overhead: usize = 4; // border (1+1) + padding (1+1)

    var visible_items: usize = min_visible_items;
    if (term_height > margin_h + header_h + form_h + title_h + footer_h + gaps + box_overhead) {
        const avail = term_height - margin_h - header_h - form_h - title_h - footer_h - gaps - box_overhead;
        visible_items = @max(min_visible_items, avail);
    }
    state.visible_count = visible_items;

    adjustScrollOffset(count, visible_items);
    const start = state.scroll_offset;
    const end = @min(start + visible_items, count);

    var title_style = zz.Style{};
    title_style = title_style.bold(true);
    title_style = title_style.fg(zz.Color.cyan);
    title_style = title_style.inline_style(true);
    const dir_title = try title_style.render(
        alloc,
        if (count == 0)
            try std.fmt.allocPrint(alloc, "User Directory  (0 cached)", .{})
        else if (count > visible_items)
            try std.fmt.allocPrint(alloc, "User Directory  ({d} cached, showing {d}-{d})", .{
                count, start + 1, end,
            })
        else
            try std.fmt.allocPrint(alloc, "User Directory  ({d} cached)", .{count}),
    );

    const dir_box = try renderUserList(alloc, ctx, users, start, end, visible_items, content_width);
    defer alloc.free(dir_box);

    const help = try render.renderHelp(
        alloc,
        "Tab/Up/Dn: navigate  PgUp/PgDn/Home/End: scroll  Enter: open  Ctrl+S/Request: fetch by id  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}\n\n{s}\n{s}\n\n{s}\n\n{s}",
        .{ top_bar, dir_title, dir_box, form_view, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
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

/// Count the number of lines a rendered string occupies (trailing newline
/// does not add an extra line). Mirrors the helper in `bulletins.zig` /
/// `chat.zig`.
fn countLines(s: []const u8) usize {
    if (s.len == 0) return 0;
    var n: usize = 1;
    for (s) |c| {
        if (c == '\n') n += 1;
    }
    if (s[s.len - 1] == '\n') n -= 1;
    return n;
}

/// Handle a navigation key while the list is focused: Tab returns to the form,
/// Up/Down/PgUp/PgDn/Home/End move the selection (clamped to `count`), Enter
/// pushes the user detail screen for the selected row.
fn handleListNavKey(k: zz.KeyEvent, users: []const client_store.User, count: usize) zz.ScreenAction {
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
        if (count > 0 and state.selected_index < count - 1) {
            state.selected_index += 1;
        }
        return .none;
    }
    if (k.key == .page_up) {
        if (state.selected_index > 0) {
            const step = @min(state.visible_count, state.selected_index);
            state.selected_index -= @max(step, 1);
        }
        return .none;
    }
    if (k.key == .page_down) {
        if (count > 0 and state.selected_index < count - 1) {
            const step = @min(state.visible_count, count - 1 - state.selected_index);
            state.selected_index += @max(step, 1);
        }
        return .none;
    }
    if (k.key == .home) {
        state.selected_index = 0;
        return .none;
    }
    if (k.key == .end) {
        if (count > 0) state.selected_index = count - 1;
        return .none;
    }
    if (k.key == .enter and !k.modifiers.ctrl and count > 0) {
        if (state.selected_index < count) {
            user_detail_screen.state.user_id = users[state.selected_index].id;
            return .{ .push = user_detail_screen.screen };
        }
        return .none;
    }
    return .none;
}

/// Clamp `selected_index` and `scroll_offset` so the focused row stays within
/// the visible viewport defined by `visible_items`.
fn adjustScrollOffset(count: usize, visible_items: usize) void {
    if (count > 0) {
        if (state.selected_index >= count) state.selected_index = count - 1;
        if (state.scroll_offset >= count) state.scroll_offset = count - 1;
        if (state.selected_index < state.scroll_offset) {
            state.scroll_offset = state.selected_index;
        } else if (state.selected_index >= state.scroll_offset + visible_items) {
            state.scroll_offset = state.selected_index - visible_items + 1;
        }
        const max_offset = if (count > visible_items) count - visible_items else 0;
        if (state.scroll_offset > max_offset) state.scroll_offset = max_offset;
    } else {
        state.scroll_offset = 0;
    }
}

/// Render the user list as a bordered, padded box of width `content_width`
/// and `visible_items` rows. Each row shows the cursor marker, "this is you"
/// star, user id, handle, callsign, and "(sysop)" tag. Lines wider than the
/// box inner width are truncated. Padded with blank lines so the box height
/// stays fixed.
fn renderUserList(
    alloc: std.mem.Allocator,
    ctx: *app.AppContext,
    users: []const client_store.User,
    start: usize,
    end: usize,
    visible_items: usize,
    content_width: u16,
) anyerror![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    const inner_width: usize = if (content_width > 4) content_width - 4 else 36;
    if (users.len == 0) {
        try buf.appendSlice(alloc, "(no users cached — request one by id below)");
    } else {
        const my_uid = ctx.identity.my_user_id;
        for (start..end) |i| {
            const u = users[i];
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

        // Pad with blank lines so the box height stays fixed when the
        // viewport is shorter than `visible_items` (e.g. the last page of
        // a long list). This keeps the layout stable as the user scrolls.
        const rendered_lines = if (buf.items.len == 0) 0 else countLines(buf.items);
        if (rendered_lines < visible_items) {
            var pad = visible_items - rendered_lines;
            while (pad > 0) : (pad -= 1) {
                try buf.append(alloc, '\n');
            }
        }
    }

    var box_style = zz.Style{};
    box_style = box_style.borderAll(zz.Border.rounded);
    box_style = box_style.borderForeground(if (state.list_focused) zz.Color.yellow else zz.Color.cyan);
    box_style = box_style.paddingAll(1);
    box_style = box_style.width(content_width);
    return box_style.render(alloc, buf.items);
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "User Directory",
};
