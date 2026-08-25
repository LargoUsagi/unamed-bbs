//! Bulletins screen — request bulletins and display received bulletin summaries.
//!
//! The list shows every bulletin cached in the local store (newest-first),
//! scrolling with Up/Down/PgUp/PgDn/Home/End when it overflows the visible
//! area. `bulletins_page` in `AppContext` still tracks the server-protocol
//! page that the most recent `bulletin_list` message reported — used by
//! `incoming.zig`, not by this screen's rendering.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const client_store = @import("../../client_store.zig");
const compose_bulletin_screen = @import("compose_bulletin.zig");
const bulletin_detail_screen = @import("bulletin_detail.zig");
const request_by_id_screen = @import("request_by_id.zig");
const settings_screen = @import("settings.zig");

/// Minimum number of list rows to render when the terminal is too short
/// for a comfortable viewport. Keeps the box useful on tiny terminals.
const min_visible_items: usize = 3;

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(3) = undefined,
    request_bulletins_button: Button = .{ .label = "Request Recent" },
    request_by_id_button: Button = .{ .label = "Request by ID" },
    new_bulletin_button: Button = .{ .label = "New Bulletin" },
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
    state.form = zz.Form(3).init();
    state.form.title = "Bulletins";
    state.form.addField("", &state.request_bulletins_button, .{ .required = false });
    state.form.addField("", &state.request_by_id_button, .{ .required = false });
    state.form.addField("", &state.new_bulletin_button, .{ .required = false });
    state.form.submit_keys = &.{};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.focus_group.wrap = false;
    state.form.hint_text = "";
    state.form.initFocus();
}

pub fn deinit() void {}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    // Preserve list focus if it was active before being suspended.
    if (!state.list_focused) {
        state.form.initFocus();
    }
    // High-bandwidth transports (direct TCP/IP) auto-fetch the newest
    // bulletin summaries on page entry so the list is fresh without a
    // manual "Request Recent". Low-bandwidth radio links skip this to avoid
    // tying up the channel; the user presses "Request Recent" instead.
    if (ctx.inbox.isHighBandwidth()) {
        outbox.sendBulletinListRequest(ctx);
    }
    state.ctx.status = if (state.ctx.identity.bbs_key != null)
        "Bulletins — Request Recent or enter an ID and press Request by ID."
    else
        "No server key — request it from the Register screen.";
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    const ctx = state.ctx;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    const count = ctx.store.count();

    if (state.list_focused) {
        if (k.key == .tab) {
            state.list_focused = false;
            state.form.initFocus();
            return .none;
        }
        if (k.key == .up) {
            if (state.selected_index == 0) {
                state.list_focused = false;
                state.new_bulletin_button.focus();
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
            return openSelectedBulletin(ctx);
        }
    } else {
        if ((k.key == .down or k.key == .tab) and state.new_bulletin_button.focused and count > 0) {
            state.new_bulletin_button.blur();
            state.list_focused = true;
            state.selected_index = 0;
            return .none;
        }
        _ = state.form.handleKey(k);
    }

    if (state.request_bulletins_button.pressed) {
        state.request_bulletins_button.pressed = false;
        outbox.sendBulletinListRequest(
            ctx,
        );
        return .none;
    }
    if (state.request_by_id_button.pressed) {
        state.request_by_id_button.pressed = false;
        return .{ .push = request_by_id_screen.screen };
    }
    if (state.new_bulletin_button.pressed) {
        state.new_bulletin_button.pressed = false;
        return .{ .push = compose_bulletin_screen.screen };
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected(), ctx.connection.active_kind);
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);
    const form_view = try state.form.view(alloc);

    // Cap content width at 80 columns.
    const max_width: u16 = 80;
    const content_width: u16 = if (zz_ctx.width > 4) @min(zz_ctx.width - 4, max_width) else 40;

    // --- Bulletins panel ---
    const summaries = ctx.store.listAll() catch &.{};
    defer {
        for (summaries) |s| ctx.store.allocator.free(s.title);
        ctx.store.allocator.free(summaries);
    }
    const count = summaries.len;

    // Layout accounting (matches the format string at the bottom):
    //   conn+status (1) + bbs (1) + blank (1) = 3 header lines
    //   form_view (form_h)
    //   blank (1) + bul_title (1) + bul_box (box_h) + blank (1) + help (1)
    // fillTerminal reserves a 1-cell margin on every side, so the usable
    // height is `term_height - 2`. The box has a 1-cell border and 1-cell
    // padding on top and bottom (4 rows of overhead).
    const term_height: usize = zz_ctx.height;
    const margin_h: usize = 2;
    const header_h: usize = 3;
    const form_h: usize = countLines(form_view);
    const title_h: usize = 1;
    const footer_h: usize = 2; // blank line + help line
    const gaps: usize = 1; // blank line between form and title
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

    var bul_title_style = zz.Style{};
    bul_title_style = bul_title_style.bold(true);
    bul_title_style = bul_title_style.fg(zz.Color.cyan);
    bul_title_style = bul_title_style.inline_style(true);
    const bul_title = try bul_title_style.render(
        alloc,
        if (count == 0)
            try std.fmt.allocPrint(alloc, "Bulletins  (0 cached)", .{})
        else if (count > visible_items)
            try std.fmt.allocPrint(alloc, "Bulletins  ({d} cached, showing {d}-{d})", .{
                count, start + 1, end,
            })
        else
            try std.fmt.allocPrint(alloc, "Bulletins  ({d} cached)", .{count}),
    );

    const bul_box = try renderBulletinsList(alloc, ctx, summaries, start, end, visible_items, content_width);
    defer alloc.free(bul_box);

    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);
    const help = try help_style.render(
        alloc,
        "Tab/Up/Dn: navigate  PgUp/PgDn/Home/End: scroll  Enter: open  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}  {s}\n{s}\n\n{s}\n\n{s}\n{s}\n\n{s}",
        .{ styled_conn, styled_status, styled_bbs, form_view, bul_title, bul_box, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
}

/// Count the number of lines a rendered string occupies (trailing newline
/// does not add an extra line). Mirrors the helper in `chat.zig`.
fn countLines(s: []const u8) usize {
    if (s.len == 0) return 0;
    var n: usize = 1;
    for (s) |c| {
        if (c == '\n') n += 1;
    }
    if (s[s.len - 1] == '\n') n -= 1;
    return n;
}

/// Called when popping back to this screen from a pushed sub-screen (e.g.
/// returning from the bulletin detail view). Mirrors `onEnter`'s high-bandwidth
/// auto-refresh so returning from reading a bulletin re-fetches the newest
/// summaries. The outbox `busy` guard dedups overlapping sends.
fn onResume(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    if (ctx.inbox.isHighBandwidth()) {
        outbox.sendBulletinListRequest(ctx);
    }
}

/// Enter-on-list handler: look up the bulletin at the selected index, mark it
/// read, and push the bulletin detail screen for it.
fn openSelectedBulletin(ctx: *app.AppContext) zz.ScreenAction {
    const summaries = ctx.store.listAll() catch return .none;
    defer {
        for (summaries) |s| ctx.store.allocator.free(s.title);
        ctx.store.allocator.free(summaries);
    }
    if (state.selected_index < summaries.len) {
        const bid = summaries[state.selected_index].id;
        ctx.store.markBulletinRead(bid);
        bulletin_detail_screen.state.bulletin_id = bid;
        return .{ .push = bulletin_detail_screen.screen };
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

/// Render the bulletins list as a bordered, padded box of width
/// `content_width` and `visible_items` rows. Each row shows the cursor marker,
/// read/unread prefix, bulletin id, title, and author handle (or `#user_id`
/// when the user isn't cached). Lines wider than the box inner width are
/// truncated. Padded with blank lines so the box height stays fixed.
fn renderBulletinsList(
    alloc: std.mem.Allocator,
    ctx: *app.AppContext,
    summaries: []const client_store.BulletinSummary,
    start: usize,
    end: usize,
    visible_items: usize,
    content_width: u16,
) anyerror![]const u8 {
    var bul_buf: std.ArrayList(u8) = .empty;
    defer bul_buf.deinit(alloc);
    const inner_width: usize = if (content_width > 4) content_width - 4 else 36;
    if (summaries.len == 0) {
        try bul_buf.appendSlice(alloc, "(no bulletins yet — press Request Recent)");
    } else {
        for (start..end) |i| {
            const b = summaries[i];
            const title = b.title;
            const is_selected = state.list_focused and i == state.selected_index;
            const is_read = ctx.store.isBulletinRead(b.id);
            const read_prefix = if (is_read) "     " else "[New]";
            const cursor = if (is_selected) ">" else " ";
            var author_buf: [80]u8 = undefined;
            const author: []const u8 = if (ctx.store.getUserById(b.user_id)) |user| blk: {
                var mut_user = user;
                const printed = std.fmt.bufPrint(&author_buf, "{s}", .{mut_user.handle}) catch "??";
                mut_user.deinit(ctx.store.allocator);
                break :blk printed;
            } else blk: {
                break :blk std.fmt.bufPrint(&author_buf, "#{d}", .{b.user_id}) catch "??";
            };
            const line = try std.fmt.allocPrint(
                alloc,
                "{s} {s} #{d:<3} {s}  (author: {s})\n",
                .{ cursor, read_prefix, b.id, title, author },
            );
            defer alloc.free(line);
            // Truncate lines wider than the box inner width.
            if (line.len > inner_width) {
                try bul_buf.appendSlice(alloc, line[0..@min(inner_width, line.len)]);
                try bul_buf.appendSlice(alloc, "\n");
            } else {
                try bul_buf.appendSlice(alloc, line);
            }
        }
        if (bul_buf.items.len > 0 and bul_buf.items[bul_buf.items.len - 1] == '\n')
            bul_buf.items.len -= 1;

        // Pad with blank lines so the box height stays fixed when the
        // viewport is shorter than `visible_items` (e.g. the last page of
        // a long list). This keeps the layout stable as the user scrolls.
        const rendered_lines = if (bul_buf.items.len == 0) 0 else countLines(bul_buf.items);
        if (rendered_lines < visible_items) {
            var pad = visible_items - rendered_lines;
            while (pad > 0) : (pad -= 1) {
                try bul_buf.append(alloc, '\n');
            }
        }
    }

    var bul_box_style = zz.Style{};
    bul_box_style = bul_box_style.borderAll(zz.Border.rounded);
    bul_box_style = bul_box_style.borderForeground(if (state.list_focused) zz.Color.yellow else zz.Color.cyan);
    bul_box_style = bul_box_style.paddingAll(1);
    bul_box_style = bul_box_style.width(content_width);
    return bul_box_style.render(alloc, bul_buf.items);
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
    .on_resume = onResume,
};

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "Bulletins",
};
