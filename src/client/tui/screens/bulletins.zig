//! Bulletins screen — request bulletins and display received bulletin summaries.

const std = @import("std");
const zz = @import("zigzag");

const types = @import("../types.zig");
const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const compose_bulletin_screen = @import("compose_bulletin.zig");
const bulletin_detail_screen = @import("bulletin_detail.zig");
const request_by_id_screen = @import("request_by_id.zig");
const settings_screen = @import("settings.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(3) = undefined,
    request_bulletins_button: Button = .{ .label = "Request Recent" },
    request_by_id_button: Button = .{ .label = "Request by ID" },
    new_bulletin_button: Button = .{ .label = "New Bulletin" },
    selected_index: usize = 0,
    list_focused: bool = false,
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

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    const ctx = state.ctx;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    const count = @min(ctx.store.count(), types.max_bulletins);

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
            if (state.selected_index < count - 1) {
                state.selected_index += 1;
            }
            return .none;
        }
        if (k.key == .enter and !k.modifiers.ctrl and count > 0) {
            // Look up the bulletin ID and pass it to the detail screen.
            const summaries = ctx.store.listPage(ctx.bulletins_page, types.max_bulletins) catch return .none;
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
        outbox.sendBulletinListRequest(ctx, );
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
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected());
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);
    const form_view = try state.form.view(alloc);

    // Cap content width at 80 columns.
    const max_width: u16 = 80;
    const content_width: u16 = if (zz_ctx.width > 4) @min(zz_ctx.width - 4, max_width) else 40;

    // --- Bulletins panel ---
    const summaries = ctx.store.listPage(ctx.bulletins_page, types.max_bulletins) catch &.{};
    defer {
        for (summaries) |s| ctx.store.allocator.free(s.title);
        ctx.store.allocator.free(summaries);
    }
    const total_pages = ctx.store.totalPages(types.max_bulletins);
    const count = summaries.len;

    var bul_title_style = zz.Style{};
    bul_title_style = bul_title_style.bold(true);
    bul_title_style = bul_title_style.fg(zz.Color.cyan);
    bul_title_style = bul_title_style.inline_style(true);
    const bul_title = try bul_title_style.render(
        alloc,
        try std.fmt.allocPrint(alloc, "Bulletins  (page {d}/{d}, {d} shown)", .{
            ctx.bulletins_page, total_pages, count,
        }),
    );

    var bul_buf: std.ArrayList(u8) = .empty;
    defer bul_buf.deinit(alloc);
    if (count == 0) {
        try bul_buf.appendSlice(alloc, "(no bulletins yet — press Request Bulletins)");
    } else {
        const inner_width: usize = if (content_width > 4) content_width - 4 else 36;
        for (0..count) |i| {
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
            const visible_len = line.len;
            if (visible_len > inner_width) {
                try bul_buf.appendSlice(alloc, line[0..@min(inner_width, line.len)]);
                try bul_buf.appendSlice(alloc, "\n");
            } else {
                try bul_buf.appendSlice(alloc, line);
            }
        }
        if (bul_buf.items.len > 0 and bul_buf.items[bul_buf.items.len - 1] == '\n')
            bul_buf.items.len -= 1;
    }

    var bul_box_style = zz.Style{};
    bul_box_style = bul_box_style.borderAll(zz.Border.rounded);
    bul_box_style = bul_box_style.borderForeground(if (state.list_focused) zz.Color.yellow else zz.Color.cyan);
    bul_box_style = bul_box_style.paddingAll(1);
    bul_box_style = bul_box_style.width(content_width);
    const bul_box = try bul_box_style.render(alloc, bul_buf.items);

    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);
    const help = try help_style.render(
        alloc,
        "Tab/Up/Down: navigate  Enter: activate  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}  {s}\n{s}\n\n{s}\n\n{s}\n{s}\n\n{s}",
        .{ styled_conn, styled_status, styled_bbs, form_view, bul_title, bul_box, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    // Preserve list focus if it was active before being suspended.
    if (!state.list_focused) {
        state.form.initFocus();
    }
    state.ctx.status = if (state.ctx.identity.bbs_key != null)
        "Bulletins — Request Recent or enter an ID and press Request by ID."
    else
        "No server key — request it from the Register screen.";
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{ .ptr = @ptrCast(&state), .vtable = &vtable, .title = "Bulletins" };
