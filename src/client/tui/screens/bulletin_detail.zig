//! Bulletin detail screen — forum-style display of a bulletin and its
//! responses.
//!
//! The original bulletin is the first post; each response is a subsequent
//! post. Each post is rendered as a bordered box with a fixed-width left
//! sidebar (user id + posting time) and the body on the right. The title
//! of the bulletin is shown above the first box (outside it).
//!
//! Navigation: Up/Down moves focus between post boxes. The focused box has
//! a highlighted border.
//!
//! Key bindings:
//!   * `R` — request the bulletin body (if not yet loaded).
//!   * `M` — request any missing responses from the server.
//!   * `C` — compose a reply (pushes the compose_response modal).
//!   * `Esc` — pop back to the bulletins list.
//!   * `Ctrl+R` — push the settings modal.

const std = @import("std");
const zz = @import("zigzag");

const types = @import("../types.zig");
const render = @import("../render.zig");
const TopBar = @import("../widgets/top_bar.zig").TopBar;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const compose_response_screen = @import("compose_response.zig");
const settings_screen = @import("settings.zig");
const client_store = @import("../../client_store.zig");
const avatar_widget = @import("../widgets/avatar.zig");

/// Width of the left sidebar in each post box.
const sidebar_width: usize = 14;

pub const State = struct {
    top_bar: TopBar = TopBar.init(true),
    ctx: *app.AppContext = undefined,
    /// Set by the bulletins screen before pushing this screen.
    bulletin_id: u32 = 0,
    /// Focused post index (0 = original bulletin, 1..N = responses).
    selected_index: usize = 0,
    /// Top line of the posts area currently scrolled to. Adjusted in view
    /// so the focused post is always visible.
    scroll_offset: usize = 0,
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
}

pub fn deinit() void {}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.selected_index = 0;
    state.scroll_offset = 0;
    state.ctx.status = "Viewing bulletin — Esc to return.";
    autoFetchBulletinData(state.ctx);
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    const ctx = state.ctx;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    if (k.key == .char and k.key.char == 'r') {
        requestBulletinBody(ctx);
        return .none;
    }

    if (k.key == .char and k.key.char == 'm') {
        outbox.sendBulletinResponseRequest(ctx, state.bulletin_id);
        return .none;
    }

    if (k.key == .char and k.key.char == 'c') {
        return composeReply(ctx);
    }

    // Navigation between post boxes.
    const post_count = postCount(ctx);
    if (post_count > 0) {
        if (k.key == .up) {
            if (state.selected_index > 0) state.selected_index -= 1;
            return .none;
        }
        if (k.key == .down) {
            if (state.selected_index < post_count - 1) state.selected_index += 1;
            return .none;
        }
    }

    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const top_bar = try state.top_bar.view(alloc, ctx);
    defer alloc.free(top_bar);

    const box_width: u16 = if (zz_ctx.width > 6) zz_ctx.width - 6 else 40;

    if (ctx.store.getById(state.bulletin_id)) |rec| {
        var mut_rec = rec;
        defer mut_rec.deinit(ctx.store.allocator);

        // Bulletin body is stored as plain text in the DB.
        var bul_body: []const u8 = "[Body not loaded. Press 'R' to request.]";
        if (mut_rec.body.len > 0) {
            bul_body = mut_rec.body;
        }

        // --- Title (outside the box, above it) ---
        const styled_title = try render.title_cyan.render(alloc, mut_rec.title);
        defer alloc.free(styled_title);

        // --- Post 0: original bulletin ---
        const bul_box = try renderPost(
            alloc,
            &ctx.store,
            mut_rec.user_id,
            mut_rec.created_at,
            bul_body,
            box_width,
            state.selected_index == 0,
            true,
        );
        defer alloc.free(bul_box);

        // --- Responses ---
        var responses: []const client_store.BulletinResponseRecord = undefined;
        var responses_owned: bool = false;
        if (ctx.store.listResponses(state.bulletin_id)) |r| {
            responses = r;
            responses_owned = true;
        } else |_| {
            responses = &.{};
        }
        defer if (responses_owned) ctx.store.freeResponseList(responses);

        // Render all response boxes.
        var resp_boxes: std.ArrayList([]const u8) = .empty;
        defer {
            for (resp_boxes.items) |b| alloc.free(b);
            resp_boxes.deinit(alloc);
        }
        for (responses, 0..) |r, i| {
            var resp_body: []const u8 = "[empty]";
            if (r.body.len > 0) {
                resp_body = r.body;
            }
            const rb = try renderPost(
                alloc,
                &ctx.store,
                r.user_id,
                r.create_datetime,
                resp_body,
                box_width,
                state.selected_index == i + 1,
                false,
            );
            try resp_boxes.append(alloc, rb);
        }

        // --- Build the posts area and track line positions of each post ---
        // The posts area = title + bul_box + each resp_box, separated by \n.
        // We track the starting line of each post so we can scroll.
        const post_count = 1 + responses.len;
        var post_start_lines = try alloc.alloc(usize, post_count);
        defer alloc.free(post_start_lines);

        var posts_buf: std.ArrayList(u8) = .empty;
        defer posts_buf.deinit(alloc);

        // Title occupies the first line.
        try posts_buf.appendSlice(alloc, styled_title);
        try posts_buf.appendSlice(alloc, "\n");

        // Post 0 (original bulletin).
        post_start_lines[0] = 1; // starts on line 1 (after title on line 0)
        try posts_buf.appendSlice(alloc, bul_box);

        // Each response.
        for (resp_boxes.items, 0..) |rb, i| {
            try posts_buf.appendSlice(alloc, "\n");
            post_start_lines[i + 1] = zz.measure.height(posts_buf.items);
            try posts_buf.appendSlice(alloc, rb);
        }

        const total_post_lines = zz.measure.height(posts_buf.items);

        // --- Response count label ---
        const resp_label = if (responses.len == 0)
            try std.fmt.allocPrint(alloc, "({d} responses cached — press 'M' to request)", .{responses.len})
        else
            try std.fmt.allocPrint(alloc, "({d} responses cached)", .{responses.len});
        defer alloc.free(resp_label);

        // --- Help line ---
        const help = try render.renderHelp(
            alloc,
            "R: body  M: responses  C: reply  Up/Dn: navigate  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
        );

        // --- Compute scroll offset ---
        // The visible content area (after fillTerminal's 1-cell margins).
        const avail_h: usize = if (zz_ctx.height > 2) zz_ctx.height - 2 else 1;
        // Header = conn+status (1 line) + bbs (1 line) + blank (1 line) = 3.
        // Footer = resp_label (1) + blank (1) + help (1) = 3.
        const header_lines: usize = 3;
        const footer_lines: usize = 3;
        const avail_for_posts: usize = if (avail_h > header_lines + footer_lines)
            avail_h - header_lines - footer_lines
        else
            1;

        computeScrollOffset(post_start_lines, total_post_lines, avail_for_posts, post_count);

        // --- Extract visible lines from the posts area ---
        const visible_posts = try extractVisiblePosts(alloc, posts_buf.items, state.scroll_offset, avail_for_posts, total_post_lines);
        defer alloc.free(visible_posts);

        const detail = try std.fmt.allocPrint(
            alloc,
            "{s}\n\n{s}\n{s}\n\n{s}",
            .{ top_bar, visible_posts, resp_label, help },
        );
        return render.fillTerminal(alloc, zz_ctx, detail);
    } else {
        const detail = try std.fmt.allocPrint(alloc, "{s}\n\n[Bulletin not found]", .{top_bar});
        return render.fillTerminal(alloc, zz_ctx, detail);
    }
}

/// Total number of posts (1 for the bulletin + number of cached responses).
/// Returns 0 if the bulletin itself is not found.
fn postCount(ctx: *app.AppContext) usize {
    if (ctx.store.getById(state.bulletin_id)) |rec| {
        var mut_rec = rec;
        defer mut_rec.deinit(ctx.store.allocator);
        return 1 + (ctx.store.countResponses(state.bulletin_id));
    }
    return 0;
}

fn formatDateTime(alloc: std.mem.Allocator, epoch: u64) ![]const u8 {
    if (epoch == 0) return alloc.dupe(u8, "      ");
    const es = std.time.epoch.EpochSeconds{ .secs = epoch };
    const ds = es.getDaySeconds();
    const ed = es.getEpochDay();
    const year_day = ed.calculateYearDay();
    const year = year_day.year;
    const month_day = year_day.calculateMonthDay();
    return std.fmt.allocPrint(alloc, "{d}{d:0>2}{d:0>2} {d:0>2}:{d:0>2} ", .{ year, month_day.month.numeric(), month_day.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour() });
}

/// Render a single post box. `is_focused` highlights the border.
/// `is_original` uses cyan for the original bulletin, gray for responses.
/// If the user is cached locally, the sidebar shows the handle and join date
/// (from `registered_datetime`) plus the post time; otherwise it shows
/// "User #N" and the post date+time.
fn renderPost(
    alloc: std.mem.Allocator,
    store: *client_store.Store,
    user_id: u16,
    create_datetime: u64,
    body_text: []const u8,
    body_width: u16,
    is_focused: bool,
    is_original: bool,
) ![]const u8 {
    // --- Left sidebar: handle, avatar, callsign, dates ---
    var sidebar_content: []const u8 = undefined;
    var sidebar_owned: bool = false;
    if (store.getUserById(user_id)) |user| {
        var mut_user = user;
        defer mut_user.deinit(store.allocator);
        const avatar = try avatar_widget.render(alloc, mut_user.avatar);
        defer alloc.free(avatar);
        const post_time = try formatDateTime(alloc, create_datetime);
        defer alloc.free(post_time);
        sidebar_content = try std.fmt.allocPrint(alloc, "{s}\n{s}\n{s}\n{s}", .{
            mut_user.handle, avatar, mut_user.callsign, post_time,
        });
        sidebar_owned = true;
    } else {
        const avatar = try avatar_widget.render(alloc, "");
        defer alloc.free(avatar);
        const post_time = try formatDateTime(alloc, create_datetime);
        defer alloc.free(post_time);
        sidebar_content = try std.fmt.allocPrint(alloc, "User #{d}\n{s}\n{s}", .{
            user_id, avatar, post_time,
        });
        sidebar_owned = true;
    }
    defer if (sidebar_owned) alloc.free(sidebar_content);

    const sidebar_style = (zz.Style{}).width(@intCast(sidebar_width)).fg(if (is_original) zz.Color.cyan else zz.Color.gray(14));
    const sidebar = try sidebar_style.render(alloc, sidebar_content);
    defer alloc.free(sidebar);

    // --- Body: render as markdown, constrained width ---
    const inner_body_width: u16 = if (body_width > @as(u16, @intCast(sidebar_width)) + 4) body_width - @as(u16, @intCast(sidebar_width)) - 4 else 40;
    var md = zz.Markdown.init();
    md.width = inner_body_width;
    const body_rendered = md.render(alloc, body_text) catch try alloc.dupe(u8, body_text);
    defer alloc.free(body_rendered);

    // --- Join sidebar + body horizontally ---
    const joined = try zz.join.horizontal(alloc, .top, &.{ sidebar, body_rendered });
    defer alloc.free(joined);

    // --- Wrap in a bordered box ---
    const border_color = if (is_focused)
        zz.Color.yellow
    else if (is_original)
        zz.Color.cyan
    else
        zz.Color.gray(14);
    const box_style = (zz.Style{}).borderAll(zz.Border.rounded).borderForeground(border_color).paddingAll(1).width(body_width);
    return box_style.render(alloc, joined);
}

/// 'R' handler: request the bulletin body from the server if not yet loaded,
/// otherwise surface a "already loaded" status.
fn requestBulletinBody(ctx: *app.AppContext) void {
    if (ctx.store.getById(state.bulletin_id)) |rec| {
        var mut_rec = rec;
        defer mut_rec.deinit(ctx.store.allocator);
        if (mut_rec.body.len == 0) {
            outbox.sendSingleBulletinRequest(ctx, state.bulletin_id);
            ctx.status = "Requesting bulletin...";
        } else {
            ctx.status = "Bulletin already loaded.";
        }
    } else {
        outbox.sendSingleBulletinRequest(ctx, state.bulletin_id);
        ctx.status = "Requesting bulletin...";
    }
}

/// 'C' handler: push the compose-response screen for this bulletin, unless
/// the bulletin is already at the response cap.
fn composeReply(ctx: *app.AppContext) zz.ScreenAction {
    const count = ctx.store.countResponses(state.bulletin_id);
    if (count >= types.max_response_id + 1) {
        ctx.status = "Compose reply blocked — bulletin is full (1024 responses).";
        return .none;
    }
    compose_response_screen.state.bulletin_id = state.bulletin_id;
    return .{ .push = compose_response_screen.screen };
}

/// Clamp `scroll_offset` so the focused post stays within the visible
/// viewport of `avail_for_posts` lines. `post_start_lines[i]` is the starting
/// line of post `i` within the assembled posts area; `total_post_lines` is
/// the total height of that area.
fn computeScrollOffset(post_start_lines: []usize, total_post_lines: usize, avail_for_posts: usize, post_count: usize) void {
    const focused_idx = if (state.selected_index < post_count) state.selected_index else 0;
    const focused_start = post_start_lines[focused_idx];
    const focused_end = if (focused_idx + 1 < post_count)
        post_start_lines[focused_idx + 1]
    else
        total_post_lines;

    // Scroll up if focused post is above the current view.
    if (focused_start < state.scroll_offset) {
        state.scroll_offset = focused_start;
    }
    // Scroll down if focused post extends below the visible area.
    if (focused_end > state.scroll_offset + avail_for_posts) {
        state.scroll_offset = focused_end - avail_for_posts;
    }
    // Clamp: don't scroll past the end.
    if (total_post_lines > avail_for_posts) {
        if (state.scroll_offset + avail_for_posts > total_post_lines) {
            state.scroll_offset = total_post_lines - avail_for_posts;
        }
    } else {
        state.scroll_offset = 0;
    }
    // Re-check visibility after clamping.
    if (focused_start < state.scroll_offset) {
        state.scroll_offset = focused_start;
    }
}

/// Extract the visible window `[scroll_offset, scroll_offset+avail_for_posts)`
/// from the assembled posts area. Returns a duplicate of the full area when
/// it fits entirely within the viewport.
fn extractVisiblePosts(alloc: std.mem.Allocator, posts_buf: []const u8, scroll_offset: usize, avail_for_posts: usize, total_post_lines: usize) anyerror![]const u8 {
    if (total_post_lines <= avail_for_posts) return try alloc.dupe(u8, posts_buf);
    // Split posts_buf into lines, take [scroll_offset, scroll_offset+avail_for_posts).
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(alloc);
    var iter = std.mem.splitScalar(u8, posts_buf, '\n');
    while (iter.next()) |line| {
        try lines.append(alloc, line);
    }
    const start = scroll_offset;
    const end = @min(start + avail_for_posts, lines.items.len);
    var vbuf: std.ArrayList(u8) = .empty;
    defer vbuf.deinit(alloc);
    for (lines.items[start..end], 0..) |line, i| {
        if (i > 0) try vbuf.append(alloc, '\n');
        try vbuf.appendSlice(alloc, line);
    }
    return vbuf.toOwnedSlice(alloc);
}

/// Auto-fetch bulletin body and responses on entry when the link is
/// high-bandwidth (direct TCP/IP). On low-bandwidth links only fill gaps in
/// the cached responses and leave the body to the user's explicit 'R' press.
fn autoFetchBulletinData(ctx: *app.AppContext) void {
    if (ctx.inbox.isHighBandwidth()) {
        if (ctx.store.getById(state.bulletin_id)) |rec| {
            var mut_rec = rec;
            if (mut_rec.body.len == 0) {
                outbox.sendSingleBulletinRequest(ctx, state.bulletin_id);
            }
            mut_rec.deinit(ctx.store.allocator);
        } else {
            // The bulletin row may not be cached yet either — request it by id.
            outbox.sendSingleBulletinRequest(ctx, state.bulletin_id);
        }
        outbox.sendBulletinResponseRequest(ctx, state.bulletin_id);
    } else {
        outbox.sendBulletinResponseRequestIfGapped(ctx, state.bulletin_id);
    }
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "Bulletin Detail",
};
