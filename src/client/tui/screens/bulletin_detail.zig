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
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const compose_response_screen = @import("compose_response.zig");
const settings_screen = @import("settings.zig");
const client_store = @import("../../client_store.zig");

/// Width of the left sidebar in each post box.
const sidebar_width: usize = 14;

/// Width of the ASCII art avatar.
const avatar_width: usize = 11;
/// Height of the ASCII art avatar.
const avatar_height: usize = 7;

/// Generate an 11×7 symmetric ASCII art avatar from a 32-byte public key.
/// The left 6 columns are generated from key bits; columns 6-10 mirror
/// columns 4-0 to create a symmetric pattern. Uses '█' for filled cells
/// and ' ' for empty. Returns 7 lines joined by '\n'. Caller owns the result.
fn generateAvatar(alloc: std.mem.Allocator, public_key: [32]u8) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    for (0..avatar_height) |row| {
        // First 6 columns (0-5) from key bits.
        for (0..6) |col| {
            const bit_idx = row * 6 + col;
            const byte_idx = bit_idx / 8;
            const bit_in_byte: u3 = @intCast(7 - (bit_idx % 8));
            const filled = (public_key[byte_idx] & (@as(u8, 1) << bit_in_byte)) != 0;
            try buf.appendSlice(alloc, if (filled) "█" else " ");
        }
        // Mirrored 5 columns (6-10 = mirror of 4-0).
        for (0..5) |col| {
            const src_col = 4 - col;
            const bit_idx = row * 6 + src_col;
            const byte_idx = bit_idx / 8;
            const bit_in_byte: u3 = @intCast(7 - (bit_idx % 8));
            const filled = (public_key[byte_idx] & (@as(u8, 1) << bit_in_byte)) != 0;
            try buf.appendSlice(alloc, if (filled) "█" else " ");
        }
        if (row < avatar_height - 1) try buf.append(alloc, '\n');
    }

    return buf.toOwnedSlice(alloc);
}

/// Generate an 11×7 avatar from a u16 user id (used when the user is not
/// cached and no public key is available). Derives a pseudo-random 32-byte
/// key from the id so the avatar is deterministic.
fn generateAvatarFromId(alloc: std.mem.Allocator, user_id: u16) ![]const u8 {
    var key: [32]u8 = std.mem.zeroes([32]u8);
    var rng_state: u32 = user_id;
    for (&key) |*b| {
        rng_state = rng_state *% 1103515245 +% 12345;
        b.* = @truncate(rng_state >> 16);
    }
    return generateAvatar(alloc, key);
}

pub const State = struct {
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

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    const ctx = state.ctx;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    if (k.key == .char and k.key.char == 'r') {
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
        return .none;
    }

    if (k.key == .char and k.key.char == 'm') {
        outbox.sendBulletinResponseRequest(ctx, state.bulletin_id);
        return .none;
    }

    if (k.key == .char and k.key.char == 'c') {
        const count = ctx.store.countResponses(state.bulletin_id);
        if (count >= types.max_response_id + 1) {
            ctx.status = "Compose reply blocked — bulletin is full (1024 responses).";
            return .none;
        }
        compose_response_screen.state.bulletin_id = state.bulletin_id;
        return .{ .push = compose_response_screen.screen };
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
    return std.fmt.allocPrint(alloc, "{d}{d:0>2}{d:0>2} {d:0>2}:{d:0>2} ", .{ year, month_day.month.numeric(), month_day.day_index + 1 ,  ds.getHoursIntoDay(), ds.getMinutesIntoHour()});
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
        const avatar = try generateAvatar(alloc, mut_user.public_key);
        defer alloc.free(avatar);
        const post_time = try formatDateTime(alloc, create_datetime);
        defer alloc.free(post_time);
        sidebar_content = try std.fmt.allocPrint(alloc, "{s}\n{s}\n{s}\n{s}", .{
            mut_user.handle, avatar, mut_user.callsign, post_time,
        });
        sidebar_owned = true;
    } else {
        const avatar = try generateAvatarFromId(alloc, user_id);
        defer alloc.free(avatar);
        const post_time = try formatDateTime(alloc, create_datetime);
        defer alloc.free(post_time);
        sidebar_content = try std.fmt.allocPrint(alloc, "User #{d}\n{s}\n{s}", .{
            user_id, avatar, post_time,
        });
        sidebar_owned = true;
    }
    defer if (sidebar_owned) alloc.free(sidebar_content);

    var sidebar_style = zz.Style{};
    sidebar_style = sidebar_style.width(@intCast(sidebar_width));
    sidebar_style = sidebar_style.fg(if (is_original) zz.Color.cyan else zz.Color.gray(14));
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
    var box_style = zz.Style{};
    box_style = box_style.borderAll(zz.Border.rounded);
    if (is_focused) {
        box_style = box_style.borderForeground(zz.Color.yellow);
    } else {
        box_style = box_style.borderForeground(if (is_original) zz.Color.cyan else zz.Color.gray(14));
    }
    box_style = box_style.paddingAll(1);
    box_style = box_style.width(body_width);
    return box_style.render(alloc, joined);
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected(), ctx.connection.active_kind);
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);

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
        var title_style = zz.Style{};
        title_style = title_style.bold(true);
        title_style = title_style.fg(zz.Color.cyan);
        title_style = title_style.inline_style(true);
        const styled_title = try title_style.render(alloc, mut_rec.title);
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
        var help_style = zz.Style{};
        help_style = help_style.fg(zz.Color.gray(12));
        help_style = help_style.inline_style(true);
        const help = try help_style.render(
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

        // Height of the focused post (lines it occupies in the posts area).
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

        // --- Extract visible lines from the posts area ---
        const visible_posts = blk: {
            if (total_post_lines <= avail_for_posts) break :blk try alloc.dupe(u8, posts_buf.items);
            // Split posts_buf into lines, take [scroll_offset, scroll_offset+avail_for_posts).
            var lines: std.ArrayList([]const u8) = .empty;
            defer lines.deinit(alloc);
            var iter = std.mem.splitScalar(u8, posts_buf.items, '\n');
            while (iter.next()) |line| {
                try lines.append(alloc, line);
            }
            const start = state.scroll_offset;
            const end = @min(start + avail_for_posts, lines.items.len);
            var vbuf: std.ArrayList(u8) = .empty;
            defer vbuf.deinit(alloc);
            for (lines.items[start..end], 0..) |line, i| {
                if (i > 0) try vbuf.append(alloc, '\n');
                try vbuf.appendSlice(alloc, line);
            }
            break :blk try vbuf.toOwnedSlice(alloc);
        };
        defer alloc.free(visible_posts);

        const detail = try std.fmt.allocPrint(
            alloc,
            "{s}  {s}\n{s}\n\n{s}\n{s}\n\n{s}",
            .{ styled_conn, styled_status, styled_bbs, visible_posts, resp_label, help },
        );
        return render.fillTerminal(alloc, zz_ctx, detail);
    } else {
        const detail = try std.fmt.allocPrint(alloc, "{s}  {s}\n{s}\n\n[Bulletin not found]", .{ styled_conn, styled_status, styled_bbs });
        return render.fillTerminal(alloc, zz_ctx, detail);
    }
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.selected_index = 0;
    state.scroll_offset = 0;
    state.ctx.status = "Viewing bulletin — Esc to return.";
    outbox.sendBulletinResponseRequestIfGapped(state.ctx, state.bulletin_id);
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{ .ptr = @ptrCast(&state), .vtable = &vtable, .title = "Bulletin Detail" };
