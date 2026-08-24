//! User detail screen — single-page profile view for a cached user.
//!
//! Pushed from the User Directory screen when Enter is pressed on a selected
//! row. Shows the user's handle, callsign, id, registered date, sysop tag,
//! "this is you" marker, key fingerprint, and avatar (rendered from the
//! server-provided string via the shared avatar widget).
//!
//! Key bindings:
//!   * `R` — request a fresh `user_info` for this id from the server.
//!   * `Esc` — pop back to the user directory.
//!   * `Ctrl+R` — push the settings modal.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const settings_screen = @import("settings.zig");
const avatar_widget = @import("../widgets/avatar.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    /// Set by the user directory screen before pushing this screen.
    user_id: u16 = 0,
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
        const ids = [_]u16{state.user_id};
        outbox.sendUserInfoRequest(ctx, &ids);
        ctx.status = "Requesting user info...";
        return .none;
    }

    return .none;
}

fn formatDateTime(alloc: std.mem.Allocator, epoch: u64) ![]const u8 {
    if (epoch == 0) return alloc.dupe(u8, "unknown");
    const es = std.time.epoch.EpochSeconds{ .secs = epoch };
    const ds = es.getDaySeconds();
    const ed = es.getEpochDay();
    const year_day = ed.calculateYearDay();
    const year = year_day.year;
    const month_day = year_day.calculateMonthDay();
    return std.fmt.allocPrint(alloc, "{d}{d:0>2}{d:0>2} {d:0>2}:{d:0>2}", .{
        year, month_day.month.numeric(), month_day.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(),
    });
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected(), ctx.connection.active_kind);
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);

    var info_style = zz.Style{};
    info_style = info_style.fg(zz.Color.gray(14));
    info_style = info_style.inline_style(true);

    const box_width: u16 = if (zz_ctx.width > 6) zz_ctx.width - 6 else 40;

    if (ctx.store.getUserById(state.user_id)) |user| {
        var mut_user = user;
        defer mut_user.deinit(ctx.store.allocator);

        const avatar = try avatar_widget.render(alloc, mut_user.avatar);
        defer alloc.free(avatar);
        const reg_date = try formatDateTime(alloc, mut_user.registered_datetime);
        defer alloc.free(reg_date);

        const me_mark: []const u8 = if (ctx.identity.my_user_id != null and ctx.identity.my_user_id.? == mut_user.id)
            "  (this is you)"
        else
            "";
        const sysop_tag: []const u8 = if (mut_user.is_sysop) "  (sysop)" else "";

        const pk = mut_user.public_key;
        const profile = try std.fmt.allocPrint(alloc,
            "User ID: #{d}{s}{s}\nHandle: {s}\nCallsign: {s}\nRegistered: {s}\nKey: {x:0>2}{x:0>2}{x:0>2}{x:0>2}\u{2026}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
            .{
                mut_user.id, me_mark, sysop_tag,
                mut_user.handle, mut_user.callsign, reg_date,
                pk[0], pk[1], pk[2], pk[3], pk[28], pk[29], pk[30], pk[31],
            },
        );
        defer alloc.free(profile);
        const styled_profile = try info_style.render(alloc, profile);
        defer alloc.free(styled_profile);

        const styled_avatar = try info_style.render(alloc, avatar);
        defer alloc.free(styled_avatar);

        const joined = try zz.join.horizontal(alloc, .top, &.{ styled_avatar, styled_profile });
        defer alloc.free(joined);

        var box_style = zz.Style{};
        box_style = box_style.borderAll(zz.Border.rounded);
        box_style = box_style.borderForeground(zz.Color.cyan);
        box_style = box_style.paddingAll(1);
        box_style = box_style.width(box_width);
        const detail_box = try box_style.render(alloc, joined);
        defer alloc.free(detail_box);

        var help_style = zz.Style{};
        help_style = help_style.fg(zz.Color.gray(12));
        help_style = help_style.inline_style(true);
        const help = try help_style.render(
            alloc,
            "R: refresh from server  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
        );

        const content = try std.fmt.allocPrint(
            alloc,
            "{s}  {s}\n{s}\n\n{s}\n\n{s}",
            .{ styled_conn, styled_status, styled_bbs, detail_box, help },
        );
        return render.fillTerminal(alloc, zz_ctx, content);
    } else {
        var help_style = zz.Style{};
        help_style = help_style.fg(zz.Color.gray(12));
        help_style = help_style.inline_style(true);
        const help = try help_style.render(
            alloc,
            "R: request from server  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
        );

        const content = try std.fmt.allocPrint(
            alloc,
            "{s}  {s}\n{s}\n\nUser #{d} not cached — press R to request.\n\n{s}",
            .{ styled_conn, styled_status, styled_bbs, state.user_id, help },
        );
        return render.fillTerminal(alloc, zz_ctx, content);
    }
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    ctx.status = "Viewing user — Esc to return.";

    // If the user is not cached and we're on a high-bandwidth link, auto-fetch.
    if (ctx.store.getUserById(state.user_id)) |user| {
        var mut_user = user;
        mut_user.deinit(ctx.store.allocator);
    } else {
        if (ctx.inbox.isHighBandwidth()) {
            const ids = [_]u16{state.user_id};
            outbox.sendUserInfoRequest(ctx, &ids);
            ctx.status = "Requesting user info...";
        }
    }
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{ .ptr = @ptrCast(&state), .vtable = &vtable, .title = "User Detail" };
