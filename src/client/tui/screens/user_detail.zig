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
const TopBar = @import("../widgets/top_bar.zig").TopBar;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const settings_screen = @import("settings.zig");
const avatar_widget = @import("../widgets/avatar.zig");
const client_store = @import("../../client_store.zig");

pub const State = struct {
    top_bar: TopBar = TopBar.init(true),
    ctx: *app.AppContext = undefined,
    /// Set by the user directory screen before pushing this screen.
    user_id: u16 = 0,
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
}

pub fn deinit() void {}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    ctx.status = "Viewing user — Esc to return.";
    autoFetchUser(ctx);
}

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

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const top_bar = try state.top_bar.view(alloc, ctx);
    defer alloc.free(top_bar);

    const box_width: u16 = if (zz_ctx.width > 6) zz_ctx.width - 6 else 40;

    if (ctx.store.getUserById(state.user_id)) |user| {
        var mut_user = user;
        defer mut_user.deinit(ctx.store.allocator);

        const detail_box = try renderCachedUserBox(alloc, ctx, &mut_user, box_width);
        defer alloc.free(detail_box);

        const help = try render.renderHelp(
            alloc,
            "R: refresh from server  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
        );

        const content = try std.fmt.allocPrint(
            alloc,
            "{s}\n\n{s}\n\n{s}",
            .{ top_bar, detail_box, help },
        );
        return render.fillTerminal(alloc, zz_ctx, content);
    } else {
        const not_cached = try renderNotCachedUser(alloc, state.user_id);
        defer alloc.free(not_cached);

        const help = try render.renderHelp(
            alloc,
            "R: request from server  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
        );

        const content = try std.fmt.allocPrint(
            alloc,
            "{s}\n\n{s}\n\n{s}",
            .{ top_bar, not_cached, help },
        );
        return render.fillTerminal(alloc, zz_ctx, content);
    }
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
        year,                 month_day.month.numeric(), month_day.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(),
    });
}

/// Render the bordered profile box for a cached user: avatar + handle/callsign/
/// id/registered date/key fingerprint, with "this is you" and "(sysop)" tags.
fn renderCachedUserBox(
    alloc: std.mem.Allocator,
    ctx: *app.AppContext,
    user: *const client_store.User,
    box_width: u16,
) anyerror![]const u8 {
    const avatar = try avatar_widget.render(alloc, user.avatar);
    defer alloc.free(avatar);
    const reg_date = try formatDateTime(alloc, user.registered_datetime);
    defer alloc.free(reg_date);

    const me_mark: []const u8 = if (ctx.identity.my_user_id != null and ctx.identity.my_user_id.? == user.id)
        "  (this is you)"
    else
        "";
    const sysop_tag: []const u8 = if (user.is_sysop) "  (sysop)" else "";

    const fp = try render.formatKeyHex(alloc, user.public_key, true);
    defer alloc.free(fp);
    const profile = try std.fmt.allocPrint(
        alloc,
        "User ID: #{d}{s}{s}\nHandle: {s}\nCallsign: {s}\nRegistered: {s}\nKey: {s}",
        .{ user.id, me_mark, sysop_tag, user.handle, user.callsign, reg_date, fp },
    );
    defer alloc.free(profile);
    const styled_profile = try render.dim.render(alloc, profile);
    defer alloc.free(styled_profile);

    const styled_avatar = try render.dim.render(alloc, avatar);
    defer alloc.free(styled_avatar);

    const joined = try zz.join.horizontal(alloc, .top, &.{ styled_avatar, styled_profile });
    defer alloc.free(joined);

    const box = (zz.Style{}).borderAll(zz.Border.rounded).borderForeground(zz.Color.cyan).paddingAll(1).width(box_width);
    return box.render(alloc, joined);
}

/// "User #N not cached — press R to request." line for the not-cached branch.
fn renderNotCachedUser(alloc: std.mem.Allocator, user_id: u16) anyerror![]const u8 {
    return std.fmt.allocPrint(alloc, "User #{d} not cached — press R to request.", .{user_id});
}

/// If the user is not cached and the link is high-bandwidth, auto-fetch it.
fn autoFetchUser(ctx: *app.AppContext) void {
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

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "User Detail",
};
