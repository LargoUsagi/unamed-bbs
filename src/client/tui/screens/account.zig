//! Account screen — shown when the client is registered and has a working
//! signing key (restored from the persisted secret key on launch). Displays
//! the user's profile (handle, callsign, user id, key fingerprint) and a
//! Logout button. Logout asks for confirmation via the modal popup, then
//! deletes the local SQLite database and quits the application.
//!
//! This is the "logged-in" counterpart to the Register/Login screen. The
//! landing page routes here when `my_user_id != null` and
//! `key_restored_from_store` is true. If the key was not restored (the user
//! didn't save credentials), the landing page routes to the Register/Login
//! screen instead so they can re-derive their key.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const logout_confirm_screen = @import("logout_confirm.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    logout_form: zz.Form(1) = undefined,
    logout_button: Button = .{ .label = "Logout" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.logout_form = zz.Form(1).init();
    state.logout_form.title = "Account";
    state.logout_form.addField("", &state.logout_button, .{ .required = false });
    state.logout_form.submit_keys = &.{};
    state.logout_form.cancel_keys = &.{};
    _ = state.logout_form.focus_group.addNextKey(.{ .key = .down });
    _ = state.logout_form.focus_group.addPrevKey(.{ .key = .up });
    state.logout_form.hint_text = "";
    state.logout_form.initFocus();
}

pub fn deinit() void {}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = @import("settings.zig").screen };
    }

    _ = state.logout_form.handleKey(k);
    if (state.logout_button.pressed) {
        state.logout_button.pressed = false;
        return .{ .push = logout_confirm_screen.screen };
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected());
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);

    var info_style = zz.Style{};
    info_style = info_style.fg(zz.Color.gray(12));
    info_style = info_style.inline_style(true);

    const logout_form_view = try state.logout_form.view(alloc);
    defer alloc.free(logout_form_view);

    // Look up the user info from the local cache.
    var user_info_line: []const u8 = "";
    var user_info_owned: bool = false;
    if (ctx.identity.my_user_id) |uid| {
        if (ctx.store.getUserById(uid)) |user| {
            var mut_user = user;
            defer mut_user.deinit(ctx.store.allocator);
            user_info_line = try std.fmt.allocPrint(alloc, "Handle: {s}\nCallsign: {s}\nUser ID: #{d}", .{
                mut_user.handle, mut_user.callsign, uid,
            });
            user_info_owned = true;
        } else {
            user_info_line = try std.fmt.allocPrint(alloc, "User ID: #{d} (user info not yet cached)", .{uid});
            user_info_owned = true;
        }
    }
    defer if (user_info_owned) alloc.free(user_info_line);

    const info = try info_style.render(alloc, user_info_line);
    defer alloc.free(info);

    // Fingerprint of the working signing key. The account screen is only
    // reachable when the key was restored/derived, so the keypair is normally
    // non-null; guard defensively in case it was cleared (e.g. logout).
    var cs_line: []const u8 = "";
    var cs_owned: bool = false;
    if (ctx.identity.keypair) |kp| {
        const pk = kp.publicKeyBytes();
        cs_line = try std.fmt.allocPrint(alloc, "Callsign: {s}  Key: {x:0>2}{x:0>2}{x:0>2}{x:0>2}\u{2026}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
            ctx.connection.callsign_input.value.items,
            pk[0], pk[1], pk[2], pk[3],
            pk[28], pk[29], pk[30], pk[31],
        });
        cs_owned = true;
    } else {
        cs_line = try std.fmt.allocPrint(alloc, "Callsign: {s}  Key: none", .{ctx.connection.callsign_input.value.items});
        cs_owned = true;
    }
    defer if (cs_owned) alloc.free(cs_line);
    const styled_cs = try info_style.render(alloc, cs_line);
    defer alloc.free(styled_cs);

    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);
    const help = try help_style.render(
        alloc,
        "Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}  {s}\n{s}\n\n{s}\n{s}\n\n{s}\n\n{s}",
        .{ styled_conn, styled_status, styled_bbs, logout_form_view, info, styled_cs, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    state.logout_form.initFocus();
    ctx.status = "Logged in — press Logout to clear local data and exit.";

    // If the user info is not cached locally, request it from the server.
    if (ctx.identity.my_user_id) |uid| {
        if (ctx.store.getUserById(uid)) |user| {
            var mut_user = user;
            mut_user.deinit(ctx.store.allocator);
        } else {
            const ids = [_]u16{uid};
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

pub const screen = zz.Screen{ .ptr = @ptrCast(&state), .vtable = &vtable, .title = "Account" };
