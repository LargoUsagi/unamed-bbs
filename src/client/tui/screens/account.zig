//! Account screen — shown when the client is registered and has a working
//! signing key (restored from the persisted secret key on launch). Displays
//! the user's profile (handle, callsign, user id, key fingerprint) and an
//! avatar preview, plus a Logout button. Logout asks for confirmation via the
//! modal popup, then deletes the local SQLite database and quits the
//! application.
//!
//! Avatar editing: the avatar is shown as a focusable, display-only preview.
//! Pressing Enter on the preview pushes the `avatar_edit` modal, which owns
//! the 7-row TextArea editor, the Save / Reset-to-Default / Cancel buttons,
//! and the `avatar_update` send. When the modal returns, this screen
//! refreshes the preview from the (server-replicated) cached `user_info`.
//!
//! This is the "logged-in" counterpart to the Register/Login screen. The
//! landing page routes here when `my_user_id != null` and
//! `key_restored_from_store` is true. If the key was not restored (the user
//! didn't save credentials), the landing page routes to the Register/Login
//! screen instead so they can re-derive their key.

const std = @import("std");
const zz = @import("zigzag");

const bbs = @import("bbs");

const store = bbs.store;

const render = @import("../render.zig");
const TopBar = @import("../widgets/top_bar.zig").TopBar;
const Button = @import("../widgets/button.zig").Button;
const AvatarPreview = @import("../widgets/avatar_preview.zig").AvatarPreview;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const settings_screen = @import("settings.zig");
const logout_confirm_screen = @import("logout_confirm.zig");
const avatar_edit_screen = @import("avatar_edit.zig");

pub const State = struct {
    top_bar: TopBar = TopBar.init(true),
    ctx: *app.AppContext = undefined,
    form: zz.Form(2) = undefined,
    avatar_preview: AvatarPreview = .{},
    logout_button: Button = .{ .label = "Logout" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;

    state.form = zz.Form(2).init();
    state.form.title = "Account";
    state.form.addField("Avatar", &state.avatar_preview, .{ .required = false });
    state.form.addField("", &state.logout_button, .{ .required = false });
    state.form.submit_keys = &.{};
    state.form.cancel_keys = &.{};
    // Up/Down navigate fields, matching every other screen in the app. The
    // avatar TextArea is no longer inline — it lives in the `avatar_edit`
    // modal — so there is no need to reserve Up/Down for cursor movement
    // here.
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "Up/Down/Tab: navigate  Enter: edit avatar  Esc: back";
    state.form.initFocus();
}

pub fn deinit() void {}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    state.form.initFocus();
    ctx.status = "Logged in — press Enter on the avatar to edit, or Logout.";
    requestUserInfoIfMissing(ctx);
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    _ = state.form.handleKey(k);

    if (state.avatar_preview.pressed) {
        state.avatar_preview.pressed = false;
        return .{ .push = avatar_edit_screen.screen };
    }
    if (state.logout_button.pressed) {
        state.logout_button.pressed = false;
        return .{ .push = logout_confirm_screen.screen };
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const top_bar = try state.top_bar.view(alloc, ctx);
    defer alloc.free(top_bar);

    // Look up the user info from the local cache and borrow the avatar for
    // the preview. The borrow lives until after `form.view` returns, so the
    // `defer mut_user.deinit(...)` must be scoped to this function — keep
    // the `user` lookup alive for the whole function by deferring its
    // deinit here.
    var user_info_line: []const u8 = "";
    var user_info_owned: bool = false;
    var cached_avatar: []const u8 = "";
    var user_lookup: ?store.User = null;
    if (ctx.identity.my_user_id) |uid| {
        if (ctx.store.getUserById(uid)) |user| {
            user_lookup = user;
            const mut_user = &user_lookup.?;
            cached_avatar = mut_user.avatar;
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
    defer if (user_lookup) |*u| u.deinit(ctx.store.allocator);

    state.avatar_preview.avatar_text = cached_avatar;

    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const info = try render.dim.render(alloc, user_info_line);
    defer alloc.free(info);

    const styled_cs = try render.renderKeyLine(alloc, ctx.identity.keypair, ctx.connection.callsign_input.value.items, ctx.identity.key_from_file);
    defer alloc.free(styled_cs);

    const help = try render.renderHelp(
        alloc,
        "Up/Down/Tab: navigate  Enter: edit avatar  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}\n\n{s}\n{s}\n\n{s}\n\n{s}",
        .{ top_bar, form_view, info, styled_cs, help },
    );
    defer alloc.free(content);
    return render.fillTerminal(alloc, zz_ctx, content);
}

/// Ask the server for our own user info when it isn't cached yet (the
/// avatar preview then populates on the next tick from the re-broadcast).
fn requestUserInfoIfMissing(ctx: *app.AppContext) void {
    if (ctx.identity.my_user_id) |uid| {
        if (ctx.store.getUserById(uid)) |user| {
            var mut_user = user;
            mut_user.deinit(ctx.store.allocator);
            return;
        }
        const ids = [_]u16{uid};
        outbox.sendUserInfoRequest(ctx, &ids);
        ctx.status = "Requesting user info...";
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
    .title = "Account",
};
