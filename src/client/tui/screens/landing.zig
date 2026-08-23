//! Landing screen — choose Chat, Bulletins, or Register.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const chat_screen = @import("chat.zig");
const bulletins_screen = @import("bulletins.zig");
const register_screen = @import("register.zig");
const account_screen = @import("account.zig");
const settings_screen = @import("settings.zig");
const server_settings_screen = @import("server_settings.zig");
const user_directory_screen = @import("user_directory.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(5) = undefined,
    chat_button: Button = .{ .label = "Chat" },
    bulletins_button: Button = .{ .label = "Bulletins" },
    /// Label/role of this button is decided in `rebuildForm` based on identity
    /// state: "Register" (no user id), "Login" (user id but no restored
    /// key), or "Account" (user id + restored key).
    auth_button: Button = .{ .label = "Register" },
    user_directory_button: Button = .{ .label = "User Directory" },
    server_settings_button: Button = .{ .label = "Server Settings" },
    /// Signature of the identity fields that gate the conditional buttons,
    /// captured the last time the form was rebuilt. `refreshIfStale`
    /// compares the current signature against this and rebuilds the form
    /// when identity state changes asynchronously (e.g. an auto-register
    /// `registration_ack`, the BBS key arriving, or a `user_info` broadcast
    /// flipping sysop status) so the buttons update without a restart.
    last_identity_sig: u32 = 0,
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    rebuildForm();
}

pub fn deinit() void {}

/// Pack the identity fields that gate the landing buttons (auth label,
/// User Directory, Server Settings) into a small signature so we can
/// cheaply detect async changes without rebuilding the form every tick.
fn identitySig() u32 {
    const id = state.ctx.identity;
    var sig: u32 = 0;
    if (id.my_user_id != null) sig |= 1;
    if (id.key_restored_from_store) sig |= 2;
    if (id.bbs_key != null) sig |= 4;
    if (id.my_is_sysop) sig |= 8;
    return sig;
}

/// Rebuild the form from the current identity state. Called on initial entry,
/// on resume (returning from a pushed sub-screen via `pop`), and whenever
/// `refreshIfStale` detects the identity signature changed. Does NOT touch
/// `ctx.status` so it is safe to call from `on_resume` / the tick path without
/// clobbering status text set by incoming handlers (e.g. "Registered as
/// user #N").
fn rebuildForm() void {
    const ctx = state.ctx;
    // Rebuild the form each entry so the conditional buttons appear only when
    // their gate conditions hold: "User Directory" requires a registered,
    // logged-in client (my_user_id set AND a known BBS key); "Server Settings"
    // is sysop-only. The auth button relabels to "Register" (no user id),
    // "Login" (user id but no restored key), or "Account" (user id + restored
    // key) and routes accordingly in the update handler.
    state.form = zz.Form(5).init();
    state.form.title = "";
    state.form.addField("", &state.chat_button, .{ .required = false });
    state.form.addField("", &state.bulletins_button, .{ .required = false });
    if (ctx.identity.my_user_id != null and ctx.identity.key_restored_from_store) {
        state.auth_button.label = "Account";
    } else if (ctx.identity.my_user_id != null) {
        state.auth_button.label = "Login";
    } else {
        state.auth_button.label = "Register";
    }
    state.form.addField("", &state.auth_button, .{ .required = false });
    if (ctx.identity.my_user_id != null and ctx.identity.bbs_key != null) {
        state.form.addField("", &state.user_directory_button, .{ .required = false });
    }
    if (ctx.identity.my_is_sysop) {
        state.form.addField("", &state.server_settings_button, .{ .required = false });
    }
    state.form.submit_keys = &.{};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.focus_group.wrap = false;
    state.form.hint_text = "";
    state.form.initFocus();
    state.last_identity_sig = identitySig();
}

/// Rebuild the form if the identity signature changed since the last rebuild.
/// Called from the model tick so the landing buttons react to async identity
/// events (auto-register ack, BBS key arrival, sysop `user_info` broadcast)
/// without requiring the user to leave and re-enter the screen.
pub fn refreshIfStale() void {
    if (identitySig() != state.last_identity_sig) rebuildForm();
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;

    if (k.key == .escape) return .quit;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    _ = state.form.handleKey(k);

    if (state.chat_button.pressed) {
        state.chat_button.pressed = false;
        return .{ .push = chat_screen.screen };
    }
    if (state.bulletins_button.pressed) {
        state.bulletins_button.pressed = false;
        return .{ .push = bulletins_screen.screen };
    }
    if (state.auth_button.pressed) {
        state.auth_button.pressed = false;
        // Route to Account when fully logged in (user id + restored key),
        // otherwise to Register/Login (which re-derives the key).
        if (state.ctx.identity.my_user_id != null and state.ctx.identity.key_restored_from_store) {
            return .{ .push = account_screen.screen };
        } else {
            return .{ .push = register_screen.screen };
        }
    }
    if (state.user_directory_button.pressed) {
        state.user_directory_button.pressed = false;
        return .{ .push = user_directory_screen.screen };
    }
    if (state.server_settings_button.pressed) {
        state.server_settings_button.pressed = false;
        if (state.ctx.identity.my_is_sysop) {
            return .{ .push = server_settings_screen.screen };
        } else {
            state.ctx.status = "Server Settings is sysop-only.";
        }
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

    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);
    const help = try help_style.render(
        alloc,
        "Tab/Up/Down: navigate  Enter: select  Esc: quit  Ctrl+R: settings  Ctrl+Q: quit",
    );

    // Cap content width at 80 columns.
    const max_width: u16 = 80;
    const content_width: u16 = if (zz_ctx.width > 4) @min(zz_ctx.width - 4, max_width) else 40;

    // MOTD rendered as markdown inside a bordered box, capped at content_width.
    var motd_section: []const u8 = "";
    if (ctx.motd_text) |motd| {
        const box_width: u16 = content_width;
        const inner_width: u16 = if (box_width > 4) box_width - 4 else 36;

        var md = zz.Markdown.init();
        md.width = inner_width;
        const motd_rendered = md.render(alloc, motd) catch try alloc.dupe(u8, motd);
        defer alloc.free(motd_rendered);

        var box_style = zz.Style{};
        box_style = box_style.borderAll(zz.Border.rounded);
        box_style = box_style.borderForeground(zz.Color.cyan);
        box_style = box_style.paddingAll(1);
        box_style = box_style.width(box_width);
        motd_section = try box_style.render(alloc, motd_rendered);
    }

    const content = if (motd_section.len > 0)
        try std.fmt.allocPrint(
            alloc,
            "{s}  {s}\n{s}\n\n{s}\n\n{s}\n\n{s}",
            .{ styled_conn, styled_status, styled_bbs, motd_section, form_view, help },
        )
    else
        try std.fmt.allocPrint(
            alloc,
            "{s}  {s}\n{s}\n\n{s}\n\n{s}",
            .{ styled_conn, styled_status, styled_bbs, form_view, help },
        );
    return render.fillTerminal(alloc, zz_ctx, content);
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    // Rebuild the form (button labels + conditional fields) from the current
    // identity state. Status is set here only on initial entry — `on_resume`
    // and the tick-driven `refreshIfStale` deliberately leave `ctx.status`
    // alone so they don't clobber messages set by incoming handlers.
    rebuildForm();

    // Welcome-back status when the identity was restored from the store.
    if (ctx.identity.my_user_id != null and ctx.identity.key_restored_from_store) {
        if (ctx.store.getUserById(ctx.identity.my_user_id.?)) |user| {
            var mut_user = user;
            defer mut_user.deinit(ctx.store.allocator);
            ctx.status = std.fmt.allocPrint(
                std.heap.page_allocator,
                "Welcome back, {s}.",
                .{mut_user.handle},
            ) catch "Welcome back.";
        } else {
            ctx.status = "Welcome back.";
        }
    } else if (ctx.identity.auto_register) {
        // Auto-registration is in progress (CLI --handle + --key); the tick
        // updates this status as the connection / key request progresses.
        if (ctx.connection.isConnected()) {
            ctx.status = "Auto-registering...";
        } else {
            ctx.status = "Connecting to auto-register...";
        }
    } else if (ctx.identity.my_user_id != null) {
        ctx.status = "Key not restored — press Login to re-derive your key.";
    } else {
        ctx.status = "Choose Chat, Bulletins, or Register.";
    }
    outbox.requestMotd(
        ctx,
    );
}

/// Called when a pushed screen pops back to the landing screen. Rebuild the
/// form so buttons reflect any identity changes that happened while we were
/// suspended (e.g. the user registered on the Register screen). `pop` calls
/// `on_resume`, not `on_enter`, so without this the buttons would stay stale
/// until the app was restarted.
fn onResume(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    rebuildForm();
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
    .on_resume = onResume,
};

pub const screen = zz.Screen{ .ptr = @ptrCast(&state), .vtable = &vtable, .title = "Home" };
