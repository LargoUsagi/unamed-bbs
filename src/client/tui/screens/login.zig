//! Login screen — re-derive the signing key to log into an existing account.
//!
//! This screen is for **login** (authenticating an existing user). The
//! separate register screen (`register.zig`) handles creating a new
//! account. The user arrives here from the landing screen's auth button.
//!
//! In this protocol there is no server-side password check: the password is
//! fed to `signing.KeyPair.fromHandleAndPassword` to deterministically derive
//! the signing key. The server verifies the signature against the stored
//! public key for the existing handle. If the handle doesn't exist, the
//! server rejects the login.
//!
//! The "Stay logged in" checkbox controls whether the derived secret key is
//! persisted to the client store for automatic restore on the next launch
//! (same as the "Remember credentials" checkbox on the register screen).
//!
//! The login wire payload uses `mode = .login` and an empty callsign — the
//! server preserves the existing stored callsign on login. The link-layer
//! callsign (from connection settings) is used only for routing the reply.
//!
//! When no BBS (server) public key is known, the client auto-requests one
//! and stashes the login as a `PendingRegistration` (same mechanism as
//! registration). `AppContext.tickPendingRegistration` resolves it.

const std = @import("std");
const zz = @import("zigzag");

const bbs = @import("bbs");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const identity_mod = @import("../identity.zig");
const settings_screen = @import("settings.zig");
const register_screen = @import("register.zig");

/// Maximum handle length, enforced on the client and server.
pub const max_handle_len: usize = bbs.protocol.max_handle_len;

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(6) = undefined,
    login_handle_input: zz.TextInput = undefined,
    password_input: zz.TextInput = undefined,
    remember_checkbox: zz.Checkbox = undefined,
    login_button: Button = .{ .label = "Login" },
    request_key_button: Button = .{ .label = "Request Server Key" },
    register_button: Button = .{ .label = "Register New Account" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.login_handle_input = zz.TextInput.init(std.heap.page_allocator);
    state.login_handle_input.placeholder = "Display name (max 20 chars)";
    state.login_handle_input.setCharLimit(max_handle_len);

    // Pre-fill handle from CLI --handle flag.
    if (ctx.identity.prefill_handle) |h| {
        state.login_handle_input.setValue(h) catch {};
    }

    state.password_input = zz.TextInput.init(std.heap.page_allocator);
    state.password_input.placeholder = "Password";
    state.password_input.setEchoMode(.password);

    // Pre-fill password from CLI --key passphrase.
    if (ctx.identity.prefill_password) |p| {
        state.password_input.setValue(p) catch {};
    }

    state.remember_checkbox = zz.Checkbox.init("Stay logged in");

    state.form = zz.Form(6).init();
    state.form.title = "Login";
    state.form.addField("", &state.request_key_button, .{ .required = false });
    state.form.addField("Handle", &state.login_handle_input, .{ .required = true });
    if (ctx.identity.key_from_file) {
        // Bring-your-own key: the signing key is already loaded from a file,
        // so the password field (KDF input) is not needed. The handle field
        // stays at form index 1, so the locked-handle check (active == 1)
        // still holds.
        state.form.addField("", &state.remember_checkbox, .{ .required = false });
        state.form.addField("", &state.login_button, .{ .required = false });
    } else {
        state.form.addField("Password", &state.password_input, .{ .required = true });
        state.form.addField("", &state.remember_checkbox, .{ .required = false });
        state.form.addField("", &state.login_button, .{ .required = false });
    }
    state.form.addField("", &state.register_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "";
    state.form.initFocus();
}

pub fn deinit() void {
    state.login_handle_input.deinit();
    state.password_input.deinit();
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    state.form.initFocus();
    if (ctx.identity.key_from_file) {
        ctx.status = "Login — key loaded from file. Enter a handle and press Ctrl+S.";
    } else {
        ctx.status = if (ctx.connection.isConnected())
            "Login — enter your handle and password, then press Ctrl+S."
        else
            "Not connected — Ctrl+R for settings to reconnect.";
    }
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    const ctx = state.ctx;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    // When the handle is locked from CLI (--handle), the handle field
    // (field 1) is read-only. Drop text-mutating keys when it's focused.
    if (ctx.identity.handle_locked and state.form.focus_group.active == 1) {
        if (isTextMutatingKey(k)) return .none;
    }

    _ = state.form.handleKey(k);

    if (state.form.isSubmitted()) {
        state.form.reset();
        _ = tryLogin();
        return .none;
    }

    if (state.login_button.pressed) {
        state.login_button.pressed = false;
        _ = tryLogin();
        return .none;
    }
    if (state.request_key_button.pressed) {
        state.request_key_button.pressed = false;
        if (ctx.pending_registration != null) {
            return .none;
        }
        outbox.sendBulletinRequestKey(ctx);
        return .none;
    }
    if (state.register_button.pressed) {
        state.register_button.pressed = false;
        return .{ .push = register_screen.screen };
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected(), ctx.connection.active_kind);
    const styled_stats = try render.renderPacketStats(alloc, ctx.packet_stats.txRecent(), ctx.packet_stats.rxRecent(), ctx.packet_stats.sparklineData());
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);

    var info_style = zz.Style{};
    info_style = info_style.fg(zz.Color.gray(12));
    info_style = info_style.inline_style(true);

    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);

    state.form.title = "Login";
    state.login_button.label = "Login";

    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const has_waiting = ctx.pending_registration != null;
    const styled_waiting = try renderWaitingLine(alloc, ctx);
    defer alloc.free(styled_waiting);

    const info_line = if (ctx.identity.key_from_file)
        "Key loaded from file — enter a handle and press Ctrl+S."
    else
        "Log in to your existing account";
    const info = try info_style.render(alloc, info_line);
    defer alloc.free(info);

    const styled_cs = try renderKeyFingerprint(alloc, ctx);
    defer alloc.free(styled_cs);

    const help_text = try std.fmt.allocPrint(
        alloc,
        "Ctrl+S: Login  Tab/Up/Down: navigate  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
        .{},
    );
    defer alloc.free(help_text);
    const help = try help_style.render(alloc, help_text);
    defer alloc.free(help);

    const content = if (has_waiting)
        try std.fmt.allocPrint(
            alloc,
            "{s} {s}  {s}\n{s}\n\n{s}\n{s}\n{s}\n\n{s}\n\n{s}",
            .{ styled_conn, styled_stats, styled_status, styled_bbs, form_view, styled_waiting, styled_cs, info, help },
        )
    else
        try std.fmt.allocPrint(
            alloc,
            "{s} {s}  {s}\n{s}\n\n{s}\n{s}\n\n{s}\n\n{s}",
            .{ styled_conn, styled_stats, styled_status, styled_bbs, form_view, styled_cs, info, help },
        );
    return render.fillTerminal(alloc, zz_ctx, content);
}

/// Returns true if the key event would mutate a text input's value (char,
/// backspace, delete, paste). Used to filter these out when the handle
/// field is locked from the CLI, making it read-only.
fn isTextMutatingKey(k: zz.KeyEvent) bool {
    return switch (k.key) {
        .char, .backspace, .delete, .paste => true,
        else => false,
    };
}

fn tryLogin() bool {
    const ctx = state.ctx;
    const handle = state.login_handle_input.value.items;
    const password = state.password_input.value.items;

    if (handle.len == 0) {
        ctx.status = "Handle is empty.";
        return false;
    }
    if (handle.len > max_handle_len) {
        ctx.status = "Handle exceeds 20 characters.";
        return false;
    }
    // The password field and the KDF derivation are only used for
    // passphrase-derived keys. When a key was loaded from a file (--key-file),
    // the keypair is already set and no password is needed.
    if (!ctx.identity.key_from_file) {
        if (password.len < 8) {
            ctx.status = "Password must be at least 8 characters.";
            return false;
        }

        if (!identity_mod.deriveKeyFromHandleAndPassword(ctx, handle, password)) {
            ctx.status = "Key derivation failed.";
            return false;
        }
    }

    ctx.identity.remember_credentials = state.remember_checkbox.isChecked();

    // Login sends an empty callsign — the server preserves the existing
    // stored callsign on login mode.
    const callsign: []const u8 = "";

    // If no BBS (server) public key is known, auto-request one and stash the
    // login as pending; AppContext.tickPendingRegistration resolves it
    // (fires the login once the key arrives, or times out after
    // bbs_key_timeout_secs with an error popup). If the key is hard-locked
    // with a bad value we cannot request one — surface an error immediately.
    if (ctx.identity.bbs_key == null) {
        if (ctx.identity.bbs_key_locked) {
            ctx.status = "Server key is hard-locked (--bbs-key) but invalid; cannot login.";
            return false;
        }
        if (ctx.pending_registration != null) {
            return false;
        }
        if (!ctx.connection.isConnected()) {
            ctx.status = "Not connected — Ctrl+R for settings to reconnect.";
            return false;
        }
        const page = std.heap.page_allocator;
        const handle_copy = page.dupe(u8, handle) catch {
            ctx.status = "Out of memory.";
            return false;
        };
        const cs_copy = page.dupe(u8, callsign) catch {
            page.free(handle_copy);
            ctx.status = "Out of memory.";
            return false;
        };
        const now: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));
        ctx.pending_registration = .{
            .handle = handle_copy,
            .callsign = cs_copy,
            .mode = .login,
            .remember = state.remember_checkbox.isChecked(),
            .deadline_secs = now + app.bbs_key_timeout_secs,
        };
        outbox.sendBulletinRequestKey(ctx);
        ctx.status = "Waiting for server key before login...";
        return true;
    }

    outbox.sendRegistration(ctx, handle, callsign, .login);
    return true;
}

/// Styled "Waiting for server key... Ns" countdown line, or an empty string
/// when no pending registration is in flight.
fn renderWaitingLine(alloc: std.mem.Allocator, ctx: *app.AppContext) anyerror![]const u8 {
    if (ctx.pending_registration == null) return try alloc.dupe(u8, "");
    const now: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));
    const remaining: i64 = @as(i64, @intCast(ctx.pending_registration.?.deadline_secs)) - @as(i64, @intCast(now));
    const secs: u64 = if (remaining > 0) @intCast(remaining) else 0;
    const waiting_line = try std.fmt.allocPrint(alloc, "Waiting for server key... {d}s", .{secs});
    defer alloc.free(waiting_line);
    var waiting_style = zz.Style{};
    waiting_style = waiting_style.fg(zz.Color.yellow);
    waiting_style = waiting_style.inline_style(true);
    return waiting_style.render(alloc, waiting_line);
}

/// Styled "Callsign: ...  Key: ..." fingerprint line.
fn renderKeyFingerprint(alloc: std.mem.Allocator, ctx: *app.AppContext) anyerror![]const u8 {
    var info_style = zz.Style{};
    info_style = info_style.fg(zz.Color.gray(12));
    info_style = info_style.inline_style(true);

    var cs_line: []const u8 = "";
    var cs_owned: bool = false;
    if (ctx.identity.keypair) |kp| {
        const pk = kp.publicKeyBytes();
        cs_line = try std.fmt.allocPrint(alloc, "Key: {x:0>2}{x:0>2}{x:0>2}{x:0>2}\u{2026}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
            pk[0],
            pk[1],
            pk[2],
            pk[3],
            pk[28],
            pk[29],
            pk[30],
            pk[31],
        });
        cs_owned = true;
    } else {
        const no_key_msg: []const u8 = if (ctx.identity.key_from_file)
            "Key: none (key file failed to load)"
        else
            "Key: none (enter handle + password to derive)";
        cs_line = try alloc.dupe(u8, no_key_msg);
        cs_owned = true;
    }
    defer if (cs_owned) alloc.free(cs_line);
    return info_style.render(alloc, cs_line);
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "Login",
};
