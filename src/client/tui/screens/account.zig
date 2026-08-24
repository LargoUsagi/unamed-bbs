//! Account screen — shown when the client is registered and has a working
//! signing key (restored from the persisted secret key on launch). Displays
//! the user's profile (handle, callsign, user id, key fingerprint) and an
//! avatar editor, plus a Logout button. Logout asks for confirmation via the
//! modal popup, then deletes the local SQLite database and quits the
//! application.
//!
//! Avatar editing: a 7-row TextArea is pre-populated with the current avatar
//! (received from the server via `user_info`). The user edits it with
//! Up/Down/Left/Right (Tab cycles to the next field, so Up/Down stay available
//! for cursor movement within the grid). "Save Avatar" sends an `avatar_update`
//! to the server (signed); the server re-broadcasts the updated `user_info`.
//! "Reset to Default" regenerates the avatar locally from the public key and
//! repopulates the TextArea — the user then presses Save to commit it.
//!
//! This is the "logged-in" counterpart to the Register/Login screen. The
//! landing page routes here when `my_user_id != null` and
//! `key_restored_from_store` is true. If the key was not restored (the user
//! didn't save credentials), the landing page routes to the Register/Login
//! screen instead so they can re-derive their key.

const std = @import("std");
const zz = @import("zigzag");

const bbs = @import("bbs");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const logout_confirm_screen = @import("logout_confirm.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(4) = undefined,
    avatar_input: zz.TextArea = undefined,
    save_avatar_button: Button = .{ .label = "Save Avatar" },
    reset_avatar_button: Button = .{ .label = "Reset to Default" },
    logout_button: Button = .{ .label = "Logout" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.avatar_input = zz.TextArea.init(std.heap.page_allocator);
    state.avatar_input.placeholder = "11x7 avatar (█ and space)";
    state.avatar_input.word_wrap = false;
    state.avatar_input.width = @intCast(bbs.avatar.avatar_width);
    state.avatar_input.height = @intCast(bbs.avatar.avatar_height);
    state.avatar_input.max_lines = bbs.avatar.avatar_height;
    state.avatar_input.max_cols = bbs.avatar.avatar_width;

    state.form = zz.Form(4).init();
    state.form.title = "Account";
    state.form.addField("Avatar", &state.avatar_input, .{ .required = false });
    state.form.addField("", &state.save_avatar_button, .{ .required = false });
    state.form.addField("", &state.reset_avatar_button, .{ .required = false });
    state.form.addField("", &state.logout_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.cancel_keys = &.{};
    // Deliberately do NOT register Up/Down as focus-nav keys so they remain
    // available for cursor movement inside the 7-row avatar TextArea. Tab /
    // Shift+Tab (the focus-group defaults) cycle between fields.
    state.form.hint_text = "Ctrl+S: save avatar  Tab: next field  Esc: back";
    state.form.initFocus();
}

pub fn deinit() void {
    state.avatar_input.deinit();
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = @import("settings.zig").screen };
    }

    _ = state.form.handleKey(k);
    clampAvatarInput();

    if (state.form.isSubmitted()) {
        state.form.reset();
        if (saveAvatar()) {
            // Stay on screen; the server will re-broadcast user_info.
        }
        return .none;
    }
    if (state.save_avatar_button.pressed) {
        state.save_avatar_button.pressed = false;
        _ = saveAvatar();
        return .none;
    }
    if (state.reset_avatar_button.pressed) {
        state.reset_avatar_button.pressed = false;
        resetAvatarToDefault();
        return .none;
    }
    if (state.logout_button.pressed) {
        state.logout_button.pressed = false;
        return .{ .push = logout_confirm_screen.screen };
    }
    return .none;
}

/// Enforce the avatar grid dimensions on the TextArea: at most
/// `avatar_height` lines (7) and at most `avatar_width` (11) display cells
/// per line. The TextArea enforces `max_lines` on newline insertion but does
/// not enforce `max_cols`, so we truncate oversize lines here after each key
/// press. This keeps the editor within the 11×7 grid so there is no wrapping.
fn clampAvatarInput() void {
    const max_w = bbs.avatar.avatar_width;
    const max_h = bbs.avatar.avatar_height;
    const lines = &state.avatar_input.lines;
    var row: usize = 0;
    while (row < lines.items.len) : (row += 1) {
        const line = &lines.items[row];
        var display_w: usize = 0;
        var byte_idx: usize = 0;
        var truncate_at: usize = line.items.len;
        while (byte_idx < line.items.len) {
            const byte_len = std.unicode.utf8ByteSequenceLength(line.items[byte_idx]) catch 1;
            if (byte_idx + byte_len > line.items.len) break;
            const cp = std.unicode.utf8Decode(line.items[byte_idx..][0..byte_len]) catch {
                display_w += 1;
                byte_idx += 1;
                continue;
            };
            const cw = zz.unicode.charWidth(cp);
            if (display_w + cw > max_w) {
                truncate_at = byte_idx;
                break;
            }
            display_w += cw;
            byte_idx += byte_len;
        }
        if (truncate_at < line.items.len) {
            line.shrinkRetainingCapacity(truncate_at);
        }
    }
    if (lines.items.len > max_h) {
        var i: usize = max_h;
        while (i < lines.items.len) : (i += 1) {
            lines.items[i].deinit();
        }
        lines.shrinkRetainingCapacity(max_h);
    }
    if (state.avatar_input.cursor_row >= lines.items.len) {
        state.avatar_input.cursor_row = if (lines.items.len > 0) lines.items.len - 1 else 0;
    }
    const cur_line = &lines.items[state.avatar_input.cursor_row];
    if (state.avatar_input.cursor_col > cur_line.items.len) {
        state.avatar_input.cursor_col = cur_line.items.len;
    }
}

/// Read the TextArea content and send an `avatar_update` to the server.
/// Returns true if the send was kicked off.
fn saveAvatar() bool {
    const ctx = state.ctx;
    const text = state.avatar_input.getValue(std.heap.page_allocator) catch {
        ctx.status = "Out of memory.";
        return false;
    };
    defer std.heap.page_allocator.free(text);
    outbox.sendAvatarUpdate(ctx, text);
    return ctx.outbox.busy;
}

/// Regenerate the default avatar from the local public key and populate the
/// TextArea. The user still needs to press "Save Avatar" to commit it to the
/// server — this is a local preview only.
fn resetAvatarToDefault() void {
    const ctx = state.ctx;
    const kp = ctx.identity.keypair orelse {
        ctx.status = "No signing key — cannot generate default avatar.";
        return;
    };
    const pk = kp.publicKeyBytes();
    const default_avatar = bbs.avatar.generateFromKey(std.heap.page_allocator, pk) catch {
        ctx.status = "Out of memory generating avatar.";
        return;
    };
    defer std.heap.page_allocator.free(default_avatar);
    state.avatar_input.setValue(default_avatar) catch {};
    ctx.status = "Avatar reset to default — press Save Avatar to commit.";
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected(), ctx.connection.active_kind);
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);

    var info_style = zz.Style{};
    info_style = info_style.fg(zz.Color.gray(12));
    info_style = info_style.inline_style(true);

    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

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
        "Ctrl+S/Save Avatar: send  Reset: regenerate from key  Tab: next field  Up/Dn/L/R: edit avatar  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}  {s}\n{s}\n\n{s}\n{s}\n\n{s}\n\n{s}",
        .{ styled_conn, styled_status, styled_bbs, form_view, info, styled_cs, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    state.form.initFocus();
    ctx.status = "Logged in — edit avatar or press Logout.";

    // Pre-populate the avatar editor with the current avatar from the cache.
    if (ctx.identity.my_user_id) |uid| {
        if (ctx.store.getUserById(uid)) |user| {
            var mut_user = user;
            defer mut_user.deinit(ctx.store.allocator);
            state.avatar_input.setValue(mut_user.avatar) catch {};
            clampAvatarInput();
        } else {
            // User info not cached yet — request it so the avatar arrives.
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
