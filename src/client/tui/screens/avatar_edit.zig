//! Avatar editor modal — pushed from the Account screen when the user
//! presses Enter on the avatar preview. Owns a 7-row `TextArea` pre-loaded
//! with the current avatar and three buttons:
//!
//!   - **Save Avatar** — sends an `avatar_update` to the server (signed),
//!     then pops the modal. The server re-broadcasts the updated
//!     `user_info`, which the Account screen refreshes from on return.
//!   - **Reset to Default** — regenerates the avatar locally from the
//!     working public key and repopulates the TextArea (a local preview;
//!     the user still presses Save to commit it).
//!   - **Cancel** — discards edits and pops the modal.
//!
//! Tab cycles fields (Up/Down stay available for cursor movement inside
//! the 7-row grid). This is scoped to the modal — the Account screen that
//! pushes it uses Up/Down for field navigation like the rest of the app,
//! which is why the editor was moved out of the Account form.

const std = @import("std");
const zz = @import("zigzag");

const bbs = @import("bbs");

const render = @import("../render.zig");
const avatar_widget = @import("../widgets/avatar.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(4) = undefined,
    avatar_input: zz.TextArea = undefined,
    save_avatar_button: Button = .{ .label = "Save Avatar" },
    reset_avatar_button: Button = .{ .label = "Reset to Default" },
    cancel_button: Button = .{ .label = "Cancel" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.avatar_input = zz.TextArea.init(std.heap.page_allocator);
    state.avatar_input.placeholder = "11x7 avatar (\xe2\x96\x88 and space)";
    state.avatar_input.word_wrap = false;
    state.avatar_input.width = @intCast(bbs.avatar.avatar_width);
    state.avatar_input.height = @intCast(bbs.avatar.avatar_height);
    state.avatar_input.max_lines = bbs.avatar.avatar_height;
    state.avatar_input.max_cols = bbs.avatar.avatar_width;

    state.form = zz.Form(4).init();
    state.form.title = "Edit Avatar";
    state.form.addField("Avatar", &state.avatar_input, .{ .required = false });
    state.form.addField("", &state.save_avatar_button, .{ .required = false });
    state.form.addField("", &state.reset_avatar_button, .{ .required = false });
    state.form.addField("", &state.cancel_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.cancel_keys = &.{};
    // Deliberately do NOT register Up/Down as focus-nav keys so they remain
    // available for cursor movement inside the 7-row avatar TextArea. Tab /
    // Shift+Tab (the focus-group defaults) cycle between fields.
    state.form.hint_text = "Ctrl+S: save  Tab: next field  Up/Dn/L/R: edit avatar  Esc: cancel";
    state.form.initFocus();
}

pub fn deinit() void {
    state.avatar_input.deinit();
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    state.form.initFocus();
    ctx.status = "Edit avatar — Save to commit, Cancel to discard.";
    populateAvatarFromCache(ctx);
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;

    if (k.key == .escape) return .pop;

    _ = state.form.handleKey(k);
    avatar_widget.clamp(&state.avatar_input);

    if (state.form.isSubmitted()) {
        state.form.reset();
        if (saveAvatar()) return .pop;
        return .none;
    }
    if (state.save_avatar_button.pressed) {
        state.save_avatar_button.pressed = false;
        if (saveAvatar()) return .pop;
        return .none;
    }
    if (state.reset_avatar_button.pressed) {
        state.reset_avatar_button.pressed = false;
        resetAvatarToDefault();
        return .none;
    }
    if (state.cancel_button.pressed) {
        state.cancel_button.pressed = false;
        return .pop;
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected(), ctx.connection.active_kind);
    defer alloc.free(styled_conn);
    const styled_stats = try render.renderPacketStats(alloc, ctx.packet_stats.txRecent(), ctx.packet_stats.rxRecent(), ctx.packet_stats.sparklineData());
    defer alloc.free(styled_stats);
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    defer alloc.free(styled_status);

    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const content = try std.fmt.allocPrint(alloc, "{s} {s}  {s}\n\n{s}", .{ styled_conn, styled_stats, styled_status, form_view });
    defer alloc.free(content);

    var box_style = zz.Style{};
    box_style = box_style.borderAll(zz.Border.rounded);
    box_style = box_style.borderForeground(zz.Color.cyan);
    box_style = box_style.paddingAll(1);
    box_style = box_style.width(60);
    const boxed = try box_style.render(alloc, content);
    defer alloc.free(boxed);

    return render.fillTerminal(alloc, zz_ctx, boxed);
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
/// TextArea. The user still needs to press "Save Avatar" to commit it to
/// the server — this is a local preview only.
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

/// Pre-populate the avatar editor with the current avatar from the cache, or
/// request the user info from the server when it isn't cached yet.
fn populateAvatarFromCache(ctx: *app.AppContext) void {
    if (ctx.identity.my_user_id) |uid| {
        if (ctx.store.getUserById(uid)) |user| {
            var mut_user = user;
            defer mut_user.deinit(ctx.store.allocator);
            state.avatar_input.setValue(mut_user.avatar) catch {};
            avatar_widget.clamp(&state.avatar_input);
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

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "Edit Avatar",
    .modal = true,
};
