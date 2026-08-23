//! Server Settings screen — sysop-only screen to set the MOTD (Message of the Day).
//!
//! Only shown when the current user is a sysop (`ctx.identity.my_is_sysop == true`).

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(2) = undefined,
    motd_input: zz.TextArea = undefined,
    set_button: Button = .{ .label = "Set MOTD" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.motd_input = zz.TextArea.init(std.heap.page_allocator);
    state.motd_input.placeholder = "Message of the Day text...  (Ctrl+S to set, Enter for newline)";
    state.motd_input.word_wrap = true;
    state.motd_input.width = 80;
    state.motd_input.height = 8;

    state.form = zz.Form(2).init();
    state.form.title = "Server Settings (Sysop)";
    state.form.addField("MOTD", &state.motd_input, .{ .required = true });
    state.form.addField("", &state.set_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "";
    state.form.initFocus();
}

pub fn deinit() void {
    state.motd_input.deinit();
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    const ctx = state.ctx;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = @import("settings.zig").screen };
    }

    // Non-sysop should not be here — pop back.
    if (!ctx.identity.my_is_sysop) {
        ctx.status = "Server Settings is sysop-only.";
        return .pop;
    }

    _ = state.form.handleKey(k);

    if (state.form.isSubmitted()) {
        state.form.reset();
        _ = trySetMotd();
        return .none;
    }

    if (state.set_button.pressed) {
        state.set_button.pressed = false;
        _ = trySetMotd();
        return .none;
    }
    return .none;
}

fn trySetMotd() bool {
    const ctx = state.ctx;
    const text = state.motd_input.getValue(std.heap.page_allocator) catch {
        ctx.status = "Out of memory.";
        return false;
    };
    defer std.heap.page_allocator.free(text);
    if (text.len == 0) {
        ctx.status = "MOTD text is empty.";
        return false;
    }
    outbox.sendMotd(ctx, text);
    if (ctx.outbox.busy) {
        state.motd_input.setValue("") catch {};
        return true;
    }
    return false;
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

    const max_width: u16 = 80;
    const content_width: u16 = if (zz_ctx.width > 4) @min(zz_ctx.width - 4, max_width) else 40;

    const box_width: u16 = content_width;
    const inner_width: u16 = if (box_width > 4) box_width - 4 else 36;



    // Show current MOTD if available.
    var current_motd_line: []const u8 = "";
    var current_motd_owned: bool = false;
    if (ctx.motd_text) |mt| {
        current_motd_line = try std.fmt.allocPrint(alloc, "Current MOTD: {s}", .{mt});
        current_motd_owned = true;

    } else {
        current_motd_line = "Current MOTD: (not set)";
    }
    defer if (current_motd_owned) alloc.free(current_motd_line);

    var md = zz.Markdown.init();
    md.width = inner_width;
    const motd_rendered = md.render(alloc, current_motd_line) catch try alloc.dupe(u8, current_motd_line);
    defer alloc.free(motd_rendered);

    // Flex the textarea width to terminal size.
    const avail: u16 = if (zz_ctx.width > 6) zz_ctx.width - 6 else 40;
    const flex_width: u16 = @max(40, @min(avail, 80));
    state.motd_input.width = flex_width;

    var motd_section: []const u8 = "";
    var box_style = zz.Style{};
    box_style = box_style.borderAll(zz.Border.rounded);
    box_style = box_style.borderForeground(zz.Color.cyan);
    box_style = box_style.paddingAll(1);
    box_style = box_style.width(box_width);
    motd_section = try box_style.render(alloc, motd_rendered);

    const form_view = try state.form.view(alloc);
    defer alloc.free(form_view);

    const help = try info_style.render(
        alloc,
        "Ctrl+S: set MOTD  Tab/Up/Down: navigate  Enter: newline  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}  {s}\n{s}\n\n{s}\n{s}\n\n{s}",
        .{ styled_conn, styled_status, styled_bbs, motd_section, form_view, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const ctx = state.ctx;
    state.form.initFocus();
    ctx.status = if (ctx.identity.my_is_sysop)
        "Server Settings — enter new MOTD and press Ctrl+S."
    else
        "Server Settings is sysop-only.";
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{ .ptr = @ptrCast(&state), .vtable = &vtable, .title = "Server Settings" };
