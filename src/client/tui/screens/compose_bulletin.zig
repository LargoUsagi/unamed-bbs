//! Compose bulletin screen — title + body input for creating a new bulletin.

const std = @import("std");
const zz = @import("zigzag");

const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const settings_screen = @import("settings.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(3) = undefined,
    bulletin_title_input: zz.TextInput = undefined,
    bulletin_body_input: zz.TextArea = undefined,
    post_bulletin_button: Button = .{ .label = "Post Bulletin" },
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.bulletin_title_input = zz.TextInput.init(std.heap.page_allocator);
    state.bulletin_title_input.placeholder = "Bulletin title (max 80 chars)";

    state.bulletin_body_input = zz.TextArea.init(std.heap.page_allocator);
    state.bulletin_body_input.placeholder = "Bulletin body...  (Ctrl+S to post, Enter for newline)";
    state.bulletin_body_input.word_wrap = true;
    state.bulletin_body_input.width = 80;
    state.bulletin_body_input.height = 8;

    state.form = zz.Form(3).init();
    state.form.title = "Compose Bulletin";
    state.form.addField("Title", &state.bulletin_title_input, .{ .required = true });
    state.form.addField("Body", &state.bulletin_body_input, .{ .required = true });
    state.form.addField("", &state.post_bulletin_button, .{ .required = false });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.cancel_keys = &.{};
    _ = state.form.focus_group.addNextKey(.{ .key = .down });
    _ = state.form.focus_group.addPrevKey(.{ .key = .up });
    state.form.hint_text = "";
    state.form.initFocus();
}

pub fn deinit() void {
    state.bulletin_title_input.deinit();
    state.bulletin_body_input.deinit();
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.form.initFocus();
    const ctx = state.ctx;
    ctx.status = if (ctx.connection.isConnected())
        "Compose bulletin — Ctrl+S to post."
    else
        "Not connected — Ctrl+R for settings to reconnect.";
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    _ = state.form.handleKey(k);

    if (state.form.isSubmitted()) {
        state.form.reset();
        if (postBulletin()) return .pop;
    }

    if (state.post_bulletin_button.pressed) {
        state.post_bulletin_button.pressed = false;
        if (postBulletin()) return .pop;
    }
    return .none;
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;

    // Flex the body input width to terminal size.
    const avail: u16 = if (zz_ctx.width > 6) zz_ctx.width - 6 else 40;
    const flex_width: u16 = @max(40, @min(avail, 120));
    state.bulletin_body_input.width = flex_width;

    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected(), ctx.connection.active_kind);
    const styled_stats = try render.renderPacketStats(alloc, ctx.packet_stats.txRecent(), ctx.packet_stats.rxRecent(), ctx.packet_stats.sparklineData());
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);
    const form_view = try state.form.view(alloc);

    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);
    const help = try help_style.render(
        alloc,
        "Ctrl+S: post  Tab/Up/Down: navigate  Enter: newline in body  Esc: back  Ctrl+R: settings  Ctrl+Q: quit",
    );

    const content = try std.fmt.allocPrint(
        alloc,
        "{s} {s}  {s}\n{s}\n\n{s}\n\n{s}",
        .{ styled_conn, styled_stats, styled_status, styled_bbs, form_view, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
}

fn postBulletin() bool {
    const ctx = state.ctx;
    const title = state.bulletin_title_input.value.items;
    const body = state.bulletin_body_input.getValue(std.heap.page_allocator) catch {
        ctx.status = "Out of memory.";
        return false;
    };
    defer std.heap.page_allocator.free(body);

    outbox.sendBulletin(ctx, title, body);
    if (ctx.outbox.busy) {
        state.bulletin_title_input.setValue("") catch {};
        state.bulletin_body_input.setValue("") catch {};
        return true;
    }
    return false;
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "Compose Bulletin",
};
