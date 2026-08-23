//! Chat screen — message log above, input box at bottom.
//!
//! Chat is routed through the BBS server. The client sends a `chat` frame
//! (signed by the client) to the BBS; the BBS validates the sender is a
//! registered (logged-in) user and the signature is valid, then stores the
//! message with the epoch time of receipt and re-broadcasts it signed by the
//! server so everyone in range hears it. The client only accepts chats signed
//! by the BBS. Chat input is limited to `types.max_chat_text_len` (256)
//! characters on the client side.

const std = @import("std");
const zz = @import("zigzag");

const types = @import("../types.zig");
const render = @import("../render.zig");
const app = @import("../app.zig");
const outbox = @import("../outbox.zig");
const logs = @import("../logs.zig");
const settings_screen = @import("settings.zig");

pub const State = struct {
    ctx: *app.AppContext = undefined,
    form: zz.Form(1) = undefined,
    message_input: zz.TextArea = undefined,
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;
    state.message_input = zz.TextArea.init(std.heap.page_allocator);
    state.message_input.placeholder = "Message to send to the BBS...  (Enter to send, Ctrl+Enter for newline, max 256 chars)";
    state.message_input.word_wrap = true;
    state.message_input.width = 80;
    state.message_input.height = 5;
    // Client-side limit: cap the chat text to 256 characters.
    state.message_input.char_limit = types.max_chat_text_len;

    state.form = zz.Form(1).init();
    state.form.title = "";
    state.form.addField("Message", &state.message_input, .{ .required = true });
    state.form.submit_keys = &.{zz.KeyEvent.ctrl('s')};
    state.form.hint_text = "";
    state.form.initFocus();
}

pub fn deinit() void {
    state.message_input.deinit();
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        return .{ .push = settings_screen.screen };
    }

    // Ctrl+H: manually request the most recent chat messages from the BBS so
    // the chat window is assembled from the server's authoritative history
    // (sorted by epoch time).
    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'h') {
        const ctx = state.ctx;
        if (!ctx.connection.isConnected()) {
            ctx.status = "Not connected — Ctrl+R for settings to reconnect.";
            return .none;
        }
        outbox.sendChatHistoryRequest(ctx);
        return .none;
    }

    if (k.key == .enter) {
        if (k.modifiers.shift or k.modifiers.ctrl) {
            _ = state.form.handleKey(.{ .key = .enter });
        } else {
            sendAndClear();
        }
        return .none;
    }

    _ = state.form.handleKey(k);

    if (state.form.isSubmitted()) {
        state.form.reset();
        sendAndClear();
    }
    return .none;
}

fn sendAndClear() void {
    const ctx = state.ctx;
    const message = state.message_input.getValue(std.heap.page_allocator) catch {
        ctx.status = "Out of memory.";
        return;
    };
    defer std.heap.page_allocator.free(message);
    if (message.len == 0) {
        ctx.status = "Message is empty.";
        return;
    }
    if (message.len > types.max_chat_text_len) {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Chat exceeds {d} characters.", .{types.max_chat_text_len}) catch "Chat exceeds 256 characters.";
        return;
    }
    // Route the chat through the BBS server (signed by the client). The
    // BBS validates the sender is registered and the signature is valid,
    // then stores and re-broadcasts the chat signed by the server.
    outbox.sendChat(ctx, message);
    if (ctx.outbox.busy) {
        state.message_input.setValue("") catch {};
    }
}

fn view(ptr: *anyopaque, zz_ctx: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;

    // Flex the message input width to terminal size.
    const avail: u16 = if (zz_ctx.width > 6) zz_ctx.width - 6 else 40;
    const flex_width: u16 = @max(40, @min(avail, 120));
    state.message_input.width = flex_width;
    const log_box_width: u16 = if (zz_ctx.width > 6) zz_ctx.width - 6 else flex_width;

    const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected());
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
    const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);
    const form_view = try state.form.view(alloc);
    const header = try std.fmt.allocPrint(alloc, "{s}  {s}\n{s}", .{ styled_conn, styled_status, styled_bbs });

    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);
    const help = try help_style.render(
        alloc,
        "Enter: send  Ctrl+Enter: newline  Ctrl+S: send  Ctrl+H: history  Ctrl+R: settings  Esc: back",
    );

    const term_height: usize = zz_ctx.height;
    const header_h = countLines(header);
    const form_h = countLines(form_view);
    const help_h = countLines(help);
    const gaps: usize = 4;
    const log_box_overhead: usize = 4;
    const min_log_content: usize = 3;

    const log_content_h: usize = if (term_height > header_h + form_h + help_h + gaps + log_box_overhead)
        @max(min_log_content, term_height - header_h - form_h - help_h - gaps - log_box_overhead)
    else
        min_log_content;

    var log_title_style = zz.Style{};
    log_title_style = log_title_style.bold(true);
    log_title_style = log_title_style.fg(zz.Color.cyan);
    log_title_style = log_title_style.inline_style(true);
    const log_title = try log_title_style.render(alloc, "Messages");

    var log_buf: std.ArrayList(u8) = .empty;
    defer log_buf.deinit(alloc);

    // Read the chat log directly from the SQLite cache (the de-duplicated,
    // sorted source of truth) rather than the in-memory ring buffer. This
    // makes a `chat_history_request` (Ctrl+H) merge cleanly into the window:
    // the store's `INSERT OR REPLACE` on `epoch_time` de-duplicates messages
    // that were already cached, and the `ORDER BY epoch_time DESC` query
    // returns them in proper chronological order — so the window never shows
    // duplicates or out-of-order lines after a history refresh.
    const recent = ctx.store.listRecentChatMessages(@intCast(log_content_h)) catch &.{};
    defer ctx.store.freeChatRecordList(recent);
    if (recent.len == 0) {
        try log_buf.appendSlice(alloc, "(no messages yet)");
    } else {
        // The store returns newest-first; display oldest-first so the most
        // recent messages appear at the bottom of the log box.
        var i: usize = recent.len;
        while (i > 0) {
            i -= 1;
            const r = recent[i];
            var display_buf: [types.chat_author_len]u8 = undefined;
            const author = logs.formatAuthorDisplayName(ctx, r.user_id, &display_buf).name;
            const text = r.text;
            if (author.len > 0) {
                const line = try std.fmt.allocPrint(alloc, "{s}: {s}\n", .{ author, text });
                defer alloc.free(line);
                try log_buf.appendSlice(alloc, line);
            }
        }
        if (log_buf.items.len > 0 and log_buf.items[log_buf.items.len - 1] == '\n')
            log_buf.items.len -= 1;
    }

    // Pad the log content with empty lines so the box fills the available
    // vertical space. Each empty line is a single '\n' appended after the
    // last content line.
    {
        const current_lines = countLines(log_buf.items);
        if (current_lines < log_content_h) {
            var pad: usize = log_content_h - current_lines;
            while (pad > 0) : (pad -= 1) {
                try log_buf.append(alloc, '\n');
            }
        }
    }

    var log_box_style = zz.Style{};
    log_box_style = log_box_style.borderAll(zz.Border.rounded);
    log_box_style = log_box_style.borderForeground(zz.Color.cyan);
    log_box_style = log_box_style.paddingAll(1);
    log_box_style = log_box_style.width(log_box_width);
    const log_box = try log_box_style.render(alloc, log_buf.items);

    const content = try std.fmt.allocPrint(
        alloc,
        "{s}\n\n{s}\n{s}\n\n{s}\n\n{s}",
        .{ header, log_title, log_box, form_view, help },
    );
    return render.fillTerminal(alloc, zz_ctx, content);
}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    state.form.initFocus();
    const ctx = state.ctx;
    ctx.status = if (ctx.connection.isConnected())
        "Connected. Ctrl+S to send, Ctrl+H for history, Ctrl+R for settings."
    else
        "Disconnected — Ctrl+R for settings to reconnect.";
}

fn countLines(s: []const u8) usize {
    if (s.len == 0) return 0;
    var n: usize = 1;
    for (s) |c| {
        if (c == '\n') n += 1;
    }
    if (s[s.len - 1] == '\n') n -= 1;
    return n;
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{ .ptr = @ptrCast(&state), .vtable = &vtable, .title = "Chat" };
