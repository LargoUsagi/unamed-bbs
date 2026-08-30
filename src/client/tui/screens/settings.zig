//! Settings screen — tabbed modal for transport configuration, signing key
//! info, and diagnostic panels (incoming messages and sent transmissions).
//!
//! Three tabs switch between the AGWPE (radio/TNC) transport, the direct
//! TCP transport, and the MeshCore (serial companion radio) transport. The
//! callsign field is shared. When the transport is locked from CLI
//! (`--connect`), the tab switcher is hidden, only the locked transport's
//! fields are shown, and the text inputs are read-only (immutable for the
//! session).

const std = @import("std");
const zz = @import("zigzag");

const types = @import("../types.zig");
const render = @import("../render.zig");
const Button = @import("../widgets/button.zig").Button;
const app = @import("../app.zig");
const connection_mod = @import("../connection.zig");

/// Which settings tab is active.
const Tab = enum { agwpe, tcp, meshcore };

pub const State = struct {
    ctx: *app.AppContext = undefined,
    /// AGWPE form (callsign, host, port, kport, reconnect, disconnect).
    agwpe_form: zz.Form(6) = undefined,
    /// TCP form (host, port, reconnect, disconnect). Uses Form(6) to match
    /// the AGWPE form's type so both can be returned from currentForm()
    /// without a ptrCast.
    tcp_form: zz.Form(6) = undefined,
    /// MeshCore form (device, baud, reconnect, disconnect). Same Form(6)
    /// shape as the other two.
    meshcore_form: zz.Form(6) = undefined,
    reconnect_button: Button = .{ .label = "Reconnect" },
    disconnect_button: Button = .{ .label = "Disconnect" },
    /// Which tab is currently shown.
    active_tab: Tab = .agwpe,
    /// True when the tab strip has focus (Left/Right switches tabs).
    /// False when a form field has focus (Tab/Up/Down navigates the form).
    tab_focused: bool = true,
};

pub var state = State{};

pub fn init(ctx: *app.AppContext) void {
    state.ctx = ctx;

    state.agwpe_form = zz.Form(6).init();
    state.agwpe_form.title = "AGWPE Radio Settings";
    state.agwpe_form.addField("Callsign", &ctx.connection.callsign_input, .{ .required = true });
    state.agwpe_form.addField("Host", &ctx.connection.host_input, .{ .required = true });
    state.agwpe_form.addField("TCP Port", &ctx.connection.port_input, .{ .required = true });
    state.agwpe_form.addField("Radio Port", &ctx.connection.kport_input, .{ .required = true });
    state.agwpe_form.addField("", &state.reconnect_button, .{ .required = false });
    state.agwpe_form.addField("", &state.disconnect_button, .{ .required = false });
    state.agwpe_form.submit_keys = &.{};
    state.agwpe_form.cancel_keys = &.{};
    _ = state.agwpe_form.focus_group.addNextKey(.{ .key = .down });
    _ = state.agwpe_form.focus_group.addPrevKey(.{ .key = .up });
    state.agwpe_form.hint_text = "";

    state.tcp_form = zz.Form(6).init();
    state.tcp_form.title = "TCP Direct Settings";
    state.tcp_form.addField("Host", &ctx.connection.tcp_host_input, .{ .required = true });
    state.tcp_form.addField("Port", &ctx.connection.tcp_port_input, .{ .required = true });
    state.tcp_form.addField("", &state.reconnect_button, .{ .required = false });
    state.tcp_form.addField("", &state.disconnect_button, .{ .required = false });
    state.tcp_form.submit_keys = &.{};
    state.tcp_form.cancel_keys = &.{};
    _ = state.tcp_form.focus_group.addNextKey(.{ .key = .down });
    _ = state.tcp_form.focus_group.addPrevKey(.{ .key = .up });
    state.tcp_form.hint_text = "";

    state.meshcore_form = zz.Form(6).init();
    state.meshcore_form.title = "MeshCore Radio Settings";
    state.meshcore_form.addField("Device", &ctx.connection.meshcore_dev_input, .{ .required = true });
    state.meshcore_form.addField("Baud", &ctx.connection.meshcore_baud_input, .{ .required = true });
    state.meshcore_form.addField("", &state.reconnect_button, .{ .required = false });
    state.meshcore_form.addField("", &state.disconnect_button, .{ .required = false });
    state.meshcore_form.submit_keys = &.{};
    state.meshcore_form.cancel_keys = &.{};
    _ = state.meshcore_form.focus_group.addNextKey(.{ .key = .down });
    _ = state.meshcore_form.focus_group.addPrevKey(.{ .key = .up });
    state.meshcore_form.hint_text = "";
}

pub fn deinit() void {}

fn onEnter(ptr: *anyopaque, _: *zz.Context) void {
    _ = ptr;
    const mgr = &state.ctx.connection;
    // Sync the active tab to the connection manager's active kind.
    state.active_tab = switch (mgr.active_kind) {
        .agwpe => .agwpe,
        .tcp => .tcp,
        .meshcore => .meshcore,
    };
    state.tab_focused = !mgr.connect_locked;
    if (!mgr.connect_locked) {
        currentForm().initFocus();
    } else {
        currentForm().initFocus();
    }
    state.ctx.status = "Settings — Esc to return.";
}

fn update(ptr: *anyopaque, _: *zz.Context, k: zz.KeyEvent) zz.ScreenAction {
    _ = ptr;
    const ctx = state.ctx;
    const mgr = &ctx.connection;

    if (k.key == .escape) return .pop;

    if (k.modifiers.ctrl and k.key == .char and k.key.char == 'r') {
        ctx.status = "Reconnecting...";
        connection_mod.startConnect(ctx);
        return .none;
    }

    // If transport is locked, skip tab navigation entirely.
    if (mgr.connect_locked) {
        return handleFormKey(ctx, k);
    }

    // Tab strip focus: Left/Right switches tabs, Down/Tab enters form.
    if (state.tab_focused) {
        return handleTabStripKey(mgr, k);
    }

    // Form focus: Tab/Up at the top returns to tab strip.
    return handleFormKey(ctx, k);
}

fn view(ptr: *anyopaque, _: *const zz.Context, alloc: std.mem.Allocator) anyerror![]const u8 {
    _ = ptr;
    const ctx = state.ctx;
    const mgr = &ctx.connection;
    const styled_conn = try render.renderConnIndicator(alloc, mgr.isConnected(), mgr.active_kind);
    const styled_stats = try render.renderPacketStats(alloc, ctx.packet_stats.txRecent(), ctx.packet_stats.rxRecent(), ctx.packet_stats.sparklineData());
    const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);

    // --- Tab strip ---
    const tab_strip = try renderTabStrip(alloc, mgr);
    defer alloc.free(tab_strip);

    // --- Active form ---
    const form_view = switch (state.active_tab) {
        .agwpe => try state.agwpe_form.view(alloc),
        .tcp => try state.tcp_form.view(alloc),
        .meshcore => try state.meshcore_form.view(alloc),
    };
    defer alloc.free(form_view);

    // --- Key info ---
    const key_info = try renderKeyInfo(alloc, ctx);
    defer alloc.free(key_info);

    // --- Incoming message log ---
    var in_title_style = zz.Style{};
    in_title_style = in_title_style.bold(true);
    in_title_style = in_title_style.fg(zz.Color.magenta);
    in_title_style = in_title_style.inline_style(true);
    const in_title = try in_title_style.render(alloc, "Message Log");

    const in_box = try renderMessageLog(alloc, ctx);
    defer alloc.free(in_box);

    // --- Sent transmissions log ---
    const sent_box = try renderSentLog(alloc, ctx);
    defer alloc.free(sent_box);

    var sent_title_style = zz.Style{};
    sent_title_style = sent_title_style.bold(true);
    sent_title_style = sent_title_style.fg(zz.Color.blue);
    sent_title_style = sent_title_style.inline_style(true);
    const sent_title = try sent_title_style.render(alloc, "Sent transmissions");

    // --- Help ---
    var help_style = zz.Style{};
    help_style = help_style.fg(zz.Color.gray(12));
    help_style = help_style.inline_style(true);
    const help = try help_style.render(
        alloc,
        if (mgr.connect_locked)
            "Up/Down: navigate  Enter: activate  Ctrl+R: reconnect  Esc: Back  (fields are read-only)"
        else
            "Left/Right: switch transport  Tab: form/tab  Up/Down: navigate  Ctrl+R: reconnect  Esc: Back",
    );

    const inner = try std.fmt.allocPrint(
        alloc,
        "{s} {s}  {s}\n{s}\n\n{s}\n\n{s}\n\n{s}\n{s}\n\n{s}\n{s}\n\n{s}",
        .{
            styled_conn, styled_stats, styled_status,
            tab_strip,   form_view,
            key_info,    in_title,
            in_box,      sent_title,
            sent_box,    help,
        },
    );
    defer alloc.free(inner);

    // Wrap in a bordered, padded panel.
    var panel_style = zz.Style{};
    panel_style = panel_style.borderAll(zz.Border.rounded);
    panel_style = panel_style.borderForeground(zz.Color.cyan);
    panel_style = panel_style.paddingAll(1);
    panel_style = panel_style.width(80);
    return panel_style.render(alloc, inner);
}

fn currentForm() *zz.Form(6) {
    return switch (state.active_tab) {
        .agwpe => &state.agwpe_form,
        .tcp => &state.tcp_form,
        .meshcore => &state.meshcore_form,
    };
}

/// Cycle to the next tab (Left/Right wrap across all three transports).
fn nextTab(current: Tab, forward: bool) Tab {
    const order = [_]Tab{ .agwpe, .tcp, .meshcore };
    for (order, 0..) |t, i| {
        if (t == current) {
            const n = if (forward)
                (i + 1) % order.len
            else
                (i + order.len - 1) % order.len;
            return order[n];
        }
    }
    return current;
}

/// Returns true if the key event would mutate a text input's value (char,
/// backspace, delete, paste). Used to filter these out when a field is
/// locked from the CLI, making it read-only.
fn isTextMutatingKey(k: zz.KeyEvent) bool {
    return switch (k.key) {
        .char, .backspace, .delete, .paste => true,
        else => false,
    };
}

/// Handle a key while a form field has focus. Up at the first field returns
/// to the tab strip (when transport isn't locked). Text-mutating keys are
/// dropped for CLI-locked transport fields. Reconnect/Disconnect buttons
/// trigger their connection actions here.
fn handleFormKey(ctx: *app.AppContext, k: zz.KeyEvent) zz.ScreenAction {
    const form = currentForm();

    // If the first field is focused and Up is pressed, go back to tabs.
    if (!ctx.connection.connect_locked) {
        if (k.key == .up and form.focus_group.active == 0) {
            state.tab_focused = true;
            return .none;
        }
    }

    // When the transport is locked from CLI (`--connect`), the transport
    // text inputs (host, port, kport) are read-only. The callsign field
    // (AGWPE field 0) is separately locked by `--callsign` — it stays
    // editable when only `--connect` was passed so the user can still set
    // their callsign in Settings. Drop text-mutating keys for locked
    // fields; navigation and button activation still pass through.
    if (ctx.connection.connect_locked) {
        // AGWPE: field 0 = callsign, fields 1-3 = host/port/kport.
        // TCP: fields 0-1 = host/port (no callsign field).
        // MeshCore: fields 0-1 = device/baud (no callsign field).
        if (state.active_tab == .agwpe) {
            // Callsign (field 0): locked only when callsign_locked.
            if (form.focus_group.active == 0 and !ctx.connection.callsign_locked and isTextMutatingKey(k)) {
                // Allow editing the callsign.
            } else if (form.focus_group.active >= 1 and form.focus_group.active <= 3 and isTextMutatingKey(k)) {
                return .none;
            }
        } else {
            // TCP / MeshCore: fields 0-1 are transport inputs.
            if (form.focus_group.active < 2 and isTextMutatingKey(k)) {
                return .none;
            }
        }
    }

    // Callsign locked from CLI (`--callsign`) — field 0 of AGWPE is read-only.
    if (state.active_tab == .agwpe and ctx.connection.callsign_locked) {
        if (form.focus_group.active == 0 and isTextMutatingKey(k)) {
            return .none;
        }
    }

    _ = form.handleKey(k);

    if (state.reconnect_button.pressed) {
        state.reconnect_button.pressed = false;
        ctx.status = "Reconnecting...";
        connection_mod.startConnect(ctx);
        return .none;
    }
    if (state.disconnect_button.pressed) {
        state.disconnect_button.pressed = false;
        connection_mod.disconnectActive(ctx);
        return .none;
    }
    return .none;
}

/// Handle a key while the tab strip has focus: Left/Right switches tabs
/// (syncing the connection manager's `active_kind`), Down/Tab enters the
/// form. Returns `.none` for any other key (the tab strip eats it).
fn handleTabStripKey(mgr: *app.ConnectionManager, k: zz.KeyEvent) zz.ScreenAction {
    if (k.key == .left or k.key == .right) {
        state.active_tab = nextTab(state.active_tab, k.key == .right);
        mgr.active_kind = switch (state.active_tab) {
            .agwpe => .agwpe,
            .tcp => .tcp,
            .meshcore => .meshcore,
        };
        return .none;
    }
    if (k.key == .down or k.key == .tab) {
        state.tab_focused = false;
        currentForm().initFocus();
        return .none;
    }
    return .none;
}

/// Render the tab strip: AGWPE / TCP labels with the active tab highlighted,
/// or a "locked from CLI" notice when the transport is locked.
fn renderTabStrip(alloc: std.mem.Allocator, mgr: *app.ConnectionManager) anyerror![]const u8 {
    var tab_buf: std.ArrayList(u8) = .empty;
    defer tab_buf.deinit(alloc);

    if (!mgr.connect_locked) {
        const agwpe_label = if (state.active_tab == .agwpe and state.tab_focused)
            " [AGWPE (Radio)]▶"
        else if (state.active_tab == .agwpe)
            " [AGWPE (Radio)] "
        else
            "  AGWPE (Radio)  ";
        const tcp_label = if (state.active_tab == .tcp and state.tab_focused)
            " [TCP (Direct)]▶"
        else if (state.active_tab == .tcp)
            " [TCP (Direct)] "
        else
            "  TCP (Direct)  ";
        const meshcore_label = if (state.active_tab == .meshcore and state.tab_focused)
            " [MeshCore (Serial)]▶"
        else if (state.active_tab == .meshcore)
            " [MeshCore (Serial)] "
        else
            "  MeshCore (Serial)  ";

        var tab_style = zz.Style{};
        tab_style = tab_style.inline_style(true);
        const agwpe_styled = if (state.active_tab == .agwpe)
            tab_style.fg(zz.Color.cyan).bold(true).render(alloc, agwpe_label) catch try alloc.dupe(u8, agwpe_label)
        else
            tab_style.fg(zz.Color.gray(12)).render(alloc, agwpe_label) catch try alloc.dupe(u8, agwpe_label);
        defer alloc.free(agwpe_styled);
        const tcp_styled = if (state.active_tab == .tcp)
            tab_style.fg(zz.Color.cyan).bold(true).render(alloc, tcp_label) catch try alloc.dupe(u8, tcp_label)
        else
            tab_style.fg(zz.Color.gray(12)).render(alloc, tcp_label) catch try alloc.dupe(u8, tcp_label);
        defer alloc.free(tcp_styled);
        const meshcore_styled = if (state.active_tab == .meshcore)
            tab_style.fg(zz.Color.cyan).bold(true).render(alloc, meshcore_label) catch try alloc.dupe(u8, meshcore_label)
        else
            tab_style.fg(zz.Color.gray(12)).render(alloc, meshcore_label) catch try alloc.dupe(u8, meshcore_label);
        defer alloc.free(meshcore_styled);

        try tab_buf.appendSlice(alloc, agwpe_styled);
        try tab_buf.appendSlice(alloc, "  ");
        try tab_buf.appendSlice(alloc, tcp_styled);
        try tab_buf.appendSlice(alloc, "  ");
        try tab_buf.appendSlice(alloc, meshcore_styled);
    } else {
        var lock_style = zz.Style{};
        lock_style = lock_style.inline_style(true);
        lock_style = lock_style.fg(zz.Color.yellow);
        const locked_label = switch (mgr.active_kind) {
            .agwpe => "Transport: AGWPE (locked from CLI \xe2\x80\x94 immutable)",
            .tcp => "Transport: TCP (locked from CLI \xe2\x80\x94 immutable)",
            .meshcore => "Transport: MeshCore (locked from CLI \xe2\x80\x94 immutable)",
        };
        const styled = lock_style.render(alloc, locked_label) catch try alloc.dupe(u8, locked_label);
        defer alloc.free(styled);
        try tab_buf.appendSlice(alloc, styled);
    }
    return alloc.dupe(u8, tab_buf.items);
}

/// "Signing Key: …" line showing the fingerprint of the working signing key,
/// or a placeholder prompting registration/login when none is derived.
fn renderKeyInfo(alloc: std.mem.Allocator, ctx: *app.AppContext) anyerror![]const u8 {
    if (ctx.identity.keypair) |kp| {
        const pk = kp.publicKeyBytes();
        return std.fmt.allocPrint(alloc, "Signing Key: {x:0>2}{x:0>2}{x:0>2}{x:0>2}\u{2026}{x:0>2}{x:0>2}{x:0>2}{x:0>2} (derived from passphrase)", .{
            pk[0],          pk[1],          pk[2],          pk[3],
            pk[pk.len - 4], pk[pk.len - 3], pk[pk.len - 2], pk[pk.len - 1],
        });
    } else {
        return alloc.dupe(u8, "Signing Key: none — register or log in to derive one");
    }
}

/// Render the incoming-message log as a bordered, padded box (magenta border).
/// Shows the most recent 15 entries (newest at top) with time, accept/reject
/// status, signature glyph, message tag, and callsign.
fn renderMessageLog(alloc: std.mem.Allocator, ctx: *app.AppContext) anyerror![]const u8 {
    const visible_log: usize = @min(ctx.buffers.message_log_count, types.max_message_log);
    var in_buf: std.ArrayList(u8) = .empty;
    defer in_buf.deinit(alloc);
    if (visible_log == 0) {
        try in_buf.appendSlice(alloc, "(no messages received yet)");
    } else {
        const max_display: usize = @min(visible_log, 15);
        var i: usize = ctx.buffers.message_log_count;
        var shown: usize = 0;
        while (i > 0 and shown < max_display) {
            i -= 1;
            const idx = i % types.max_message_log;
            const entry = ctx.buffers.message_log[idx];

            const time_str = entry.time[0..entry.time_len];
            const tag_str = entry.tag[0..entry.tag_len];
            const cs_str = entry.callsign[0..entry.callsign_len];

            const sig_sym: []const u8 = switch (entry.sig) {
                .none => " ",
                .valid => "\xe2\x9c\x93",
                .invalid => "\xe2\x9c\x97",
                .unknown_key => "?",
            };

            const status_label: []const u8 = switch (entry.status) {
                .accepted => "ok",
                .rejected_no_key => "REJ:no-key",
                .rejected_unsigned => "REJ:unsigned",
                .rejected_sig => "REJ:bad-sig",
            };

            const line = if (entry.callsign_len > 0)
                try std.fmt.allocPrint(alloc, "{s} {s} {s} {s} {s}\n", .{ time_str, status_label, sig_sym, tag_str, cs_str })
            else
                try std.fmt.allocPrint(alloc, "{s} {s} {s} {s}\n", .{ time_str, status_label, sig_sym, tag_str });
            defer alloc.free(line);
            try in_buf.appendSlice(alloc, line);
            shown += 1;
        }
        if (in_buf.items.len > 0 and in_buf.items[in_buf.items.len - 1] == '\n')
            in_buf.items.len -= 1;
    }

    var in_box_style = zz.Style{};
    in_box_style = in_box_style.borderAll(zz.Border.rounded);
    in_box_style = in_box_style.borderForeground(zz.Color.magenta);
    in_box_style = in_box_style.paddingAll(1);
    return in_box_style.render(alloc, in_buf.items);
}

/// Render the sent-transmissions log as a bordered, padded box (gray border).
/// Shows every entry currently in the ring buffer, oldest-to-newest.
fn renderSentLog(alloc: std.mem.Allocator, ctx: *app.AppContext) anyerror![]const u8 {
    const visible_sent: usize = @min(ctx.buffers.sent_log_count, types.max_sent_log);
    var sent_buf: std.ArrayList(u8) = .empty;
    defer sent_buf.deinit(alloc);
    if (visible_sent == 0) {
        try sent_buf.appendSlice(alloc, "(none yet)");
    } else {
        const start: usize = ctx.buffers.sent_log_count - visible_sent;
        var i: usize = start;
        while (i < ctx.buffers.sent_log_count) : (i += 1) {
            const idx = i % types.max_sent_log;
            try sent_buf.appendSlice(alloc, ctx.buffers.sent_log_lines[idx][0..ctx.buffers.sent_log_lens[idx]]);
            if (i + 1 < ctx.buffers.sent_log_count) try sent_buf.append(alloc, '\n');
        }
    }

    var sent_box_style = zz.Style{};
    sent_box_style = sent_box_style.borderAll(zz.Border.rounded);
    sent_box_style = sent_box_style.borderForeground(zz.Color.gray(10));
    sent_box_style = sent_box_style.paddingAll(1);
    return sent_box_style.render(alloc, sent_buf.items);
}

pub const vtable = zz.Screen.VTable{
    .update = update,
    .view = view,
    .on_enter = onEnter,
};

pub const screen = zz.Screen{
    .ptr = @ptrCast(&state),
    .vtable = &vtable,
    .title = "Settings",
    .modal = true,
};
