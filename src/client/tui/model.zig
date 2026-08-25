//! Top-level TUI model — a slim router that delegates to `AppContext` for
//! shared state/logic and `ScreenStack` for screen navigation.
//!
//! Per-screen state lives in the screen modules (`landing.zig`, `chat.zig`,
//! etc.). Each screen is a singleton with module-level state, a vtable, and
//! a `pub const screen` value for the `ScreenStack`. Shared application
//! state (connection, store, keys, incoming buffer, chat log) lives in
//! `app.zig` (`AppContext`).

const std = @import("std");
const zz = @import("zigzag");

const types = @import("types.zig");
const cli = @import("cli.zig");
const app = @import("app.zig");
const logs = @import("logs.zig");
const connection_mod = @import("connection.zig");

const landing = @import("screens/landing.zig");
const chat = @import("screens/chat.zig");
const settings = @import("screens/settings.zig");
const bulletins = @import("screens/bulletins.zig");
const bulletin_detail = @import("screens/bulletin_detail.zig");
const compose_bulletin = @import("screens/compose_bulletin.zig");
const compose_response = @import("screens/compose_response.zig");
const register = @import("screens/register.zig");
const account = @import("screens/account.zig");
const logout_confirm = @import("screens/logout_confirm.zig");
const server_settings = @import("screens/server_settings.zig");
const request_by_id = @import("screens/request_by_id.zig");
const status_popup = @import("screens/status_popup.zig");
const notice_popup = @import("screens/notice_popup.zig");
const user_directory = @import("screens/user_directory.zig");
const user_detail = @import("screens/user_detail.zig");

pub const Msg = types.Msg;

pub const Model = @This();

ctx: app.AppContext,
stack: zz.ScreenStack,
overrides: ?cli.TuiOverrides = null,

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

pub fn init(self: *Model, ctx: *zz.Context) zz.Cmd(Msg) {
    const ov = self.overrides orelse cli.TuiOverrides{};
    self.overrides = null;

    // Initialize shared app context (connection, store, keys, buffers).
    self.ctx.init(ctx.persistent_allocator, ctx.io, ov);

    // Initialize each screen (sets up forms, buttons, per-screen inputs).
    landing.init(&self.ctx);
    chat.init(&self.ctx);
    settings.init(&self.ctx);
    bulletins.init(&self.ctx);
    bulletin_detail.init(&self.ctx);
    compose_bulletin.init(&self.ctx);
    compose_response.init(&self.ctx);
    register.init(&self.ctx);
    account.init(&self.ctx);
    logout_confirm.init(&self.ctx);
    server_settings.init(&self.ctx);
    request_by_id.init(&self.ctx);
    status_popup.init(&self.ctx);
    notice_popup.init(&self.ctx);
    user_directory.init(&self.ctx);
    user_detail.init(&self.ctx);

    // Create the screen stack with the landing screen as the root.
    self.stack = zz.ScreenStack.init(ctx.persistent_allocator);
    self.stack.pushWithCtx(landing.screen, ctx) catch return .quit;

    return zz.Cmd(Msg).everyMs(200);
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

pub fn update(self: *Model, msg: Msg, ctx: *zz.Context) zz.Cmd(Msg) {
    switch (msg) {
        .key => |k| {
            // Ctrl+Q / Ctrl+C always quits.
            if (k.modifiers.ctrl and k.key == .char and (k.key.char == 'q' or k.key.char == 'c'))
                return .quit;

            // Forward to the top-of-stack screen.
            const result = self.stack.handleKey(ctx, k) catch return .none;
            if (result == .quit) return .quit;
            if (self.stack.isEmpty()) return .quit;
            return .none;
        },
        .tick => {
            // Let the app context poll async results and drain incoming.
            self.ctx.tick(ctx);

            // Refresh the landing buttons when identity state changes
            // asynchronously (auto-register ack, BBS key arrival, sysop
            // `user_info` broadcast) while the landing screen is on top.
            // `pop`-driven refresh is handled by landing's `on_resume`; this
            // covers the case where the user never leaves the landing screen.
            if (self.stack.top()) |top| {
                if (top.vtable == &landing.vtable) landing.refreshIfStale();
            }

            // Push the status popup if a pending status is available and the
            // popup isn't already on screen.
            if (self.ctx.pending_status != null) {
                if (self.stack.top()) |top| {
                    if (top.vtable == &status_popup.vtable) {
                        // Already showing — do nothing.
                    } else {
                        self.stack.pushWithCtx(status_popup.screen, ctx) catch {};
                    }
                } else {
                    self.stack.pushWithCtx(status_popup.screen, ctx) catch {};
                }
            }

            // Navigate to the Account screen after a successful registration
            // ack — but only when the user was on the Register screen (i.e.
            // they actively registered). Coming from CLI auto-register, the
            // user starts on the Landing screen and should stay there (the
            // landing buttons refresh to show "Account" via
            // `landing.refreshIfStale`). Already-on-Account is a no-op
            // (defensive against duplicate acks).
            if (self.ctx.pending_account_navigation) {
                self.ctx.pending_account_navigation = false;
                if (self.stack.top()) |top| {
                    if (top.vtable == &register.vtable) {
                        self.stack.popWithCtx(ctx);
                        self.stack.pushWithCtx(account.screen, ctx) catch {};
                    }
                }
            }

            // Push the startup notice popup if a notice is pending and the
            // popup isn't already on screen. The popup clears the notice on
            // dismissal.
            if (self.ctx.startup_notice != null) {
                if (self.stack.top()) |top| {
                    if (top.vtable == &notice_popup.vtable) {
                        // Already showing — do nothing.
                    } else {
                        self.stack.pushWithCtx(notice_popup.screen, ctx) catch {};
                    }
                } else {
                    self.stack.pushWithCtx(notice_popup.screen, ctx) catch {};
                }
            }

            return zz.Cmd(Msg).everyMs(200);
        },
        .send_done => |sr| {
            logs.recordSendResult(&self.ctx, sr);
            return .none;
        },
        .connect_done => |cr| {
            connection_mod.handleConnectResult(&self.ctx, cr);
            return .none;
        },
    }
    return .none;
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

pub fn view(self: *const Model, ctx: *const zz.Context) ![]const u8 {
    // Each non-modal screen pads itself to terminal size via `fillTerminal`,
    // so the modal composition in ScreenStack has a full-sized background to
    // center on. No additional `place` needed here.
    return self.stack.view(ctx, ctx.allocator);
}

// ---------------------------------------------------------------------------
// Deinit
// ---------------------------------------------------------------------------

pub fn deinit(self: *Model) void {
    self.stack.deinit();
    landing.deinit();
    chat.deinit();
    settings.deinit();
    bulletins.deinit();
    bulletin_detail.deinit();
    compose_bulletin.deinit();
    compose_response.deinit();
    register.deinit();
    account.deinit();
    logout_confirm.deinit();
    server_settings.deinit();
    request_by_id.deinit();
    status_popup.deinit();
    notice_popup.deinit();
    user_directory.deinit();
    user_detail.deinit();
    self.ctx.deinit();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(process_init: std.process.Init, overrides: cli.TuiOverrides) !void {
    var program = zz.Program(Model).init(process_init.gpa, process_init.io, process_init.environ_map);
    defer program.deinit();
    program.model.overrides = overrides;
    try program.run();
}
