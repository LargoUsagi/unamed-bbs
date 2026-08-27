//! AppContext — the root application state for the TUI.
//!
//! Composes three cohesive sub-structs, each owning a single concern:
//!   - `connection` (`ConnectionManager`) — AGWPE TCP connection + the
//!     host/port/kport/callsign text inputs + connect lifecycle.
//!   - `identity` (`Identity`) — signing key pair, trusted BBS key, user id,
//!     known-key cache, and crypto derivation helpers.
//!   - `buffers` (`RingBuffers`) — the four ring buffers (incoming messages,
//!     message log, sent-transmission log, chat log).
//!
//! App-wide fields that don't belong to any single sub-struct remain here:
//! `io`, `store` (SQLite), `status` / `sending` (UI flags touched by ~15
//! modules), `async_runner`, MOTD cache, bulletin pagination, pending-status
//! popup trigger, and the receive-side inbox (see `inbox.zig`).
//!
//! Send/receive/log logic lives in sibling modules (`outbox.zig`,
//! `incoming.zig`, `inbox.zig`, `logs.zig`); screens import those modules
//! directly and call e.g. `outbox.sendBulletin(ctx, ...)`.

const std = @import("std");
const zz = @import("zigzag");

const types = @import("types.zig");
const cli = @import("cli.zig");
const client_store = @import("../client_store.zig");

const protocol = @import("bbs").protocol;

const connection_mod = @import("connection.zig");
const identity_mod = @import("identity.zig");
const buffers_mod = @import("buffers.zig");
const outbox_mod = @import("outbox.zig");
const logs = @import("logs.zig");
const inbox_mod = @import("inbox.zig");

pub const ConnectionManager = connection_mod.ConnectionManager;
pub const Identity = identity_mod.Identity;
pub const RingBuffers = buffers_mod.RingBuffers;
pub const Outbox = outbox_mod.Outbox;
pub const Inbox = inbox_mod.Inbox;

pub const SendArgs = types.SendArgs;
pub const ConnectArgs = types.ConnectArgs;
pub const SendResult = types.SendResult;
pub const ConnectResult = types.ConnectResult;
pub const Msg = types.Msg;
pub const ChatDirection = types.ChatDirection;
pub const SigStatus = types.SigStatus;
pub const MsgLogStatus = types.MsgLogStatus;
pub const MsgLogEntry = types.MsgLogEntry;
pub const OverheardNak = inbox_mod.OverheardNak;

/// A server-originated status report awaiting display in a popup modal.
pub const PendingStatus = struct {
    outcome: protocol.RequestOutcome,
    detail: [256]u8 = std.mem.zeroes([256]u8),
    detail_len: u8 = 0,
};

/// A registration held pending while the client waits for the server's public
/// key (BBS key). When the user registers with no known BBS key, the client
/// auto-requests the key and stashes the registration here; `tick()` resolves
/// it — firing the registration once the key arrives, or surfacing a timeout
/// error popup if the deadline passes.
pub const PendingRegistration = struct {
    /// The handle the user entered, page-allocated. Owned by AppContext and
    /// freed when the pending registration is resolved (sent or timed out).
    handle: []u8,
    /// Whether "Remember credentials" was checked; passed to `sendRegistration`.
    remember: bool,
    /// Unix-epoch seconds by which the key must arrive, else the registration
    /// is aborted with a timeout error popup.
    deadline_secs: u64,
};

pub const AppContext = @This();

// --- App-wide fields ---
io: std.Io,
store: client_store.Store,
status: []const u8,
async_runner: zz.AsyncRunner(Msg),

// --- Sub-structs ---
connection: ConnectionManager,
identity: Identity,
buffers: RingBuffers,

// --- MOTD (Message of the Day) ---
/// Cached MOTD text (plain text, owned by AppContext). null if not yet received.
motd_text: ?[]const u8,
/// Unix epoch seconds when the MOTD was last updated. 0 if never received.
motd_timestamp: u64,

// --- Bulletin pagination (updated by incoming bulletin_list messages) ---
bulletins_page: u16,
bulletins_total_pages: u16,

// --- Pending server status (for popup modal) ---
/// When non-null, a `request_status` message from the server is pending
/// display. The model pushes the status modal on the next tick and the
/// modal reads + clears this field.
pending_status: ?PendingStatus = null,

// --- Pending account navigation (after registration ack) ---
/// When true, a successful `registration_ack` arrived and the model should
/// navigate to the Account screen on the next tick — but only when the user
/// was actively on the Register screen. Set by `inbox.handleRegistrationAck`;
/// the model clears it after handling. When the ack comes from CLI
/// auto-register (the user is on the Landing screen), the model leaves the
/// user on Landing — the landing buttons refresh to "Account" via
/// `landing.refreshIfStale`.
pending_account_navigation: bool = false,

// --- Pending registration (waiting for BBS key) ---
/// When non-null, a registration is on hold until the server's public key
/// arrives (auto-requested on Register because no BBS key was known).
/// `tickPendingRegistration` resolves it each tick.
pending_registration: ?PendingRegistration = null,

// --- Startup notice (one-time popup) ---
/// When non-null, a startup notice (e.g. duplicate `--connect` warning) is
/// pending display. The model pushes the notice popup on the next tick and
/// the popup reads + clears this field. Owned by the process arena.
startup_notice: ?[]const u8 = null,

/// When true, the client store is in-memory only — never persisted to disk.
/// Set by the `--in-memory` CLI flag. Skips loading `client_store.sqlite` on
/// init and deleting it on logout.
in_memory: bool = false,

// --- Receive-side inbox (drain + reassembly + NAK + verify) ---
/// Owns the transport handle, multipart reassembler, and overheard-NAK
/// suppression table. `tick()` calls `inbox.drain` then `inbox.processTimeouts`.
inbox: Inbox = .{},

// --- Send-side outbox (encode + sign + transmit) ---
/// Owns the per-send busy flag and the connection parameters captured at
/// connect (kport/host/port — the latter two for the sent-log display only).
/// Reads the transport handle from `inbox.transport`. Screens and handlers
/// call `outbox.sendBulletin(...)`, `outbox.requestMotd(...)`, etc. — the
/// single send abstraction for the whole client.
outbox: Outbox = .{},

// ---------------------------------------------------------------------------
// Init / deinit
// ---------------------------------------------------------------------------

pub fn init(
    self: *AppContext,
    allocator: std.mem.Allocator,
    io: std.Io,
    overrides: cli.TuiOverrides,
) void {
    self.io = io;
    self.in_memory = overrides.in_memory;

    // --- Persistent store ---
    // In in-memory mode, `:memory:` tells SQLite to use a RAM-only database
    // that is never written to disk. `store.load` handles schema creation
    // and migrations either way.
    self.store = client_store.Store.init(allocator);
    const db_path: []const u8 = if (overrides.in_memory) ":memory:" else "client_store.sqlite";
    self.store.load(io, db_path) catch {};

    // --- Sub-structs ---
    connection_mod.init(&self.connection, allocator, &self.store, overrides);
    identity_mod.init(self, overrides);
    self.buffers = .{};
    self.buffers.init();

    // --- UI status ---
    self.async_runner = zz.AsyncRunner(Msg).init(std.heap.page_allocator);

    // --- Restore the chat log from the local chat cache (sorted by epoch time) ---
    logs.loadChatHistoryFromStore(self);

    // --- Restore MOTD from the store ---
    if (self.store.getMotd()) |saved| {
        defer self.store.allocator.free(saved);
        self.motd_text = std.heap.page_allocator.dupe(u8, saved) catch null;
        self.motd_timestamp = self.store.getMotdTimestamp();
    } else {
        self.motd_text = null;
        self.motd_timestamp = 0;
    }

    self.bulletins_page = 0;
    self.bulletins_total_pages = 0;

    // --- Restore the startup notice from overrides (if any) ---
    self.startup_notice = overrides.startup_notice;

    // Spawn a background connect attempt — but only if the active transport
    // has a valid configuration (from CLI flags or the saved DB store).
    // Defaults alone are not enough; the user must have explicitly configured
    // the transport at least once. `startConnect` sets the status (including
    // a callsign-required error for AGWPE if the callsign isn't set).
    if (self.connection.activeConfigured()) {
        connection_mod.startConnect(self);
    } else {
        self.status = "Not connected — press Ctrl+R for settings.";
    }
}

pub fn deinit(self: *AppContext) void {
    connection_mod.deinit(&self.connection);
    self.async_runner.deinit();
    if (self.pending_registration) |pending| {
        std.heap.page_allocator.free(pending.handle);
        self.pending_registration = null;
    }
    self.store.deinit();
    if (self.motd_text) |t| std.heap.page_allocator.free(@constCast(t));
}

/// Delete the client SQLite database file and reset in-memory state. Called
/// when the user confirms logout. After this, the caller should return `.quit`
/// from the screen update to exit the application.
pub fn logout(self: *AppContext) void {
    identity_mod.reset(self);

    // Free any pending registration (user logged out / DB deleted).
    if (self.pending_registration) |pending| {
        std.heap.page_allocator.free(pending.handle);
        self.pending_registration = null;
    }

    self.store.deinit();
    if (!self.in_memory) {
        std.Io.Dir.cwd().deleteFile(self.io, "client_store.sqlite") catch {};
    }
    self.store = client_store.Store.init(std.heap.page_allocator);
}

/// Called on every tick (200 ms). Polls async results, drains incoming
/// messages, processes reassembly timeouts, and requests MOTD refresh.
pub fn tick(self: *AppContext, zz_ctx: *zz.Context) void {
    _ = zz_ctx;

    // Poll background send/connect results.
    const results = self.async_runner.poll();
    for (results) |r| switch (r) {
        .send_done => |sr| logs.recordSendResult(self, sr),
        .connect_done => |cr| connection_mod.handleConnectResult(self, cr),
        else => {},
    };

    // Drain + process incoming messages through the receive-side inbox.
    self.inbox.drain(self);

    // Process multipart reassembly timeouts and NAK backoff.
    self.inbox.processTimeouts(self);

    // Request MOTD refresh if stale (also fires once connected).
    outbox_mod.requestMotd(self);

    // Detect connection loss.
    if ((self.connection.agwpe_conn_initialized or self.connection.tcp_conn_initialized) and !self.connection.connecting and !self.connection.isConnected()) {
        self.status = "Connection lost — Ctrl+R for settings to reconnect.";
    }

    // Auto-register: when the CLI provided --handle + --key but no stored
    // user id exists, fire the registration automatically once connected (and
    // the BBS key is known). If the BBS key is unknown, kick off a key request
    // and stash a pending registration — tickPendingRegistration resolves it.
    self.tickAutoRegister();

    // Resolve a pending registration: fire it once the BBS key arrives (and
    // the outbox is free), or surface a timeout error if the deadline passed.
    self.tickPendingRegistration();
}

/// Number of seconds the client waits for the server's public key after an
/// auto-request triggered by the Register screen. Radio/AX.25 transport can be
/// slow, so this is generous.
pub const bbs_key_timeout_secs: u64 = 30;

/// Auto-register: when the CLI provided `--handle` + `--key` but no stored
/// `my_user_id` exists, fire the registration automatically once connected.
/// If the BBS key is already known, send the registration immediately;
/// otherwise kick off a key request and stash a pending registration (which
/// `tickPendingRegistration` resolves). Called every tick (200 ms).
pub fn tickAutoRegister(self: *AppContext) void {
    if (!self.identity.auto_register) return;
    // Wait for a connection before doing anything.
    if (!self.connection.isConnected()) return;
    // Already done (a registration ack may have arrived and set my_user_id).
    if (self.identity.my_user_id != null) {
        self.identity.auto_register = false;
        return;
    }
    // Don't conflict with an in-flight send or an existing pending registration.
    if (self.outbox.busy) return;
    if (self.pending_registration != null) return;

    const handle = self.identity.prefill_handle orelse {
        self.identity.auto_register = false;
        return;
    };

    if (self.identity.bbs_key != null) {
        // Key known — send the registration now.
        outbox_mod.sendRegistration(self, handle);
        self.identity.auto_register = false;
    } else if (!self.identity.bbs_key_locked) {
        // Key unknown — request it and stash a pending registration.
        const page = std.heap.page_allocator;
        const handle_copy = page.dupe(u8, handle) catch {
            self.identity.auto_register = false;
            return;
        };
        const now: u64 = @intCast(@max(0, std.Io.Timestamp.now(self.io, .real).toSeconds()));
        self.pending_registration = .{
            .handle = handle_copy,
            .remember = false,
            .deadline_secs = now + bbs_key_timeout_secs,
        };
        outbox_mod.sendBulletinRequestKey(self);
        self.status = "Auto-registering: waiting for server key...";
        // The pending_registration drives the rest of the flow (fires the
        // registration when the key arrives, or times out). Clear the
        // auto_register flag so we don't retry on rejection/timeout.
        self.identity.auto_register = false;
    } else {
        // Key hard-locked but null (bad --bbs-key hex) — can't proceed.
        var ps = PendingStatus{ .outcome = .failure };
        const msg = "Server key is hard-locked (--bbs-key) but invalid; cannot auto-register.";
        const n = @min(msg.len, ps.detail.len);
        @memcpy(ps.detail[0..n], msg[0..n]);
        ps.detail_len = @intCast(n);
        self.pending_status = ps;
        self.identity.auto_register = false;
        self.status = "Auto-register failed: invalid --bbs-key.";
    }
}

/// Resolve a pending registration (waiting for the BBS key). Called every
/// tick (200 ms). When the key arrives, fires the stashed registration; when
/// the deadline passes, surfaces a timeout error via the status popup.
pub fn tickPendingRegistration(self: *AppContext) void {
    const pending = self.pending_registration orelse return;

    // Key arrived — fire the registration now (if the outbox is free).
    if (self.identity.bbs_key != null and !self.outbox.busy) {
        outbox_mod.sendRegistration(self, pending.handle);
        std.heap.page_allocator.free(pending.handle);
        self.pending_registration = null;
        return;
    }

    // Deadline passed — surface a timeout error popup and abort.
    const now: u64 = @intCast(@max(0, std.Io.Timestamp.now(self.io, .real).toSeconds()));
    if (now >= pending.deadline_secs) {
        var ps = PendingStatus{ .outcome = .failure };
        const msg = "Server did not respond to key request (timeout).";
        const n = @min(msg.len, ps.detail.len);
        @memcpy(ps.detail[0..n], msg[0..n]);
        ps.detail_len = @intCast(n);
        self.pending_status = ps;
        std.heap.page_allocator.free(pending.handle);
        self.pending_registration = null;
        self.status = "Key request timed out.";
        return;
    }
}
