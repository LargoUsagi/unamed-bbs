//! Outbox — the client-side send abstraction, mirroring the server's
//! `outbox.zig`. Owns the send policy (busy flag, precondition checks,
//! payload lifetime, per-send status reporting) while the shared mechanics —
//! encode + sign + transmit — live in `bbs.messaging.txSend` over a single
//! `TxTarget`, the same core the server's outbox drives through its pool.
//!
//! The outbox does NOT hold its own transport handle: it reads the inbox's
//! handle (`ctx.inbox.transport`) since the underlying physical transport is
//! the same for send and receive. It does own the per-send busy flag and the
//! connection parameters (kport/host/port) captured at connect — the latter
//! purely for the sent-transmission log display line. A future meshcore
//! transport hands its handle to the inbox (and is read here for TX) without
//! touching any screen or handler — the same extensibility property the
//! server enjoys via `TransportPool`.

const std = @import("std");

const types = @import("types.zig");
const app = @import("app.zig");
const bbs = @import("bbs");

const signing = types.signing;
const message_frame = types.message_frame;
const messaging = bbs.messaging;
const protocol = bbs.protocol;
const limits = message_frame;

const AppContext = app.AppContext;
const SendArgs = types.SendArgs;
const SendResult = types.SendResult;
const Msg = types.Msg;

/// 12-hour MOTD refresh interval in seconds.
const motd_ttl: u64 = 12 * 60 * 60;

/// Owns the send-side state: the busy flag (replaces the former app-wide
/// `sending` flag) and the connection parameters captured at connect for the
/// sent-transmission log display. Reads the transport handle from
/// `ctx.inbox.transport`. Exposed as `ctx.outbox`; screens call
/// `ctx.outbox.sendBulletin(...)` etc.
pub const Outbox = struct {
    /// True while a background send task is in flight. Screens read this to
    /// render the status line and to decide whether to clear input fields.
    busy: bool = false,
    /// KISS radio channel captured at connect. Used as the `port` argument to
    /// `transport.sendMultipart`.
    kport: u4 = 0,
    /// TNC host (TCP) captured at connect — sent-log display only.
    host: [64]u8 = std.mem.zeroes([64]u8),
    host_len: u8 = 0,
    /// TNC TCP port — sent-log display only.
    port: u16 = 0,

    /// Capture connection parameters after a successful connect. The transport
    /// handle itself is owned by the inbox (`ctx.inbox.setTransport`); this
    /// records only the TX-side params (kport for the wire, host/port for the
    /// log line).
    pub fn setParams(self: *Outbox, kport: u4, host: []const u8, port: u16) void {
        self.kport = kport;
        const n = @min(host.len, self.host.len);
        @memcpy(self.host[0..n], host[0..n]);
        self.host_len = @intCast(n);
        self.port = port;
    }

    /// Returns the captured host slice (for the sent-log line).
    pub fn hostSlice(self: *const Outbox) []const u8 {
        return self.host[0..self.host_len];
    }
};

// ---------------------------------------------------------------------------
// prepareSend — shared boilerplate for send* functions
// ---------------------------------------------------------------------------

/// Common parameters extracted from `AppContext` needed to build a `SendArgs`.
const SendParams = struct {
    kport: u4,
    port: u16,
    host: []u8,
    secret_key: [signing.secret_key_len]u8,
};

/// Check preconditions (not already busy, connected, transport attached) and
/// capture the connection parameters from the outbox. Returns `null` (after
/// setting `ctx.status`) on failure. On success, `host` is page-allocated and
/// ownership transfers to the caller (typically into `SendArgs.host`).
fn prepareSend(ctx: *AppContext) ?SendParams {
    if (ctx.outbox.busy) {
        ctx.status = "Already sending...";
        return null;
    }
    // Block all outbound commands until a valid signing key exists. The
    // keypair is only set by CLI derivation, store restoration, or successful
    // registration/login — never a random placeholder — so a `null` keypair
    // means the user must register or log in before sending anything.
    const kp = ctx.identity.keypair orelse {
        ctx.status = "No signing key — register or log in first.";
        return null;
    };
    return prepareSendNoKey(ctx, kp.secretKeyBytes());
}

/// Same as `prepareSend` but does NOT require a signing key — for the one
/// public, unsigned request in the protocol: `public_key_request`. The
/// caller passes an all-zero `secret_key` (the `sendTask` unsigned path
/// skips key reconstruction for `public_key_request`).
fn prepareSendNoKey(ctx: *AppContext, secret_key: [signing.secret_key_len]u8) ?SendParams {
    if (ctx.outbox.busy) {
        ctx.status = "Already sending...";
        return null;
    }
    const t = ctx.inbox.transport orelse {
        ctx.status = "Not connected — Ctrl+R for settings to reconnect.";
        return null;
    };
    if (!t.isConnected()) {
        ctx.status = "Not connected — Ctrl+R for settings to reconnect.";
        return null;
    }
    const page = std.heap.page_allocator;
    const host_copy = page.dupe(u8, ctx.outbox.hostSlice()) catch {
        ctx.status = "Out of memory.";
        return null;
    };
    return .{
        .kport = ctx.outbox.kport,
        .port = ctx.outbox.port,
        .host = host_copy,
        .secret_key = secret_key,
    };
}

/// Page-allocate a copy of `src`. On failure, frees `host` and sets
/// `ctx.status = "Out of memory."`. Returns `null` on failure.
fn dupeOrOOM(ctx: *AppContext, host: []u8, src: []const u8) ?[]u8 {
    const page = std.heap.page_allocator;
    const copy = page.dupe(u8, src) catch {
        page.free(host);
        ctx.status = "Out of memory.";
        return null;
    };
    return copy;
}

/// Spawn `sendTask` with `args` and set `ctx.outbox.busy` + `ctx.status`.
fn spawnAndSet(ctx: *AppContext, args: SendArgs, status_msg: []const u8) void {
    _ = ctx.async_runner.spawnWithArg(SendArgs, args, &sendTask);
    ctx.outbox.busy = true;
    ctx.status = status_msg;
}

// ---------------------------------------------------------------------------
// sendTask — background encode + sign + transmit
// ---------------------------------------------------------------------------

fn copyHost(host: []const u8) [64]u8 {
    var buf: [64]u8 = std.mem.zeroes([64]u8);
    const n = @min(host.len, 64);
    @memcpy(buf[0..n], host[0..n]);
    return buf;
}

/// Free page-allocated slices embedded in a `Payload`. Called by `sendTask`
/// after encoding so the background thread owns the payload's lifetime.
fn freePayloadSlices(payload: message_frame.Payload) void {
    const page = std.heap.page_allocator;
    switch (payload) {
        .bulletin => |b| {
            if (b.title.len > 0) page.free(b.title);
            if (b.body.len > 0) page.free(b.body);
        },
        .registration => |r| {
            if (r.handle.len > 0) page.free(r.handle);
            if (r.callsign.len > 0) page.free(r.callsign);
        },
        .bulletin_response => |r| if (r.body.len > 0) page.free(r.body),
        .user_info_request => |uir| if (uir.user_ids.len > 0) page.free(uir.user_ids),
        .packet_request => |pr| if (pr.packet_numbers.len > 0) page.free(pr.packet_numbers),
        .motd => |m| if (m.text.len > 0) page.free(m.text),
        .chat => |c| if (c.text.len > 0) page.free(c.text),
        .avatar_update => |au| if (au.avatar.len > 0) page.free(au.avatar),
        else => {},
    }
}

/// Map a `txSend` outcome to a `SendResult` for the sent-transmission log.
/// Error-stage fidelity is preserved: encode/sign failures report unsigned
/// with their stage name; a total wire failure reports the transport error
/// name with the post-sign flag.
fn finishSend(
    r: messaging.PrepareError!messaging.TxResult,
    args: SendArgs,
    host: [64]u8,
    host_len: u8,
    success_signed: bool,
) SendResult {
    const result = r catch |err| {
        return .{
            .ok = false,
            .input_len = args.input_len,
            .compressed_len = 0,
            .err = @errorName(err),
            .host = host,
            .host_len = host_len,
            .port = args.port,
            .kport = args.kport,
        };
    };
    if (!result.ok()) {
        return .{
            .ok = false,
            .input_len = args.input_len,
            .compressed_len = 0,
            .err = if (result.first_error) |e| @errorName(e) else "NoTarget",
            .host = host,
            .host_len = host_len,
            .port = args.port,
            .kport = args.kport,
            .signed = success_signed,
        };
    }
    return .{
        .ok = true,
        .input_len = args.input_len,
        .compressed_len = 0,
        .host = host,
        .host_len = host_len,
        .port = args.port,
        .kport = args.kport,
        .signed = success_signed,
    };
}

/// Background send task: delegate encode + sign + transmit to the shared
/// `messaging.txSend` core over the single transport target. For
/// `registration`, the public key is injected from the keypair. For
/// `public_key_request` (the one unsigned request in the protocol), no key is
/// passed and an all-zero signature is sent on the wire — this lets a client
/// with no derived signing key request the server key (the bootstrap path
/// before registration).
fn sendTask(args: SendArgs) ?Msg {
    defer std.heap.page_allocator.free(args.host);
    defer freePayloadSlices(args.payload);

    const host = copyHost(args.host);
    const host_len: u8 = @intCast(@min(args.host.len, 64));
    const msg_type: message_frame.MessageType = @as(message_frame.MessageType, args.payload);

    const targets = [_]messaging.TxTarget{.{
        .transport = args.transport,
        .port = args.kport,
        .call_to = "CQ",
        .opts = args.send_options,
    }};

    if (args.payload == .public_key_request) {
        const r = messaging.txSend(msg_type, args.payload, null, &targets);
        return .{ .send_done = finishSend(r, args, host, host_len, false) };
    }

    const kp = signing.KeyPair.fromSecretKeyBytes(args.secret_key) catch return .{ .send_done = .{
        .ok = false,
        .input_len = args.input_len,
        .compressed_len = 0,
        .err = "InvalidKey",
        .host = host,
        .host_len = host_len,
        .port = args.port,
        .kport = args.kport,
    } };

    const payload = if (args.payload == .registration)
        message_frame.Payload{ .registration = .{
            .mode = args.payload.registration.mode,
            .handle = args.payload.registration.handle,
            .callsign = args.payload.registration.callsign,
            .public_key = kp.publicKeyBytes(),
        } }
    else
        args.payload;

    const r = messaging.txSend(msg_type, payload, kp, &targets);
    return .{ .send_done = finishSend(r, args, host, host_len, true) };
}

// ---------------------------------------------------------------------------
// send* — public triggers called by TUI screens and incoming.zig / inbox.zig
// ---------------------------------------------------------------------------

pub fn sendBulletinRequestKey(ctx: *AppContext) void {
    if (ctx.identity.bbs_key_locked) {
        ctx.status = "Server key is hard-locked (--bbs-key).";
        return;
    }
    // `public_key_request` is the one public, unsigned request in the
    // protocol — the server's handler doesn't verify a signature, it just
    // broadcasts the server's public key to whoever asks. So this must work
    // before the user has derived a signing key (the whole point is to get
    // the server key so registration can proceed). Use the no-key prepare
    // path and an all-zero secret key; `sendTask` skips signing for this
    // payload type.
    const p = prepareSendNoKey(ctx, std.mem.zeroes([signing.secret_key_len]u8)) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .public_key_request = {} },
    };
    spawnAndSet(ctx, args, "Requesting server public key...");
}

pub fn sendSingleBulletinRequest(ctx: *AppContext, id: u32) void {
    const p = prepareSend(ctx) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .bulletin_request = .{ .mode = .range, .start_id = id, .end_id = id } },
    };
    spawnAndSet(ctx, args, std.fmt.allocPrint(std.heap.page_allocator, "Requesting bulletin {d}...", .{id}) catch "Requesting bulletin...");
}

pub fn sendBulletinRequestRange(ctx: *AppContext, start_id: u32, end_id: u32) void {
    if (end_id < start_id) return;
    const p = prepareSend(ctx) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .bulletin_request = .{ .mode = .range, .start_id = start_id, .end_id = end_id } },
    };
    spawnAndSet(ctx, args, std.fmt.allocPrint(std.heap.page_allocator, "Requesting bulletins {d}-{d}...", .{ start_id, end_id }) catch "Requesting bulletins...");
}

pub fn sendUserInfoRequest(ctx: *AppContext, user_ids: []const u16) void {
    if (user_ids.len == 0) return;
    const p = prepareSend(ctx) orelse return;
    const page = std.heap.page_allocator;
    const ids_copy = page.dupe(u16, user_ids) catch {
        page.free(p.host);
        ctx.status = "Out of memory.";
        return;
    };
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .user_info_request = .{ .user_ids = ids_copy } },
    };
    spawnAndSet(ctx, args, std.fmt.allocPrint(std.heap.page_allocator, "Requesting user info for {d} user(s)...", .{user_ids.len}) catch "Requesting user info...");
}

pub fn sendBulletinListRequest(ctx: *AppContext) void {
    const p = prepareSend(ctx) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .bulletin_list_request = .{ .page = 0, .page_size = 5 } },
    };
    spawnAndSet(ctx, args, "Requesting bulletins (page 0, 5 entries)...");
}

/// Send an `avatar_update` to the server with new avatar text. The server
/// identifies the sender by signature and re-broadcasts the updated
/// `user_info`. `avatar_text` is duped here so the caller's slice is decoupled
/// from the background send lifetime.
pub fn sendAvatarUpdate(ctx: *AppContext, avatar_text: []const u8) void {
    const p = prepareSend(ctx) orelse return;
    const page = std.heap.page_allocator;
    const avatar_copy = page.dupe(u8, avatar_text) catch {
        page.free(p.host);
        ctx.status = "Out of memory.";
        return;
    };
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .avatar_update = .{ .avatar = avatar_copy } },
    };
    spawnAndSet(ctx, args, "Updating avatar...");
}

pub fn requestMotd(ctx: *AppContext) void {
    if (ctx.outbox.busy) return;
    const t = ctx.inbox.transport orelse return;
    if (!t.isConnected()) return;
    if (ctx.identity.bbs_key == null) return;
    // No MOTD request can be signed without a derived signing key.
    if (ctx.identity.keypair == null) return;

    const now: u64 = bbs.time.nowSecs(ctx.io);
    if (now >= ctx.motd_timestamp) {
        if (now - ctx.motd_timestamp < motd_ttl) return;
    } else {
        return;
    }

    const page = std.heap.page_allocator;
    const host_copy = page.dupe(u8, ctx.outbox.hostSlice()) catch return;

    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = host_copy,
        .port = ctx.outbox.port,
        .kport = ctx.outbox.kport,
        .secret_key = ctx.identity.keypair.?.secretKeyBytes(),
        .payload = .{ .motd_request = {} },
    };
    _ = ctx.async_runner.spawnWithArg(SendArgs, args, &sendTask);

    ctx.outbox.busy = true;
    ctx.motd_timestamp = now;
    ctx.store.setMotdTimestamp(now) catch {};
    ctx.status = "Requesting MOTD...";
}

pub fn sendMotd(ctx: *AppContext, text: []const u8) void {
    if (text.len > limits.max_body_len) {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "MOTD exceeds {d} characters.", .{limits.max_body_len}) catch "MOTD exceeds 2048 characters.";
        return;
    }
    const p = prepareSend(ctx) orelse return;
    const text_copy = dupeOrOOM(ctx, p.host, text) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .input_len = text_copy.len,
        .payload = .{ .motd = .{ .text = text_copy } },
    };
    spawnAndSet(ctx, args, "Sending MOTD to server...");
}

pub fn sendRegistration(ctx: *AppContext, handle: []const u8, callsign: []const u8, mode: protocol.RegistrationMode) void {
    if (handle.len == 0) {
        ctx.status = "Handle is empty.";
        return;
    }
    if (handle.len > limits.max_handle_len) {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Handle exceeds {d} characters.", .{limits.max_handle_len}) catch "Handle exceeds 20 characters.";
        return;
    }
    if (callsign.len > limits.max_callsign_len) {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Callsign exceeds {d} characters.", .{limits.max_callsign_len}) catch "Callsign exceeds 10 characters.";
        return;
    }
    // The signing key must have been derived (Login/Register screen or CLI)
    // before a registration can be sent. `tickPendingRegistration` and the
    // login/register screens both derive the key before calling this, so the
    // keypair is normally non-null here; guard defensively anyway.
    const kp = ctx.identity.keypair orelse {
        ctx.status = "No signing key — enter handle and password to derive one.";
        return;
    };
    const p = prepareSend(ctx) orelse return;
    const page = std.heap.page_allocator;
    const handle_copy = page.dupe(u8, handle) catch {
        page.free(p.host);
        ctx.status = "Out of memory.";
        return;
    };
    const callsign_copy = page.dupe(u8, callsign) catch {
        page.free(handle_copy);
        page.free(p.host);
        ctx.status = "Out of memory.";
        return;
    };
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .input_len = handle_copy.len,
        .payload = .{ .registration = .{
            .mode = mode,
            .handle = handle_copy,
            .callsign = callsign_copy,
            .public_key = kp.publicKeyBytes(),
        } },
    };
    const status_msg: []const u8 = if (mode == .login) "Logging in..." else "Registering with BBS...";
    spawnAndSet(ctx, args, status_msg);
}

pub fn sendBulletin(ctx: *AppContext, title: []const u8, body: []const u8) void {
    if (title.len == 0) {
        ctx.status = "Bulletin title is empty.";
        return;
    }
    if (title.len > limits.max_title_len) {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Title exceeds {d} characters.", .{limits.max_title_len}) catch "Title exceeds 80 characters.";
        return;
    }
    if (body.len == 0) {
        ctx.status = "Bulletin body is empty.";
        return;
    }
    if (body.len > limits.max_body_len) {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Body exceeds {d} characters.", .{limits.max_body_len}) catch "Body exceeds 2048 characters.";
        return;
    }
    const p = prepareSend(ctx) orelse return;
    const page = std.heap.page_allocator;
    const title_copy = page.dupe(u8, title) catch {
        page.free(p.host);
        ctx.status = "Out of memory.";
        return;
    };
    const body_copy = dupeOrOOM(ctx, p.host, body) orelse {
        page.free(title_copy);
        return;
    };

    const ts_seconds = std.Io.Timestamp.now(ctx.io, .real).toSeconds();
    const created_at: u64 = @intCast(@max(0, ts_seconds));

    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .input_len = body_copy.len,
        .payload = .{ .bulletin = .{
            .id = 0,
            .user_id = 0,
            .created_at = created_at,
            .title = title_copy,
            .body = body_copy,
        } },
    };
    spawnAndSet(ctx, args, "Composing and transmitting bulletin...");
}

pub fn sendBulletinResponse(ctx: *AppContext, bulletin_id: u32, body: []const u8) void {
    if (body.len == 0) {
        ctx.status = "Response body is empty.";
        return;
    }
    if (body.len > limits.max_body_len) {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Response body exceeds {d} characters.", .{limits.max_body_len}) catch "Response body exceeds 2048 characters.";
        return;
    }
    const p = prepareSend(ctx) orelse return;
    const body_copy = dupeOrOOM(ctx, p.host, body) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .input_len = body_copy.len,
        .payload = .{ .bulletin_response = .{
            .bulletin_id = bulletin_id,
            .response_id = 0,
            .user_id = 0,
            .create_datetime = 0,
            .body = body_copy,
        } },
    };
    spawnAndSet(ctx, args, std.fmt.allocPrint(std.heap.page_allocator, "Composing and transmitting response to bulletin {d}...", .{bulletin_id}) catch "Composing and transmitting response...");
}

pub fn sendBulletinResponseRequest(ctx: *AppContext, bulletin_id: u32) void {
    const req = buildResponseRequest(ctx, bulletin_id) orelse {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "All responses already cached for bulletin {d}.", .{bulletin_id}) catch "All responses already cached.";
        return;
    };
    const p = prepareSend(ctx) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .bulletin_response_request = req },
    };
    spawnAndSet(ctx, args, std.fmt.allocPrint(std.heap.page_allocator, "Requesting responses for bulletin {d}...", .{bulletin_id}) catch "Requesting responses...");
}

/// Automatically request missing responses for a bulletin when the cached
/// response ids are non-contiguous — i.e. there is a gap in the expected
/// 0, 1, 2, ... sequence (including the case where id 0 itself is missing).
/// Silent no-op when no responses are cached, the bulletin is full, or the
/// cached ids are already contiguous. Called by the bulletin detail screen on
/// entry so gaps are filled without user action.
pub fn sendBulletinResponseRequestIfGapped(ctx: *AppContext, bulletin_id: u32) void {
    const responses = ctx.store.listResponses(bulletin_id) catch return;
    defer ctx.store.freeResponseList(responses);

    if (responses.len == 0) return;
    if (responses.len >= types.max_response_id + 1) return;

    var gap_start: ?u16 = null;
    for (responses, 0..) |r, i| {
        if (r.response_id != @as(u16, @intCast(i))) {
            gap_start = @intCast(i);
            break;
        }
    }
    if (gap_start == null) return;

    const p = prepareSend(ctx) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .bulletin_response_request = .{
            .bulletin_id = bulletin_id,
            .mode = .range,
            .start_id = gap_start.?,
            .end_id = types.max_response_id,
        } },
    };
    spawnAndSet(ctx, args, std.fmt.allocPrint(std.heap.page_allocator, "Auto-requesting missing responses for bulletin {d}...", .{bulletin_id}) catch "Auto-requesting missing responses...");
}

/// Send a chat message to the BBS (routed through the server). The message
/// is limited to `max_chat_text_len` (256) characters on the client side.
pub fn sendChat(ctx: *AppContext, message: []const u8) void {
    if (message.len == 0) {
        ctx.status = "Message is empty.";
        return;
    }
    if (message.len > limits.max_chat_text_len) {
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Chat exceeds {d} characters.", .{limits.max_chat_text_len}) catch "Chat exceeds 256 characters.";
        return;
    }
    const p = prepareSend(ctx) orelse return;
    const msg_copy = dupeOrOOM(ctx, p.host, message) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .input_len = msg_copy.len,
        .payload = .{ .chat = .{ .timestamp = 0, .user_id = 0, .text = msg_copy } },
    };
    spawnAndSet(ctx, args, "Sending chat to BBS...");
}

/// Request the most recent chat messages from the BBS. The server responds
/// with up to `chat_history_count` individual `chat` frames (signed by the
/// server), which the client caches in its local `chat_messages` table.
pub fn sendChatHistoryRequest(ctx: *AppContext) void {
    const p = prepareSend(ctx) orelse return;
    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = p.host,
        .port = p.port,
        .kport = p.kport,
        .secret_key = p.secret_key,
        .payload = .{ .chat_history_request = .{ .count = types.chat_history_count } },
    };
    spawnAndSet(ctx, args, std.fmt.allocPrint(std.heap.page_allocator, "Requesting {d} recent chats...", .{types.chat_history_count}) catch "Requesting recent chats...");
}

/// Send a signed packet_request to the server for missing packets.
/// Used by the NAK controller. Silent on failure (no status messages).
pub fn sendPacketRequest(ctx: *AppContext, group_id: u4, packet_numbers: []const u8) void {
    if (ctx.outbox.busy) return;
    const t = ctx.inbox.transport orelse return;
    if (!t.isConnected()) return;
    // NAK re-requests must be signed with the user's key; silently skip when
    // no key is available (the user will re-register/re-login to restore it).
    if (ctx.identity.keypair == null) return;

    const page = std.heap.page_allocator;
    const host_copy = page.dupe(u8, ctx.outbox.hostSlice()) catch return;
    const pn_copy = page.dupe(u8, packet_numbers) catch {
        page.free(host_copy);
        return;
    };

    const args = SendArgs{
        .transport = ctx.inbox.transport.?,
        .host = host_copy,
        .port = ctx.outbox.port,
        .kport = ctx.outbox.kport,
        .secret_key = ctx.identity.keypair.?.secretKeyBytes(),
        .payload = .{ .packet_request = .{ .packet_numbers = pn_copy } },
        .send_options = .{ .group_id = group_id },
    };
    _ = ctx.async_runner.spawnWithArg(SendArgs, args, &sendTask);

    ctx.outbox.busy = true;
}

// ---------------------------------------------------------------------------
// buildResponseRequest — inspect cached responses to build a NAK-style request
// ---------------------------------------------------------------------------

fn buildResponseRequest(ctx: *AppContext, bulletin_id: u32) ?message_frame.BulletinResponseRequest {
    const responses = ctx.store.listResponses(bulletin_id) catch return null;
    defer ctx.store.freeResponseList(responses);

    if (responses.len >= types.max_response_id + 1) return null;

    if (responses.len == 0) {
        return .{
            .bulletin_id = bulletin_id,
            .mode = .range,
            .start_id = 0,
            .end_id = types.max_response_id,
        };
    }

    var highest_contiguous: u16 = 0;
    var first_gap: ?u16 = null;
    for (responses, 0..) |r, i| {
        if (i == 0) {
            if (r.response_id != 0) {
                first_gap = 0;
                break;
            }
            highest_contiguous = 0;
        } else {
            const expected: u16 = @intCast(i);
            if (r.response_id != expected) {
                first_gap = expected;
                break;
            }
            highest_contiguous = r.response_id;
        }
    }

    if (first_gap) |gap| {
        return .{
            .bulletin_id = bulletin_id,
            .mode = .range,
            .start_id = gap,
            .end_id = types.max_response_id,
        };
    }

    if (highest_contiguous >= types.max_response_id) return null;
    return .{
        .bulletin_id = bulletin_id,
        .mode = .tail_after,
        .after_id = highest_contiguous,
    };
}
