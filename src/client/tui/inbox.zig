//! Inbox — the client-side receive abstraction, mirroring the server's
//! `inbox.zig`. Owns the receive policy (drain + NAK tracking + BBS-key
//! learning + signature verification against the trusted BBS key + logging)
//! while the shared mechanics — multipart routing, reassembly, and 30s
//! stale-entry eviction — live in `bbs.messaging.RxCore`, the same core the
//! server's inbox uses. Complete logical messages surface through the core's
//! `onMessage` callback as `bbs.messaging.Message` values (type + payload +
//! signature + link context); packetization details never reach this layer.
//! The one sanctioned raw-packet consumer here is the overheard-NAK
//! suppression table, wired via the optional `onPacket` hook.
//!
//! Type-specific `store*` / `handle*` dispatch for decoded payloads lives
//! in this file (merged from the former `incoming.zig`): the inbox owns the
//! receive mechanics *and* decodes each verified server message, so the wire
//! codec stays confined to this single boundary module.
//!
//! `transport.Transport` vtable handle (obtained from a concrete connection's
//! `asTransport()` on connect). A future meshcore transport hands in its own
//! `Transport` handle without touching `logs.zig`, or `outbox.zig` — the same
//! extensibility property the server enjoys via `TransportPool`.

const std = @import("std");

const types = @import("types.zig");
const app = @import("app.zig");
const outbox = @import("outbox.zig");
const logs = @import("logs.zig");
const identity_mod = @import("identity.zig");

const signing = types.signing;
const message_frame = types.message_frame;
const messaging = types.messaging;
const transport = types.transport;
const reassembly_mod = types.transport;

const AppContext = app.AppContext;
const SigStatus = types.SigStatus;

/// Outcome of processing an incoming message, returned from the labeled
/// block inside `addIncoming` so we can log every message exactly once.
const IncomingOutcome = struct {
    sig: SigStatus,
    status: types.MsgLogStatus,
};

/// An overheard NAK from another station, for suppression.
pub const OverheardNak = struct {
    active: bool = false,
    group_id: u4 = 0,
    packet_number: u8 = 0,
    timestamp: u64 = 0,
};

/// Owns the receive-side state: the transport handle, the shared RxCore
/// (reassembler + multipart routing), and the overheard-NAK suppression
/// table. Exposed as `ctx.inbox`; `tick()` calls `drain` then
/// `processTimeouts`.
pub const Inbox = struct {
    /// Transport handle set on successful connect (`conn.asTransport()`).
    /// null until the first connect succeeds. The underlying connection
    /// field address is stable for the program's life, so the handle remains
    /// valid across reconnects (drain is guarded by `isConnected()`).
    transport: ?transport.Transport = null,
    /// Shared receive mechanics: multipart reassembly + stale eviction.
    core: messaging.RxCore = .{},
    overheard_naks: [16]OverheardNak = std.mem.zeroes([16]OverheardNak),

    /// Attach (or refresh) the transport handle after a successful connect.
    pub fn setTransport(self: *Inbox, t: transport.Transport) void {
        self.transport = t;
    }

    /// True when the attached transport is a high-bandwidth link (e.g. direct
    /// TCP/IP). Returns false when no transport is attached. UI screens use
    /// this to gate automatic data fetches on page entry that would be wasteful
    /// or impolite over a slow radio channel (AGWPE/AX.25, meshcore).
    pub fn isHighBandwidth(self: *const Inbox) bool {
        const t = self.transport orelse return false;
        return t.isHighBandwidth();
    }

    /// Drain queued incoming packets from the transport and route each one
    /// through the shared core. Called from `tick()`. Does nothing when no
    /// transport is attached or the transport is not connected (e.g. during
    /// the reconnect window, where the underlying connection may be
    /// mid-teardown/rebuild).
    pub fn drain(self: *Inbox, ctx: *AppContext) void {
        const t = self.transport orelse return;
        if (!t.isConnected()) return;

        var buf: [16]transport.IncomingMessage = undefined;
        const n = t.drainIncoming(&buf);
        const handler = messaging.RxHandler{
            .ctx = @ptrCast(ctx),
            .onMessage = rxMessage,
            .onPacket = rxPacket,
            .onOverflow = rxOverflow,
        };
        const now = nowMs(ctx);
        for (buf[0..n]) |*im| self.core.process(handler, im, now);
    }

    /// Process reassembly timeouts (shared-core eviction plus client-only
    /// NAK sending with suppression-aware backoff), then age out stale
    /// overheard-NAK entries. Called from `tick()` every 200ms.
    /// Safe to run regardless of connection state: NAK sends self-guard on
    /// `isConnected()`, and reassembler cleanup is connection-independent.
    pub fn processTimeouts(self: *Inbox, ctx: *AppContext) void {
        const now = nowMs(ctx);

        if (self.core.evictStale(now) > 0) {
            ctx.status = "Multipart message timed out.";
        }

        for (self.core.reassembler.entriesSlice()) |*entry| {
            if (!entry.active) continue;

            // 2-second gap detection.
            if (now - entry.last_received_ts < 2_000) continue;
            if (entry.received_count >= entry.packet_count) continue;

            // Find missing packets.
            var missing: [message_frame.max_packets_per_message]u8 = undefined;
            var missing_count: usize = 0;
            var i: u8 = 0;
            while (i < entry.packet_count) : (i += 1) {
                if (entry.packets[i] == null) {
                    missing[missing_count] = i;
                    missing_count += 1;
                }
            }
            if (missing_count == 0) continue;

            // Check if it's time to send a NAK.
            if (now < entry.next_nak_ts) continue;
            if (entry.nak_attempts >= 3) {
                ctx.status = "Multipart message failed after 3 NAK attempts.";
                self.core.reassembler.freeEntry(entry);
                continue;
            }

            // Check for overheard NAKs — if another station requested the same
            // packets, double the backoff (max 10s) and wait.
            var suppressed = false;
            for (missing[0..missing_count]) |pn| {
                for (&self.overheard_naks) |*on| {
                    if (on.active and on.group_id == entry.group_id and on.packet_number == pn) {
                        if (now - on.timestamp < 5_000) {
                            suppressed = true;
                            break;
                        }
                    }
                }
                if (suppressed) break;
            }

            if (suppressed) {
                const backoff_ms: u64 = switch (entry.nak_attempts) {
                    0 => 2_000,
                    1 => 4_000,
                    2 => 8_000,
                    else => 10_000,
                };
                entry.next_nak_ts = now + backoff_ms;
                continue;
            }

            // Send the NAK.
            entry.nak_attempts += 1;
            const next_backoff: u64 = switch (entry.nak_attempts) {
                1 => 4_000,
                2 => 8_000,
                else => 10_000,
            };
            entry.next_nak_ts = now + next_backoff;
            outbox.sendPacketRequest(ctx, entry.group_id, missing[0..missing_count]);
        }

        // Age out old overheard NAKs.
        for (&self.overheard_naks) |*on| {
            if (on.active and now - on.timestamp > 10_000) {
                on.active = false;
            }
        }
    }

    /// RxCore packet hook — the sanctioned raw-packet view for radio-link
    /// policy. Tracks overheard NAK requests from other stations so the NAK
    /// controller can back off when someone else already asked. Callsigns are
    /// optional (identity-less links like MeshCore surface none), so the
    /// guard does not require one — `trackOverheardNak` keys by group_id.
    fn rxPacket(opaque_ctx: *anyopaque, im: *const transport.IncomingMessage) void {
        const ctx: *AppContext = @ptrCast(@alignCast(opaque_ctx));

        if (im.is_message_frame and im.msg_type == .packet_request) {
            trackOverheardNak(ctx, im);
        }
    }

    /// RxCore overflow diagnostic: a reassembled group exceeded the session
    /// Message payload cap and was dropped by the shared core.
    fn rxOverflow(opaque_ctx: *anyopaque, total: usize) void {
        _ = opaque_ctx;
        _ = total;
    }

    /// RxCore message callback: learn the BBS key, dispatch server messages
    /// (verified against the trusted BBS key), and log every complete message
    /// exactly once.
    fn rxMessage(opaque_ctx: *anyopaque, msg: messaging.Message) void {
        const ctx: *AppContext = @ptrCast(@alignCast(opaque_ctx));

        maybeLearnBbsKey(ctx, msg);

        const outcome: IncomingOutcome = if (isServerMessage(msg))
            handleServerMessage(ctx, msg)
        else
            .{ .sig = .none, .status = .accepted };

        logs.logIncoming(ctx, msg.msg_type, msg.callsignSlice(), outcome.sig, outcome.status);
    }
};

/// Learn the BBS (server) public key from a signed server-role `public_key`
/// message, unless the key was hard-locked via --bbs-key. Callsigns are
/// optional at the session boundary (only AGWPE provides link-layer
/// identity), so key learning does not require one.
fn maybeLearnBbsKey(ctx: *AppContext, msg: messaging.Message) void {
    if (msg.msg_type == .public_key and msg.has_public_key and
        msg.pub_key_role == .server)
    {
        if (!ctx.identity.bbs_key_locked and ctx.identity.bbs_key == null) {
            ctx.identity.bbs_key = msg.public_key;
            ctx.store.setBbsKey(msg.public_key) catch {};
        }
    }
}

/// Returns true if `msg` is a type that must be signed by the server (BBS)
/// and verified against the trusted BBS key.
fn isServerMessage(msg: messaging.Message) bool {
    return switch (msg.msg_type) {
        .bulletin_list,
        .bulletin,
        .bulletin_response,
        .bulletin_response_list,
        .registration_ack,
        .user_info,
        .user_info_list,
        .request_status,
        .motd,
        .chat,
        => true,
        .public_key => msg.pub_key_role == .server,
        else => false,
    };
}

/// Verify a server-originated message against the trusted BBS key and, on
/// success, store it in the incoming buffer and dispatch the payload.
fn handleServerMessage(ctx: *AppContext, msg: messaging.Message) IncomingOutcome {
    if (ctx.identity.bbs_key == null) return .{ .sig = .none, .status = .rejected_no_key };
    if (!msg.signed) return .{ .sig = .none, .status = .rejected_unsigned };

    if (!signing.verify(msg.signature, msg.payloadSlice(), ctx.identity.bbs_key.?)) {
        return .{ .sig = .invalid, .status = .rejected_sig };
    }

    const idx = ctx.buffers.incoming_count % types.max_incoming;
    ctx.buffers.incoming[idx] = msg;
    ctx.buffers.sig_statuses[idx] = .valid;
    ctx.buffers.incoming_count += 1;

    dispatchServerPayload(ctx, msg);

    return .{ .sig = .valid, .status = .accepted };
}

/// Track an overheard packet_request packet from another station for NAK
/// suppression. Operates on the raw packet (not a session Message): the
/// request's own group id names the group being requested.
fn trackOverheardNak(ctx: *AppContext, im: *const transport.IncomingMessage) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .packet_request, im.frame_payload[0..im.frame_payload_len]) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const req = decoded.?.packet_request;
    const now = nowMs(ctx);
    for (req.packet_numbers) |pn| {
        for (&ctx.inbox.overheard_naks) |*on| {
            if (on.active and on.group_id == im.group_id and on.packet_number == pn) {
                on.timestamp = now;
                break;
            }
        } else {
            for (&ctx.inbox.overheard_naks) |*on| {
                if (!on.active) {
                    on.active = true;
                    on.group_id = im.group_id;
                    on.packet_number = pn;
                    on.timestamp = now;
                    break;
                }
            }
        }
    }
}

fn nowMs(ctx: *AppContext) u64 {
    const secs = std.Io.Timestamp.now(ctx.io, .real).toSeconds();
    return @intCast(@max(0, secs) * 1000);
}

// ---------------------------------------------------------------------------
// Server-payload dispatch (decoded in-file). Mirrors the server handlers:
// the inbox is the sole client-side consumer of the wire codec.
// ---------------------------------------------------------------------------

/// Dispatch a verified server payload to the appropriate store/handler based
/// on message type. Called after signature verification succeeds. Handles
/// every server-to-client type, regardless of whether it arrived as a single
/// packet or was reassembled from multipart packets.
fn dispatchServerPayload(ctx: *AppContext, msg: messaging.Message) void {
    const payload = msg.payloadSlice();
    switch (msg.msg_type) {
        .bulletin_list => populateBulletins(ctx, payload),
        .bulletin => storeBulletin(ctx, payload),
        .bulletin_response => storeBulletinResponse(ctx, payload),
        .bulletin_response_list => storeBulletinResponseList(ctx, payload),
        .registration_ack => handleRegistrationAck(ctx, payload),
        .user_info => storeUserInfo(ctx, payload),
        .user_info_list => storeUserInfoList(ctx, payload),
        .motd => handleMotd(ctx, payload),
        .request_status => handleRequestStatus(ctx, msg),
        .chat => storeChat(ctx, payload),
        .public_key => {
            if (msg.has_callsign and msg.has_public_key) {
                identity_mod.storePublicKey(ctx, msg.callsignSlice(), msg.public_key);
            }
        },
        else => {},
    }
}

fn populateBulletins(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .bulletin_list, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const bl = decoded.?.bulletin_list;
    ctx.bulletins_page = bl.page;
    ctx.bulletins_total_pages = bl.total_pages;

    if (bl.bulletins.len == 0) return;

    var missing_users: std.ArrayList(u16) = .empty;
    defer missing_users.deinit(allocator);

    var min_missing_id: ?u32 = null;
    var max_id: u32 = 0;

    for (bl.bulletins) |s| {
        if (ctx.store.getUserById(s.user_id)) |user| {
            var mut_user = user;
            mut_user.deinit(ctx.store.allocator);
        } else {
            var found = false;
            for (missing_users.items) |mu| {
                if (mu == s.user_id) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                missing_users.append(allocator, s.user_id) catch {};
            }
        }

        var need_request = true;
        if (ctx.store.getById(s.id)) |rec| {
            var mut_rec = rec;
            defer mut_rec.deinit(ctx.store.allocator);
            if (mut_rec.body.len > 0) {
                need_request = false;
            }
        } else {
            _ = ctx.store.addWithId(s.id, s.user_id, 0, s.title, &.{}) catch {};
        }

        if (need_request) {
            if (min_missing_id == null or s.id < min_missing_id.?) {
                min_missing_id = s.id;
            }
        }
        if (s.id > max_id) max_id = s.id;
    }

    if (missing_users.items.len > 0) {
        outbox.sendUserInfoRequest(ctx, missing_users.items);
    }

    if (min_missing_id) |start_id| {
        outbox.sendBulletinRequestRange(ctx, start_id, max_id);
    }
}

fn storeBulletin(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .bulletin, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const b = decoded.?.bulletin;

    if (ctx.store.getById(b.id)) |rec| {
        var mut_rec = rec;
        defer mut_rec.deinit(ctx.store.allocator);
        if (mut_rec.body.len > 0) return;
    }

    _ = ctx.store.addWithId(b.id, b.user_id, b.created_at, b.title, b.body) catch return;

    if (ctx.store.getUserById(b.user_id)) |user| {
        var mut_user = user;
        mut_user.deinit(ctx.store.allocator);
    } else {
        const ids = [_]u16{b.user_id};
        outbox.sendUserInfoRequest(ctx, &ids);
    }
}

fn storeBulletinResponse(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .bulletin_response, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const r = decoded.?.bulletin_response;
    ctx.store.addResponseWithId(r.bulletin_id, r.response_id, r.user_id, r.create_datetime, r.body) catch return;

    if (ctx.store.getUserById(r.user_id)) |user| {
        var mut_user = user;
        mut_user.deinit(ctx.store.allocator);
    } else {
        const ids = [_]u16{r.user_id};
        outbox.sendUserInfoRequest(ctx, &ids);
    }
}

fn storeBulletinResponseList(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .bulletin_response_list, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const rl = decoded.?.bulletin_response_list;

    var missing_users: std.ArrayList(u16) = .empty;
    defer missing_users.deinit(allocator);

    for (rl.responses) |r| {
        ctx.store.addResponseWithId(r.bulletin_id, r.response_id, r.user_id, r.create_datetime, r.body) catch continue;

        if (ctx.store.getUserById(r.user_id)) |user| {
            var mut_user = user;
            mut_user.deinit(ctx.store.allocator);
        } else {
            var found = false;
            for (missing_users.items) |mu| {
                if (mu == r.user_id) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                missing_users.append(allocator, r.user_id) catch {};
            }
        }
    }

    if (missing_users.items.len > 0) {
        outbox.sendUserInfoRequest(ctx, missing_users.items);
    }
}

fn handleRegistrationAck(ctx: *AppContext, payload: []const u8) void {
    const decoded = message_frame.decodePayload(std.heap.page_allocator, .registration_ack, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(std.heap.page_allocator, decoded.?);

    const ack = decoded.?.registration_ack;
    if (ack.ok) {
        ctx.identity.my_user_id = ack.user_id;
        ctx.store.setMyUserId(ack.user_id) catch {};
        // A successful registration means the key was derived from the UI
        // and is now the working signing key, so mark it as restored.
        ctx.identity.key_restored_from_store = true;
        // Stop any auto-register attempt — we're registered now.
        ctx.identity.auto_register = false;
        if (ctx.identity.key_from_ui and ctx.identity.remember_credentials) {
            if (ctx.identity.keypair) |kp| ctx.store.setSecretKey(kp.secretKeyBytes()) catch {};
        }
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Registered as user #{d}.", .{ack.user_id}) catch "Registered.";
        // Ask the model to navigate to the Account screen on the next tick.
        ctx.pending_account_navigation = true;
    } else {
        // Surface the rejection as a status popup (consistent with the
        // key-request timeout error) so the user gets a clear modal.
        var ps = app.PendingStatus{ .outcome = .failure };
        const msg = "Registration rejected by server.";
        const n = @min(msg.len, ps.detail.len);
        @memcpy(ps.detail[0..n], msg[0..n]);
        ps.detail_len = @intCast(n);
        ctx.pending_status = ps;
        ctx.status = "Registration rejected by server.";
    }
}

fn storeUserInfo(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .user_info, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const ui = decoded.?.user_info;
    ctx.store.upsertUserWithId(ui.id, ui.handle, ui.callsign, ui.public_key, ui.registered_datetime, ui.is_sysop, ui.avatar) catch return;

    if (ctx.identity.my_user_id != null and ctx.identity.my_user_id.? == ui.id) {
        ctx.identity.my_is_sysop = ui.is_sysop;
    }

    ctx.store.upsertKnownKey(ui.callsign, ui.public_key) catch {};
}

/// Decode a batched `user_info_list` and upsert every entry, mirroring
/// `storeUserInfo` per user. The server sends this in reply to a
/// `user_info_request` (one message for N users instead of N messages).
fn storeUserInfoList(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .user_info_list, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const list = decoded.?.user_info_list;
    for (list.users) |ui| {
        ctx.store.upsertUserWithId(ui.id, ui.handle, ui.callsign, ui.public_key, ui.registered_datetime, ui.is_sysop, ui.avatar) catch continue;
        if (ctx.identity.my_user_id != null and ctx.identity.my_user_id.? == ui.id) {
            ctx.identity.my_is_sysop = ui.is_sysop;
        }
        ctx.store.upsertKnownKey(ui.callsign, ui.public_key) catch {};
    }
}

fn handleMotd(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .motd, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const m = decoded.?.motd;
    if (ctx.motd_text) |old| allocator.free(@constCast(old));
    ctx.motd_text = allocator.dupe(u8, m.text) catch return;
    ctx.store.setMotd(m.text) catch {};
}

fn handleRequestStatus(ctx: *AppContext, msg: messaging.Message) void {
    // `request_status` is always sent directed to a specific callsign. Only
    // show the popup when the destination matches this client's callsign, so
    // overheard status messages addressed to other stations are ignored.
    if (msg.has_dest_callsign) {
        const my_callsign = ctx.connection.conn.core.callsign[0..ctx.connection.conn.core.callsign_len];
        if (!std.ascii.eqlIgnoreCase(my_callsign, msg.destCallsignSlice())) return;
    }

    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .request_status, msg.payloadSlice()) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const rs = decoded.?.request_status;
    var ps = app.PendingStatus{ .outcome = rs.outcome };
    const n = @min(rs.detail.len, ps.detail.len);
    @memcpy(ps.detail[0..n], rs.detail[0..n]);
    ps.detail_len = @intCast(n);
    ctx.pending_status = ps;
}

/// Cache a chat message received from the BBS (signed by the server). The
/// server stamps the `timestamp` (epoch time of receipt) and fills in the
/// `user_id` (looked up from the AX.25 callsign of the original sender). The
/// client stores the message in its local `chat_messages` table so the chat
/// window can be assembled and sorted by `timestamp`, and adds it to the
/// in-memory chat log ring buffer for immediate display.
fn storeChat(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .chat, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const c = decoded.?.chat;

    // Cache the chat in the local sqlite so the chat window can be rebuilt on
    // restart and sorted by epoch time.
    ctx.store.addChatMessage(c.timestamp, c.user_id, c.text) catch {};

    // Show the author's handle if the user is cached, otherwise "User {id}".
    // If the author's user info isn't cached, request it from the server so
    // the handle appears on the next message.
    var display_buf: [types.chat_author_len]u8 = undefined;
    const author = logs.formatAuthorDisplayName(ctx, c.user_id, &display_buf);
    if (!author.known and c.user_id != 0) {
        const ids = [_]u16{c.user_id};
        outbox.sendUserInfoRequest(ctx, &ids);
    }

    logs.addChatEntry(ctx, .recv, author.name, c.text, .valid, c.timestamp);
}

