//! Send-side helpers for the bulletin server. The sole server-side consumer
//! of the wire codec (`transport.message_frame`): each typed `sendX` takes
//! store records or plain fields, builds the wire `Payload` here, and routes
//! it through the `TransportPool` via the shared `bbs.messaging` tx core.
//!
//! Handlers and other server modules call only the typed `sendX` functions;
//! they never touch `message_frame` / `Payload` directly. This keeps the wire
//! protocol confined to the inbox (decode) and outbox (encode) boundary.

const std = @import("std");
const Io = std.Io;

const kiss = @import("bbs");
const message_frame = kiss.transport.message_frame;
const store = kiss.store;
const protocol = kiss.protocol;

const bulletin_store = @import("bulletin_store.zig");
const context = @import("context.zig");
const routing = @import("routing.zig");

const ServerCtx = context.ServerCtx;
const Route = routing.Route;

/// Encode a `Payload`, sign it (if the server has a key), and transmit it
/// through the transport pool according to `route`. The pool fills the
/// targets (`fillTargets`) and the shared `txSend` loop transmits. Encode /
/// sign failures are logged to stderr; per-target wire failures are
/// intentionally silent — one dead transport must not abort a fan-out.
fn sendPayload(
    ctx: *const ServerCtx,
    port: u4,
    payload: message_frame.Payload,
    msg_type: protocol.MessageType,
    route: Route,
) !void {
    var targets: [kiss.messaging.max_tx_targets]kiss.messaging.TxTarget = undefined;
    const n = ctx.pool.fillTargets(route, ctx.source_transport_id, port, .{}, &targets);

    _ = kiss.messaging.txSend(msg_type, payload, ctx.kp, targets[0..n]) catch |err| {
        switch (err) {
            error.EncodeFailed => try ctx.stderr.writeAll("  error: failed to encode payload\n"),
            error.SignFailed => try ctx.stderr.writeAll("  error: signing failed\n"),
        }
        try ctx.stderr.flush();
        return;
    };
}

// ---------------------------------------------------------------------------
// Typed send helpers — one per outbound message type. Handlers pass store
// records / primitives; the wire `Payload` is constructed here.
// ---------------------------------------------------------------------------

/// Broadcast a stored bulletin (with the canonical server-set id/time) so all
/// clients can cache it.
pub fn sendBulletin(
    ctx: *const ServerCtx,
    port: u4,
    id: u32,
    user_id: u16,
    created_at: u64,
    title: []const u8,
    body: []const u8,
    route: Route,
) !void {
    const payload: message_frame.Payload = .{ .bulletin = .{
        .id = id,
        .user_id = user_id,
        .created_at = created_at,
        .title = title,
        .body = body,
    } };
    try sendPayload(ctx, port, payload, .bulletin, route);
}

/// Send a single page of bulletin summaries as a `bulletin_list`. Maps
/// store-native `BulletinSummary` records to the wire type field-by-field
/// (the titles are borrowed from the store records and stay alive until the
/// encode completes inside `sendPayload`).
pub fn sendBulletinList(
    ctx: *const ServerCtx,
    port: u4,
    page: u16,
    total_pages: u16,
    summaries: []const store.BulletinSummary,
    route: Route,
) !void {
    var wire = ctx.store.allocator.alloc(message_frame.BulletinSummary, summaries.len) catch return;
    defer ctx.store.allocator.free(wire);
    for (summaries, 0..) |s, i| {
        wire[i] = .{ .id = s.id, .user_id = s.user_id, .title = s.title };
    }
    const payload: message_frame.Payload = .{ .bulletin_list = .{
        .page = page,
        .total_pages = total_pages,
        .bulletins = wire,
    } };
    try sendPayload(ctx, port, payload, .bulletin_list, route);
}

/// Broadcast a stored bulletin response (with the canonical server-assigned
/// response id, user id, and timestamp) so all clients can cache it.
pub fn sendBulletinResponse(
    ctx: *const ServerCtx,
    port: u4,
    bulletin_id: u32,
    response_id: u16,
    user_id: u16,
    create_datetime: u64,
    body: []const u8,
    route: Route,
) !void {
    const payload: message_frame.Payload = .{ .bulletin_response = .{
        .bulletin_id = bulletin_id,
        .response_id = response_id,
        .user_id = user_id,
        .create_datetime = create_datetime,
        .body = body,
    } };
    try sendPayload(ctx, port, payload, .bulletin_response, route);
}

/// Re-broadcast a stored chat message (signed by the server, with the
/// server-set timestamp and canonical user id) so everyone in range hears it.
pub fn sendChat(
    ctx: *const ServerCtx,
    port: u4,
    timestamp: u64,
    user_id: u16,
    text: []const u8,
    route: Route,
) !void {
    const payload: message_frame.Payload = .{ .chat = .{
        .timestamp = timestamp,
        .user_id = user_id,
        .text = text,
    } };
    try sendPayload(ctx, port, payload, .chat, route);
}

/// Broadcast the message-of-the-day text (signed by the server).
pub fn sendMotd(ctx: *const ServerCtx, port: u4, text: []const u8, route: Route) !void {
    const payload: message_frame.Payload = .{ .motd = .{ .text = text } };
    try sendPayload(ctx, port, payload, .motd, route);
}

/// Broadcast the server's public key (role hardcoded to `.server`) so
/// anyone listening can learn it. Does nothing if the server has no signing
/// key.
pub fn sendPublicKey(ctx: *const ServerCtx, port: u4, route: Route) !void {
    if (ctx.kp == null) {
        try ctx.stderr.writeAll("  ignoring: server has no signing key\n");
        try ctx.stderr.flush();
        return;
    }
    const k = ctx.kp.?;
    const payload: message_frame.Payload = .{
        .public_key = .{ .role = .server, .public_key = k.publicKeyBytes() },
    };
    try sendPayload(ctx, port, payload, .public_key, route);
}

/// Send a directed or broadcast `request_status` reporting the outcome of a
/// specific client request.
pub fn sendRequestStatus(
    ctx: *const ServerCtx,
    port: u4,
    request_id: u16,
    outcome: protocol.RequestOutcome,
    detail: []const u8,
    route: Route,
) !void {
    const payload: message_frame.Payload = .{ .request_status = .{
        .request_id = request_id,
        .outcome = outcome,
        .detail = detail,
    } };
    try sendPayload(ctx, port, payload, .request_status, route);
}

/// Send one batched `user_info_list` carrying every requested user the server
/// knows about, so a request for N users produces one reply instead of N. If
/// the batched list is too large to encode, falls back to per-user
/// `user_info` broadcasts.
pub fn sendUserInfoList(
    ctx: *const ServerCtx,
    port: u4,
    users: []const store.User,
    route: Route,
) !void {
    const allocator = ctx.store.allocator;
    const infos = allocator.alloc(message_frame.UserInfo, users.len) catch return;
    defer allocator.free(infos);
    for (users, 0..) |u, i| {
        infos[i] = .{
            .id = u.id,
            .registered_datetime = u.registered_datetime,
            .handle = u.handle,
            .callsign = u.callsign,
            .public_key = u.public_key,
            .is_sysop = u.is_sysop,
            .avatar = u.avatar,
        };
    }

    // Encode-probe: if the batched list fits, send it as one message;
    // otherwise fall back to per-user user_info broadcasts.
    var check_buf: [message_frame.max_encode_len]u8 = undefined;
    const list = message_frame.UserInfoList{ .users = infos };
    if (list.encode(&check_buf)) |_| {
        try sendPayload(ctx, port, .{ .user_info_list = .{ .users = infos } }, .user_info_list, route);
    } else {
        for (users) |u| {
            try broadcastUserInfo(ctx, port, u.id, route);
        }
    }
}

// ---------------------------------------------------------------------------
// Existing typed helpers (kept as before).
// ---------------------------------------------------------------------------

/// Broadcast a `user_info` message for a given user id. Signs the payload
/// if the server has a key. Does nothing if the user id doesn't exist.
pub fn broadcastUserInfo(
    ctx: *const ServerCtx,
    port: u4,
    user_id: u16,
    route: Route,
) !void {
    var user = ctx.store.getUserById(user_id) orelse {
        try ctx.stderr.print("  user id={d} not found, skipping\n", .{user_id});
        try ctx.stderr.flush();
        return;
    };
    defer user.deinit(ctx.store.allocator);

    const ui_payload: message_frame.Payload = .{ .user_info = .{
        .id = user.id,
        .registered_datetime = user.registered_datetime,
        .handle = user.handle,
        .callsign = user.callsign,
        .public_key = user.public_key,
        .is_sysop = user.is_sysop,
        .avatar = user.avatar,
    } };

    try sendPayload(ctx, port, ui_payload, .user_info, route);

    try ctx.stderr.print("  TX user_info id={d} handle=\"{s}\"\n", .{ user.id, user.handle });
    try ctx.stderr.flush();
}

/// Transmit the first page of bulletins as a heartbeat. The caller picks the
/// route: `Route.onTransport(id)` to beacon one silent beacon-capable radio
/// (the heartbeat loop's use), or `.broadcast_all` for a full fan-out.
pub fn sendHeartbeat(ctx: *const ServerCtx, route: Route) !void {
    const page: u16 = 0;
    const page_size: u8 = 5;

    const summaries = ctx.store.listPage(page, page_size) catch {
        try ctx.stderr.writeAll("  heartbeat: failed to build page\n");
        try ctx.stderr.flush();
        return;
    };
    defer {
        for (summaries) |s| ctx.store.allocator.free(s.title);
        ctx.store.allocator.free(summaries);
    }

    const total_pages = ctx.store.totalPages(page_size);

    try sendBulletinList(ctx, 0, page, total_pages, summaries, route);

    try ctx.stderr.print("  TX heartbeat bulletin_list: {d} entries, page 0/{d}\n", .{ summaries.len, total_pages });
    try ctx.stderr.flush();
}

/// Send a directed `request_status` to the requesting callsign when a chat
/// message is rejected. Always directed (single radio, single client).
pub fn sendChatReject(
    ctx: *const ServerCtx,
    port: u4,
    callsign: []const u8,
    detail: []const u8,
) !void {
    try sendRequestStatus(ctx, port, 0, .failure, detail, Route.directed(callsign));
    try ctx.stderr.print("  TX request_status failure to {s}: {s}\n", .{ callsign, detail });
    try ctx.stderr.flush();
}

/// Send a `registration_ack` back to the registering callsign. Always
/// directed (single radio, single client). Encode / sign failures are logged;
/// wire failures are silent.
pub fn sendRegistrationAck(
    ctx: *const ServerCtx,
    port: u4,
    callsign: []const u8,
    ok: bool,
    user_id: u16,
) !void {
    const ack_payload: message_frame.Payload = .{
        .registration_ack = .{ .ok = ok, .user_id = user_id },
    };

    var targets: [kiss.messaging.max_tx_targets]kiss.messaging.TxTarget = undefined;
    const n = ctx.pool.fillTargets(Route.directed(callsign), ctx.source_transport_id, port, .{}, &targets);

    _ = kiss.messaging.txSend(.registration_ack, ack_payload, ctx.kp, targets[0..n]) catch |err| {
        switch (err) {
            error.EncodeFailed => try ctx.stderr.writeAll("  error: failed to encode registration_ack\n"),
            error.SignFailed => try ctx.stderr.writeAll("  error: signing registration_ack failed\n"),
        }
        try ctx.stderr.flush();
        return;
    };

    if (ok) {
        try ctx.stderr.print("  TX registration_ack ok id={d}\n", .{user_id});
    } else {
        try ctx.stderr.writeAll("  TX registration_ack fail\n");
    }
    try ctx.stderr.flush();
}
