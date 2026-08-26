//! Send-side helpers for the bulletin server. Encodes payloads, signs them
//! with the server key (delegated to the shared `bbs.messaging`
//! `preparePayload` core), and routes them through the `TransportPool` based
//! on a `Route` decision (all-radios/all-clients, single-radio/all-clients,
//! or single-radio/single-client).

const std = @import("std");
const Io = std.Io;

const kiss = @import("bbs");
const message_frame = kiss.message_frame;

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
pub fn send(
    ctx: *const ServerCtx,
    port: u4,
    payload: message_frame.Payload,
    msg_type: message_frame.MessageType,
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

    try send(ctx, port, ui_payload, .user_info, route);

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

    const bl_payload: message_frame.Payload = .{ .bulletin_list = .{
        .page = page,
        .total_pages = total_pages,
        .bulletins = summaries,
    } };

    try send(ctx, 0, bl_payload, .bulletin_list, route);

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
    const status_payload: message_frame.Payload = .{ .request_status = .{
        .request_id = 0,
        .outcome = .failure,
        .detail = detail,
    } };
    try send(ctx, port, status_payload, .request_status, Route.directed(callsign));
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
