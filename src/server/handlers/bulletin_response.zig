//! Handler for `bulletin_response` — stores a response to an existing
//! bulletin submitted by a registered user. Verifies the signature against
//! the user's stored key, assigns the next response id, stamps the server's
//! time, persists the store, and broadcasts the stored response.

const std = @import("std");

const kiss = @import("bbs");
const transport = kiss.transport;
const message_frame = kiss.message_frame;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, im: transport.IncomingMessage) !void {
    const callsign = im.callsign[0..@min(im.callsign_str_len, message_frame.callsign_len)];
    const payload_bytes = im.frame_payload[0..im.frame_payload_len];
    const allocator = std.heap.page_allocator;

    try ctx.stderr.print("RX bulletin_response from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .bulletin_response, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode bulletin_response\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed bulletin_response\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const resp = decoded.?.bulletin_response;

    // Identify the sender by their signing key — try to verify the
    // signature against every registered user's public key. This is
    // correct even when multiple users share a callsign (e.g. "NOCALL").
    if (!im.signed) {
        try ctx.stderr.writeAll("  error: response not signed (rejected)\n");
        try ctx.stderr.flush();
        return;
    }
    var user = ctx.store.findUserBySignature(im.signature, payload_bytes) orelse {
        try ctx.stderr.writeAll("  error: response signature does not match any registered user\n");
        try ctx.stderr.flush();
        return;
    };
    defer user.deinit(ctx.store.allocator);

    // Verify the referenced bulletin actually exists.
    if (ctx.store.getById(resp.bulletin_id) == null) {
        try ctx.stderr.print("  error: bulletin id={d} not found\n", .{resp.bulletin_id});
        try ctx.stderr.flush();
        return;
    }

    // Assign the next response id (the client's `response_id` field
    // is ignored and overwritten). If the bulletin is full (1024
    // responses), reject.
    const next_id = ctx.store.nextResponseId(resp.bulletin_id) orelse {
        try ctx.stderr.print("  error: bulletin id={d} is full (1024 responses)\n", .{resp.bulletin_id});
        try ctx.stderr.flush();
        return;
    };

    // Use the server's current time as the authoritative creation
    // timestamp for the response.
    const now_secs: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));

    ctx.store.addResponseWithId(resp.bulletin_id, next_id, user.id, now_secs, resp.body) catch |err| {
        try ctx.stderr.print("  error: failed to store response: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        return;
    };

    ctx.store.save(ctx.io, ctx.store_path) catch |err| {
        try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
    };

    try ctx.stderr.print("  stored: bulletin={d} response_id={d} user={d} body={d}B total={d}\n", .{
        resp.bulletin_id,                           next_id, user.id, resp.body.len,
        ctx.store.countResponses(resp.bulletin_id),
    });
    try ctx.stderr.flush();

    // Broadcast the stored response (with the canonical response_id,
    // user_id, and server-set create_datetime) so anyone listening can
    // cache it.
    const out_payload: message_frame.Payload = .{ .bulletin_response = .{
        .bulletin_id = resp.bulletin_id,
        .response_id = next_id,
        .user_id = user.id,
        .create_datetime = now_secs,
        .body = resp.body,
    } };

    outbox.send(ctx, im.port, out_payload, .bulletin_response, .broadcast_all) catch {
        try ctx.stderr.writeAll("  error: failed to broadcast response\n");
        try ctx.stderr.flush();
        return;
    };

    try ctx.stderr.print("  TX broadcast bulletin_response bulletin={d} id={d}\n", .{ resp.bulletin_id, next_id });
    try ctx.stderr.flush();
}
