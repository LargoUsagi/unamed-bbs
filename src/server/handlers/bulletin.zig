//! Handler for `bulletin` — stores a new bulletin submitted by a registered
//! user. Verifies the signature against the user's stored key, stamps the
//! server's current time, persists the store, and broadcasts the stored
//! bulletin to all clients.

const std = @import("std");

const kiss = @import("bbs");
const messaging = kiss.messaging;
const transport = kiss.transport;
const message_frame = kiss.message_frame;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, msg: messaging.Message) !void {
    const callsign = msg.callsignSlice();
    const payload_bytes = msg.payloadSlice();
    const allocator = std.heap.page_allocator;

    try ctx.stderr.print("RX bulletin from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .bulletin, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode bulletin\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed bulletin\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const bul = decoded.?.bulletin;

    if (bul.title.len > message_frame.max_title_len or bul.body.len > message_frame.max_body_len) {
        try ctx.stderr.writeAll("  error: bulletin title or body exceeds limit\n");
        try ctx.stderr.flush();
        return;
    }

    // Identify the sender by their signing key — try to verify the
    // signature against every registered user's public key. This is
    // correct even when multiple users share a callsign (e.g. "NOCALL").
    if (!msg.signed) {
        try ctx.stderr.writeAll("  signature: none (rejected)\n");
        try ctx.stderr.flush();
        return;
    }
    var user = ctx.store.findUserBySignature(msg.signature, payload_bytes) orelse {
        try ctx.stderr.writeAll("  signature: INVALID (no matching registered user)\n");
        try ctx.stderr.flush();
        return;
    };
    defer user.deinit(ctx.store.allocator);
    try ctx.stderr.writeAll("  signature: verified\n");

    // Use the server's current time as the authoritative creation
    // timestamp — the client's value is ignored.
    const now_secs: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));

    const id = ctx.store.add(user.id, now_secs, bul.title, bul.body) catch |err| {
        try ctx.stderr.print("  error: failed to store bulletin: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        return;
    };

    ctx.store.save(ctx.io, ctx.store_path) catch |err| {
        try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
    };

    try ctx.stderr.print("  stored: id={d} title=\"{s}\" body={d}B created_at={d} total={d}\n", .{
        id, bul.title, bul.body.len, now_secs, ctx.store.count(),
    });
    try ctx.stderr.flush();

    // Broadcast the newly stored bulletin so clients can cache it
    // immediately. Use the canonical user id and server-set time.
    const bul_payload: message_frame.Payload = .{ .bulletin = .{
        .id = id,
        .user_id = user.id,
        .created_at = now_secs,
        .title = bul.title,
        .body = bul.body,
    } };

    outbox.send(ctx, msg.port, bul_payload, .bulletin, .broadcast_all) catch {
        try ctx.stderr.writeAll("  error: failed to broadcast new bulletin\n");
        try ctx.stderr.flush();
        return;
    };

    try ctx.stderr.print("  TX broadcast bulletin id={d}\n", .{id});
    try ctx.stderr.flush();
}
