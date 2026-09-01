//! Handler for `bulletin_response` — stores a response to an existing
//! bulletin submitted by a registered user. Verifies the signature against
//! the user's stored key, assigns the next response id, stamps the server's
//! time, persists the store, and broadcasts the stored response.

const std = @import("std");

const kiss = @import("bbs");
const protocol = kiss.protocol;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta, bulletin_id: u32, body: []const u8) !void {
    try ctx.stderr.print("RX bulletin_response from {s}\n", .{meta.callsign});

    if (body.len > protocol.max_body_len) {
        try ctx.stderr.writeAll("  error: response body exceeds limit\n");
        try ctx.stderr.flush();
        return;
    }

    // Identify the sender by their signing key — try to verify the
    // signature against every registered user's public key. This is
    // correct even when multiple users share a callsign (e.g. "NOCALL").
    if (!meta.signed) {
        try ctx.stderr.writeAll("  error: response not signed (rejected)\n");
        try ctx.stderr.flush();
        return;
    }
    var user = ctx.store.findUserBySignature(meta.signature, meta.payload_bytes) orelse {
        try ctx.stderr.writeAll("  error: response signature does not match any registered user\n");
        try ctx.stderr.flush();
        return;
    };
    defer user.deinit(ctx.store.allocator);

    // Verify the referenced bulletin actually exists.
    if (ctx.store.getById(bulletin_id) == null) {
        try ctx.stderr.print("  error: bulletin id={d} not found\n", .{bulletin_id});
        try ctx.stderr.flush();
        return;
    }

    // Assign the next response id (the client's `response_id` field
    // is ignored and overwritten). If the bulletin is full (1024
    // responses), reject.
    const next_id = ctx.store.nextResponseId(bulletin_id) orelse {
        try ctx.stderr.print("  error: bulletin id={d} is full (1024 responses)\n", .{bulletin_id});
        try ctx.stderr.flush();
        return;
    };

    // Use the server's current time as the authoritative creation
    // timestamp for the response.
    const now_secs: u64 = kiss.time.nowSecs(ctx.io);

    ctx.store.addResponseWithId(bulletin_id, next_id, user.id, now_secs, body) catch |err| {
        try ctx.stderr.print("  error: failed to store response: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        return;
    };

    ctx.store.save(ctx.io, ctx.store_path) catch |err| {
        try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
    };

    try ctx.stderr.print("  stored: bulletin={d} response_id={d} user={d} body={d}B total={d}\n", .{
        bulletin_id,                           next_id, user.id, body.len,
        ctx.store.countResponses(bulletin_id),
    });
    try ctx.stderr.flush();

    // Broadcast the stored response (with the canonical response_id,
    // user_id, and server-set create_datetime) so anyone listening can
    // cache it.
    outbox.sendBulletinResponse(ctx, meta.port, bulletin_id, next_id, user.id, now_secs, body, .broadcast_all) catch {
        try ctx.stderr.writeAll("  error: failed to broadcast response\n");
        try ctx.stderr.flush();
        return;
    };

    try ctx.stderr.print("  TX broadcast bulletin_response bulletin={d} id={d}\n", .{ bulletin_id, next_id });
    try ctx.stderr.flush();
}
