//! Handler for `motd` — sets the message-of-the-day. Only a signed message
//! from a registered sysop is accepted. Updates the in-memory MOTD state,
//! persists it to the store, and broadcasts the new MOTD signed by the server.

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

    try ctx.stderr.print("RX motd from {s}\n", .{callsign});
    try ctx.stderr.flush();

    // Only a signed message from a registered sysop can set the MOTD.
    // The sender is identified by their signing key, not by callsign.
    if (!msg.signed) {
        try ctx.stderr.writeAll("  ignoring: unsigned motd\n");
        try ctx.stderr.flush();
        return;
    }
    var user = ctx.store.findUserBySignature(msg.signature, payload_bytes) orelse {
        try ctx.stderr.writeAll("  ignoring: signature does not match any registered user\n");
        try ctx.stderr.flush();
        return;
    };
    defer user.deinit(ctx.store.allocator);
    if (!user.is_sysop) {
        try ctx.stderr.writeAll("  ignoring: user is not a sysop\n");
        try ctx.stderr.flush();
        return;
    }

    // Decode the MOTD payload.
    const decoded = message_frame.decodePayload(allocator, .motd, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: malformed motd\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed motd\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const new_motd = decoded.?.motd.text;

    if (new_motd.len > message_frame.max_body_len) {
        try ctx.stderr.writeAll("  error: MOTD text exceeds limit\n");
        try ctx.stderr.flush();
        return;
    }

    try ctx.stderr.print("  sysop set new MOTD: \"{s}\"\n", .{new_motd});
    try ctx.stderr.flush();

    // Persist the new MOTD in the server's mutable state so subsequent
    // motd_request handlers return the updated text. The decoded
    // payload is about to be freed, so dup the string.
    const motd_copy = allocator.dupe(u8, new_motd) catch {
        try ctx.stderr.writeAll("  error: out of memory storing MOTD\n");
        try ctx.stderr.flush();
        return;
    };
    ctx.motd_text.* = motd_copy;

    // Persist the new MOTD to the database so it survives restarts.
    ctx.store.setMotd(motd_copy) catch {
        try ctx.stderr.writeAll("  warning: failed to persist MOTD to database\n");
        try ctx.stderr.flush();
    };

    // Broadcast the new MOTD to all stations (signed by the server).
    const motd_payload: message_frame.Payload = .{ .motd = .{ .text = motd_copy } };
    try outbox.send(ctx, msg.port, motd_payload, .motd, .broadcast_all);

    try ctx.stderr.writeAll("  TX motd broadcast\n");
    try ctx.stderr.flush();
}
