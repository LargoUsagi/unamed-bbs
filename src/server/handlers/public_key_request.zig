//! Handler for `public_key_request` — broadcasts the server's public key.

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
    try ctx.stderr.print("RX public_key_request from {s}\n", .{callsign});

    if (ctx.kp == null) {
        try ctx.stderr.writeAll("  ignoring: server has no signing key\n");
        try ctx.stderr.flush();
        return;
    }
    const k = ctx.kp.?;

    const pk_payload: message_frame.Payload = .{
        .public_key = .{ .role = .server, .public_key = k.publicKeyBytes() },
    };

    // Broadcast to CQ so anyone listening can learn the server key.
    // The outbox handles encoding, signing, and routing.
    outbox.send(ctx, msg.port, pk_payload, .public_key, .broadcast_source) catch |err| {
        try ctx.stderr.print("  error: failed to broadcast public_key: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        return;
    };

    try ctx.stderr.writeAll("  TX public_key (server role) broadcast\n");
    try ctx.stderr.flush();
}
