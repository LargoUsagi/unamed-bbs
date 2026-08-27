//! Handler for `public_key_request` — broadcasts the server's public key.

const std = @import("std");

const kiss = @import("bbs");

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta) !void {
    try ctx.stderr.print("RX public_key_request from {s}\n", .{meta.callsign});

    outbox.sendPublicKey(ctx, meta.port, .broadcast_source) catch |err| {
        try ctx.stderr.print("  error: failed to broadcast public_key: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        return;
    };

    try ctx.stderr.writeAll("  TX public_key (server role) broadcast\n");
    try ctx.stderr.flush();
}
