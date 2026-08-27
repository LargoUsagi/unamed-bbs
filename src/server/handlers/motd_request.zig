//! Handler for `motd_request` — returns the current message-of-the-day text
//! to the requester as a `motd` frame.

const std = @import("std");

const kiss = @import("bbs");

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta) !void {
    try ctx.stderr.print("RX motd_request from {s}\n", .{meta.callsign});
    try ctx.stderr.flush();

    const cur = ctx.motd_text.*;
    try outbox.sendMotd(ctx, meta.port, cur, .broadcast_source);

    try ctx.stderr.print("  TX motd ({d} bytes)\n", .{cur.len});
    try ctx.stderr.flush();
}
