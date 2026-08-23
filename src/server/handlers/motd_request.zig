//! Handler for `motd_request` — returns the current message-of-the-day text
//! to the requester as a `motd` frame.

const std = @import("std");

const kiss = @import("bbs");
const transport = kiss.transport;
const signing = kiss.signing;
const message_frame = kiss.message_frame;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, im: transport.IncomingMessage) !void {
    const callsign = im.callsign[0..@min(im.callsign_str_len, message_frame.callsign_len)];

    try ctx.stderr.print("RX motd_request from {s}\n", .{callsign});
    try ctx.stderr.flush();

    const cur = ctx.motd_text.*;
    const motd_payload: message_frame.Payload = .{ .motd = .{ .text = cur } };
    try outbox.send(ctx, im.port, motd_payload, .motd, .broadcast_source);

    try ctx.stderr.print("  TX motd ({d} bytes)\n", .{cur.len});
    try ctx.stderr.flush();
}
