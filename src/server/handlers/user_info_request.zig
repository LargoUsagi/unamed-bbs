//! Handler for `user_info_request` — broadcasts `user_info` frames for each
//! requested user id to CQ so all listening clients can cache them.

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
    const payload_bytes = im.frame_payload[0..im.frame_payload_len];
    const allocator = std.heap.page_allocator;

    try ctx.stderr.print("RX user_info_request from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .user_info_request, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode user_info_request\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed user_info_request\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const req = decoded.?.user_info_request;
    try ctx.stderr.print("  requesting {d} user(s)\n", .{req.user_ids.len});

    for (req.user_ids) |uid| {
        outbox.broadcastUserInfo(ctx, im.port, uid, .broadcast_source) catch {
            try ctx.stderr.print("  error: failed to broadcast user_info for id={d}\n", .{uid});
            try ctx.stderr.flush();
        };
    }

    try ctx.stderr.print("  TX {d} user_info(s)\n", .{req.user_ids.len});
    try ctx.stderr.flush();
}
