//! Handler for `bulletin_list_request` — returns a single page of bulletin
//! summaries (id, title) to the requester as a `bulletin_list` frame.

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

    try ctx.stderr.print("RX bulletin_list_request from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .bulletin_list_request, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode bulletin_list_request\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed bulletin_list_request\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const req = decoded.?.bulletin_list_request;
    try ctx.stderr.print("  page={d} page_size={d}\n", .{ req.page, req.page_size });

    // Build the response.
    const summaries = ctx.store.listPage(req.page, req.page_size) catch {
        try ctx.stderr.writeAll("  error: failed to build page\n");
        try ctx.stderr.flush();
        return;
    };
    defer {
        for (summaries) |s| ctx.store.allocator.free(s.title);
        ctx.store.allocator.free(summaries);
    }

    const total_pages = ctx.store.totalPages(req.page_size);
    const bl_payload: message_frame.Payload = .{ .bulletin_list = .{
        .page = req.page,
        .total_pages = total_pages,
        .bulletins = summaries,
    } };

    try outbox.send(ctx, im.port, bl_payload, .bulletin_list, .broadcast_source);

    try ctx.stderr.print("  TX bulletin_list: {d} entries, page {d}/{d}\n", .{
        summaries.len, req.page, total_pages,
    });
    try ctx.stderr.flush();
}
