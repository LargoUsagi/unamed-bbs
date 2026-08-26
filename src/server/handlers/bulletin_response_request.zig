//! Handler for `bulletin_response_request` — queries responses for a
//! bulletin (by tail-after or id range) and broadcasts each as an individual
//! `bulletin_response` frame. If no responses exist, sends a directed
//! `request_status no_data` to the requester.

const std = @import("std");

const kiss = @import("bbs");
const messaging = kiss.messaging;
const transport = kiss.transport;
const signing = kiss.signing;
const message_frame = kiss.message_frame;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");
const routing = @import("../routing.zig");

pub fn handle(ctx: *const ServerCtx, msg: messaging.Message) !void {
    const callsign = msg.callsignSlice();
    const payload_bytes = msg.payloadSlice();
    const allocator = std.heap.page_allocator;

    try ctx.stderr.print("RX bulletin_response_request from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .bulletin_response_request, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode bulletin_response_request\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed bulletin_response_request\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const req = decoded.?.bulletin_response_request;
    try ctx.stderr.print("  bulletin={d} mode={s}\n", .{
        req.bulletin_id,
        @tagName(req.mode),
    });

    // Query the appropriate responses from the store.
    const responses = switch (req.mode) {
        .tail_after => ctx.store.listResponsesAfter(req.bulletin_id, req.after_id) catch {
            try ctx.stderr.writeAll("  error: failed to query responses (tail_after)\n");
            try ctx.stderr.flush();
            return;
        },
        .range => ctx.store.listResponsesRange(req.bulletin_id, req.start_id, req.end_id) catch {
            try ctx.stderr.writeAll("  error: failed to query responses (range)\n");
            try ctx.stderr.flush();
            return;
        },
    };
    defer ctx.store.freeResponseList(responses);

    if (responses.len == 0) {
        // No data to return — send a directed RequestStatus to the
        // requesting callsign so the client knows the request was
        // processed but yielded nothing.
        try ctx.stderr.print("  no responses — sending request_status no_data to {s}\n", .{callsign});
        try ctx.stderr.flush();

        var detail_buf: [128]u8 = undefined;
        const detail = std.fmt.bufPrint(&detail_buf, "No responses found for bulletin {d}.", .{req.bulletin_id}) catch "";
        const status_payload: message_frame.Payload = .{ .request_status = .{
            .request_id = 0,
            .outcome = .no_data,
            .detail = detail,
        } };
        outbox.send(ctx, msg.port, status_payload, .request_status, routing.Route.directed(callsign)) catch {};
        return;
    }

    try ctx.stderr.print("  broadcasting {d} response(s)\n", .{responses.len});
    try ctx.stderr.flush();

    // Broadcast each missing response as an individual
    // `bulletin_response` frame so any client listening can cache it.
    for (responses) |r| {
        const out_payload: message_frame.Payload = .{ .bulletin_response = .{
            .bulletin_id = r.bulletin_id,
            .response_id = r.response_id,
            .user_id = r.user_id,
            .create_datetime = r.create_datetime,
            .body = r.body,
        } };
        outbox.send(ctx, msg.port, out_payload, .bulletin_response, .broadcast_source) catch {
            try ctx.stderr.writeAll("  error: failed to send response\n");
            try ctx.stderr.flush();
            continue;
        };
    }

    try ctx.stderr.print("  TX {d} bulletin_response(s) for bulletin={d}\n", .{ responses.len, req.bulletin_id });
    try ctx.stderr.flush();
}
