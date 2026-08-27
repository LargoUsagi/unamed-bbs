//! Handler for `bulletin_response_request` — queries responses for a
//! bulletin (by tail-after or id range) and broadcasts each as an individual
//! `bulletin_response` frame. If no responses exist, sends a directed
//! `request_status no_data` to the requester.

const std = @import("std");

const kiss = @import("bbs");
const protocol = kiss.protocol;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");
const routing = @import("../routing.zig");

pub fn handle(
    ctx: *const ServerCtx,
    meta: RequestMeta,
    bulletin_id: u32,
    mode: protocol.ResponseRequestMode,
    after_id: u16,
    start_id: u16,
    end_id: u16,
) !void {
    try ctx.stderr.print("RX bulletin_response_request from {s}\n", .{meta.callsign});
    try ctx.stderr.print("  bulletin={d} mode={s}\n", .{ bulletin_id, @tagName(mode) });

    // Query the appropriate responses from the store.
    const responses = switch (mode) {
        .tail_after => ctx.store.listResponsesAfter(bulletin_id, after_id) catch {
            try ctx.stderr.writeAll("  error: failed to query responses (tail_after)\n");
            try ctx.stderr.flush();
            return;
        },
        .range => ctx.store.listResponsesRange(bulletin_id, start_id, end_id) catch {
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
        try ctx.stderr.print("  no responses — sending request_status no_data to {s}\n", .{meta.callsign});
        try ctx.stderr.flush();

        var detail_buf: [128]u8 = undefined;
        const detail = std.fmt.bufPrint(&detail_buf, "No responses found for bulletin {d}.", .{bulletin_id}) catch "";
        outbox.sendRequestStatus(ctx, meta.port, 0, .no_data, detail, routing.Route.directed(meta.callsign)) catch {};
        return;
    }

    try ctx.stderr.print("  broadcasting {d} response(s)\n", .{responses.len});
    try ctx.stderr.flush();

    // Broadcast each missing response as an individual
    // `bulletin_response` frame so any client listening can cache it.
    for (responses) |r| {
        outbox.sendBulletinResponse(ctx, meta.port, r.bulletin_id, r.response_id, r.user_id, r.create_datetime, r.body, .broadcast_source) catch {
            try ctx.stderr.writeAll("  error: failed to send response\n");
            try ctx.stderr.flush();
            continue;
        };
    }

    try ctx.stderr.print("  TX {d} bulletin_response(s) for bulletin={d}\n", .{ responses.len, bulletin_id });
    try ctx.stderr.flush();
}
