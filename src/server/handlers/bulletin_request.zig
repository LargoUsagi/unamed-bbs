//! Handler for `bulletin_request` — queries bulletins (by tail-after or id
//! range) from the store and broadcasts each as an individual `bulletin`
//! frame so all listening clients can cache it.

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

    try ctx.stderr.print("RX bulletin_request from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .bulletin_request, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode bulletin_request\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed bulletin_request\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const req = decoded.?.bulletin_request;
    try ctx.stderr.print("  mode={s}\n", .{@tagName(req.mode)});

    // Query the appropriate bulletins from the store.
    const bulletins = switch (req.mode) {
        .tail_after => ctx.store.listBulletinsAfter(req.after_id) catch {
            try ctx.stderr.writeAll("  error: failed to query bulletins (tail_after)\n");
            try ctx.stderr.flush();
            return;
        },
        .range => ctx.store.listBulletinsRange(req.start_id, req.end_id) catch {
            try ctx.stderr.writeAll("  error: failed to query bulletins (range)\n");
            try ctx.stderr.flush();
            return;
        },
    };
    defer ctx.store.freeBulletinRecordList(bulletins);

    try ctx.stderr.print("  broadcasting {d} bulletin(s)\n", .{bulletins.len});
    try ctx.stderr.flush();

    // Broadcast each bulletin as an individual `bulletin` frame so any
    // client listening can cache it.
    for (bulletins) |r| {
        const bul_payload: message_frame.Payload = .{ .bulletin = .{
            .id = r.id,
            .user_id = r.user_id,
            .created_at = r.created_at,
            .title = r.title,
            .body = r.body,
        } };
        outbox.send(ctx, im.port, bul_payload, .bulletin, .broadcast_source) catch {
            try ctx.stderr.writeAll("  error: failed to send bulletin\n");
            try ctx.stderr.flush();
            continue;
        };
    }

    try ctx.stderr.print("  TX {d} bulletin(s)\n", .{bulletins.len});
    try ctx.stderr.flush();
}
