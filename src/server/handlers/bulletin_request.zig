//! Handler for `bulletin_request` — queries bulletins (by tail-after or id
//! range) from the store and broadcasts each as an individual `bulletin`
//! frame so all listening clients can cache it.

const std = @import("std");

const kiss = @import("bbs");
const protocol = kiss.protocol;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(
    ctx: *const ServerCtx,
    meta: RequestMeta,
    mode: protocol.BulletinRequestMode,
    after_id: u32,
    start_id: u32,
    end_id: u32,
) !void {
    try ctx.stderr.print("RX bulletin_request from {s}\n", .{meta.callsign});
    try ctx.stderr.print("  mode={s}\n", .{@tagName(mode)});

    // Query the appropriate bulletins from the store.
    const bulletins = switch (mode) {
        .tail_after => ctx.store.listBulletinsAfter(after_id) catch {
            try ctx.stderr.writeAll("  error: failed to query bulletins (tail_after)\n");
            try ctx.stderr.flush();
            return;
        },
        .range => ctx.store.listBulletinsRange(start_id, end_id) catch {
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
        outbox.sendBulletin(ctx, meta.port, r.id, r.user_id, r.created_at, r.title, r.body, .broadcast_source) catch {
            try ctx.stderr.writeAll("  error: failed to send bulletin\n");
            try ctx.stderr.flush();
            continue;
        };
    }

    try ctx.stderr.print("  TX {d} bulletin(s)\n", .{bulletins.len});
    try ctx.stderr.flush();
}
