//! Handler for `bulletin_list_request` — returns a single page of bulletin
//! summaries (id, title) to the requester as a `bulletin_list` frame.

const std = @import("std");

const kiss = @import("bbs");

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta, page: u16, page_size: u8) !void {
    try ctx.stderr.print("RX bulletin_list_request from {s}\n", .{meta.callsign});
    try ctx.stderr.print("  page={d} page_size={d}\n", .{ page, page_size });

    // Build the response. The store returns store-native `BulletinSummary`
    // records; the outbox maps them to the wire type (titles are borrowed
    // from the store records and stay alive until the encode completes).
    const summaries = ctx.store.listPage(page, page_size) catch {
        try ctx.stderr.writeAll("  error: failed to build page\n");
        try ctx.stderr.flush();
        return;
    };
    defer {
        for (summaries) |s| ctx.store.allocator.free(s.title);
        ctx.store.allocator.free(summaries);
    }

    const total_pages = ctx.store.totalPages(page_size);

    try outbox.sendBulletinList(ctx, meta.port, page, total_pages, summaries, .broadcast_source);

    try ctx.stderr.print("  TX bulletin_list: {d} entries, page {d}/{d}\n", .{
        summaries.len, page, total_pages,
    });
    try ctx.stderr.flush();
}
