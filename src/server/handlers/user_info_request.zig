//! Handler for `user_info_request` — replies with a single batched
//! `user_info_list` carrying every requested user the server knows about, so
//! that a request for N users produces one reply message instead of N. The
//! encode-probe / per-user fallback lives in the outbox; this handler just
//! collects the matching users and hands them over.

const std = @import("std");

const kiss = @import("bbs");
const store = kiss.store;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta, user_ids: []const u16) !void {
    // The store's allocator owns the per-user handle/callsign/avatar slices
    // returned by getUserById, so all lookup allocations and their deinit must
    // go through it (freeing them with a different allocator misaligns and
    // panics — see broadcastUserInfo for the same pattern).
    const allocator = ctx.store.allocator;

    try ctx.stderr.print("RX user_info_request from {s}\n", .{meta.callsign});
    try ctx.stderr.print("  requesting {d} user(s)\n", .{user_ids.len});

    // Collect every found user into a lookup array. The lookup structs own
    // their handle/callsign/avatar slices, so they must outlive the
    // sendUserInfoList call (which borrows those slices for the synchronous
    // encode) — deinit happens after.
    const lookups = allocator.alloc(store.User, user_ids.len) catch return;
    var found: usize = 0;
    defer {
        for (lookups[0..found]) |*u| u.deinit(allocator);
        allocator.free(lookups);
    }
    for (user_ids) |uid| {
        if (ctx.store.getUserById(uid)) |user| {
            lookups[found] = user;
            found += 1;
        } else {
            try ctx.stderr.print("  user id={d} not found, skipping\n", .{uid});
        }
    }
    if (found == 0) {
        try ctx.stderr.writeAll("  no matching users\n");
        try ctx.stderr.flush();
        return;
    }

    outbox.sendUserInfoList(ctx, meta.port, lookups[0..found], .broadcast_source) catch {
        try ctx.stderr.writeAll("  error: failed to send user_info_list\n");
        try ctx.stderr.flush();
        return;
    };
    try ctx.stderr.print("  TX user_info reply ({d} users)\n", .{found});
    try ctx.stderr.flush();
}
