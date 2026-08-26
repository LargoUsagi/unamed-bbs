//! Handler for `user_info_request` — replies with a single batched
//! `user_info_list` carrying every requested user the server knows about, so
//! that a request for N users produces one reply message instead of N
//! (multipart-split when the list exceeds one frame). Falls back to per-user
//! `user_info` broadcasts only when the batch is too large to encode.

const std = @import("std");

const kiss = @import("bbs");
const messaging = kiss.messaging;
const transport = kiss.transport;
const signing = kiss.signing;
const message_frame = kiss.message_frame;
const store = kiss.store;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, msg: messaging.Message) !void {
    const callsign = msg.callsignSlice();
    const payload_bytes = msg.payloadSlice();
    // The store's allocator owns the per-user handle/callsign/avatar slices
    // returned by getUserById, so all lookup allocations and their deinit must
    // go through it (freeing them with a different allocator misaligns and
    // panics — see broadcastUserInfo for the same pattern).
    const allocator = ctx.store.allocator;

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

    // Collect every found user into a lookup array. The lookup structs own
    // their handle/callsign/avatar slices, so they must outlive the UserInfo
    // views built below (which borrow those slices) — deinit happens last.
    const lookups = allocator.alloc(store.User, req.user_ids.len) catch return;
    var found: usize = 0;
    defer {
        for (lookups[0..found]) |*u| u.deinit(allocator);
        allocator.free(lookups);
    }
    for (req.user_ids) |uid| {
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

    // Build UserInfo views backed by the lookup slices (no copies — the
    // lookups are kept alive until after the send completes).
    const infos = allocator.alloc(message_frame.UserInfo, found) catch return;
    defer allocator.free(infos);
    for (lookups[0..found], 0..) |u, i| {
        infos[i] = .{
            .id = u.id,
            .registered_datetime = u.registered_datetime,
            .handle = u.handle,
            .callsign = u.callsign,
            .public_key = u.public_key,
            .is_sysop = u.is_sysop,
            .avatar = u.avatar,
        };
    }

    // Send one batched user_info_list when it fits in an encoded payload;
    // otherwise fall back to per-user user_info broadcasts. The encode check
    // is done up front because outbox.send silently drops a payload whose
    // encoding exceeds max_encode_len, and we want the fallback to cover it.
    var check_buf: [message_frame.max_encode_len]u8 = undefined;
    const list = message_frame.UserInfoList{ .users = infos };
    if (list.encode(&check_buf)) |_| {
        outbox.send(ctx, msg.port, .{ .user_info_list = .{ .users = infos } }, .user_info_list, .broadcast_source) catch {
            try ctx.stderr.writeAll("  error: failed to send user_info_list\n");
            try ctx.stderr.flush();
            return;
        };
        try ctx.stderr.print("  TX 1 user_info_list ({d} users)\n", .{found});
        try ctx.stderr.flush();
    } else {
        try ctx.stderr.print("  user_info_list too large, falling back to per-user ({d} users)\n", .{found});
        try ctx.stderr.flush();
        for (lookups[0..found]) |u| {
            outbox.broadcastUserInfo(ctx, msg.port, u.id, .broadcast_source) catch {
                try ctx.stderr.print("  error: failed to broadcast user_info for id={d}\n", .{u.id});
                try ctx.stderr.flush();
            };
        }
    }
}
