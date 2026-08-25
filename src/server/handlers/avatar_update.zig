//! Handler for `avatar_update` — a client updates its own avatar (the 11×7
//! ASCII art shown alongside its posts and profile).
//!
//! The payload must be signed. The sender is identified by verifying the
//! signature against every stored public key (callsigns are not unique, so
//! signature identity is the only secure way — same pattern as `motd` and
//! `bulletin`). The identified user's `avatar` column is updated, the store
//! is persisted, and the updated `user_info` is re-broadcast so all clients
//! refresh their cache.

const std = @import("std");

const kiss = @import("bbs");
const transport = kiss.transport;
const message_frame = kiss.message_frame;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, im: transport.IncomingMessage) !void {
    const callsign = im.callsign[0..@min(im.callsign_str_len, message_frame.callsign_len)];
    const payload_bytes = im.frame_payload[0..im.frame_payload_len];
    const allocator = std.heap.page_allocator;

    try ctx.stderr.print("RX avatar_update from {s}\n", .{callsign});
    try ctx.stderr.flush();

    if (!im.signed) {
        try ctx.stderr.writeAll("  ignoring: unsigned avatar_update\n");
        try ctx.stderr.flush();
        return;
    }
    var user = ctx.store.findUserBySignature(im.signature, payload_bytes) orelse {
        try ctx.stderr.writeAll("  ignoring: signature does not match any registered user\n");
        try ctx.stderr.flush();
        return;
    };
    defer user.deinit(ctx.store.allocator);

    const decoded = message_frame.decodePayload(allocator, .avatar_update, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode avatar_update\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed avatar_update\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const new_avatar = decoded.?.avatar_update.avatar;

    if (new_avatar.len > message_frame.max_avatar_len) {
        try ctx.stderr.writeAll("  error: avatar exceeds limit\n");
        try ctx.stderr.flush();
        return;
    }

    try ctx.stderr.print("  updating avatar for id={d} handle=\"{s}\" ({d} bytes)\n", .{
        user.id, user.handle, new_avatar.len,
    });
    try ctx.stderr.flush();

    ctx.store.updateAvatar(user.id, new_avatar) catch |err| {
        try ctx.stderr.print("  error: failed to update avatar: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        return;
    };

    ctx.store.save(ctx.io, ctx.store_path) catch |err| {
        try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
    };

    // Re-broadcast the updated user_info so all clients refresh their cache.
    outbox.broadcastUserInfo(ctx, im.port, user.id, .broadcast_source) catch {
        try ctx.stderr.writeAll("  error: failed to broadcast updated user_info\n");
        try ctx.stderr.flush();
    };
}
