//! Handler for `registration` — registers or re-registers a user (handle,
//! callsign, public key) in the store. Verifies the signature against either
//! the existing stored key (re-registration) or the payload key (new
//! registration), persists the store, and broadcasts the updated user info.

const std = @import("std");

const kiss = @import("bbs");
const messaging = kiss.messaging;
const transport = kiss.transport;
const signing = kiss.signing;
const message_frame = kiss.message_frame;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, msg: messaging.Message) !void {
    const callsign = msg.callsignSlice();
    const payload_bytes = msg.payloadSlice();
    const allocator = std.heap.page_allocator;

    try ctx.stderr.print("RX registration from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .registration, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode registration\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed registration\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const reg = decoded.?.registration;

    // Enforce maximum handle length.
    if (reg.handle.len > message_frame.max_handle_len) {
        try ctx.stderr.print("  error: handle \"{s}\" exceeds {d} chars\n", .{ reg.handle, message_frame.max_handle_len });
        try ctx.stderr.flush();
        outbox.sendRegistrationAck(ctx, msg.port, callsign, false, 0) catch {};
        return;
    }

    // The callsign comes exclusively from the AX.25 header — it is
    // not carried in the payload (so it can't be forged by the
    // sender). Reject registrations with no header callsign.
    if (callsign.len == 0) {
        try ctx.stderr.writeAll("  error: registration has no header callsign\n");
        try ctx.stderr.flush();
        outbox.sendRegistrationAck(ctx, msg.port, callsign, false, 0) catch {};
        return;
    }
    const cs = callsign;

    // The registration payload must be signed. Which key it must be
    // signed with depends on whether the handle already exists:
    //
    //   New registration (handle not found):
    //     The signature must verify against the public key embedded
    //     in the payload — this proves the sender owned the key they
    //     are registering.
    //
    //   Re-registration (handle exists):
    //     The signature must verify against the EXISTING stored
    //     public key — this proves the current owner is authorizing
    //     the change to a new callsign and/or public key. A request
    //     signed with any other key (including the new one in the
    //     payload) is rejected.
    if (!msg.signed) {
        try ctx.stderr.writeAll("  error: registration not signed\n");
        try ctx.stderr.flush();
        outbox.sendRegistrationAck(ctx, msg.port, callsign, false, 0) catch {};
        return;
    }

    if (ctx.store.getUserByHandle(reg.handle)) |existing| {
        var mut_existing = existing;
        defer mut_existing.deinit(ctx.store.allocator);

        try ctx.stderr.print("  re-registration: handle=\"{s}\" id={d}\n", .{ reg.handle, existing.id });
        try ctx.stderr.flush();

        // Verify against the EXISTING stored key, not the new one.
        const sig_ok = signing.verify(msg.signature, payload_bytes, existing.public_key);
        if (!sig_ok) {
            try ctx.stderr.writeAll("  error: signature does not match existing key — rejected\n");
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, msg.port, callsign, false, 0) catch {};
            return;
        }

        // Authorized by the current owner — apply the update. The avatar is
        // preserved across re-registration (the user may have customized it);
        // only callsign/key/datetime are refreshed.
        const now_secs: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));
        ctx.store.updateUser(existing.id, cs, reg.public_key, now_secs, existing.is_sysop, existing.avatar) catch |err| {
            try ctx.stderr.print("  error: failed to update user: {s}\n", .{@errorName(err)});
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, msg.port, callsign, false, 0) catch {};
            return;
        };

        ctx.store.save(ctx.io, ctx.store_path) catch |err| {
            try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
        };

        try ctx.stderr.print("  updated: handle=\"{s}\" callsign=\"{s}\" id={d}\n", .{
            reg.handle, cs, existing.id,
        });
        try ctx.stderr.flush();

        outbox.sendRegistrationAck(ctx, msg.port, callsign, true, existing.id) catch {};

        // Re-registration: broadcast the updated user info on the source
        // transport only. Other transports already have this user cached
        // and didn't see the re-login.
        outbox.broadcastUserInfo(ctx, msg.port, existing.id, .broadcast_source) catch {};
    } else {
        // New registration: verify against the payload's public key.
        const sig_ok = signing.verify(msg.signature, payload_bytes, reg.public_key);
        if (!sig_ok) {
            try ctx.stderr.writeAll("  error: registration signature INVALID\n");
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, msg.port, callsign, false, 0) catch {};
            return;
        }

        const now_secs: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));
        // The first registered user becomes the sysop.
        const is_sysop = ctx.store.countUsers() == 0;
        // Compute the default avatar once, server-side, from the public key.
        const avatar_str = kiss.avatar.generateFromKey(allocator, reg.public_key) catch &.{};
        defer if (avatar_str.len != 0) allocator.free(avatar_str);
        const user_id = ctx.store.addUser(reg.handle, cs, reg.public_key, now_secs, is_sysop, avatar_str) catch |err| {
            try ctx.stderr.print("  error: failed to store user: {s}\n", .{@errorName(err)});
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, msg.port, callsign, false, 0) catch {};
            return;
        };

        ctx.store.save(ctx.io, ctx.store_path) catch |err| {
            try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
        };

        try ctx.stderr.print("  registered: handle=\"{s}\" callsign=\"{s}\" id={d}\n", .{
            reg.handle, cs, user_id,
        });
        try ctx.stderr.flush();

        outbox.sendRegistrationAck(ctx, msg.port, callsign, true, user_id) catch {};

        // Broadcast the new user info to all radios so all listening clients
        // can instantly cache the new user.
        outbox.broadcastUserInfo(ctx, msg.port, user_id, .broadcast_all) catch {};
    }
}
