//! Handler for `registration` — registers or re-registers a user (handle,
//! public key, and — when the link provides a genuine HAM callsign —
//! callsign) in the store. Verifies the signature against either the existing
//! stored key (re-registration) or the payload key (new registration),
//! persists the store, and broadcasts the updated user info. The callsign
//! field stores only a HAM radio callsign (never a routing/link identity), so
//! identity-less links like MeshCore register with an empty callsign.

const std = @import("std");

const kiss = @import("bbs");
const signing = kiss.signing;
const protocol = kiss.protocol;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta, handle_str: []const u8, public_key: [32]u8) !void {
    const callsign = meta.callsign;
    const payload_bytes = meta.payload_bytes;
    const allocator = std.heap.page_allocator;

    try ctx.stderr.print("RX registration from {s}\n", .{callsign});

    // Enforce maximum handle length.
    if (handle_str.len > protocol.max_handle_len) {
        try ctx.stderr.print("  error: handle \"{s}\" exceeds {d} chars\n", .{ handle_str, protocol.max_handle_len });
        try ctx.stderr.flush();
        outbox.sendRegistrationAck(ctx, meta.port, callsign, false, 0) catch {};
        return;
    }

    // The callsign comes from the link-layer header (AX.25 for HAM radio
    // links) — it is not carried in the payload, so it can't be forged by the
    // sender. The User.callsign field stores ONLY a genuine HAM radio
    // callsign; it is not used for routing. Identity-less links (e.g.
    // MeshCore) surface no callsign, so their registrations are accepted with
    // an empty callsign (new user) or preserve an existing HAM callsign set
    // during a prior HAM-radio session (re-registration).
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
    if (!meta.signed) {
        try ctx.stderr.writeAll("  error: registration not signed\n");
        try ctx.stderr.flush();
        outbox.sendRegistrationAck(ctx, meta.port, callsign, false, 0) catch {};
        return;
    }

    if (ctx.store.getUserByHandle(handle_str)) |existing| {
        var mut_existing = existing;
        defer mut_existing.deinit(ctx.store.allocator);

        try ctx.stderr.print("  re-registration: handle=\"{s}\" id={d}\n", .{ handle_str, existing.id });
        try ctx.stderr.flush();

        // Verify against the EXISTING stored key, not the new one.
        const sig_ok = signing.verify(meta.signature, payload_bytes, existing.public_key);
        if (!sig_ok) {
            try ctx.stderr.writeAll("  error: signature does not match existing key — rejected\n");
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, callsign, false, 0) catch {};
            return;
        }

        // Authorized by the current owner — apply the update. The avatar is
        // preserved across re-registration (the user may have customized it);
        // only callsign/key/datetime are refreshed. A HAM callsign set during
        // a prior HAM-radio session is preserved when re-registering over an
        // identity-less link (which surfaces no callsign).
        const stored_cs = if (cs.len != 0) cs else existing.callsign;
        const now_secs: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));
        ctx.store.updateUser(existing.id, stored_cs, public_key, now_secs, existing.is_sysop, existing.avatar) catch |err| {
            try ctx.stderr.print("  error: failed to update user: {s}\n", .{@errorName(err)});
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, callsign, false, 0) catch {};
            return;
        };

        ctx.store.save(ctx.io, ctx.store_path) catch |err| {
            try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
        };

        try ctx.stderr.print("  updated: handle=\"{s}\" callsign=\"{s}\" id={d}\n", .{
            handle_str, stored_cs, existing.id,
        });
        try ctx.stderr.flush();

        outbox.sendRegistrationAck(ctx, meta.port, callsign, true, existing.id) catch {};

        // Re-registration: broadcast the updated user info on the source
        // transport only. Other transports already have this user cached
        // and didn't see the re-login.
        outbox.broadcastUserInfo(ctx, meta.port, existing.id, .broadcast_source) catch {};
    } else {
        // New registration: verify against the payload's public key.
        const sig_ok = signing.verify(meta.signature, payload_bytes, public_key);
        if (!sig_ok) {
            try ctx.stderr.writeAll("  error: registration signature INVALID\n");
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, callsign, false, 0) catch {};
            return;
        }

        const now_secs: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));
        // The first registered user becomes the sysop.
        const is_sysop = ctx.store.countUsers() == 0;
        // Compute the default avatar once, server-side, from the public key.
        const avatar_str = kiss.avatar.generateFromKey(allocator, public_key) catch &.{};
        defer if (avatar_str.len != 0) allocator.free(avatar_str);
        const user_id = ctx.store.addUser(handle_str, cs, public_key, now_secs, is_sysop, avatar_str) catch |err| {
            try ctx.stderr.print("  error: failed to store user: {s}\n", .{@errorName(err)});
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, callsign, false, 0) catch {};
            return;
        };

        ctx.store.save(ctx.io, ctx.store_path) catch |err| {
            try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
        };

        try ctx.stderr.print("  registered: handle=\"{s}\" callsign=\"{s}\" id={d}\n", .{
            handle_str, cs, user_id,
        });
        try ctx.stderr.flush();

        outbox.sendRegistrationAck(ctx, meta.port, callsign, true, user_id) catch {};

        // Broadcast the new user info to all radios so all listening clients
        // can instantly cache the new user.
        outbox.broadcastUserInfo(ctx, meta.port, user_id, .broadcast_all) catch {};
    }
}
