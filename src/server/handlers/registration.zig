//! Handler for `registration` — registers a new user or logs in an existing
//! one. The `mode` field distinguishes the two flows:
//!
//!   `register`: creates a new user. The signature must verify against the
//!   payload's public key (proving the sender owns the key). If the handle
//!   already exists (case-insensitive), the registration is rejected.
//!
//!   `login`: authenticates an existing user. The signature must verify
//!   against the stored public key (proving the current owner). The user's
//!   key/datetime are refreshed; the callsign is updated if a non-empty
//!   self-identified callsign is provided.
//!
//! The **self-identified callsign** is carried in the payload (distinct from
//! the link-layer AX.25 callsign in `meta.callsign`) and stored in
//! `users.callsign` for display on posts and in the user directory. It is
//! uppercased before storage. The link-layer callsign is used only for
//! routing the directed `registration_ack` reply.

const std = @import("std");

const kiss = @import("bbs");
const signing = kiss.signing;
const protocol = kiss.protocol;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(
    ctx: *const ServerCtx,
    meta: RequestMeta,
    mode: protocol.RegistrationMode,
    handle_str: []const u8,
    callsign: []const u8,
    public_key: [32]u8,
) !void {
    const link_callsign = meta.callsign;
    const payload_bytes = meta.payload_bytes;
    const allocator = std.heap.page_allocator;

    try ctx.stderr.print("RX {s} from {s}\n", .{ @tagName(mode), link_callsign });

    // Enforce maximum handle length.
    if (handle_str.len > protocol.max_handle_len) {
        try ctx.stderr.print("  error: handle \"{s}\" exceeds {d} chars\n", .{ handle_str, protocol.max_handle_len });
        try ctx.stderr.flush();
        outbox.sendRegistrationAck(ctx, meta.port, link_callsign, false, 0) catch {};
        return;
    }

    // The self-identified callsign is uppercased before storage. The
    // link-layer callsign (from the AX.25 header) is used only for routing
    // the directed reply — it is NOT stored in the user record.
    var upper_callsign: [protocol.max_callsign_len]u8 = std.mem.zeroes([protocol.max_callsign_len]u8);
    const cs_len = @min(callsign.len, protocol.max_callsign_len);
    for (0..cs_len) |i| upper_callsign[i] = std.ascii.toUpper(callsign[i]);
    const stored_cs = upper_callsign[0..cs_len];

    // The registration/login payload must be signed. Which key it must be
    // signed with depends on the mode:
    //
    //   register: the signature must verify against the payload's public
    //   key — this proves the sender owns the key they are registering.
    //
    //   login: the signature must verify against the EXISTING stored
    //   public key — this proves the current owner is logging in.
    if (!meta.signed) {
        try ctx.stderr.writeAll("  error: not signed\n");
        try ctx.stderr.flush();
        outbox.sendRegistrationAck(ctx, meta.port, link_callsign, false, 0) catch {};
        return;
    }

    if (ctx.store.getUserByHandle(handle_str)) |existing| {
        var mut_existing = existing;
        defer mut_existing.deinit(ctx.store.allocator);

        if (mode == .register) {
            // A new registration with an existing handle (case-insensitive)
            // is rejected — the user should use login instead.
            try ctx.stderr.print("  error: handle \"{s}\" already taken\n", .{handle_str});
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, link_callsign, false, 0) catch {};
            return;
        }

        // login: verify against the EXISTING stored key.
        try ctx.stderr.print("  login: handle=\"{s}\" id={d}\n", .{ handle_str, existing.id });
        try ctx.stderr.flush();

        const sig_ok = signing.verify(meta.signature, payload_bytes, existing.public_key);
        if (!sig_ok) {
            try ctx.stderr.writeAll("  error: signature does not match existing key — rejected\n");
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, link_callsign, false, 0) catch {};
            return;
        }

        // Authorized — apply the update. The avatar is preserved across
        // login. Use the self-identified callsign from the payload if
        // non-empty, otherwise preserve the existing stored callsign.
        const final_cs = if (stored_cs.len != 0) stored_cs else existing.callsign;
        const now_secs: u64 = kiss.time.nowSecs(ctx.io);
        ctx.store.updateUser(existing.id, final_cs, public_key, now_secs, existing.is_sysop, existing.avatar) catch |err| {
            try ctx.stderr.print("  error: failed to update user: {s}\n", .{@errorName(err)});
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, link_callsign, false, 0) catch {};
            return;
        };

        ctx.store.save(ctx.io, ctx.store_path) catch |err| {
            try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
        };

        try ctx.stderr.print("  updated: handle=\"{s}\" callsign=\"{s}\" id={d}\n", .{
            handle_str, final_cs, existing.id,
        });
        try ctx.stderr.flush();

        outbox.sendRegistrationAck(ctx, meta.port, link_callsign, true, existing.id) catch {};

        // Re-broadcast the updated user info on the source transport only.
        outbox.broadcastUserInfo(ctx, meta.port, existing.id, .broadcast_source) catch {};
    } else {
        // No existing user with this handle.
        if (mode == .login) {
            // Login to a non-existent handle is rejected.
            try ctx.stderr.print("  error: no account with handle \"{s}\"\n", .{handle_str});
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, link_callsign, false, 0) catch {};
            return;
        }

        // register: verify against the payload's public key.
        const sig_ok = signing.verify(meta.signature, payload_bytes, public_key);
        if (!sig_ok) {
            try ctx.stderr.writeAll("  error: registration signature INVALID\n");
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, link_callsign, false, 0) catch {};
            return;
        }

        const now_secs: u64 = kiss.time.nowSecs(ctx.io);
        // The first registered user becomes the sysop.
        const is_sysop = ctx.store.countUsers() == 0;
        // Compute the default avatar once, server-side, from the public key.
        const avatar_str = kiss.avatar.generateFromKey(allocator, public_key) catch &.{};
        defer if (avatar_str.len != 0) allocator.free(avatar_str);
        const user_id = ctx.store.addUser(handle_str, stored_cs, public_key, now_secs, is_sysop, avatar_str) catch |err| {
            try ctx.stderr.print("  error: failed to store user: {s}\n", .{@errorName(err)});
            try ctx.stderr.flush();
            outbox.sendRegistrationAck(ctx, meta.port, link_callsign, false, 0) catch {};
            return;
        };

        ctx.store.save(ctx.io, ctx.store_path) catch |err| {
            try ctx.stderr.print("  warning: failed to persist store: {s}\n", .{@errorName(err)});
        };

        try ctx.stderr.print("  registered: handle=\"{s}\" callsign=\"{s}\" id={d}\n", .{
            handle_str, stored_cs, user_id,
        });
        try ctx.stderr.flush();

        outbox.sendRegistrationAck(ctx, meta.port, link_callsign, true, user_id) catch {};

        // Broadcast the new user info to all radios so all listening clients
        // can instantly cache the new user.
        outbox.broadcastUserInfo(ctx, meta.port, user_id, .broadcast_all) catch {};
    }
}
