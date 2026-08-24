//! Inbox — the server-side receive abstraction, mirroring the client's
//! `inbox.zig`. Owns the receive mechanics (drain from the transport pool +
//! multipart reassembly + dispatch to type-specific handlers + stale-entry
//! eviction) so `main.zig` is free of message processing: main owns only
//! lifecycle (connect/reconnect, heartbeat timing) and wires the inbox and
//! outbox together.
//!
//! This is the exact inverse of `outbox.zig`: handlers call *into* the outbox
//! to send; the inbox calls *out* to the handlers to process received
//! messages. Together the two modules are the sole data-flow boundary for
//! the whole server — every byte in flows through `inbox`, every byte out
//! through `outbox`.
//!
//! Unlike the client inbox, the server inbox holds no transport handle (the
//! pool is passed via `ServerCtx`), tracks no overheard NAKs (the
//! retransmission cache's dedup window already suppresses duplicate
//! retransmits when multiple clients NAK the same packet), and sends no NAKs
//! (the server is the *source* of multipart messages; clients NAK *to* it via
//! the `packet_request` handler). It does own the reassembler and evicts
//! stale entries on a 30-second timeout, mirroring the client.

const std = @import("std");
const Io = std.Io;

const kiss = @import("bbs");
const transport_mod = kiss.transport;
const reassembly_mod = kiss.reassembly;

const context = @import("context.zig");
const ServerCtx = context.ServerCtx;

// Handler imports — the type-specific dispatch targets called by `dispatch`.
const h_public_key_request = @import("handlers/public_key_request.zig");
const h_registration = @import("handlers/registration.zig");
const h_bulletin_list_request = @import("handlers/bulletin_list_request.zig");
const h_bulletin_request = @import("handlers/bulletin_request.zig");
const h_bulletin = @import("handlers/bulletin.zig");
const h_bulletin_response = @import("handlers/bulletin_response.zig");
const h_bulletin_response_request = @import("handlers/bulletin_response_request.zig");
const h_user_info_request = @import("handlers/user_info_request.zig");
const h_packet_request = @import("handlers/packet_request.zig");
const h_motd_request = @import("handlers/motd_request.zig");
const h_motd = @import("handlers/motd.zig");
const h_chat = @import("handlers/chat.zig");
const h_chat_history_request = @import("handlers/chat_history_request.zig");
const h_avatar_update = @import("handlers/avatar_update.zig");

/// Owns the receive-side state: the multipart reassembler. Exposed as a `var`
/// in `main`; the loop calls `drain` then `processTimeouts`. Reads the
/// transport pool from the `ServerCtx` passed to each call (the pool is
/// shared, not owned).
pub const Inbox = struct {
    reassembler: reassembly_mod.Reassembler = .{},

    /// Drain queued incoming messages from all connected transports in the
    /// pool and process each one. Returns the number of messages processed
    /// (so the caller can update activity timestamps). Per-message handler
    /// errors are logged to `ctx.stderr` and swallowed so one bad message
    /// doesn't abort the drain. Called from the main loop each iteration.
    pub fn drain(self: *Inbox, ctx: *const ServerCtx) usize {
        var count: usize = 0;
        var buf: [1]transport_mod.IncomingMessage = undefined;
        while (ctx.pool.drainOne(&buf)) |drained| {
            count += 1;
            // The one per-message field that varies: which transport the
            // message arrived on. All other ctx fields are shared pointers,
            // so copying the base ctx is cheap. Handlers read
            // `source_transport_id` to route directed/single-radio responses.
            var msg_ctx = ctx.*;
            msg_ctx.source_transport_id = drained.transport_id;
            self.process(&msg_ctx, drained.msg) catch |err| {
                ctx.stderr.print("error: handler failed: {s}\n", .{@errorName(err)}) catch {};
                ctx.stderr.flush() catch {};
            };
        }
        return count;
    }

    /// Evict stale multipart reassembly entries (no packet received in 30s).
    /// The server sends no NAKs (it is the multipart source; clients NAK to
    /// it), so this is pure cleanup — mirroring the client inbox's eviction
    /// branch without the NAK-sending branch. Safe to call regardless of
    /// connection state. Called from the main loop each iteration.
    pub fn processTimeouts(self: *Inbox, ctx: *const ServerCtx) void {
        const now_ms: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()) * 1000);
        for (self.reassembler.entriesSlice()) |*entry| {
            if (!entry.active) continue;
            if (now_ms - entry.last_received_ts > 30_000) {
                self.reassembler.freeEntry(entry);
            }
        }
    }

    /// Process a single drained message: guard, route multipart frames to the
    /// reassembler, and dispatch single-packet messages directly. The
    /// per-message `ServerCtx` (with the correct `source_transport_id`) is
    /// passed through to handlers.
    fn process(self: *Inbox, ctx: *const ServerCtx, im: transport_mod.IncomingMessage) !void {
        if (!im.is_message_frame) return;
        if (!im.has_callsign) return;

        // Route multipart frames to the reassembly buffer.
        if (im.packet_count > 1) {
            return try self.handleMultipart(ctx, im);
        }

        try dispatch(ctx, im);
    }

    /// Handle an incoming multipart packet. Stores the chunk, and when all
    /// packets are received, reassembles and re-dispatches as a single-packet
    /// message via a synthetic `IncomingMessage`.
    fn handleMultipart(self: *Inbox, ctx: *const ServerCtx, im: transport_mod.IncomingMessage) !void {
        const now_ms: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()) * 1000);

        const msg = self.reassembler.feed(im, now_ms) orelse return;

        const allocator = std.heap.page_allocator;
        defer allocator.free(msg.payload);

        // Build a synthetic IncomingMessage carrying the reassembled payload so
        // dispatch can handle it exactly like a single-packet message.
        var synth_im = im;
        if (msg.payload.len > synth_im.frame_payload.len) {
            try ctx.stderr.print("  error: reassembled payload ({d} bytes) exceeds frame buffer ({d})\n", .{ msg.payload.len, synth_im.frame_payload.len });
            try ctx.stderr.flush();
            return;
        }
        @memcpy(synth_im.frame_payload[0..msg.payload.len], msg.payload);
        synth_im.frame_payload_len = @intCast(msg.payload.len);
        synth_im.packet_count = 1;
        synth_im.packet_number = 0;
        if (msg.signature) |sig| {
            synth_im.signed = true;
            synth_im.signature = sig;
        } else {
            synth_im.signed = false;
        }

        try ctx.stderr.print("  reassembled {d} bytes, dispatching\n", .{msg.payload.len});
        try ctx.stderr.flush();

        try dispatch(ctx, synth_im);
    }
};

/// Dispatch a single-part (or reassembled) message to the appropriate handler
/// based on message type. Called by `process` / `handleMultipart` after the
/// receive mechanics (guard + reassembly) succeed. Signature verification
/// stays in each handler (the key source varies by type: sender's stored key,
/// payload key, or existing key on re-registration), so it is not centralised
/// here — unlike the client inbox, which verifies all server messages against
/// the single trusted BBS key.
fn dispatch(ctx: *const ServerCtx, im: transport_mod.IncomingMessage) !void {
    switch (im.msg_type) {
        .public_key_request => try h_public_key_request.handle(ctx, im),
        .registration => try h_registration.handle(ctx, im),
        .bulletin_list_request => try h_bulletin_list_request.handle(ctx, im),
        .bulletin_request => try h_bulletin_request.handle(ctx, im),
        .bulletin => try h_bulletin.handle(ctx, im),
        .bulletin_response => try h_bulletin_response.handle(ctx, im),
        .bulletin_response_request => try h_bulletin_response_request.handle(ctx, im),
        .user_info_request => try h_user_info_request.handle(ctx, im),
        .packet_request => try h_packet_request.handle(ctx, im),
        .motd_request => try h_motd_request.handle(ctx, im),
        .motd => try h_motd.handle(ctx, im),
        .chat => try h_chat.handle(ctx, im),
        .chat_history_request => try h_chat_history_request.handle(ctx, im),
        .avatar_update => try h_avatar_update.handle(ctx, im),
        else => {},
    }
}
