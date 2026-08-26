//! Inbox — the server-side receive abstraction, mirroring the client's
//! `inbox.zig`. Owns the receive mechanics (drain packets from the transport
//! pool + session routing/reassembly via the shared `bbs.messaging.RxCore`)
//! and hands complete `bbs.messaging.Message` values to the type-specific
//! handlers, so `main.zig` is free of message processing: main owns only
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
//! the `packet_request` handler). The mechanical core (reassembly + 30s
//! eviction) lives in `bbs.messaging.RxCore`; policy (per-handler signature
//! verification, dispatch) stays here.

const std = @import("std");
const Io = std.Io;

const kiss = @import("bbs");
const messaging = kiss.messaging;

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

/// Owns the receive-side state: the shared RxCore (reassembler + multipart
/// routing). Exposed as a `var` in `main`; the loop calls `drain` then
/// `processTimeouts`. Reads the transport pool from the `ServerCtx` passed
/// to each call (the pool is shared, not owned).
pub const Inbox = struct {
    core: messaging.RxCore = .{},

    /// Drain queued incoming packets from all connected transports in the
    /// pool and route each through the shared core. Complete logical messages
    /// are dispatched to handlers. Returns the number of packets processed
    /// (so the caller can update activity timestamps). Per-message handler
    /// errors are logged to `ctx.stderr` and swallowed so one bad message
    /// doesn't abort the drain. Called from the main loop each iteration.
    pub fn drain(self: *Inbox, ctx: *const ServerCtx) usize {
        var count: usize = 0;
        var buf: [1]kiss.transport.IncomingMessage = undefined;
        while (ctx.pool.drainOne(&buf)) |drained| {
            count += 1;
            // The one per-message field that varies: which transport the
            // message arrived on. All other ctx fields are shared pointers,
            // so copying the base ctx is cheap. Handlers read
            // `source_transport_id` to route directed/single-radio responses.
            var msg_ctx = ctx.*;
            msg_ctx.source_transport_id = drained.transport_id;
            self.process(&msg_ctx, &drained.msg);
        }
        return count;
    }

    /// Evict stale multipart reassembly entries (no packet received in 30s)
    /// via the shared core. The server sends no NAKs (it is the multipart
    /// source; clients NAK to it), so this is pure cleanup. Safe to call
    /// regardless of connection state. Called from the main loop each
    /// iteration.
    pub fn processTimeouts(self: *Inbox, ctx: *const ServerCtx) void {
        _ = self.core.evictStale(nowMs(ctx));
    }

    /// Route one drained packet through the shared core. The per-message
    /// `ServerCtx` (with the correct `source_transport_id`) is passed through
    /// to handlers. Takes a mutable pointer only so it can be handed to the
    /// type-erased `RxHandler.ctx`.
    ///
    /// Callsigns are optional at the session boundary: only AGWPE provides
    /// link-layer identity (the AX.25 header). Identity-less links (MeshCore
    /// RAW packets) deliver messages with an empty callsign slice; handlers
    /// that need an asserted identity (registration) enforce that themselves.
    fn process(self: *Inbox, ctx: *ServerCtx, im: *const kiss.transport.IncomingMessage) void {
        if (!im.is_message_frame) return;

        const handler = messaging.RxHandler{
            .ctx = @ptrCast(ctx),
            .onMessage = rxMessage,
            .onOverflow = rxOverflow,
        };
        self.core.process(handler, im, nowMs(ctx));
    }

    /// RxCore callback: a complete logical message (single-packet or
    /// reassembled) ready for dispatch. Reassembly bookkeeping — including
    /// rebuilding link context from the completing packet — happened inside
    /// the shared core, so this is a straight hand-off.
    fn rxMessage(opaque_ctx: *anyopaque, msg: messaging.Message) void {
        const ctx: *const ServerCtx = @ptrCast(@alignCast(opaque_ctx));

        if (msg.reassembled) {
            ctx.stderr.print("  reassembled {d} bytes, dispatching\n", .{msg.payload_len}) catch {};
            ctx.stderr.flush() catch {};
        }
        dispatch(ctx, msg) catch |err| logHandlerError(ctx, err);
    }

    fn rxOverflow(opaque_ctx: *anyopaque, total: usize) void {
        const ctx: *const ServerCtx = @ptrCast(@alignCast(opaque_ctx));
        ctx.stderr.print("  error: reassembled payload ({d} bytes) exceeds frame buffer ({d})\n", .{ total, kiss.transport.max_encode_len }) catch {};
        ctx.stderr.flush() catch {};
    }
};

fn logHandlerError(ctx: *const ServerCtx, err: anyerror) void {
    ctx.stderr.print("error: handler failed: {s}\n", .{@errorName(err)}) catch {};
    ctx.stderr.flush() catch {};
}

fn nowMs(ctx: *const ServerCtx) u64 {
    return @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()) * 1000);
}

/// Dispatch a single-part (or reassembled) message to the appropriate handler
/// based on message type. Called by the RxCore callbacks after the receive
/// mechanics (guard + reassembly) succeed. Signature verification stays in
/// each handler (the key source varies by type: sender's stored key, payload
/// key, or existing key on re-registration), so it is not centralised here —
/// unlike the client inbox, which verifies all server messages against the
/// single trusted BBS key.
fn dispatch(ctx: *const ServerCtx, msg: messaging.Message) !void {
    switch (msg.msg_type) {
        .public_key_request => try h_public_key_request.handle(ctx, msg),
        .registration => try h_registration.handle(ctx, msg),
        .bulletin_list_request => try h_bulletin_list_request.handle(ctx, msg),
        .bulletin_request => try h_bulletin_request.handle(ctx, msg),
        .bulletin => try h_bulletin.handle(ctx, msg),
        .bulletin_response => try h_bulletin_response.handle(ctx, msg),
        .bulletin_response_request => try h_bulletin_response_request.handle(ctx, msg),
        .user_info_request => try h_user_info_request.handle(ctx, msg),
        .packet_request => try h_packet_request.handle(ctx, msg),
        .motd_request => try h_motd_request.handle(ctx, msg),
        .motd => try h_motd.handle(ctx, msg),
        .chat => try h_chat.handle(ctx, msg),
        .chat_history_request => try h_chat_history_request.handle(ctx, msg),
        .avatar_update => try h_avatar_update.handle(ctx, msg),
        else => {},
    }
}
