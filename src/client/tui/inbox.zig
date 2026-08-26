//! Inbox — the client-side receive abstraction, mirroring the server's
//! `inbox.zig`. Owns the receive policy (drain + NAK tracking + BBS-key
//! learning + signature verification against the trusted BBS key + logging)
//! while the shared mechanics — multipart routing, reassembly, and 30s
//! stale-entry eviction — live in `bbs.messaging.RxCore`, the same core the
//! server's inbox uses. Complete logical messages surface through the core's
//! `onMessage` callback as `bbs.messaging.Message` values (type + payload +
//! signature + link context); packetization details never reach this layer.
//! The one sanctioned raw-packet consumer here is the overheard-NAK
//! suppression table, wired via the optional `onPacket` hook.
//!
//! Type-specific `store*` / `handle*` dispatch lives in `incoming.zig` and is
//! invoked by the inbox, exactly inverted from how server handlers call *into*
//! the outbox to send.
//!
//! The inbox holds a `transport.Transport` vtable handle (obtained from a
//! concrete connection's `asTransport()` on connect). A future meshcore
//! transport hands in its own `Transport` handle without touching
//! `incoming.zig`, `logs.zig`, or `outbox.zig` — the same extensibility
//! property the server enjoys via `TransportPool`.

const std = @import("std");

const types = @import("types.zig");
const app = @import("app.zig");
const outbox = @import("outbox.zig");
const logs = @import("logs.zig");
const incoming = @import("incoming.zig");

const signing = types.signing;
const message_frame = types.message_frame;
const messaging = types.messaging;
const transport = types.transport;
const reassembly_mod = types.transport;

const AppContext = app.AppContext;
const SigStatus = types.SigStatus;

/// Outcome of processing an incoming message, returned from the labeled
/// block inside `addIncoming` so we can log every message exactly once.
const IncomingOutcome = struct {
    sig: SigStatus,
    status: types.MsgLogStatus,
};

/// An overheard NAK from another station, for suppression.
pub const OverheardNak = struct {
    active: bool = false,
    group_id: u4 = 0,
    packet_number: u8 = 0,
    timestamp: u64 = 0,
};

/// Owns the receive-side state: the transport handle, the shared RxCore
/// (reassembler + multipart routing), and the overheard-NAK suppression
/// table. Exposed as `ctx.inbox`; `tick()` calls `drain` then
/// `processTimeouts`.
pub const Inbox = struct {
    /// Transport handle set on successful connect (`conn.asTransport()`).
    /// null until the first connect succeeds. The underlying connection
    /// field address is stable for the program's life, so the handle remains
    /// valid across reconnects (drain is guarded by `isConnected()`).
    transport: ?transport.Transport = null,
    /// Shared receive mechanics: multipart reassembly + stale eviction.
    core: messaging.RxCore = .{},
    overheard_naks: [16]OverheardNak = std.mem.zeroes([16]OverheardNak),

    /// Attach (or refresh) the transport handle after a successful connect.
    pub fn setTransport(self: *Inbox, t: transport.Transport) void {
        self.transport = t;
    }

    /// True when the attached transport is a high-bandwidth link (e.g. direct
    /// TCP/IP). Returns false when no transport is attached. UI screens use
    /// this to gate automatic data fetches on page entry that would be wasteful
    /// or impolite over a slow radio channel (AGWPE/AX.25, meshcore).
    pub fn isHighBandwidth(self: *const Inbox) bool {
        const t = self.transport orelse return false;
        return t.isHighBandwidth();
    }

    /// Drain queued incoming packets from the transport and route each one
    /// through the shared core. Called from `tick()`. Does nothing when no
    /// transport is attached or the transport is not connected (e.g. during
    /// the reconnect window, where the underlying connection may be
    /// mid-teardown/rebuild).
    pub fn drain(self: *Inbox, ctx: *AppContext) void {
        const t = self.transport orelse return;
        if (!t.isConnected()) return;

        var buf: [16]transport.IncomingMessage = undefined;
        const n = t.drainIncoming(&buf);
        const handler = messaging.RxHandler{
            .ctx = @ptrCast(ctx),
            .onMessage = rxMessage,
            .onPacket = rxPacket,
            .onOverflow = rxOverflow,
        };
        const now = nowMs(ctx);
        for (buf[0..n]) |*im| self.core.process(handler, im, now);
    }

    /// Process reassembly timeouts (shared-core eviction plus client-only
    /// NAK sending with suppression-aware backoff), then age out stale
    /// overheard-NAK entries. Called from `tick()` every 200ms.
    /// Safe to run regardless of connection state: NAK sends self-guard on
    /// `isConnected()`, and reassembler cleanup is connection-independent.
    pub fn processTimeouts(self: *Inbox, ctx: *AppContext) void {
        const now = nowMs(ctx);

        if (self.core.evictStale(now) > 0) {
            ctx.status = "Multipart message timed out.";
        }

        for (self.core.reassembler.entriesSlice()) |*entry| {
            if (!entry.active) continue;

            // 2-second gap detection.
            if (now - entry.last_received_ts < 2_000) continue;
            if (entry.received_count >= entry.packet_count) continue;

            // Find missing packets.
            var missing: [message_frame.max_packets_per_message]u8 = undefined;
            var missing_count: usize = 0;
            var i: u8 = 0;
            while (i < entry.packet_count) : (i += 1) {
                if (entry.packets[i] == null) {
                    missing[missing_count] = i;
                    missing_count += 1;
                }
            }
            if (missing_count == 0) continue;

            // Check if it's time to send a NAK.
            if (now < entry.next_nak_ts) continue;
            if (entry.nak_attempts >= 3) {
                ctx.status = "Multipart message failed after 3 NAK attempts.";
                self.core.reassembler.freeEntry(entry);
                continue;
            }

            // Check for overheard NAKs — if another station requested the same
            // packets, double the backoff (max 10s) and wait.
            var suppressed = false;
            for (missing[0..missing_count]) |pn| {
                for (&self.overheard_naks) |*on| {
                    if (on.active and on.group_id == entry.group_id and on.packet_number == pn) {
                        if (now - on.timestamp < 5_000) {
                            suppressed = true;
                            break;
                        }
                    }
                }
                if (suppressed) break;
            }

            if (suppressed) {
                const backoff_ms: u64 = switch (entry.nak_attempts) {
                    0 => 2_000,
                    1 => 4_000,
                    2 => 8_000,
                    else => 10_000,
                };
                entry.next_nak_ts = now + backoff_ms;
                continue;
            }

            // Send the NAK.
            entry.nak_attempts += 1;
            const next_backoff: u64 = switch (entry.nak_attempts) {
                1 => 4_000,
                2 => 8_000,
                else => 10_000,
            };
            entry.next_nak_ts = now + next_backoff;
            outbox.sendPacketRequest(ctx, entry.group_id, missing[0..missing_count]);
        }

        // Age out old overheard NAKs.
        for (&self.overheard_naks) |*on| {
            if (on.active and now - on.timestamp > 10_000) {
                on.active = false;
            }
        }
    }

    /// RxCore packet hook — the sanctioned raw-packet view for radio-link
    /// policy. Tracks overheard NAK requests from other stations so the NAK
    /// controller can back off when someone else already asked. Callsigns are
    /// optional (identity-less links like MeshCore surface none), so the
    /// guard does not require one — `trackOverheardNak` keys by group_id.
    fn rxPacket(opaque_ctx: *anyopaque, im: *const transport.IncomingMessage) void {
        const ctx: *AppContext = @ptrCast(@alignCast(opaque_ctx));

        if (im.is_message_frame and im.msg_type == .packet_request) {
            trackOverheardNak(ctx, im);
        }
    }

    /// RxCore overflow diagnostic: a reassembled group exceeded the session
    /// Message payload cap and was dropped by the shared core.
    fn rxOverflow(opaque_ctx: *anyopaque, total: usize) void {
        _ = opaque_ctx;
        _ = total;
    }

    /// RxCore message callback: learn the BBS key, dispatch server messages
    /// (verified against the trusted BBS key), and log every complete message
    /// exactly once.
    fn rxMessage(opaque_ctx: *anyopaque, msg: messaging.Message) void {
        const ctx: *AppContext = @ptrCast(@alignCast(opaque_ctx));

        maybeLearnBbsKey(ctx, msg);

        const outcome: IncomingOutcome = if (isServerMessage(msg))
            handleServerMessage(ctx, msg)
        else
            .{ .sig = .none, .status = .accepted };

        logs.logIncoming(ctx, msg, outcome.sig, outcome.status);
    }
};

/// Learn the BBS (server) public key from a signed server-role `public_key`
/// message, unless the key was hard-locked via --bbs-key. Callsigns are
/// optional at the session boundary (only AGWPE provides link-layer
/// identity), so key learning does not require one.
fn maybeLearnBbsKey(ctx: *AppContext, msg: messaging.Message) void {
    if (msg.msg_type == .public_key and msg.has_public_key and
        msg.pub_key_role == .server)
    {
        if (!ctx.identity.bbs_key_locked and ctx.identity.bbs_key == null) {
            ctx.identity.bbs_key = msg.public_key;
            ctx.store.setBbsKey(msg.public_key) catch {};
        }
    }
}

/// Returns true if `msg` is a type that must be signed by the server (BBS)
/// and verified against the trusted BBS key.
fn isServerMessage(msg: messaging.Message) bool {
    return switch (msg.msg_type) {
        .bulletin_list,
        .bulletin,
        .bulletin_response,
        .bulletin_response_list,
        .registration_ack,
        .user_info,
        .user_info_list,
        .request_status,
        .motd,
        .chat,
        => true,
        .public_key => msg.pub_key_role == .server,
        else => false,
    };
}

/// Verify a server-originated message against the trusted BBS key and, on
/// success, store it in the incoming buffer and dispatch the payload.
fn handleServerMessage(ctx: *AppContext, msg: messaging.Message) IncomingOutcome {
    if (ctx.identity.bbs_key == null) return .{ .sig = .none, .status = .rejected_no_key };
    if (!msg.signed) return .{ .sig = .none, .status = .rejected_unsigned };

    if (!signing.verify(msg.signature, msg.payloadSlice(), ctx.identity.bbs_key.?)) {
        return .{ .sig = .invalid, .status = .rejected_sig };
    }

    const idx = ctx.buffers.incoming_count % types.max_incoming;
    ctx.buffers.incoming[idx] = msg;
    ctx.buffers.sig_statuses[idx] = .valid;
    ctx.buffers.incoming_count += 1;

    incoming.dispatchServerPayload(ctx, msg);

    return .{ .sig = .valid, .status = .accepted };
}

/// Track an overheard packet_request packet from another station for NAK
/// suppression. Operates on the raw packet (not a session Message): the
/// request's own group id names the group being requested.
fn trackOverheardNak(ctx: *AppContext, im: *const transport.IncomingMessage) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .packet_request, im.frame_payload[0..im.frame_payload_len]) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const req = decoded.?.packet_request;
    const now = nowMs(ctx);
    for (req.packet_numbers) |pn| {
        for (&ctx.inbox.overheard_naks) |*on| {
            if (on.active and on.group_id == im.group_id and on.packet_number == pn) {
                on.timestamp = now;
                break;
            }
        } else {
            for (&ctx.inbox.overheard_naks) |*on| {
                if (!on.active) {
                    on.active = true;
                    on.group_id = im.group_id;
                    on.packet_number = pn;
                    on.timestamp = now;
                    break;
                }
            }
        }
    }
}

fn nowMs(ctx: *AppContext) u64 {
    const secs = std.Io.Timestamp.now(ctx.io, .real).toSeconds();
    return @intCast(@max(0, secs) * 1000);
}

