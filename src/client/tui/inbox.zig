//! Inbox — the client-side receive abstraction, mirroring the server's
//! `outbox.zig`. Owns the receive mechanics (drain + multipart reassembly +
//! NAK tracking + BBS-key learning + signature verification) so the rest of
//! the client code is transport-neutral: type-specific `store*` / `handle*`
//! dispatch lives in `incoming.zig` and is invoked by the inbox, exactly
//! inverted from how server handlers call *into* the outbox to send.
//!
//! The inbox holds a `transport.Transport` vtable handle (obtained from
//! `agwpe.Connection.asTransport()` on connect). A future meshcore transport
//! hands in its own `Transport` handle without touching `incoming.zig`,
//! `logs.zig`, or `outbox.zig` — the same extensibility property the server
//! enjoys via `TransportPool`.

const std = @import("std");

const types = @import("types.zig");
const app = @import("app.zig");
const outbox = @import("outbox.zig");
const logs = @import("logs.zig");
const incoming = @import("incoming.zig");

const signing = types.signing;
const message_frame = types.message_frame;
const transport = @import("bbs").transport;
const reassembly_mod = @import("bbs").reassembly;

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

/// Owns the receive-side state: the transport handle, the multipart
/// reassembler, and the overheard-NAK suppression table. Exposed as
/// `ctx.inbox`; `tick()` calls `drain` then `processTimeouts`.
pub const Inbox = struct {
    /// Transport handle set on successful connect (`conn.asTransport()`).
    /// null until the first connect succeeds. The underlying `agwpe.Connection`
    /// field address is stable for the program's life, so the handle remains
    /// valid across reconnects (drain is guarded by `isConnected()`).
    transport: ?transport.Transport = null,
    reassembler: reassembly_mod.Reassembler = .{},
    overheard_naks: [16]OverheardNak = std.mem.zeroes([16]OverheardNak),

    /// Attach (or refresh) the transport handle after a successful connect.
    pub fn setTransport(self: *Inbox, t: transport.Transport) void {
        self.transport = t;
    }

    /// Drain queued incoming messages from the transport and process each one.
    /// Called from `tick()`. Does nothing when no transport is attached or the
    /// transport is not connected (e.g. during the reconnect window, where the
    /// underlying connection may be mid-teardown/rebuild).
    pub fn drain(self: *Inbox, ctx: *AppContext) void {
        const t = self.transport orelse return;
        if (!t.isConnected()) return;

        var buf: [16]transport.IncomingMessage = undefined;
        const n = t.drainIncoming(&buf);
        for (buf[0..n]) |im| self.addIncoming(ctx, im);
    }

    /// Process reassembly timeouts and send NAKs for missing packets, then
    /// age out stale overheard-NAK entries. Called from `tick()` every 200ms.
    /// Safe to run regardless of connection state: NAK sends self-guard on
    /// `isConnected()`, and reassembler cleanup is connection-independent.
    pub fn processTimeouts(self: *Inbox, ctx: *AppContext) void {
        const now = nowMs(ctx);

        for (self.reassembler.entriesSlice()) |*entry| {
            if (!entry.active) continue;

            // 30-second total timeout → evict.
            if (now - entry.last_received_ts > 30_000) {
                ctx.status = "Multipart message timed out.";
                self.reassembler.freeEntry(entry);
                continue;
            }

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
                self.reassembler.freeEntry(entry);
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

    /// Entry point for a single drained incoming message. Routes multipart
    /// frames to the reassembler (not logged), tracks overheard NAKs, learns
    /// the BBS key, then dispatches server messages (verified against the
    /// trusted BBS key) and logs every single-packet message exactly once.
    fn addIncoming(self: *Inbox, ctx: *AppContext, im: transport.IncomingMessage) void {
        // Route multipart frames to the reassembly buffer.
        if (im.is_message_frame and im.packet_count > 1) {
            self.handleMultipartPacket(ctx, im);
            return;
        }

        // Track overheard packet_request messages from other stations for NAK suppression.
        if (im.is_message_frame and im.msg_type == .packet_request and im.has_callsign) {
            self.trackOverheardNak(ctx, im);
        }

        self.maybeLearnBbsKey(ctx, im);

        const outcome: IncomingOutcome = if (isServerMessage(im))
            self.handleServerMessage(ctx, im)
        else
            .{ .sig = .none, .status = .accepted };

        logs.logIncoming(ctx, im, outcome.sig, outcome.status);
    }

    /// Learn the BBS (server) public key from a signed server-role `public_key`
    /// frame, unless the key was hard-locked via --bbs-key.
    fn maybeLearnBbsKey(self: *Inbox, ctx: *AppContext, im: transport.IncomingMessage) void {
        _ = self;
        if (im.is_message_frame and im.msg_type == .public_key and
            im.has_public_key and im.pub_key_role == .server and im.has_callsign)
        {
            if (!ctx.identity.bbs_key_locked and ctx.identity.bbs_key == null) {
                ctx.identity.bbs_key = im.public_key;
                ctx.store.setBbsKey(im.public_key) catch {};
            }
        }
    }

    /// Returns true if `im` is a message-frame type that must be signed by the
    /// server (BBS) and verified against the trusted BBS key.
    fn isServerMessage(im: transport.IncomingMessage) bool {
        if (!im.is_message_frame) return false;
        return switch (im.msg_type) {
            .bulletin_list,
            .bulletin,
            .bulletin_response,
            .bulletin_response_list,
            .registration_ack,
            .user_info,
            .request_status,
            .motd,
            .chat,
            => true,
            .public_key => im.pub_key_role == .server,
            else => false,
        };
    }

    /// Verify a server-originated message against the trusted BBS key and, on
    /// success, store it in the incoming buffer and dispatch the payload.
    fn handleServerMessage(self: *Inbox, ctx: *AppContext, im: transport.IncomingMessage) IncomingOutcome {
        _ = self;
        if (ctx.identity.bbs_key == null) return .{ .sig = .none, .status = .rejected_no_key };
        if (!im.signed) return .{ .sig = .none, .status = .rejected_unsigned };

        const payload = im.frame_payload[0..im.frame_payload_len];
        if (!signing.verify(im.signature, payload, ctx.identity.bbs_key.?)) {
            return .{ .sig = .invalid, .status = .rejected_sig };
        }

        const idx = ctx.buffers.incoming_count % types.max_incoming;
        ctx.buffers.incoming[idx] = im;
        ctx.buffers.sig_statuses[idx] = .valid;
        ctx.buffers.incoming_count += 1;

        incoming.dispatchServerPayload(ctx, im, payload);

        return .{ .sig = .valid, .status = .accepted };
    }

    /// Handle an incoming multipart packet. Feeds it to the reassembler; when
    /// all packets have arrived the reassembler returns the concatenated
    /// payload, which we verify and dispatch. Multipart frames are not logged.
    fn handleMultipartPacket(self: *Inbox, ctx: *AppContext, im: transport.IncomingMessage) void {
        const now_ms: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()) * 1000);
        const msg = self.reassembler.feed(im, now_ms) orelse return;

        // Verify signature (from packet 0) against the reassembled payload.
        const sig_valid = if (msg.signature) |sig|
            if (ctx.identity.bbs_key) |bbs| signing.verify(sig, msg.payload, bbs) else false
        else
            false;

        const allocator = std.heap.page_allocator;
        if (!sig_valid) {
            allocator.free(msg.payload);
            return;
        }

        // Dispatch the reassembled payload through the type-specific handlers.
        incoming.dispatchReassembled(ctx, msg.msg_type, msg.payload);

        allocator.free(msg.payload);
    }

    /// Track an overheard packet_request from another station for NAK suppression.
    fn trackOverheardNak(self: *Inbox, ctx: *AppContext, im: transport.IncomingMessage) void {
        const allocator = std.heap.page_allocator;
        const decoded = message_frame.decodePayload(allocator, .packet_request, im.frame_payload[0..im.frame_payload_len]) catch return;
        if (decoded == null) return;
        defer message_frame.deinitPayload(allocator, decoded.?);

        const req = decoded.?.packet_request;
        const now = nowMs(ctx);
        for (req.packet_numbers) |pn| {
            for (&self.overheard_naks) |*on| {
                if (on.active and on.group_id == im.group_id and on.packet_number == pn) {
                    on.timestamp = now;
                    break;
                }
            } else {
                for (&self.overheard_naks) |*on| {
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
};

fn nowMs(ctx: *AppContext) u64 {
    const secs = std.Io.Timestamp.now(ctx.io, .real).toSeconds();
    return @intCast(@max(0, secs) * 1000);
}
