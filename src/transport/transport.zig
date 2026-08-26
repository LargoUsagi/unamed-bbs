//! Transport abstraction — the general data plane between concrete link
//! implementations (AGWPE today, serial/meshcore/UDP in the future) and the
//! session layer (`messaging.zig`).
//!
//! Defines a `Transport` vtable that link implementations satisfy. The key
//! property each transport exposes is `mtu_payload`: the maximum payload bytes
//! per packet chunk. `sendMultipart` uses this to split an outgoing encoded
//! payload into `MessageFrame` packets of the right size (`frame.zig`),
//! delegating the actual wire transmission to `transport.sendWire`. On the
//! receive side links yield decoded `IncomingMessage` packets
//! (`incoming.zig`) which the session layer turns into complete messages.
//!
//! Connection establishment (`connect`) is intentionally NOT part of the
//! vtable: its parameters are transport-specific (TCP host:port for AGWPE,
//! serial device path for a future TNC, etc.) and don't share a useful
//! uniform signature. Callers construct and connect the concrete transport
//! (e.g. `agwpe.Connection.connect`) then obtain a `Transport` handle via
//! `asTransport()` for the data plane.

const std = @import("std");

pub const frame = @import("frame.zig");
pub const incoming = @import("incoming.zig");

const MessageFrame = frame.MessageFrame;
const MessageType = frame.MessageType;

/// Re-exported so callers can reference the incoming-packet type through the
/// transport namespace.
pub const IncomingMessage = incoming.IncomingMessage;
pub const decodePacket = incoming.decodePacket;
pub const callsign_len = incoming.callsign_len;
pub const max_encode_len = frame.max_encode_len;
pub const max_chunk_len = frame.max_chunk_len;
pub const max_packets_per_message = frame.max_packets_per_message;

/// Options passed to `sendMultipart`. Transport-neutral: any concrete
/// transport that supports multipart splitting uses these.
pub const SendOptions = struct {
    /// Logical message identifier (0–15).  Used by receivers to group
    /// multipart packets and by NAK retransmission to look up cached frames.
    group_id: u4 = 0,
    /// When set, send a single frame with these explicit packet_number /
    /// packet_count values instead of auto-splitting.  Used for NAK
    /// retransmission of a specific packet from a multipart message.
    packet_override: ?struct { packet_number: u8, packet_count: u8 } = null,
};

/// Information about a single frame built by `sendMultipart`, passed to an
/// optional `FrameObserver`.  The server uses this to populate its
/// retransmission cache.
pub const FrameInfo = struct {
    msg_type: MessageType,
    group_id: u4,
    packet_number: u8,
    packet_count: u8,
    /// The payload chunk for this specific packet (≤ `max_chunk_len`).
    chunk: []const u8,
    /// Ed25519 signature over the *full* payload (empty for continuation
    /// packets where `packet_number > 0`).
    signature: []const u8,
};

/// Observer callback invoked for every frame built by `sendMultipart`.
/// Pass `null` when you don't need per-frame info (e.g. the TUI client).
pub const FrameObserver = struct {
    ctx: *anyopaque,
    observe: *const fn (ctx: *anyopaque, info: FrameInfo) void,
};

/// Opaque transport handle backed by a vtable. A concrete transport (e.g.
/// `agwpe.Connection`) constructs one via `asTransport()`.
pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Maximum payload bytes per packet chunk. `sendMultipart` splits
        /// outgoing payloads into chunks of this size. AGWPE: 256 (matches
        /// `message_frame.max_chunk_len`); a future transport with a
        /// different MTU (e.g. meshcore at 255-byte radio frames) exposes
        /// its own smaller value. Must not exceed
        /// `message_frame.max_chunk_len` (the fixed backing-array cap).
        mtu_payload: usize,

        /// True when the transport is a high-bandwidth link (e.g. direct
        /// TCP/IP). False for low-bandwidth radio links (AGWPE/AX.25, a
        /// future meshcore transport). The client UI uses this to decide
        /// whether to auto-fetch data on page entry (e.g. request the
        /// bulletins list, bulletin bodies, and responses) that would be
        /// wasteful or impolite over a slow radio channel. Pure capability
        /// flag — does not affect framing or the wire protocol.
        high_bandwidth: bool,

        /// True when the link needs periodic unsolicited broadcasts
        /// (beacons): half-duplex shared-medium channels (e.g. AX.25 ham
        /// radio via AGWPE) where listeners join at any time and only hear
        /// traffic actually transmitted on the frequency. False for
        /// connected point-to-point links (direct TCP) where clients pull
        /// data themselves and beacons are pure waste. The server's
        /// heartbeat consults this per transport and only beacons links
        /// whose own last-transmit time has gone stale.
        requires_beacon: bool,

        /// Returns true while the transport is connected and usable.
        isConnected: *const fn (ctx: *anyopaque) bool,

        /// Send pre-built message-frame wire bytes as a UI frame to
        /// `call_to` (or broadcast). The transport wraps them in its own
        /// layer-2 framing (e.g. AGWPE 'V' command with AX.25 header).
        sendWire: *const fn (
            ctx: *anyopaque,
            port: u4,
            call_to: []const u8,
            wire: []const u8,
        ) anyerror!void,

        /// Drain queued incoming messages into `dest`. Returns the count.
        drainIncoming: *const fn (
            ctx: *anyopaque,
            dest: []IncomingMessage,
        ) usize,

        /// Tear down the connection.
        disconnect: *const fn (ctx: *anyopaque) void,
    };

    pub inline fn mtuPayload(self: Transport) usize {
        return self.vtable.mtu_payload;
    }

    /// True when this transport is a high-bandwidth link (e.g. direct TCP/IP).
    /// UI code uses this to gate automatic data fetches that would be wasteful
    /// over a slow radio link. Returns false when no transport is attached
    /// (callers check `inbox.isHighBandwidth()` which guards the null case).
    pub inline fn isHighBandwidth(self: Transport) bool {
        return self.vtable.high_bandwidth;
    }

    /// True when this link expects periodic unsolicited broadcasts
    /// (beacons). The server's heartbeat checks this per transport before
    /// deciding to transmit.
    pub inline fn requiresBeacon(self: Transport) bool {
        return self.vtable.requires_beacon;
    }

    pub inline fn isConnected(self: Transport) bool {
        return self.vtable.isConnected(self.ctx);
    }

    pub inline fn sendWire(
        self: Transport,
        port: u4,
        call_to: []const u8,
        wire: []const u8,
    ) !void {
        return self.vtable.sendWire(self.ctx, port, call_to, wire);
    }

    pub inline fn drainIncoming(self: Transport, dest: []IncomingMessage) usize {
        return self.vtable.drainIncoming(self.ctx, dest);
    }

    pub inline fn disconnect(self: Transport) void {
        self.vtable.disconnect(self.ctx);
    }
};

/// Errors from `sendMultipart`.
pub const MultipartError = error{
    /// Payload would require more than `max_packets_per_message` chunks.
    PayloadTooLarge,
    /// Transport is not connected (or a `sendWire` call failed).
    NotConnected,
};

/// Split `payload` into chunks of `transport.mtuPayload()`, build a
/// `MessageFrame` per chunk, and call `transport.sendWire(...)` for each.
/// The Ed25519 `signature` (computed over the *full* payload) is carried
/// on packet 0 only; continuation packets send an empty signature.
///
/// `opts.group_id` identifies the logical message (0–15) so receivers can
/// group the packets. When `opts.packet_override` is set, a single frame is
/// sent with the explicit packet_number/packet_count (used for NAK
/// retransmission) instead of auto-splitting.
///
/// `observer` (optional) is invoked with `FrameInfo` for every frame built,
/// so callers (e.g. the server) can cache per-packet info for retransmission.
pub fn sendMultipart(
    transport: Transport,
    port: u4,
    call_to: []const u8,
    msg_type: MessageType,
    payload: []const u8,
    sig: []const u8,
    opts: SendOptions,
    observer: ?FrameObserver,
) MultipartError!void {
    if (!transport.isConnected()) return MultipartError.NotConnected;

    const chunk_size = transport.mtuPayload();
    // The frame backing array is sized by `frame.max_chunk_len`.
    // A transport MTU larger than that would silently truncate chunks, so
    // catch misconfiguration early in debug builds.
    std.debug.assert(chunk_size <= frame.max_chunk_len);

    // Retransmit path: send a single frame with explicit packet numbers.
    if (opts.packet_override) |po| {
        const chunk_len = @min(payload.len, chunk_size);
        const frame_pkt = MessageFrame.init(
            msg_type,
            payload[0..chunk_len],
            sig,
            opts.group_id,
            po.packet_number,
            po.packet_count,
        );
        transport.sendWire(port, call_to, frame_pkt.wireBytes()) catch return MultipartError.NotConnected;
        if (observer) |o| o.observe(o.ctx, .{
            .msg_type = msg_type,
            .group_id = opts.group_id,
            .packet_number = po.packet_number,
            .packet_count = po.packet_count,
            .chunk = payload[0..chunk_len],
            .signature = sig,
        });
        return;
    }

    // Single-packet message: fits in one chunk.
    if (payload.len <= chunk_size) {
        const frame_pkt = MessageFrame.init(msg_type, payload, sig, opts.group_id, 0, 1);
        transport.sendWire(port, call_to, frame_pkt.wireBytes()) catch return MultipartError.NotConnected;
        if (observer) |o| o.observe(o.ctx, .{
            .msg_type = msg_type,
            .group_id = opts.group_id,
            .packet_number = 0,
            .packet_count = 1,
            .chunk = payload,
            .signature = sig,
        });
        return;
    }

    // Multipart: split into chunks, signature on packet 0 only.
    const total_calc = std.math.divTrunc(usize, payload.len + chunk_size - 1, chunk_size) catch unreachable;
    if (total_calc > frame.max_packets_per_message) return MultipartError.PayloadTooLarge;
    const total: u8 = @intCast(total_calc);

    var offset: usize = 0;
    var pn: u8 = 0;
    while (offset < payload.len) : (pn += 1) {
        const chunk_len = @min(payload.len - offset, chunk_size);
        const chunk = payload[offset .. offset + chunk_len];
        const frame_pkt = if (pn == 0)
            MessageFrame.init(msg_type, chunk, sig, opts.group_id, pn, total)
        else
            MessageFrame.init(msg_type, chunk, &.{}, opts.group_id, pn, total);
        transport.sendWire(port, call_to, frame_pkt.wireBytes()) catch return MultipartError.NotConnected;
        if (observer) |o| o.observe(o.ctx, .{
            .msg_type = msg_type,
            .group_id = opts.group_id,
            .packet_number = pn,
            .packet_count = total,
            .chunk = chunk,
            .signature = if (pn == 0) sig else &.{},
        });
        offset += chunk_len;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A stub VTable for testing `isHighBandwidth` without a real transport.
const StubCtx = struct {};

fn stubIsConnected(_: *anyopaque) bool {
    return true;
}
fn stubSendWire(_: *anyopaque, _: u4, _: []const u8, _: []const u8) anyerror!void {}
fn stubDrainIncoming(_: *anyopaque, _: []IncomingMessage) usize {
    return 0;
}
fn stubDisconnect(_: *anyopaque) void {}

// The vtable literals carry runtime `high_bandwidth` / `requires_beacon`
// values, so they must live in static vars — an anonymous literal would be a
// dangling temporary.
test "Transport.isHighBandwidth reflects the vtable field" {
    const vtable_high: Transport.VTable = .{
        .mtu_payload = 256,
        .high_bandwidth = true,
        .requires_beacon = false,
        .isConnected = stubIsConnected,
        .sendWire = stubSendWire,
        .drainIncoming = stubDrainIncoming,
        .disconnect = stubDisconnect,
    };
    const vtable_low: Transport.VTable = .{
        .mtu_payload = 256,
        .high_bandwidth = false,
        .requires_beacon = true,
        .isConnected = stubIsConnected,
        .sendWire = stubSendWire,
        .drainIncoming = stubDrainIncoming,
        .disconnect = stubDisconnect,
    };
    var ctx: *StubCtx = undefined;
    const high = Transport{ .ctx = @ptrCast(&ctx), .vtable = &vtable_high };
    const low = Transport{ .ctx = @ptrCast(&ctx), .vtable = &vtable_low };

    try testing.expect(high.isHighBandwidth());
    try testing.expect(!low.isHighBandwidth());
    try testing.expect(!high.requiresBeacon());
    try testing.expect(low.requiresBeacon());
}
