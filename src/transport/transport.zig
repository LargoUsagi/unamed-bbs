//! Transport interface and shared send-side multipart splitting.
//!
//! Defines a `Transport` vtable that layer-2 link implementations (AGWPE
//! today, serial/meshcore/UDP in the future) satisfy. The key property each
//! transport exposes is `mtu_payload`: the maximum payload bytes per packet
//! chunk. `sendMultipart` uses this to split an outgoing payload into
//! `MessageFrame` packets of the right size, delegating the actual wire
//! transmission to `transport.sendWire`.
//!
//! Connection establishment (`connect`) is intentionally NOT part of the
//! vtable: its parameters are transport-specific (TCP host:port for AGWPE,
//! serial device path for a future TNC, etc.) and don't share a useful
//! uniform signature. Callers construct and connect the concrete transport
//! (e.g. `agwpe.Connection.connect`) then obtain a `Transport` handle via
//! `asTransport()` for the data plane.

const std = @import("std");
const message_frame = @import("../message_frame.zig");

const MessageFrame = message_frame.MessageFrame;
const MessageType = message_frame.MessageType;

/// Re-exported so callers can reference the incoming-message type through the
/// transport namespace. `IncomingMessage` is transport-neutral — it describes
/// a decoded message-frame payload with source/destination callsigns.
pub const IncomingMessage = message_frame.IncomingMessage;

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
    /// The payload chunk for this specific packet (≤ `max_payload_len`).
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
        /// `message_frame.max_payload_len`); a future transport with a
        /// different MTU (e.g. meshcore at 255-byte radio frames) exposes
        /// its own smaller value. Must not exceed
        /// `message_frame.max_payload_len` (the fixed backing-array cap).
        mtu_payload: usize,

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
    // The frame backing array is sized by `message_frame.max_payload_len`.
    // A transport MTU larger than that would silently truncate chunks, so
    // catch misconfiguration early in debug builds.
    std.debug.assert(chunk_size <= message_frame.max_payload_len);

    // Retransmit path: send a single frame with explicit packet numbers.
    if (opts.packet_override) |po| {
        const chunk_len = @min(payload.len, chunk_size);
        const frame = MessageFrame.init(
            msg_type,
            payload[0..chunk_len],
            sig,
            opts.group_id,
            po.packet_number,
            po.packet_count,
        );
        transport.sendWire(port, call_to, frame.wireBytes()) catch return MultipartError.NotConnected;
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
        const frame = MessageFrame.init(msg_type, payload, sig, opts.group_id, 0, 1);
        transport.sendWire(port, call_to, frame.wireBytes()) catch return MultipartError.NotConnected;
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
    if (total_calc > message_frame.max_packets_per_message) return MultipartError.PayloadTooLarge;
    const total: u8 = @intCast(total_calc);

    var offset: usize = 0;
    var pn: u8 = 0;
    while (offset < payload.len) : (pn += 1) {
        const chunk_len = @min(payload.len - offset, chunk_size);
        const chunk = payload[offset .. offset + chunk_len];
        const frame = if (pn == 0)
            MessageFrame.init(msg_type, chunk, sig, opts.group_id, pn, total)
        else
            MessageFrame.init(msg_type, chunk, &.{}, opts.group_id, pn, total);
        transport.sendWire(port, call_to, frame.wireBytes()) catch return MultipartError.NotConnected;
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
