//! Shared message-session mechanics over the `Transport` vtable — the common
//! core extracted from the client (`client/tui/inbox.zig` / `outbox.zig`) and
//! server (`server/inbox.zig` / `outbox.zig`) abstractions.
//!
//! This module IS the Tx/Rx seam the two sides program against. The sides
//! never see link transports' wire process, packetization fields, or
//! reassembly internals — they hand over `(MessageType, Payload)` triples on
//! TX and receive complete `Message` values on RX.
//!
//! Send side: `preparePayload` owns the encode + sign pipeline (encode a
//! `Payload` into a caller buffer, sign it with a `KeyPair` when one is
//! provided). A null key produces an all-zero signature field on the wire,
//! byte-identical to the historical unsigned paths of both sides (the frame
//! `hasSignature()` flag reads false whenever the field is all zeros).
//! `txSend` is the shared transmit loop: encode once, then fan the encoding
//! out to every `TxTarget` — the server fills its targets per a `Route`
//! decision (`TransportPool.fillTargets`, wiring each transport's retransmit
//! cache), the client fills exactly one. Per-target wire failures are
//! captured in `TxResult`, never fatal to the remaining targets; callers
//! decide severity (client: zero-sent = failed send; server: silent).
//!
//! Receive side: `RxCore` owns the multipart reassembler plus the routing
//! every side repeats — packets feed `Reassembler.feed` when they are slices
//! of a larger logical message; everything else becomes a `Message`
//! immediately. Completed groups also surface as one `Message`. Handlers
//! receive only complete logical messages through `RxHandler.onMessage`;
//! `onPacket` is an optional raw view reserved for radio-link policy such as
//! the client's NAK controller. `evictStale` implements the shared 30-second
//! TTL.
//!
//! Policy stays on the sides behind `RxHandler`: signature verification
//! strategy (single trusted BBS key vs per-handler lookup), logging, NAK
//! tracking, and routing decisions are deliberately not here.

const std = @import("std");

const message_frame = @import("../message_frame.zig");
const signing = @import("../signing.zig");

const transport_mod = @import("transport.zig");
const frame_mod = transport_mod.frame;
const incoming_mod = transport_mod.incoming;
const reassembly = @import("reassembly.zig");

const IncomingMessage = incoming_mod.IncomingMessage;
const MessageType = frame_mod.MessageType;
const max_encode_len = frame_mod.max_encode_len;
const callsign_len = incoming_mod.callsign_len;

// ---------------------------------------------------------------------------
// Send side — encode + sign (+ transmit)
// ---------------------------------------------------------------------------

/// Errors from `preparePayload`. Distinct stages so callers can report the
/// failing step (the client maps these to log strings, the server to stderr).
pub const PrepareError = error{
    EncodeFailed,
    SignFailed,
};

/// The result of preparing a payload for transmission: the encoded bytes
/// (a slice into the caller's buffer) and the signature over them.
pub const Prepared = struct {
    /// Encoded payload bytes, valid until the caller's buffer is reused.
    encoded: []const u8,
    /// Signature over `encoded`; all zeros when unsigned.
    sig: [signing.signature_len]u8 = std.mem.zeroes([signing.signature_len]u8),
    signed: bool = false,

    /// The signature slice to hand to `sendMultipart` / routing: empty when
    /// unsigned (renders as an all-zero signature field on the wire).
    pub fn sigSlice(self: *const Prepared) []const u8 {
        return if (self.signed) &self.sig else &.{};
    }
};

/// Encode `payload` into `buf` and sign the encoding with `key`. A null key
/// leaves the frame unsigned (all-zero signature field) — used by the server
/// when no signing key is configured and by the client for the one unsigned
/// request in the protocol (`public_key_request`).
pub fn preparePayload(
    buf: *[max_encode_len]u8,
    payload: message_frame.Payload,
    key: ?signing.KeyPair,
) PrepareError!Prepared {
    const n = message_frame.encodePayload(buf, payload) orelse return PrepareError.EncodeFailed;
    const encoded = buf[0..n];

    const kp = key orelse return .{ .encoded = encoded };
    const sig = kp.sign(encoded) catch return PrepareError.SignFailed;

    return .{ .encoded = encoded, .sig = sig, .signed = true };
}

/// Upper bound on transmit targets per logical message. Matches the server
/// `TransportPool` capacity; the client always fills exactly one.
pub const max_tx_targets: usize = 16;

/// One transmit destination for a prepared message. The server fills one per
/// connected pool transport according to its `Route` decision (wiring each
/// target's retransmit-cache observer); the client fills exactly one.
pub const TxTarget = struct {
    transport: transport_mod.Transport,
    /// Radio channel / KISS port for this transmission.
    port: u4,
    /// Destination callsign ("CQ" for broadcast).
    call_to: []const u8,
    opts: transport_mod.SendOptions = .{},
    /// Optional per-frame callback (the server's retransmit cache).
    observer: ?transport_mod.FrameObserver = null,
};

/// Outcome of `txSend`. Per-target wire failures are captured, not fatal:
/// `first_error` records the first failure and `sent`/`attempted` say how
/// many targets succeeded. Callers decide severity — the client treats a
/// zero-sent result as a failed send, the server logs nothing (matching its
/// historical silent-swallow broadcast behavior).
pub const TxResult = struct {
    attempted: usize = 0,
    sent: usize = 0,
    first_error: ?transport_mod.MultipartError = null,

    /// True when every attempted target transmitted successfully. An empty
    /// target slice counts as success (nothing to fail).
    pub fn ok(self: TxResult) bool {
        return self.sent == self.attempted;
    }
};

/// The shared transmit loop: encode + sign once (`preparePayload`), then
/// hand the encoding to every target. A failing target does not abort the
/// remaining ones — its error is recorded in `TxResult.first_error`.
pub fn txSend(
    msg_type: MessageType,
    payload: message_frame.Payload,
    key: ?signing.KeyPair,
    targets: []const TxTarget,
) PrepareError!TxResult {
    var buf: [max_encode_len]u8 = undefined;
    const prepared = try preparePayload(&buf, payload, key);

    var result: TxResult = .{ .attempted = targets.len };
    for (targets) |tgt| {
        if (transport_mod.sendMultipart(tgt.transport, tgt.port, tgt.call_to, msg_type, prepared.encoded, prepared.sigSlice(), tgt.opts, tgt.observer)) |_| {
            result.sent += 1;
        } else |err| {
            if (result.first_error == null) result.first_error = err;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Receive side — complete messages + multipart routing + eviction
// ---------------------------------------------------------------------------

/// Reassembly entries older than this are evicted by `evictStale`.
pub const stale_timeout_ms: u64 = 30_000;

/// A complete logical message at the session boundary: message type, payload,
/// signature, and the link context (port + source/destination callsigns)
/// copied from the packet that completed it. Multipart mechanics (group ids,
/// packet numbers/counts) are gone by this point — handlers see exactly one
/// of these per logical message regardless of how many packets carried it.
///
/// All fields are fixed-size so the struct can be stored in ring buffers and
/// copied between threads without ownership concerns.
pub const Message = struct {
    // --- Link context ---
    /// Radio channel / port the completing packet arrived on.
    port: u4 = 0,
    has_callsign: bool = false,
    callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8),
    callsign_str_len: u8 = 0,
    has_dest_callsign: bool = false,
    dest_callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8),
    dest_callsign_str_len: u8 = 0,

    // --- Payload + signature ---
    /// Logical message id (0–15). Survives reassembly: senders stamp every
    /// packet of one logical message with the same group id, and NAK
    /// retransmission addresses cached packets by `(group_id, packet_number)`.
    group_id: u4 = 0,
    msg_type: MessageType = @enumFromInt(0),
    /// True when this message was delivered via multipart reassembly (as
    /// opposed to arriving in a single packet).
    reassembled: bool = false,
    signed: bool = false,
    signature: [signing.signature_len]u8 = std.mem.zeroes([signing.signature_len]u8),
    payload_buf: [max_encode_len]u8 = std.mem.zeroes([max_encode_len]u8),
    payload_len: u16 = 0,

    // --- Decode convenience for `.public_key` messages ---
    public_key: [incoming_mod.public_key_len]u8 = std.mem.zeroes([incoming_mod.public_key_len]u8),
    has_public_key: bool = false,
    pub_key_role: message_frame.PublicKeyRole = .client,

    /// The valid portion of the payload buffer.
    pub fn payloadSlice(self: *const Message) []const u8 {
        return self.payload_buf[0..self.payload_len];
    }

    /// The source callsign slice (empty when absent).
    pub fn callsignSlice(self: *const Message) []const u8 {
        return self.callsign[0..@min(self.callsign_str_len, callsign_len)];
    }

    /// The destination callsign slice (empty when absent).
    pub fn destCallsignSlice(self: *const Message) []const u8 {
        return self.dest_callsign[0..@min(self.dest_callsign_str_len, callsign_len)];
    }
};

/// Fill `msg` from a single-packet `IncomingMessage`. Returns false when the
/// packet is not a decoded message frame or its payload exceeds
/// `max_encode_len` (impossible from a compliant sender).
pub fn messageFromPacket(im: *const IncomingMessage, msg: *Message) bool {
    if (!im.is_message_frame) return false;
    copyLinkContext(im, msg);
    msg.group_id = im.group_id;
    copyFrameFields(im.msg_type, im.signed, im.signature, im.frame_payload[0..im.frame_payload_len], msg);
    extractPublicKey(im.msg_type, im.frame_payload[0..im.frame_payload_len], msg);
    return true;
}

fn copyLinkContext(im: *const IncomingMessage, msg: *Message) void {
    msg.port = im.port;
    msg.has_callsign = im.has_callsign;
    msg.callsign = im.callsign;
    msg.callsign_str_len = im.callsign_str_len;
    msg.has_dest_callsign = im.has_dest_callsign;
    msg.dest_callsign = im.dest_callsign;
    msg.dest_callsign_str_len = im.dest_callsign_str_len;
}

fn copyFrameFields(
    msg_type: MessageType,
    signed: bool,
    signature: [signing.signature_len]u8,
    payload: []const u8,
    msg: *Message,
) void {
    msg.msg_type = msg_type;
    msg.signed = signed;
    msg.signature = signature;
    const n: u16 = @intCast(@min(payload.len, max_encode_len));
    @memcpy(msg.payload_buf[0..n], payload[0..n]);
    msg.payload_len = n;
}

fn extractPublicKey(msg_type: MessageType, payload: []const u8, msg: *Message) void {
    if (msg_type == .public_key and payload.len >= 33) {
        msg.pub_key_role = @enumFromInt(@as(u4, @truncate(payload[0])));
        @memcpy(msg.public_key[0..32], payload[1..33]);
        msg.has_public_key = true;
    }
}

/// Callbacks invoked by `RxCore.process`.
///
/// `onMessage` receives each complete logical message exactly once —
/// single-packet frames directly, multipart groups after reassembly (the
/// link context comes from the packet that completed the group). The
/// fixed-size `Message` is owned by the callback.
///
/// `onPacket` is optional and reserved for radio-link policy that must see
/// individual packets before/independent of reassembly (the client's
/// overheard-NAK suppression). It is called for every decoded packet,
/// including multipart intermediates. Leave null when unneeded.
pub const RxHandler = struct {
    ctx: *anyopaque,
    onMessage: *const fn (ctx: *anyopaque, msg: Message) void,
    onPacket: ?*const fn (ctx: *anyopaque, im: *const IncomingMessage) void = null,
    /// Optional diagnostic when a reassembled payload exceeds
    /// `max_encode_len` and cannot be delivered as a `Message`. Receives the
    /// total reassembled size. Leave null to drop silently.
    onOverflow: ?*const fn (ctx: *anyopaque, total: usize) void = null,
};

/// The receive-side mechanical core shared by the client and server inboxes:
/// owns the reassembler and applies the identical multipart-routing rules on
/// both sides. Handlers see only complete `Message`s (plus the optional raw
/// packet hook); reassembly bookkeeping stays inside.
pub const RxCore = struct {
    reassembler: reassembly.Reassembler = .{},

    /// Route one drained incoming packet: multipart frames feed the
    /// reassembler (a completed group invokes `onMessage` once), everything
    /// else becomes a `Message` directly. Non-frame packets invoke neither
    /// callback except through the optional `onPacket` hook.
    pub fn process(self: *RxCore, h: RxHandler, im: *const IncomingMessage, now_ms: u64) void {
        if (!im.is_message_frame) {
            if (h.onPacket) |cb| cb(h.ctx, im);
            return;
        }

        if (h.onPacket) |cb| cb(h.ctx, im);

        if (im.packet_count > 1) {
            if (self.reassembler.feed(im.*, now_ms)) |reassembled| {
                var msg: Message = .{};
                copyLinkContext(im, &msg);
                msg.group_id = reassembled.group_id;
                if (reassembled.payload.len > max_encode_len) {
                    reassembly.Reassembler.freePayload(reassembled.payload);
                    if (h.onOverflow) |cb| cb(h.ctx, reassembled.payload.len);
                    return;
                }
                var sig: [signing.signature_len]u8 = std.mem.zeroes([signing.signature_len]u8);
                var signed = false;
                if (reassembled.signature) |s| {
                    sig = s;
                    signed = true;
                }
                copyFrameFields(reassembled.msg_type, signed, sig, reassembled.payload, &msg);
                msg.reassembled = true;
                reassembly.Reassembler.freePayload(reassembled.payload);
                h.onMessage(h.ctx, msg);
            }
            return;
        }

        var msg: Message = .{};
        if (!messageFromPacket(im, &msg)) return;
        h.onMessage(h.ctx, msg);
    }

    /// Free reassembly entries that have not received a packet within
    /// `stale_timeout_ms`. Returns the number of entries evicted.
    pub fn evictStale(self: *RxCore, now_ms: u64) usize {
        var evicted: usize = 0;
        for (self.reassembler.entriesSlice()) |*entry| {
            if (!entry.active) continue;
            if (now_ms - entry.last_received_ts > stale_timeout_ms) {
                self.reassembler.freeEntry(entry);
                evicted += 1;
            }
        }
        return evicted;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Capturing stub transport for TX tests: records every wire frame passed
/// to `sendWire` without touching a real link. Set `connected = false` to
/// simulate an unreachable link; set `mtu` to exercise per-transport
/// chunk splitting.
const Capture = struct {
    frames: [8][frame_mod.message_frame_size]u8 = undefined,
    lens: [8]usize = @splat(0),
    count: usize = 0,
    connected: bool = true,
    mtu: usize = transport_mod.max_chunk_len,
    /// Storage for the vtable handle returned by `asTransport`. Because
    /// `mtu_payload` is a runtime value, the vtable cannot be an anonymous
    /// literal (that would dangle); each Capture owns its copy.
    vtable_storage: transport_mod.Transport.VTable = undefined,

    fn sendWire(ctx: *anyopaque, _: u4, _: []const u8, wire: []const u8) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        @memcpy(self.frames[self.count][0..wire.len], wire);
        self.lens[self.count] = wire.len;
        self.count += 1;
    }

    fn isConnected(ctx: *anyopaque) bool {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        return self.connected;
    }

    fn drainIncoming(_: *anyopaque, _: []transport_mod.IncomingMessage) usize {
        return 0;
    }

    fn disconnect(_: *anyopaque) void {}

    fn asTransport(self: *Capture) transport_mod.Transport {
        self.vtable_storage = .{
            .mtu_payload = self.mtu,
            .high_bandwidth = false,
            .isConnected = isConnected,
            .sendWire = sendWire,
            .drainIncoming = drainIncoming,
            .disconnect = disconnect,
        };
        return .{ .ctx = @ptrCast(self), .vtable = &self.vtable_storage };
    }
};

test "preparePayload signs the encoding so verify passes" {
    const kp = try signing.KeyPair.fromSeed(@splat(7));
    var buf: [max_encode_len]u8 = undefined;

    const prepared = try preparePayload(&buf, .{ .motd = .{ .text = "hello net" } }, kp);

    try testing.expect(prepared.signed);
    try testing.expectEqual(signing.signature_len, prepared.sigSlice().len);
    try testing.expect(signing.verify(prepared.sig, prepared.encoded, kp.publicKeyBytes()));
}

test "preparePayload with a null key produces an empty signature slice" {
    var buf: [max_encode_len]u8 = undefined;

    const prepared = try preparePayload(&buf, .{ .motd = .{ .text = "anon" } }, null);

    try testing.expect(!prepared.signed);
    try testing.expectEqual(@as(usize, 0), prepared.sigSlice().len);
}

test "txSend transmits to a single target with the signature on packet 0" {
    const kp = try signing.KeyPair.fromSeed(@splat(13));
    var cap = Capture{};
    const targets = [_]TxTarget{.{ .transport = cap.asTransport(), .port = 1, .call_to = "CQ" }};

    const result = try txSend(.motd, .{ .motd = .{ .text = "hello" } }, kp, &targets);

    try testing.expect(result.ok());
    try testing.expectEqual(@as(usize, 1), result.attempted);
    try testing.expectEqual(@as(usize, 1), result.sent);
    try testing.expectEqual(@as(usize, 1), cap.count);

    var buf: [max_encode_len]u8 = undefined;
    const prepared = try preparePayload(&buf, .{ .motd = .{ .text = "hello" } }, kp);

    var im: IncomingMessage = .{};
    try testing.expect(transport_mod.decodePacket(cap.frames[0][0..cap.lens[0]], &im));
    try testing.expect(im.signed);
    try testing.expectEqual(prepared.sig, im.signature);
    try testing.expectEqualSlices(u8, prepared.encoded, im.frame_payload[0..im.frame_payload_len]);
}

test "txSend with a null key sends an unsigned frame" {
    var cap = Capture{};
    const targets = [_]TxTarget{.{ .transport = cap.asTransport(), .port = 0, .call_to = "CQ" }};

    const result = try txSend(.public_key_request, .{ .public_key_request = {} }, null, &targets);

    try testing.expect(result.ok());
    var im: IncomingMessage = .{};
    try testing.expect(transport_mod.decodePacket(cap.frames[0][0..cap.lens[0]], &im));
    try testing.expect(!im.signed);
}

test "txSend continues past a failing target and records first_error" {
    var down = Capture{ .connected = false };
    var up = Capture{};
    const targets = [_]TxTarget{
        .{ .transport = down.asTransport(), .port = 0, .call_to = "CQ" },
        .{ .transport = up.asTransport(), .port = 0, .call_to = "CQ" },
    };

    const result = try txSend(.motd, .{ .motd = .{ .text = "fan-out" } }, null, &targets);

    try testing.expect(!result.ok());
    try testing.expectEqual(@as(usize, 2), result.attempted);
    try testing.expectEqual(@as(usize, 1), result.sent);
    try testing.expectEqual(transport_mod.MultipartError.NotConnected, result.first_error.?);
    try testing.expectEqual(@as(usize, 1), up.count);
}

test "txSend reports NotConnected when no target is reachable" {
    var down = Capture{ .connected = false };
    const targets = [_]TxTarget{.{ .transport = down.asTransport(), .port = 0, .call_to = "CQ" }};

    const result = try txSend(.motd, .{ .motd = .{ .text = "lost" } }, null, &targets);

    try testing.expect(!result.ok());
    try testing.expectEqual(@as(usize, 0), result.sent);
    try testing.expectEqual(transport_mod.MultipartError.NotConnected, result.first_error.?);
}

test "messageFromPacket fills the session Message from a single packet" {
    const payload = [_]u8{ 1, 2, 3, 4 };
    const sig = [_]u8{0x22} ** signing.signature_len;
    const f = frame_mod.MessageFrame.init(.motd, &payload, &sig, 9, 0, 1);
    var im: IncomingMessage = .{};
    im.port = 3;
    im.has_callsign = true;
    im.callsign[0] = 'K';
    im.callsign[1] = 'W';
    im.callsign_str_len = 2;
    im.has_dest_callsign = true;
    @memcpy(im.dest_callsign[0..5], "CQSRV");
    im.dest_callsign_str_len = 5;
    try testing.expect(transport_mod.decodePacket(f.wireBytes(), &im));

    var msg: Message = .{};
    try testing.expect(messageFromPacket(&im, &msg));

    try testing.expectEqual(MessageType.motd, msg.msg_type);
    try testing.expect(msg.signed);
    try testing.expectEqualSlices(u8, &sig, &msg.signature);
    try testing.expectEqualSlices(u8, &payload, msg.payloadSlice());
    try testing.expectEqual(@as(u4, 3), msg.port);
    try testing.expectEqualStrings("KW", msg.callsignSlice());
    try testing.expectEqualStrings("CQSRV", msg.destCallsignSlice());
}

test "RxCore routes single-packet frames to onMessage" {
    var core: RxCore = .{};
    var rec = Recv{};

    core.process(rec.handler(), &makePacket(0, 0, 1, "hi"), 1000);

    try testing.expectEqual(@as(usize, 1), rec.messages);
    try testing.expectEqual(@as(usize, 0), rec.packets_seen);
}

test "RxCore delivers one Message for a completed multipart group" {
    var core: RxCore = .{};
    var rec = Recv{};

    core.process(rec.handler(), &makePacket(3, 0, 3, "aa"), 1000);
    core.process(rec.handler(), &makePacket(3, 1, 3, "bb"), 1100);
    try testing.expectEqual(@as(usize, 0), rec.messages);

    core.process(rec.handler(), &makePacket(3, 2, 3, "cc"), 1200);

    try testing.expectEqual(@as(usize, 1), rec.messages);
    try testing.expectEqualStrings("aabbcc", rec.last_msg.payloadSlice());
    // Link context comes from the completing packet.
    try testing.expectEqualStrings("XY", rec.last_msg.callsignSlice());
    try testing.expect(rec.last_msg.signed == false);
}

test "RxCore.onPacket sees every raw packet including intermediates" {
    var core: RxCore = .{};
    var rec = Recv{};

    core.process(rec.handlerWithPacketHook(), &makePacket(3, 0, 2, "aa"), 1000);
    try testing.expectEqual(@as(usize, 0), rec.messages);
    try testing.expectEqual(@as(usize, 1), rec.packets_seen);

    core.process(rec.handlerWithPacketHook(), &makePacket(3, 1, 2, "bb"), 1100);
    try testing.expectEqual(@as(usize, 1), rec.messages);
    try testing.expectEqual(@as(usize, 2), rec.packets_seen);
}

test "RxCore reports overflow when reassembly exceeds max_encode_len" {
    var core: RxCore = .{};
    var rec = Recv{};

    // 16 full chunks fill max_encode_len exactly; a 17th single byte pushes
    // the reassembled total past the Message payload cap.
    const full = [_]u8{'A'} ** transport_mod.max_chunk_len;
    const total_packets: u8 = @intCast(max_encode_len / full.len + 1);
    var i: u8 = 0;
    while (i < total_packets) : (i += 1) {
        const chunk: []const u8 = if (i == total_packets - 1) full[0..1] else &full;
        var im = makePacket(6, i, total_packets, chunk);
        im.signed = i == 0;
        core.process(rec.overflowHandler(), &im, 1000 + @as(u64, i));
    }

    try testing.expectEqual(@as(usize, 0), rec.messages);
    try testing.expectEqual(@as(usize, 1), rec.overflows);
}

test "RxCore.evictStale frees only entries past the timeout" {
    var core: RxCore = .{};
    var rec = Recv{};

    core.process(rec.handler(), &makePacket(1, 0, 2, "half"), 1000);
    try testing.expectEqual(@as(usize, 0), core.evictStale(1000 + stale_timeout_ms));
    try testing.expectEqual(@as(usize, 1), core.evictStale(1000 + stale_timeout_ms + 1));

    // The freed slot is reusable: the same packet starts a fresh entry.
    core.process(rec.handler(), &makePacket(1, 0, 2, "half"), 40_000);
    try testing.expectEqual(@as(usize, 0), core.evictStale(41_000));
}

/// Records RxHandler invocations.
const Recv = struct {
    messages: usize = 0,
    packets_seen: usize = 0,
    overflows: usize = 0,
    last_msg: Message = .{},

    fn onMessage(ctx: *anyopaque, msg: Message) void {
        const self: *Recv = @ptrCast(@alignCast(ctx));
        self.messages += 1;
        self.last_msg = msg;
    }

    fn onPacket(ctx: *anyopaque, _: *const IncomingMessage) void {
        const self: *Recv = @ptrCast(@alignCast(ctx));
        self.packets_seen += 1;
    }

    fn onOverflow(ctx: *anyopaque, _: usize) void {
        const self: *Recv = @ptrCast(@alignCast(ctx));
        self.overflows += 1;
    }

    fn handler(self: *Recv) RxHandler {
        return .{
            .ctx = @ptrCast(self),
            .onMessage = onMessage,
        };
    }

    fn handlerWithPacketHook(self: *Recv) RxHandler {
        return .{
            .ctx = @ptrCast(self),
            .onMessage = onMessage,
            .onPacket = onPacket,
        };
    }

    fn overflowHandler(self: *Recv) RxHandler {
        return .{
            .ctx = @ptrCast(self),
            .onMessage = onMessage,
            .onOverflow = onOverflow,
        };
    }
};

/// Build a synthetic multipart `IncomingMessage` (unsigned) for RxCore tests.
fn makePacket(group_id: u4, pn: u8, pc: u8, chunk: []const u8) IncomingMessage {
    var im: IncomingMessage = .{};
    im.is_message_frame = true;
    im.msg_type = .motd;
    im.has_callsign = true;
    im.callsign[0] = 'X';
    im.callsign[1] = 'Y';
    im.callsign_str_len = 2;
    im.group_id = group_id;
    im.packet_number = pn;
    im.packet_count = pc;
    @memcpy(im.frame_payload[0..chunk.len], chunk);
    im.frame_payload_len = @intCast(chunk.len);
    return im;
}

test "sendMultipart chunks per-transport MTU" {
    var slow = Capture{ .mtu = 180 };
    var fast = Capture{ .mtu = 1024 };
    const t_slow = slow.asTransport();
    const t_fast = fast.asTransport();

    var payload: [700]u8 = @splat(7);
    const sig = [_]u8{0x33} ** signing.signature_len;

    try transport_mod.sendMultipart(t_slow, 0, "CQ", .motd, &payload, &sig, .{}, null);
    try transport_mod.sendMultipart(t_fast, 0, "CQ", .motd, &payload, &sig, .{}, null);

    // 180-B link: ceil(700/180) = 4 frames; 1024-B link carries it in one.
    try testing.expectEqual(@as(usize, 4), slow.count);
    try testing.expectEqual(@as(usize, 1), fast.count);

    // Packet-count headers reflect each link's own split.
    var im: IncomingMessage = .{};
    try testing.expect(transport_mod.decodePacket(slow.frames[0][0..slow.lens[0]], &im));
    try testing.expectEqual(@as(u8, 4), im.packet_count);
    try testing.expectEqual(@as(u8, 0), im.packet_number);

    var im2: IncomingMessage = .{};
    try testing.expect(transport_mod.decodePacket(fast.frames[0][0..fast.lens[0]], &im2));
    try testing.expectEqual(@as(u8, 1), im2.packet_count);
    try testing.expect(im2.signed);
    try testing.expectEqualSlices(u8, &sig, &im2.signature);
}
