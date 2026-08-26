//! Transport-layer receive-side packet type and decoder.
//!
//! `IncomingMessage` is what a link transport yields after stripping its own
//! framing: the link addressing it knows from its headers (port, source and
//! destination callsigns) plus the decoded `MessageFrame` fields. It is
//! deliberately *not* the type application handlers see — the session layer
//! (`messaging.zig`) turns these into complete `Message` values, hiding
//! multipart mechanics. The one sanctioned consumer of raw packets above the
//! session core is radio-link policy such as the client's NAK controller.
//!
//! All fields are fixed-size (no heap pointers) so the struct can be copied
//! between threads without ownership concerns.

const std = @import("std");
const signing = @import("../signing.zig");
const message_type = @import("../message_frame/message_type.zig");
const frame = @import("frame.zig");

const MessageType = message_type.MessageType;
const MessageFrame = frame.MessageFrame;

pub const signature_len = frame.signature_len;

/// Length of a callsign field (AX.25 standard, shared by all transports).
pub const callsign_len: usize = 10;

/// Length of an Ed25519 public key.
pub const public_key_len: usize = signing.public_key_len;

/// One received transport packet with its link context. Link transports
/// populate `port` and the callsigns from their own headers, then call
/// `decodePacket` to fill in the message-frame fields. Display/debug
/// formatting (text decompression, hex dumps) is done on-demand by the TUI,
/// NOT stored here.
pub const IncomingMessage = struct {
    /// Radio channel / port the message arrived on.
    port: u4 = 0,
    has_callsign: bool = false,
    callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8),
    callsign_str_len: u8 = 0,
    /// Destination callsign (call_to) from the transport header. Used to
    /// filter directed messages so a client only acts on those addressed to
    /// its own callsign.
    has_dest_callsign: bool = false,
    dest_callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8),
    dest_callsign_str_len: u8 = 0,
    /// True when the payload was a `MessageFrame` with a recognized `MessageType`.
    is_message_frame: bool = false,
    /// Message type from the frame header (valid when `is_message_frame` is true).
    msg_type: MessageType = @enumFromInt(0),
    signed: bool = false,
    signature: [signature_len]u8 = std.mem.zeroes([signature_len]u8),
    /// Raw payload bytes from the MessageFrame (for signature verification).
    frame_payload: [frame.max_encode_len]u8 = std.mem.zeroes([frame.max_encode_len]u8),
    frame_payload_len: u16 = 0,
    /// When `msg_type == .public_key`, the 32-byte public key.
    public_key: [public_key_len]u8 = std.mem.zeroes([public_key_len]u8),
    has_public_key: bool = false,
    /// When `msg_type == .public_key`, the role (client/server) from byte 0.
    pub_key_role: message_type.PublicKeyRole = .client,
    /// Group ID for multipart message reassembly (u4, 0–15).
    group_id: u4 = 0,
    /// Packet number within a multipart message (0-based).
    packet_number: u8 = 0,
    /// Total packet count in the logical message (1 for single-packet).
    packet_count: u8 = 1,
};

/// Parse raw wire bytes into an `IncomingMessage`'s frame fields.
/// Returns `true` if the payload was a valid MessageFrame.
///
/// This is link-neutral: any transport that delivers a raw payload
/// (AGWPE AX.25 info field, TCP envelope frame field, meshcore message body,
/// etc.) calls this to populate the message-frame fields. Display/debug
/// formatting is NOT done here — the TUI handles that on-demand.
pub fn decodePacket(payload: []const u8, msg: *IncomingMessage) bool {
    if (payload.len < MessageFrame.min_wire_size_cont) return false;
    const f = MessageFrame.fromBytes(payload) orelse return false;
    const pl = f.payloadLen();
    if (pl > frame.max_chunk_len) return false;

    msg.is_message_frame = true;
    msg.msg_type = f.messageType();
    msg.group_id = f.groupId();
    msg.packet_number = f.packetNumber();
    msg.packet_count = f.packetCount();
    msg.signed = f.hasSignature();
    if (msg.signed) {
        msg.signature = f.signatureBytes();
    }

    const fp = f.payloadBytes();
    msg.frame_payload_len = @intCast(fp.len);
    @memcpy(msg.frame_payload[0..fp.len], fp);

    // Extract public key if applicable.
    if (msg.msg_type == .public_key and fp.len >= 33) {
        msg.pub_key_role = @enumFromInt(@as(u4, @truncate(fp[0])));
        @memcpy(msg.public_key[0..32], fp[1..33]);
        msg.has_public_key = true;
    }
    return true;
}

test "decodePacket round trips a single-packet frame" {
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const sig = [_]u8{0x11} ** signature_len;
    const f = MessageFrame.init(.motd, &payload, &sig, 2, 0, 1);
    const wire = f.wireBytes();

    var im: IncomingMessage = .{};
    try std.testing.expect(decodePacket(wire, &im));
    try std.testing.expect(im.is_message_frame);
    try std.testing.expectEqual(MessageType.motd, im.msg_type);
    try std.testing.expectEqual(@as(u4, 2), im.group_id);
    try std.testing.expectEqual(@as(u8, 0), im.packet_number);
    try std.testing.expectEqual(@as(u8, 1), im.packet_count);
    try std.testing.expect(im.signed);
    try std.testing.expectEqualSlices(u8, &sig, &im.signature);
    try std.testing.expectEqualSlices(u8, &payload, im.frame_payload[0..im.frame_payload_len]);
}

test "decodePacket rejects garbage" {
    var im: IncomingMessage = .{};
    try std.testing.expect(!decodePacket(&.{}, &im));
    try std.testing.expect(!im.is_message_frame);
}
