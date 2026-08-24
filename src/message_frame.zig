//! Wire format for AGWPE TNC payloads.
//!
//! This file is the public entry point for the `message_frame` module. The
//! actual implementation lives in the `message_frame/` directory:
//!   - `frame.zig` — `MessageFrame` struct and wire-layout constants
//!   - `message_type.zig` — `MessageType` enum, `Payload` union, and the
//!     `encodePayload` / `decodePayload` / `deinitPayload` dispatchers
//!   - `public_key.zig`, `public_key_request.zig`,
//!     `bulletin_request.zig`, `bulletin.zig`, `bulletin_list.zig`,
//!     `bulletin_response.zig`, `registration.zig`, `registration_ack.zig`,
//!     `chat.zig`, `chat_history_request.zig` —
//!     one file per message type with its struct (if any) and
//!     encode/decode/deinit helpers
//!
//! Callers should import this file (e.g. `@import("message_frame.zig")`) and
//! use the re-exported symbols below; existing imports continue to work
//! unchanged.

const std = @import("std");

pub const frame = @import("message_frame/frame.zig");
pub const message_type = @import("message_frame/message_type.zig");
pub const public_key = @import("message_frame/public_key.zig");
pub const public_key_request = @import("message_frame/public_key_request.zig");
pub const bulletin_request = @import("message_frame/bulletin_request.zig");
pub const bulletin = @import("message_frame/bulletin.zig");
pub const bulletin_list = @import("message_frame/bulletin_list.zig");
pub const bulletin_response = @import("message_frame/bulletin_response.zig");
pub const registration = @import("message_frame/registration.zig");
pub const registration_ack = @import("message_frame/registration_ack.zig");
pub const chat = @import("message_frame/chat.zig");
pub const chat_history_request = @import("message_frame/chat_history_request.zig");
const avatar_update = @import("message_frame/avatar_update.zig");
const user_info = @import("message_frame/user_info.zig");
const request_status = @import("message_frame/request_status.zig");
const motd = @import("message_frame/motd.zig");

// Frame layout constants (from `frame.zig`).
pub const protocol_version = frame.protocol_version;
pub const signature_len = frame.signature_len;
pub const max_payload_len = frame.max_payload_len;
pub const max_packets_per_message = frame.max_packets_per_message;
pub const max_encode_len = frame.max_encode_len;
pub const message_frame_size = frame.message_frame_size;
pub const min_wire_size = frame.MessageFrame.min_wire_size;
pub const min_wire_size_cont = frame.MessageFrame.min_wire_size_cont;
pub const max_compressed_len = frame.max_compressed_len;

// `MessageFrame` struct (from `frame.zig`).
pub const MessageFrame = frame.MessageFrame;

// `MessageType`, `Payload`, and dispatch functions (from `message_type.zig`).
pub const MessageType = message_type.MessageType;
pub const Payload = message_type.Payload;
pub const encodePayload = message_type.encodePayload;
pub const decodePayload = message_type.decodePayload;
pub const deinitPayload = message_type.deinitPayload;

// Per-type structs (re-exported from `message_type.zig` for convenience).
pub const PublicKeyRole = message_type.PublicKeyRole;
pub const PublicKeyPayload = message_type.PublicKeyPayload;
pub const BulletinListRequest = message_type.BulletinListRequest;
pub const BulletinRequest = message_type.BulletinRequest;
pub const BulletinRequestMode = message_type.BulletinRequestMode;
pub const Bulletin = message_type.Bulletin;
pub const BulletinSummary = message_type.BulletinSummary;
pub const BulletinList = message_type.BulletinList;
pub const BulletinResponse = message_type.BulletinResponse;
pub const BulletinResponseList = message_type.BulletinResponseList;
pub const BulletinResponseRequest = message_type.BulletinResponseRequest;
pub const ResponseRequestMode = message_type.ResponseRequestMode;
pub const Registration = message_type.Registration;
pub const RegistrationAck = message_type.RegistrationAck;
pub const UserInfo = message_type.UserInfo;
pub const UserInfoRequest = message_type.UserInfoRequest;
pub const RequestStatus = message_type.RequestStatus;
pub const RequestOutcome = message_type.RequestOutcome;
pub const PacketRequest = message_type.PacketRequest;
pub const Motd = message_type.Motd;
pub const Chat = message_type.Chat;
pub const ChatHistoryRequest = message_type.ChatHistoryRequest;
pub const AvatarUpdate = message_type.AvatarUpdate;
pub const chat_max_text_len = message_type.chat_max_text_len;

// ---------------------------------------------------------------------------
// IncomingMessage — transport-neutral decoded message
// ---------------------------------------------------------------------------

/// Length of a callsign field (AX.25 standard, shared by all transports).
pub const callsign_len: usize = 10;

/// Length of an Ed25519 public key.
pub const public_key_len: usize = 32;

/// A decoded incoming message. All fields are fixed-size (no heap pointers)
/// so the struct can be copied between threads without ownership concerns.
///
/// This is transport-neutral: the transport layer (AGWPE, future meshcore,
/// etc.) populates `port` and `callsign` from its own header, then calls
/// `decodeIncoming` to fill in the message-frame fields. Display/debug
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
    frame_payload: [max_encode_len]u8 = std.mem.zeroes([max_encode_len]u8),
    frame_payload_len: u16 = 0,
    /// When `msg_type == .public_key`, the 32-byte public key.
    public_key: [public_key_len]u8 = std.mem.zeroes([public_key_len]u8),
    has_public_key: bool = false,
    /// When `msg_type == .public_key`, the role (client/server) from byte 0.
    pub_key_role: PublicKeyRole = .client,
    /// Group ID for multipart message reassembly (u4, 0–15).
    group_id: u4 = 0,
    /// Packet number within a multipart message (0-based).
    packet_number: u8 = 0,
    /// Total packet count in the logical message (1 for single-packet).
    packet_count: u8 = 1,
};

/// Parse raw wire bytes into an frame fields of `msg`.
/// Returns `true` if the payload was a valid MessageFrame.
///
/// This is transport-neutral: any transport that delivers a raw payload
/// (AGWPE AX.25 info field, meshcore message body, etc.) calls this to
/// populate the message-frame fields. Display/debug formatting is NOT done
/// here — the TUI handles that on-demand.
pub fn decodeIncoming(payload: []const u8, msg: *IncomingMessage) bool {
    if (payload.len < MessageFrame.min_wire_size_cont) return false;
    const f = MessageFrame.fromBytes(payload) orelse return false;
    const pl = f.payloadLen();
    if (pl > max_payload_len) return false;

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

// Re-export the tests from the sub-modules so `zig build test` picks them up
// when this file is the test entry point.
test {
    _ = @import("message_frame/frame.zig");
    _ = @import("message_frame/message_type.zig");
    _ = @import("message_frame/public_key.zig");
    _ = @import("message_frame/public_key_request.zig");
    _ = @import("message_frame/bulletin_request.zig");
    _ = @import("message_frame/bulletin.zig");
    _ = @import("message_frame/bulletin_list.zig");
    _ = @import("message_frame/bulletin_response.zig");
    _ = @import("message_frame/registration.zig");
    _ = @import("message_frame/registration_ack.zig");
    _ = @import("message_frame/user_info.zig");
    _ = @import("message_frame/request_status.zig");
    _ = @import("message_frame/packet_request.zig");
    _ = @import("message_frame/motd.zig");
    _ = @import("message_frame/chat.zig");
    _ = @import("message_frame/chat_history_request.zig");
    _ = @import("message_frame/avatar_update.zig");
}
