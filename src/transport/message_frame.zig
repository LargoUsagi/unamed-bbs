//! Typed application payloads for the BBS protocol.
//!
//! This is the **application layer** of the wire protocol: it defines
//! `MessageType`, the `Payload` tagged union, and the per-type encode /
//! decode / deinit dispatchers. It knows nothing about transports,
//! packetization, or signatures — those live in `src/transport/`
//! (`frame.zig` builds packets from `(type, bytes, signature)` triples;
//! `messaging.zig` owns signing and multipart splitting).
//!
//! This file is the public entry point for the `message_frame` module:
//!   - `limits.zig` — string-field and wire payload size limits
//!   - `message_type.zig` — `MessageType` enum, `Payload` union, and the
//!     `encodePayload` / `decodePayload` / `deinitPayload` dispatchers
//!   - `public_key.zig`, `public_key_request.zig`,
//!     `bulletin_request.zig`, `bulletin.zig`, `bulletin_list.zig`,
//!     `bulletin_response.zig`, `registration.zig`, `registration_ack.zig`,
//!     `chat.zig`, `chat_history_request.zig`, etc. —
//!     one file per message type with its struct (if any) and
//!     encode/decode/deinit helpers
//!
//! Callers should import this file (e.g. `@import("message_frame.zig")`) and
//! use the re-exported symbols below.

const std = @import("std");

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
const user_info_list = @import("message_frame/user_info_list.zig");
const request_status = @import("message_frame/request_status.zig");
const motd = @import("message_frame/motd.zig");
pub const limits = @import("message_frame/limits.zig");

// Size limits (from `limits.zig`): string fields and wire payload/packetization.
pub const max_handle_len = limits.max_handle_len;
pub const max_callsign_len = limits.max_callsign_len;
pub const max_title_len = limits.max_title_len;
pub const max_body_len = limits.max_body_len;
pub const max_chat_text_len = limits.max_chat_text_len;
pub const max_avatar_len = limits.max_avatar_len;
pub const max_detail_len = limits.max_detail_len;
pub const max_chunk_len = limits.max_chunk_len;
pub const max_encode_len = limits.max_encode_len;
pub const max_packets_per_message = limits.max_packets_per_message;

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
pub const RegistrationMode = message_type.RegistrationMode;
pub const UserInfo = message_type.UserInfo;
pub const UserInfoRequest = message_type.UserInfoRequest;
pub const UserInfoList = message_type.UserInfoList;
pub const RequestStatus = message_type.RequestStatus;
pub const RequestOutcome = message_type.RequestOutcome;
pub const PacketRequest = message_type.PacketRequest;
pub const Motd = message_type.Motd;
pub const Chat = message_type.Chat;
pub const ChatHistoryRequest = message_type.ChatHistoryRequest;
pub const AvatarUpdate = message_type.AvatarUpdate;
pub const chat_max_text_len = message_type.chat_max_text_len;

// Re-export the tests from the sub-modules so `zig build test` picks them up
// when this file is the test entry point.
test {
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
    _ = @import("message_frame/user_info_list.zig");
    _ = @import("message_frame/limits.zig");
}
