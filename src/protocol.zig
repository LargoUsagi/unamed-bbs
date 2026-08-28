//! Protocol-contract constants and enums shared across the layer stack.
//!
//! This module holds the parts of the BBS wire protocol that are neither
//! transport mechanics nor the store data model: the `MessageType` tag, the
//! per-request mode/role enums, the request-outcome enum, the per-bulletin
//! `max_response_id` bound, and the uncompressed string-field size limits.
//!
//! Both `store/` and `transport/message_frame/` import from here; the module
//! itself imports nothing from either, so the dependency direction stays
//! clean: `store` and `transport` each depend on `protocol`, never on each
//! other. Handlers and screens reach these via `bbs.protocol` so they never
//! have to touch the transport module just to name a message type or check a
//! field-length cap.

const std = @import("std");

// ---------------------------------------------------------------------------
// String-field size limits (uncompressed UTF-8 bytes)
// ---------------------------------------------------------------------------
//
// The maximum uncompressed (plain UTF-8) byte length of each string field.
// These are checked in each message type's `encode` function *before*
// Unishox2 compression, so the rejection is predictable and independent of
// the compressor's behaviour. The wire length-prefix fields (u8 or u16)
// continue to store the *compressed* byte count (the decoder needs that to
// know how many bytes to read).

/// Maximum handle length (uncompressed UTF-8 bytes).
pub const max_handle_len: usize = 20;

/// Maximum callsign length (uncompressed UTF-8 bytes). Matches the AX.25
/// callsign field width (`transport.callsign_len`).
pub const max_callsign_len: usize = 10;

/// Maximum bulletin title length (uncompressed UTF-8 bytes).
pub const max_title_len: usize = 80;

/// Maximum bulletin body / response body / MOTD length (uncompressed UTF-8
/// bytes).
pub const max_body_len: usize = 2048;

/// Maximum chat text length (uncompressed UTF-8 bytes).
pub const max_chat_text_len: usize = 256;

/// Maximum avatar text length (uncompressed UTF-8 bytes). The 11x7 grid is
/// ~237 bytes raw; 255 is the u8 length-field cap.
pub const max_avatar_len: usize = 255;

/// Maximum request-status detail length (uncompressed UTF-8 bytes).
pub const max_detail_len: usize = 256;

// ---------------------------------------------------------------------------
// Data-contract bounds
// ---------------------------------------------------------------------------

/// Maximum value of a bulletin `response_id` (the id space is 0..1023, a
/// u10). When a bulletin reaches this count the reply UI on the client is
/// hidden - no more responses can be added.
pub const max_response_id: u16 = 1023;

// ---------------------------------------------------------------------------
// MessageType
// ---------------------------------------------------------------------------

/// Message types carried by a `MessageFrame`. Wire values are u6 (stored in
/// 1 byte), supporting up to 64 distinct types.
///
/// IMPORTANT: The order of variants here MUST match the field order in the
/// `Payload` union in `transport/message_frame/message_type.zig` - Zig
/// requires union field order to match enum source order.
pub const MessageType = enum(u6) {
    public_key = 2,
    bulletin_list_request = 3,
    bulletin = 4,
    bulletin_list = 5,
    public_key_request = 6,
    bulletin_request = 7,
    registration = 8,
    registration_ack = 9,
    bulletin_response = 10,
    bulletin_response_list = 11,
    bulletin_response_request = 12,
    user_info = 13,
    user_info_request = 14,
    request_status = 15,
    packet_request = 16,
    motd_request = 17,
    motd = 18,
    chat = 19,
    chat_history_request = 20,
    avatar_update = 21,
    user_info_list = 22,
    _,
};

// ---------------------------------------------------------------------------
// Per-request mode / role enums
// ---------------------------------------------------------------------------

/// Mode for a `bulletin_request`.
pub const BulletinRequestMode = enum(u8) {
    /// Send all bulletins with `id > after_id`.
    tail_after = 0,
    /// Send all bulletins with `start_id <= id <= end_id`.
    range = 1,
};

/// Mode for a `bulletin_response_request`.
pub const ResponseRequestMode = enum(u8) {
    /// "I have all of 0..after_id; send everything after after_id."
    tail_after = 0,
    /// "Send responses in the inclusive range [start_id, end_id]."
    range = 1,
};

/// Role encoded in a `public_key` message (u4, stored in the low nibble of
/// the first payload byte). Clients mark their key with `.client`; a
/// bulletin server marks its key with `.server` so receivers know which key
/// to trust for server-originated messages (bulletin lists, etc.).
pub const PublicKeyRole = enum(u4) {
    client = 0,
    server = 1,
    _,
};

/// Outcome of a request, reported back by the server via `request_status`.
/// Wire values are stored as a single byte. New values can be appended;
/// existing values must not be renumbered.
pub const RequestOutcome = enum(u8) {
    /// The request was processed successfully.
    success = 1,
    /// The request failed (e.g. malformed, unauthorized, not found).
    failure = 2,
    /// No response data is available for this request (e.g. no bulletins in
    /// the requested range, no responses for a bulletin).
    no_data = 3,
};

/// Whether a `registration` message is a new-account registration or a login
/// to an existing account. Wire value is a single byte (0 = register, 1 =
/// login). The server uses this to decide whether to create a new user or
/// verify against an existing stored key.
pub const RegistrationMode = enum(u8) {
    register = 0,
    login = 1,
};
