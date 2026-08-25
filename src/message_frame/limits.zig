//! Uncompressed string field length limits for the wire protocol.
//!
//! These constants define the **maximum uncompressed (plain UTF-8) byte
//! length** of each string field. They are checked in each message type's
//! `encode` function *before* Unishox2 compression, so the rejection is
//! predictable and independent of the compressor's behaviour. The wire
//! length-prefix fields (u8 or u16) continue to store the *compressed* byte
//! count (the decoder needs that to know how many bytes to read).
//!
//! Both the client (TUI input validation) and the server (handler validation)
//! import these constants from `@import("bbs")` so the limits are defined in
//! exactly one place.

/// Maximum handle length (uncompressed UTF-8 bytes).
pub const max_handle_len: usize = 20;

/// Maximum callsign length (uncompressed UTF-8 bytes). Matches the AX.25
/// callsign field width (`message_frame.callsign_len`).
pub const max_callsign_len: usize = 10;

/// Maximum bulletin title length (uncompressed UTF-8 bytes).
pub const max_title_len: usize = 80;

/// Maximum bulletin body / response body / MOTD length (uncompressed UTF-8
/// bytes).
pub const max_body_len: usize = 2048;

/// Maximum chat text length (uncompressed UTF-8 bytes).
pub const max_chat_text_len: usize = 256;

/// Maximum avatar text length (uncompressed UTF-8 bytes). The 11×7 grid is
/// ~237 bytes raw; 255 is the u8 length-field cap.
pub const max_avatar_len: usize = 255;

/// Maximum request-status detail length (uncompressed UTF-8 bytes).
pub const max_detail_len: usize = 256;
