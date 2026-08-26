//! Size limits for the wire protocol.
//!
//! Two families of constants live here:
//!
//! **Uncompressed string field limits** — the maximum uncompressed (plain
//! UTF-8) byte length of each string field. These are checked in each message
//! type's `encode` function *before* Unishox2 compression, so the rejection is
//! predictable and independent of the compressor's behaviour. The wire
//! length-prefix fields (u8 or u16) continue to store the *compressed* byte
//! count (the decoder needs that to know how many bytes to read).
//!
//! **Wire payload/packetization limits** — how large an encoded payload may
//! be and how it is split across transport packets. The application codecs
//! (`message_type.zig` encode/decode) and the transport layer
//! (`transport/frame.zig`) both need them, so they are defined in exactly one
//! place here.
//!
//! Both the client (TUI input validation) and the server (handler validation)
//! import these constants from `@import("bbs")`.

const std = @import("std");

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

// ---------------------------------------------------------------------------
// Wire payload / packetization limits (shared by codecs and the transport)
// ---------------------------------------------------------------------------

/// Absolute per-packet capacity of the `MessageFrame` wire format. This
/// sizes the frame's fixed backing array and is the largest payload chunk
/// ANY receiver must be able to parse, regardless of its own link's MTU.
///
/// It is the *ceiling*, not the operational chunk size: each link transport
/// picks its own chunk size via its `Transport.mtu_payload` vtable value
/// (AGWPE 512, direct TCP 1024, a future meshcore ~180), which must not
/// exceed this limit.
pub const max_chunk_len: usize = 1024;

/// Maximum size of a fully encoded payload before multipart splitting.
/// Encode functions check against this (not `max_chunk_len`) so that
/// payloads larger than a single packet can be split by the sender.
pub const max_encode_len: usize = 4096;

/// Maximum number of packets in one multipart message. `packet_number` and
/// `packet_count` are u8 fields in the packet header, so the index space is
/// 0..255 (256 slots). Senders must not split a payload into more than this
/// many chunks.
pub const max_packets_per_message: usize = std.math.maxInt(u8) + 1;
