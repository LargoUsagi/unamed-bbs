//! Wire payload / packetization limits.
//!
//! These define how large an encoded payload may be and how it is split
//! across transport packets. The application codecs (`message_type.zig`
//! encode/decode) and the transport layer (`transport/frame.zig`) both need
//! them, so they are defined in exactly one place here.
//!
//! The string-field size limits (`max_handle_len`, `max_title_len`, …) that
//! constrain the *uncompressed* form of each field live in
//! `src/protocol.zig` (shared with `store/` and handlers); the per-type
//! encode functions import them from there.

const std = @import("std");

const protocol = @import("../../protocol.zig");

pub const max_handle_len = protocol.max_handle_len;
pub const max_callsign_len = protocol.max_callsign_len;
pub const max_title_len = protocol.max_title_len;
pub const max_body_len = protocol.max_body_len;
pub const max_chat_text_len = protocol.max_chat_text_len;
pub const max_avatar_len = protocol.max_avatar_len;
pub const max_detail_len = protocol.max_detail_len;
pub const max_response_id = protocol.max_response_id;

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
