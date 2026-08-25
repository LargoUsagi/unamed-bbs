//! Shared types, constants, and helpers used across the TUI logic modules.
//!
//! This is the import target for `app.zig`, `outbox.zig`, `incoming.zig`,
//! `inbox.zig`, and `logs.zig`. It re-exports the wire-format / link-layer /
//! signing modules from `bbs` so the TUI logic siblings can reference
//! them through one import, and it defines the shared value types those
//! modules pass between each other (`SendArgs`, `SendResult`, `Msg`, etc.)
//! along with the ring-buffer sizing constants.

const std = @import("std");
const zz = @import("zigzag");

pub const agwpe = @import("bbs").agwpe;
pub const signing = @import("bbs").signing;
pub const message_frame = @import("bbs").message_frame;
pub const transport = @import("bbs").transport;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const default_host = "127.0.0.1";
pub const default_tcp_port = "8000";
pub const default_radio_port = "0";
pub const default_tcp_server_port = "9000";
pub const default_callsign = "NOCALL";

/// Maximum input message length in characters (before compression).
/// Alias for `message_frame.max_body_len`.
pub const max_message_len: usize = message_frame.max_body_len;

/// Maximum value of a bulletin response id. The id space per bulletin is
/// 0..1023 (a u10). When a bulletin reaches 1024 responses the reply UI is
/// hidden — no more responses can be added.
pub const max_response_id: u16 = 1023;

pub const max_incoming: usize = 50;
pub const max_message_log: usize = 100;
pub const max_sent_log: usize = 8;
pub const log_line_len: usize = 200;
pub const max_err_len: usize = 96;
pub const max_bulletins: usize = 16;
pub const bulletin_title_len: usize = 64;
pub const max_chat_log: usize = 50;
pub const chat_text_len: usize = 256;

/// Maximum chat text length in characters (client-side limit, before
/// compression). The chat input is capped to this value. Alias for
/// `message_frame.max_chat_text_len`.
pub const max_chat_text_len: usize = message_frame.max_chat_text_len;

/// Number of recent chat messages the client requests from the BBS in a
/// `chat_history_request`.
pub const chat_history_count: u8 = 20;

/// Maximum length of a chat author display name in `ChatEntry`, large enough
/// for a user handle (max 20 chars from registration) or "User 65535".
pub const chat_author_len: usize = 24;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Fixed-size bulletin summary stored for the Bulletins screen.
pub const BulletinEntry = struct {
    id: u32 = 0,
    user_id: u16 = 0,
    title: [bulletin_title_len]u8 = std.mem.zeroes([bulletin_title_len]u8),
    title_len: u8 = 0,
};

pub const ChatDirection = enum { sent, recv };

/// A single chat message (received) for the Chat screen log. Only
/// server-signed received messages are shown — outbound messages are
/// deliberately not shown. `author` holds the sender's handle (if the user is
/// cached locally) or "User {id}".
pub const ChatEntry = struct {
    direction: ChatDirection = .recv,
    author: [chat_author_len]u8 = std.mem.zeroes([chat_author_len]u8),
    author_len: u8 = 0,
    text: [chat_text_len]u8 = std.mem.zeroes([chat_text_len]u8),
    text_len: usize = 0,
    sig_status: SigStatus = .none,
    /// Server-set epoch time (seconds) for sorting the chat window. 0 for
    /// locally-composed (sent) messages that haven't been echoed back by
    /// the server yet.
    timestamp: u64 = 0,
};

pub const SigStatus = enum { none, valid, invalid, unknown_key };

/// Outcome of processing an incoming message, used by the message log.
pub const MsgLogStatus = enum {
    accepted, // message was accepted and processed
    rejected_no_key, // server msg rejected: no BBS key to verify against
    rejected_unsigned, // server msg rejected: not signed
    rejected_sig, // server msg rejected: signature verification failed
};

/// A single entry in the message log ring buffer. Captures every incoming
/// message (accepted or rejected) for display in the settings modal.
pub const MsgLogEntry = struct {
    /// "HH:MM:SS" wall-clock time
    time: [8]u8 = std.mem.zeroes([8]u8),
    time_len: u8 = 0,
    /// 3-letter type tag (TXT, KEY, BUL, etc.)
    tag: [4]u8 = std.mem.zeroes([4]u8),
    tag_len: u8 = 0,
    /// Originating callsign (if known)
    callsign: [message_frame.callsign_len]u8 = std.mem.zeroes([message_frame.callsign_len]u8),
    callsign_len: u8 = 0,
    /// Signature verification result
    sig: SigStatus = .none,
    /// Acceptance / rejection outcome
    status: MsgLogStatus = .accepted,
};

/// Returns a 4-byte tag (null-padded) for the message type of an IncomingMessage.
pub fn msgTypeTag(im: *const transport.IncomingMessage) [4]u8 {
    var buf: [4]u8 = std.mem.zeroes([4]u8);
    const tag: []const u8 = if (im.is_message_frame) switch (im.msg_type) {
        .public_key => "KEY",
        .bulletin_request => "BRQ",
        .bulletin => "BUL",
        .bulletin_list => "BLT",
        .public_key_request => "KRQ",
        .bulletin_list_request => "BLR",
        .registration => "REG",
        .registration_ack => "RAK",
        .bulletin_response => "RSP",
        .bulletin_response_list => "RPL",
        .bulletin_response_request => "RRQ",
        .user_info => "USR",
        .user_info_request => "URQ",
        .request_status => "STA",
        .packet_request => "NAK",
        .chat => "CHT",
        .chat_history_request => "CHR",
        .motd => "MOT",
        .motd_request => "MRQ",
        .avatar_update => "AVT",
        .user_info_list => "ULS",
        else => "???",
    } else "RAW";
    @memcpy(buf[0..tag.len], tag);
    return buf;
}

// ---------------------------------------------------------------------------
// Send / connect plumbing
// ---------------------------------------------------------------------------

pub const SendResult = struct {
    ok: bool,
    input_len: usize,
    compressed_len: usize,
    err: []const u8 = "",
    host: [64]u8 = std.mem.zeroes([64]u8),
    host_len: u8 = 0,
    port: u16 = 0,
    kport: u4 = 0,
    signed: bool = false,
};

/// Arguments for the background send task. The caller builds a
/// `message_frame.Payload` directly — the task encodes, signs, and transmits
/// it without needing to know the specific message type.
///
/// `payload` owns any slices it contains (e.g. `bulletin.title`,
/// `chat.text`). The background task frees them via
/// `freePayloadSlices` after encoding.
///
/// `input_len` is the user-facing text length (for log reporting).
/// `send_options` carries transport-level metadata (e.g. `group_id` for
/// packet retransmission requests).
pub const SendArgs = struct {
    transport: transport.Transport,
    host: []const u8,
    port: u16,
    kport: u4,
    secret_key: [signing.secret_key_len]u8,
    payload: message_frame.Payload,
    send_options: transport.SendOptions = .{},
    input_len: usize = 0,
};

/// Result of a background connect attempt.
pub const ConnectResult = struct {
    ok: bool,
    err: [64]u8 = std.mem.zeroes([64]u8),
    err_len: u8 = 0,
    /// Connection parameters used for the attempt — echoed back so the
    /// outbox can capture them (kport for the wire, host/port for the
    /// sent-log display) without re-reading the TUI inputs.
    kport: u4 = 0,
    host: [64]u8 = std.mem.zeroes([64]u8),
    host_len: u8 = 0,
    port: u16 = 0,
};

/// Arguments for the background connect task.
pub const ConnectArgs = struct {
    connection: *agwpe.Connection,
    io: std.Io,
    address: std.Io.net.IpAddress,
    allocator: std.mem.Allocator,
    port: u4,
    callsign: []const u8,
    /// TCP port (for the sent-log display echo). Page-allocated copy owned by
    /// the task.
    tcp_port: u16 = 0,
    /// TNC host string (for the sent-log display echo). Page-allocated copy
    /// owned by the task.
    host: []const u8 = "",
};

// ---------------------------------------------------------------------------
// Msg type (used by Model.update and screen handleKey)
// ---------------------------------------------------------------------------

pub const Msg = union(enum) {
    key: zz.KeyEvent,
    tick: zz.msg.Tick,
    send_done: SendResult,
    connect_done: ConnectResult,
};

// ---------------------------------------------------------------------------
// Pure helper functions
// ---------------------------------------------------------------------------

pub fn callsignEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = std.ascii.toLower(ca);
        const lb = std.ascii.toLower(cb);
        if (la != lb) return false;
    }
    return true;
}

/// Parse 64 hex chars into a 32-byte Ed25519 public key. Returns `null` if
/// the input is not exactly 64 hex characters.
pub fn parseHexKey(hex: []const u8) ?[32]u8 {
    if (hex.len != 64) return null;
    var key: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const hi = std.fmt.charToDigit(hex[i * 2], 16) catch return null;
        const lo = std.fmt.charToDigit(hex[i * 2 + 1], 16) catch return null;
        key[i] = (hi << 4) | lo;
    }
    return key;
}
