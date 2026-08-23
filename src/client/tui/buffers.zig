//! RingBuffers — the four fixed-size ring buffers used by the TUI for
//! incoming messages, the message log, the sent-transmission log, and the
//! chat log.
//!
//! Grouping the arrays and their counts into one struct lets `AppContext`
//! shed 10 fields and lets `logs.zig` / `incoming.zig` / `settings.zig`
//! reference them through `ctx.buffers.*` instead of flat `ctx.*` fields.

const std = @import("std");

const types = @import("types.zig");
const transport = types.transport;

const SigStatus = types.SigStatus;

/// The four ring buffers and their write cursors (counts). Exposed as
/// `ctx.buffers`; `logs.zig` and `incoming.zig` mutate them, while
/// `settings.zig` and `chat.zig` read them for rendering.
pub const RingBuffers = struct {
    // --- Incoming message buffer ---
    incoming: [types.max_incoming]transport.IncomingMessage = undefined,
    incoming_count: usize = 0,
    sig_statuses: [types.max_incoming]SigStatus = .{.none} ** types.max_incoming,

    // --- Message log (every received message, for settings modal) ---
    message_log: [types.max_message_log]types.MsgLogEntry = std.mem.zeroes([types.max_message_log]types.MsgLogEntry),
    message_log_count: usize = 0,

    // --- Sent transmission log ---
    sent_log_lines: [types.max_sent_log][types.log_line_len]u8 = std.mem.zeroes([types.max_sent_log][types.log_line_len]u8),
    sent_log_lens: [types.max_sent_log]usize = std.mem.zeroes([types.max_sent_log]usize),
    sent_log_count: usize = 0,

    // --- Chat log ---
    chat_log: [types.max_chat_log]types.ChatEntry = std.mem.zeroes([types.max_chat_log]types.ChatEntry),
    chat_log_count: usize = 0,

    pub fn init(self: *RingBuffers) void {
        self.incoming_count = 0;
        self.message_log_count = 0;
        self.sent_log_count = 0;
        self.chat_log_count = 0;
    }
};
