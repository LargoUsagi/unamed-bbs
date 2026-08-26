//! Log ring buffers — sent-transmission log, chat log, and incoming-message log.
//!
//! These are pure append-to-ring-buffer operations shared by the root model
//! and the incoming-message handler. Extracted from `app.zig` to keep the
//! root model focused on state ownership and lifecycle.

const std = @import("std");

const types = @import("types.zig");
const app = @import("app.zig");
const transport = types.transport;
const message_frame = types.message_frame;

const AppContext = app.AppContext;
const SendResult = types.SendResult;
const ChatDirection = types.ChatDirection;
const SigStatus = types.SigStatus;

/// Load up to `types.max_chat_log` cached chat messages from the local
/// `chat_messages` table into the in-memory chat log ring buffer, sorted
/// ascending by epoch time so the chat window displays them in chronological
/// order. Called once during `AppContext.init` so the chat window is
/// assembled from the persisted cache on startup. Chats whose author is not
/// yet cached locally are shown with a numeric placeholder; a `user_info`
/// request for the missing ids is fired so they get resolved.
pub fn loadChatHistoryFromStore(ctx: *AppContext) void {
    // Fetch the most recent chats (the store returns them newest-first).
    const recent = ctx.store.listRecentChatMessages(@intCast(types.max_chat_log)) catch return;
    defer ctx.store.freeChatRecordList(recent);
    if (recent.len == 0) return;

    // The store returns newest-first; insert oldest-first so the ring buffer
    // displays chats in chronological order (the chat screen shows the tail
    // of the ring buffer).
    var i: usize = recent.len;
    while (i > 0) {
        i -= 1;
        const r = recent[i];

        // Resolve the author's display name from the local user cache. This
        // shows the user's handle if available, otherwise "User {id}".
        var display_buf: [types.chat_author_len]u8 = undefined;
        const display = formatAuthorDisplayName(ctx, r.user_id, &display_buf).name;

        addChatEntry(ctx, .recv, display, r.text, .valid, r.epoch_time);
    }
}

/// Build the display name for a chat author. Returns the user's handle if the
/// user is cached locally, otherwise `User {id}` (or `BBS` for user id 0).
/// Writes into `buf` (which should be at least `types.chat_author_len`
/// bytes) and returns a slice of it. `known` is true when the author's user
/// info was found in the local cache.
pub fn formatAuthorDisplayName(ctx: *AppContext, user_id: u16, buf: []u8) struct { name: []const u8, known: bool } {
    if (user_id == 0) return .{ .name = "BBS", .known = true };
    if (ctx.store.getUserById(user_id)) |user| {
        var mut_user = user;
        defer mut_user.deinit(ctx.store.allocator);
        const n = @min(mut_user.handle.len, buf.len);
        @memcpy(buf[0..n], mut_user.handle[0..n]);
        return .{ .name = buf[0..n], .known = true };
    }
    const s = std.fmt.bufPrint(buf, "User {d}", .{user_id}) catch return .{ .name = buf[0..0], .known = false };
    return .{ .name = s, .known = false };
}

/// Record the outcome of a background send task into the sent-transmission
/// ring buffer and update `ctx.status`. Called from `Model.update` when a
/// `send_done` message arrives.
pub fn recordSendResult(ctx: *AppContext, sr: SendResult) void {
    ctx.outbox.busy = false;

    const host = sr.host[0..sr.host_len];
    const idx = ctx.buffers.sent_log_count % types.max_sent_log;
    const line = &ctx.buffers.sent_log_lines[idx];
    const pct: u64 = if (sr.input_len == 0) 100 else
        @as(u64, sr.compressed_len) * 100 / @as(u64, sr.input_len);

    const written: ?[]const u8 = if (sr.ok)
        std.fmt.bufPrint(line, "[OK]{s} {s}:{d} k{d}  {d}->{d}B ({d}%)", .{
            if (sr.signed) " \xe2\x9c\x93" else "", host, sr.port, sr.kport,
            sr.input_len, sr.compressed_len, pct,
        }) catch null
    else
        std.fmt.bufPrint(line, "[FAIL] {s}:{d}  {d}->{d}B  err: {s}", .{
            host, sr.port, sr.input_len, sr.compressed_len, sr.err,
        }) catch null;

    ctx.buffers.sent_log_lens[idx] = if (written) |w| w.len else 0;
    ctx.buffers.sent_log_count += 1;
    if (sr.ok) {
        ctx.status = "Transmitted successfully.";
    } else {
        ctx.status = "Send failed.";
    }
}

/// Append an entry to the chat log ring buffer. `timestamp` is the server-set
/// epoch time (seconds) for received chats. Outbound messages are not added
/// to the chat log (the chat window shows only server-signed received chats).
/// `author` is the display name (handle or "User {id}").
///
/// De-duplicates by `timestamp` (the server-stamped epoch time, which is the
/// primary key of the `chat_messages` table): if an entry with the same
/// timestamp already exists in the ring buffer (e.g. it was loaded from the
/// SQLite cache at startup, or a `chat_history_request` re-sent a message
/// already received live), the existing entry is left in place and no
/// duplicate is appended. This keeps the chat window in chronological order
/// without duplicate lines when history is requested.
pub fn addChatEntry(
    ctx: *AppContext,
    dir: ChatDirection,
    author: []const u8,
    text: []const u8,
    sig: SigStatus,
    timestamp: u64,
) void {
    if (chatEntryExists(ctx, timestamp)) return;
    const idx = ctx.buffers.chat_log_count % types.max_chat_log;
    var entry = &ctx.buffers.chat_log[idx];
    entry.direction = dir;
    entry.timestamp = timestamp;
    entry.author = std.mem.zeroes([types.chat_author_len]u8);
    const an = @min(author.len, types.chat_author_len);
    @memcpy(entry.author[0..an], author[0..an]);
    entry.author_len = @intCast(an);
    const tn = @min(text.len, types.chat_text_len);
    @memcpy(entry.text[0..tn], text[0..tn]);
    entry.text_len = tn;
    entry.sig_status = sig;
    ctx.buffers.chat_log_count += 1;
}

/// Returns true when an entry with the given `timestamp` is already present
/// in the chat log ring buffer. Used by `addChatEntry` to de-duplicate
/// history-request replies and live messages that overlap with the cached
/// history. Scans only the valid (non-overwritten) entries.
pub fn chatEntryExists(ctx: *AppContext, timestamp: u64) bool {
    const total = @min(ctx.buffers.chat_log_count, types.max_chat_log);
    var i: usize = 0;
    while (i < total) : (i += 1) {
        const idx = i % types.max_chat_log;
        if (ctx.buffers.chat_log[idx].timestamp == timestamp) return true;
    }
    return false;
}

/// Append an entry to the message log ring buffer. Called once for every
/// complete incoming message (accepted or rejected).
pub fn logIncoming(
    ctx: *AppContext,
    msg: types.messaging.Message,
    sig: SigStatus,
    status: types.MsgLogStatus,
) void {
    const idx = ctx.buffers.message_log_count % types.max_message_log;
    var entry = &ctx.buffers.message_log[idx];

    // Timestamp "HH:MM:SS" from wall-clock time.
    entry.time_len = blk: {
        const ts = std.Io.Timestamp.now(ctx.io, .real);
        const secs_signed = ts.toSeconds();
        if (secs_signed < 0) break :blk 0;
        const secs: u64 = @intCast(secs_signed);
        const es = std.time.epoch.EpochSeconds{ .secs = secs };
        const ds = es.getDaySeconds();
        const buf = std.fmt.bufPrint(&entry.time, "{d:0>2}:{d:0>2}:{d:0>2}", .{
            ds.getHoursIntoDay(),
            ds.getMinutesIntoHour(),
            ds.getSecondsIntoMinute(),
        }) catch break :blk 0;
        break :blk @intCast(buf.len);
    };

    // Type tag
    entry.tag = types.msgTypeTag(&msg);
    entry.tag_len = 3;

    // Callsign
    if (msg.has_callsign) {
        const cs = msg.callsignSlice();
        const cn = @min(cs.len, transport.callsign_len);
        @memcpy(entry.callsign[0..cn], cs[0..cn]);
        entry.callsign_len = @intCast(cn);
    } else {
        entry.callsign_len = 0;
    }

    entry.sig = sig;
    entry.status = status;

    ctx.buffers.message_log_count += 1;
}
