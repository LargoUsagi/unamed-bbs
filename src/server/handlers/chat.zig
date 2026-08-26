//! Handler for `chat` — stores a chat message from a registered user.
//! Verifies the signature against the user's stored key, stamps the server's
//! epoch time as the primary key, persists it, and re-broadcasts the chat
//! signed by the server so all stations hear it. Rejects unsigned chats or
//! unregistered callsigns with a directed `request_status failure`.

const std = @import("std");

const kiss = @import("bbs");
const messaging = kiss.messaging;
const transport = kiss.transport;
const message_frame = kiss.message_frame;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, msg: messaging.Message) !void {
    const callsign = msg.callsignSlice();
    const payload_bytes = msg.payloadSlice();
    const allocator = std.heap.page_allocator;

    // A client sends a chat to the BBS. The BBS validates the sender
    // is a registered (logged-in) user and the signature is valid,
    // then stores the message with the epoch time of receipt as the
    // primary key and re-broadcasts it signed by the server so
    // everyone in range hears it.
    try ctx.stderr.print("RX chat from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .chat, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode chat\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed chat\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const chat = decoded.?.chat;

    if (chat.text.len > message_frame.max_chat_text_len) {
        try ctx.stderr.writeAll("  error: chat text exceeds limit\n");
        try ctx.stderr.flush();
        outbox.sendChatReject(ctx, msg.port, callsign, "Chat text too long.") catch {};
        return;
    }

    // The chat must be signed by the sender. The sender is identified by
    // their signing key, not by callsign — multiple users may share a
    // callsign, so we verify against every registered user's public key.
    if (!msg.signed) {
        try ctx.stderr.writeAll("  error: chat not signed\n");
        try ctx.stderr.flush();
        outbox.sendChatReject(ctx, msg.port, callsign, "Chat not signed.") catch {};
        return;
    }

    var user = ctx.store.findUserBySignature(msg.signature, payload_bytes) orelse {
        try ctx.stderr.writeAll("  error: chat signature does not match any registered user (not logged in)\n");
        try ctx.stderr.flush();
        outbox.sendChatReject(ctx, msg.port, callsign, "Not logged into the BBS.") catch {};
        return;
    };
    defer user.deinit(ctx.store.allocator);

    // The server stamps the message with the current epoch time, which
    // is also the primary key in the chat_messages table.
    const now_secs: u64 = @intCast(@max(0, std.Io.Timestamp.now(ctx.io, .real).toSeconds()));

    ctx.store.addChatMessage(now_secs, user.id, chat.text) catch |err| {
        try ctx.stderr.print("  error: failed to store chat: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        outbox.sendChatReject(ctx, msg.port, callsign, "Server error storing chat.") catch {};
        return;
    };

    try ctx.stderr.print("  stored: epoch={d} user={d} body={d}B total={d}\n", .{
        now_secs, user.id, chat.text.len, ctx.store.countChatMessages(),
    });
    try ctx.stderr.flush();

    // Re-broadcast the chat to CQ signed by the server (with the
    // server-set timestamp and the canonical user id) so everyone in
    // range hears it.
    const chat_payload: message_frame.Payload = .{ .chat = .{
        .timestamp = now_secs,
        .user_id = user.id,
        .text = chat.text,
    } };
    try outbox.send(ctx, msg.port, chat_payload, .chat, .broadcast_all);

    try ctx.stderr.print("  TX chat broadcast epoch={d} user={d}\n", .{ now_secs, user.id });
    try ctx.stderr.flush();
}
