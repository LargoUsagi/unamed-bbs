//! Handler for `chat` — stores a chat message from a registered user.
//! Verifies the signature against the user's stored key, stamps the server's
//! epoch time as the primary key, persists it, and re-broadcasts the chat
//! signed by the server so all stations hear it. Rejects unsigned chats or
//! unregistered callsigns with a directed `request_status failure`.

const std = @import("std");

const kiss = @import("bbs");
const protocol = kiss.protocol;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta, text: []const u8) !void {
    // A client sends a chat to the BBS. The BBS validates the sender
    // is a registered (logged-in) user and the signature is valid,
    // then stores the message with the epoch time of receipt as the
    // primary key and re-broadcasts it signed by the server so
    // everyone in range hears it.
    try ctx.stderr.print("RX chat from {s}\n", .{meta.callsign});

    if (text.len > protocol.max_chat_text_len) {
        try ctx.stderr.writeAll("  error: chat text exceeds limit\n");
        try ctx.stderr.flush();
        outbox.sendChatReject(ctx, meta.port, meta.callsign, "Chat text too long.") catch {};
        return;
    }

    // The chat must be signed by the sender. The sender is identified by
    // their signing key, not by callsign — multiple users may share a
    // callsign, so we verify against every registered user's public key.
    if (!meta.signed) {
        try ctx.stderr.writeAll("  error: chat not signed\n");
        try ctx.stderr.flush();
        outbox.sendChatReject(ctx, meta.port, meta.callsign, "Chat not signed.") catch {};
        return;
    }

    var user = ctx.store.findUserBySignature(meta.signature, meta.payload_bytes) orelse {
        try ctx.stderr.writeAll("  error: chat signature does not match any registered user (not logged in)\n");
        try ctx.stderr.flush();
        outbox.sendChatReject(ctx, meta.port, meta.callsign, "Not logged into the BBS.") catch {};
        return;
    };
    defer user.deinit(ctx.store.allocator);

    // The server stamps the message with the current epoch time, which
    // is also the primary key in the chat_messages table.
    const now_secs: u64 = kiss.time.nowSecs(ctx.io);

    ctx.store.addChatMessage(now_secs, user.id, text) catch |err| {
        try ctx.stderr.print("  error: failed to store chat: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        outbox.sendChatReject(ctx, meta.port, meta.callsign, "Server error storing chat.") catch {};
        return;
    };

    try ctx.stderr.print("  stored: epoch={d} user={d} body={d}B total={d}\n", .{
        now_secs, user.id, text.len, ctx.store.countChatMessages(),
    });
    try ctx.stderr.flush();

    // Re-broadcast the chat to CQ signed by the server (with the
    // server-set timestamp and the canonical user id) so everyone in
    // range hears it.
    try outbox.sendChat(ctx, meta.port, now_secs, user.id, text, .broadcast_all);

    try ctx.stderr.print("  TX chat broadcast epoch={d} user={d}\n", .{ now_secs, user.id });
    try ctx.stderr.flush();
}
