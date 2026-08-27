//! Handler for `chat_history_request` — returns the most recent N chat
//! messages by broadcasting up to N individual `chat` frames (signed by the
//! server, newest first) so the requester and any other listening station can
//! cache them. If no chats exist, sends a directed `request_status no_data`.

const std = @import("std");

const kiss = @import("bbs");

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

const outbox = @import("../outbox.zig");
const routing = @import("../routing.zig");

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta, count: u8) !void {
    // A client asks for the most recent N chat messages. The server
    // responds by broadcasting up to N individual `chat` frames
    // (signed by the server, newest first) so the requester — and any
    // other listening station — can cache them.
    try ctx.stderr.print("RX chat_history_request from {s}\n", .{meta.callsign});
    try ctx.stderr.print("  requesting {d} recent chat(s)\n", .{count});
    try ctx.stderr.flush();

    const chats = ctx.store.listRecentChatMessages(count) catch |err| {
        try ctx.stderr.print("  error: failed to query chat history: {s}\n", .{@errorName(err)});
        try ctx.stderr.flush();
        return;
    };
    defer ctx.store.freeChatRecordList(chats);

    if (chats.len == 0) {
        // No chat history yet — send a directed request_status so the
        // client knows the request was processed but yielded nothing.
        try ctx.stderr.print("  no chats — sending request_status no_data to {s}\n", .{meta.callsign});
        try ctx.stderr.flush();
        outbox.sendRequestStatus(ctx, meta.port, 0, .no_data, "No chat messages yet.", routing.Route.directed(meta.callsign)) catch {};
        return;
    }

    try ctx.stderr.print("  broadcasting {d} chat(s)\n", .{chats.len});
    try ctx.stderr.flush();

    // Broadcast each chat as an individual `chat` frame (signed by the
    // server) so any client listening can cache it.
    for (chats) |c| {
        outbox.sendChat(ctx, meta.port, c.epoch_time, c.user_id, c.text, .broadcast_source) catch {
            try ctx.stderr.writeAll("  error: failed to send chat\n");
            try ctx.stderr.flush();
            continue;
        };
    }

    try ctx.stderr.print("  TX {d} chat(s)\n", .{chats.len});
    try ctx.stderr.flush();
}
