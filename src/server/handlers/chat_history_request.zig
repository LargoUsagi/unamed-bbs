//! Handler for `chat_history_request` — returns the most recent N chat
//! messages by broadcasting up to N individual `chat` frames (signed by the
//! server, newest first) so the requester and any other listening station can
//! cache them. If no chats exist, sends a directed `request_status no_data`.

const std = @import("std");

const kiss = @import("bbs");
const transport = kiss.transport;
const signing = kiss.signing;
const message_frame = kiss.message_frame;

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;

const outbox = @import("../outbox.zig");
const routing = @import("../routing.zig");

pub fn handle(ctx: *const ServerCtx, im: transport.IncomingMessage) !void {
    const callsign = im.callsign[0..@min(im.callsign_str_len, message_frame.callsign_len)];
    const payload_bytes = im.frame_payload[0..im.frame_payload_len];
    const allocator = std.heap.page_allocator;

    // A client asks for the most recent N chat messages. The server
    // responds by broadcasting up to N individual `chat` frames
    // (signed by the server, newest first) so the requester — and any
    // other listening station — can cache them.
    try ctx.stderr.print("RX chat_history_request from {s}\n", .{callsign});

    const decoded = message_frame.decodePayload(allocator, .chat_history_request, payload_bytes) catch {
        try ctx.stderr.writeAll("  error: failed to decode chat_history_request\n");
        try ctx.stderr.flush();
        return;
    };
    if (decoded == null) {
        try ctx.stderr.writeAll("  error: malformed chat_history_request\n");
        try ctx.stderr.flush();
        return;
    }
    defer message_frame.deinitPayload(allocator, decoded.?);

    const req = decoded.?.chat_history_request;
    const count = req.count;
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
        try ctx.stderr.print("  no chats — sending request_status no_data to {s}\n", .{callsign});
        try ctx.stderr.flush();
        const status_payload: message_frame.Payload = .{ .request_status = .{
            .request_id = 0,
            .outcome = .no_data,
            .detail = "No chat messages yet.",
        } };
        outbox.send(ctx, im.port, status_payload, .request_status, routing.Route.directed(callsign)) catch {};
        return;
    }

    try ctx.stderr.print("  broadcasting {d} chat(s)\n", .{chats.len});
    try ctx.stderr.flush();

    // Broadcast each chat as an individual `chat` frame (signed by the
    // server) so any client listening can cache it.
    for (chats) |c| {
        const chat_payload: message_frame.Payload = .{ .chat = .{
            .timestamp = c.epoch_time,
            .user_id = c.user_id,
            .text = c.text,
        } };
        outbox.send(ctx, im.port, chat_payload, .chat, .broadcast_source) catch {
            try ctx.stderr.writeAll("  error: failed to send chat\n");
            try ctx.stderr.flush();
            continue;
        };
    }

    try ctx.stderr.print("  TX {d} chat(s)\n", .{chats.len});
    try ctx.stderr.flush();
}
