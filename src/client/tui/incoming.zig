//! Type-specific dispatch + payload handlers for incoming server messages.
//!
//! The receive mechanics (drain, multipart reassembly, NAK tracking, BBS-key
//! learning, signature verification) live in `inbox.zig`, which calls the two
//! `pub` dispatch functions here — `dispatchServerPayload` for single-packet
//! server messages and `dispatchReassembled` for completed multipart messages.
//! This mirrors the server, where `outbox.zig` owns the send mechanics and
//! handlers call into it; here the inbox owns the receive mechanics and calls
//! out to these handlers.

const std = @import("std");

const types = @import("types.zig");
const app = @import("app.zig");
const identity_mod = @import("identity.zig");
const outbox = @import("outbox.zig");
const logs = @import("logs.zig");

const transport = types.transport;
const message_frame = types.message_frame;

const AppContext = app.AppContext;

/// Dispatch a verified single-packet server payload to the appropriate
/// store/handler based on message type. Called by the inbox after signature
/// verification succeeds.
pub fn dispatchServerPayload(ctx: *AppContext, im: transport.IncomingMessage, payload: []const u8) void {
    switch (im.msg_type) {
        .bulletin_list => populateBulletins(ctx, payload),
        .bulletin => storeBulletin(ctx, payload),
        .bulletin_response => storeBulletinResponse(ctx, payload),
        .bulletin_response_list => storeBulletinResponseList(ctx, payload),
        .registration_ack => handleRegistrationAck(ctx, payload),
        .user_info => storeUserInfo(ctx, payload),
        .user_info_list => storeUserInfoList(ctx, payload),
        .motd => handleMotd(ctx, payload),
        .request_status => handleRequestStatus(ctx, im, payload),
        .chat => storeChat(ctx, payload),
        .public_key => {
            if (im.has_callsign) {
                identity_mod.storePublicKey(ctx, im.callsign[0..im.callsign_str_len], im.public_key);
            }
        },
        else => {},
    }
}

/// Dispatch a reassembled multipart server payload. This is the subset of
/// message types that can arrive multipart (bulletins, responses, user info,
/// MOTD, chat); directed single-packet types like `registration_ack` and
/// `request_status` are handled only via `dispatchServerPayload`. Called by
/// the inbox after signature verification succeeds on the reassembled payload.
pub fn dispatchReassembled(ctx: *AppContext, msg_type: message_frame.MessageType, payload: []const u8) void {
    switch (msg_type) {
        .bulletin_list => populateBulletins(ctx, payload),
        .bulletin => storeBulletin(ctx, payload),
        .bulletin_response => storeBulletinResponse(ctx, payload),
        .bulletin_response_list => storeBulletinResponseList(ctx, payload),
        .user_info => storeUserInfo(ctx, payload),
        .user_info_list => storeUserInfoList(ctx, payload),
        .motd => handleMotd(ctx, payload),
        .chat => storeChat(ctx, payload),
        else => {},
    }
}

fn populateBulletins(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .bulletin_list, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const bl = decoded.?.bulletin_list;
    ctx.bulletins_page = bl.page;
    ctx.bulletins_total_pages = bl.total_pages;

    if (bl.bulletins.len == 0) return;

    var missing_users: std.ArrayList(u16) = .empty;
    defer missing_users.deinit(allocator);

    var min_missing_id: ?u32 = null;
    var max_id: u32 = 0;

    for (bl.bulletins) |s| {
        if (ctx.store.getUserById(s.user_id)) |user| {
            var mut_user = user;
            mut_user.deinit(ctx.store.allocator);
        } else {
            var found = false;
            for (missing_users.items) |mu| {
                if (mu == s.user_id) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                missing_users.append(allocator, s.user_id) catch {};
            }
        }

        var need_request = true;
        if (ctx.store.getById(s.id)) |rec| {
            var mut_rec = rec;
            defer mut_rec.deinit(ctx.store.allocator);
            if (mut_rec.body.len > 0) {
                need_request = false;
            }
        } else {
            _ = ctx.store.addWithId(s.id, s.user_id, 0, s.title, &.{}) catch {};
        }

        if (need_request) {
            if (min_missing_id == null or s.id < min_missing_id.?) {
                min_missing_id = s.id;
            }
        }
        if (s.id > max_id) max_id = s.id;
    }

    if (missing_users.items.len > 0) {
        outbox.sendUserInfoRequest(ctx, missing_users.items);
    }

    if (min_missing_id) |start_id| {
        outbox.sendBulletinRequestRange(ctx, start_id, max_id);
    }
}

fn storeBulletin(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .bulletin, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const b = decoded.?.bulletin;

    if (ctx.store.getById(b.id)) |rec| {
        var mut_rec = rec;
        defer mut_rec.deinit(ctx.store.allocator);
        if (mut_rec.body.len > 0) return;
    }

    _ = ctx.store.addWithId(b.id, b.user_id, b.created_at, b.title, b.body) catch return;

    if (ctx.store.getUserById(b.user_id)) |user| {
        var mut_user = user;
        mut_user.deinit(ctx.store.allocator);
    } else {
        const ids = [_]u16{b.user_id};
        outbox.sendUserInfoRequest(ctx, &ids);
    }
}

fn storeBulletinResponse(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .bulletin_response, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const r = decoded.?.bulletin_response;
    ctx.store.addResponseWithId(r.bulletin_id, r.response_id, r.user_id, r.create_datetime, r.body) catch return;

    if (ctx.store.getUserById(r.user_id)) |user| {
        var mut_user = user;
        mut_user.deinit(ctx.store.allocator);
    } else {
        const ids = [_]u16{r.user_id};
        outbox.sendUserInfoRequest(ctx, &ids);
    }
}

fn storeBulletinResponseList(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .bulletin_response_list, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const rl = decoded.?.bulletin_response_list;

    var missing_users: std.ArrayList(u16) = .empty;
    defer missing_users.deinit(allocator);

    for (rl.responses) |r| {
        ctx.store.addResponseWithId(r.bulletin_id, r.response_id, r.user_id, r.create_datetime, r.body) catch continue;

        if (ctx.store.getUserById(r.user_id)) |user| {
            var mut_user = user;
            mut_user.deinit(ctx.store.allocator);
        } else {
            var found = false;
            for (missing_users.items) |mu| {
                if (mu == r.user_id) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                missing_users.append(allocator, r.user_id) catch {};
            }
        }
    }

    if (missing_users.items.len > 0) {
        outbox.sendUserInfoRequest(ctx, missing_users.items);
    }
}

fn handleRegistrationAck(ctx: *AppContext, payload: []const u8) void {
    const decoded = message_frame.decodePayload(std.heap.page_allocator, .registration_ack, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(std.heap.page_allocator, decoded.?);

    const ack = decoded.?.registration_ack;
    if (ack.ok) {
        ctx.identity.my_user_id = ack.user_id;
        ctx.store.setMyUserId(ack.user_id) catch {};
        // A successful registration means the key was derived from the UI
        // and is now the working signing key, so mark it as restored.
        ctx.identity.key_restored_from_store = true;
        // Stop any auto-register attempt — we're registered now.
        ctx.identity.auto_register = false;
        if (ctx.identity.key_from_ui and ctx.identity.remember_credentials) {
            if (ctx.identity.keypair) |kp| ctx.store.setSecretKey(kp.secretKeyBytes()) catch {};
        }
        ctx.status = std.fmt.allocPrint(std.heap.page_allocator, "Registered as user #{d}.", .{ack.user_id}) catch "Registered.";
        // Ask the model to navigate to the Account screen on the next tick.
        ctx.pending_account_navigation = true;
    } else {
        // Surface the rejection as a status popup (consistent with the
        // key-request timeout error) so the user gets a clear modal.
        var ps = app.PendingStatus{ .outcome = .failure };
        const msg = "Registration rejected by server.";
        const n = @min(msg.len, ps.detail.len);
        @memcpy(ps.detail[0..n], msg[0..n]);
        ps.detail_len = @intCast(n);
        ctx.pending_status = ps;
        ctx.status = "Registration rejected by server.";
    }
}

fn storeUserInfo(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .user_info, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const ui = decoded.?.user_info;
    ctx.store.upsertUserWithId(ui.id, ui.handle, ui.callsign, ui.public_key, ui.registered_datetime, ui.is_sysop, ui.avatar) catch return;

    if (ctx.identity.my_user_id != null and ctx.identity.my_user_id.? == ui.id) {
        ctx.identity.my_is_sysop = ui.is_sysop;
    }

    ctx.store.upsertKnownKey(ui.callsign, ui.public_key) catch {};
}

/// Decode a batched `user_info_list` and upsert every entry, mirroring
/// `storeUserInfo` per user. The server sends this in reply to a
/// `user_info_request` (one message for N users instead of N messages).
fn storeUserInfoList(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .user_info_list, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const list = decoded.?.user_info_list;
    for (list.users) |ui| {
        ctx.store.upsertUserWithId(ui.id, ui.handle, ui.callsign, ui.public_key, ui.registered_datetime, ui.is_sysop, ui.avatar) catch continue;
        if (ctx.identity.my_user_id != null and ctx.identity.my_user_id.? == ui.id) {
            ctx.identity.my_is_sysop = ui.is_sysop;
        }
        ctx.store.upsertKnownKey(ui.callsign, ui.public_key) catch {};
    }
}

fn handleMotd(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .motd, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const m = decoded.?.motd;
    if (ctx.motd_text) |old| allocator.free(@constCast(old));
    ctx.motd_text = allocator.dupe(u8, m.text) catch return;
    ctx.store.setMotd(m.text) catch {};
}

fn handleRequestStatus(ctx: *AppContext, im: transport.IncomingMessage, payload: []const u8) void {
    // `request_status` is always sent directed to a specific callsign. Only
    // show the popup when the destination matches this client's callsign, so
    // overheard status messages addressed to other stations are ignored.
    if (im.has_dest_callsign) {
        const my_callsign = ctx.connection.conn.callsign[0..ctx.connection.conn.callsign_len];
        const dest = im.dest_callsign[0..im.dest_callsign_str_len];
        if (!std.ascii.eqlIgnoreCase(my_callsign, dest)) return;
    }

    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .request_status, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const rs = decoded.?.request_status;
    var ps = app.PendingStatus{ .outcome = rs.outcome };
    const n = @min(rs.detail.len, ps.detail.len);
    @memcpy(ps.detail[0..n], rs.detail[0..n]);
    ps.detail_len = @intCast(n);
    ctx.pending_status = ps;
}

/// Cache a chat message received from the BBS (signed by the server). The
/// server stamps the `timestamp` (epoch time of receipt) and fills in the
/// `user_id` (looked up from the AX.25 callsign of the original sender). The
/// client stores the message in its local `chat_messages` table so the chat
/// window can be assembled and sorted by `timestamp`, and adds it to the
/// in-memory chat log ring buffer for immediate display.
fn storeChat(ctx: *AppContext, payload: []const u8) void {
    const allocator = std.heap.page_allocator;
    const decoded = message_frame.decodePayload(allocator, .chat, payload) catch return;
    if (decoded == null) return;
    defer message_frame.deinitPayload(allocator, decoded.?);

    const c = decoded.?.chat;

    // Cache the chat in the local sqlite so the chat window can be rebuilt on
    // restart and sorted by epoch time.
    ctx.store.addChatMessage(c.timestamp, c.user_id, c.text) catch {};

    // Show the author's handle if the user is cached, otherwise "User {id}".
    // If the author's user info isn't cached, request it from the server so
    // the handle appears on the next message.
    var display_buf: [types.chat_author_len]u8 = undefined;
    const author = logs.formatAuthorDisplayName(ctx, c.user_id, &display_buf);
    if (!author.known and c.user_id != 0) {
        const ids = [_]u16{c.user_id};
        outbox.sendUserInfoRequest(ctx, &ids);
    }

    logs.addChatEntry(ctx, .recv, author.name, c.text, .valid, c.timestamp);
}
