//! `MessageType` enum and `Payload` tagged union, plus dispatch functions
//! that route encode/decode/deinit calls to the per-message-type modules.
//!
//! The `Payload` union provides typed access to the payload area of a
//! `MessageFrame`. Each variant has a dedicated serialization format in its
//! own file under `message_frame/`.

const std = @import("std");
const frame = @import("frame.zig");

const max_encode_len = frame.max_encode_len;

const public_key = @import("public_key.zig");
const public_key_request = @import("public_key_request.zig");
const bulletin_request_mod = @import("bulletin_request.zig");
const bulletin = @import("bulletin.zig");
const bulletin_list = @import("bulletin_list.zig");
const bulletin_response = @import("bulletin_response.zig");
const registration = @import("registration.zig");
const registration_ack = @import("registration_ack.zig");
const user_info = @import("user_info.zig");
const request_status = @import("request_status.zig");
const packet_request = @import("packet_request.zig");
const motd = @import("motd.zig");
const chat_mod = @import("chat.zig");
const chat_history_request_mod = @import("chat_history_request.zig");
const avatar_update_mod = @import("avatar_update.zig");
const user_info_list_mod = @import("user_info_list.zig");

// Re-export the per-type structs so callers can import everything from one
// place via `message_frame.Payload`, `message_frame.Bulletin`, etc.
pub const PublicKeyRole = public_key.PublicKeyRole;
pub const PublicKeyPayload = public_key.PublicKeyPayload;
pub const BulletinListRequest = bulletin_request_mod.BulletinListRequest;
pub const BulletinRequest = bulletin_request_mod.BulletinRequest;
pub const BulletinRequestMode = bulletin_request_mod.BulletinRequestMode;
pub const Bulletin = bulletin.Bulletin;
pub const BulletinSummary = bulletin_list.BulletinSummary;
pub const BulletinList = bulletin_list.BulletinList;
pub const BulletinResponse = bulletin_response.BulletinResponse;
pub const BulletinResponseList = bulletin_response.BulletinResponseList;
pub const BulletinResponseRequest = bulletin_response.BulletinResponseRequest;
pub const ResponseRequestMode = bulletin_response.ResponseRequestMode;
pub const Registration = registration.Registration;
pub const RegistrationAck = registration_ack.RegistrationAck;
pub const UserInfo = user_info.UserInfo;
pub const UserInfoRequest = user_info.UserInfoRequest;
pub const RequestStatus = request_status.RequestStatus;
pub const RequestOutcome = request_status.Outcome;
pub const PacketRequest = packet_request.PacketRequest;
pub const Motd = motd.Motd;
pub const Chat = chat_mod.Chat;
pub const ChatHistoryRequest = chat_history_request_mod.ChatHistoryRequest;
pub const AvatarUpdate = avatar_update_mod.AvatarUpdate;
pub const UserInfoList = user_info_list_mod.UserInfoList;
pub const chat_max_text_len = chat_mod.max_chat_text_len;

/// Message types carried by a `MessageFrame`. Wire values are u6 (stored in
/// 1 byte), supporting up to 64 distinct types.
///
/// IMPORTANT: The order of variants here MUST match the field order in the
/// `Payload` union below — Zig requires union field order to match enum
/// source order.
pub const MessageType = enum(u6) {
    public_key = 2,
    bulletin_list_request = 3,
    bulletin = 4,
    bulletin_list = 5,
    public_key_request = 6,
    bulletin_request = 7,
    registration = 8,
    registration_ack = 9,
    bulletin_response = 10,
    bulletin_response_list = 11,
    bulletin_response_request = 12,
    user_info = 13,
    user_info_request = 14,
    request_status = 15,
    packet_request = 16,
    motd_request = 17,
    motd = 18,
    chat = 19,
    chat_history_request = 20,
    avatar_update = 21,
    user_info_list = 22,
    _,
};

/// Typed payload carried by a `MessageFrame`. The active variant is determined
/// by the `MessageType` tag stored in the frame header.
///
/// For `public_key`, the payload is a `PublicKeyPayload` (role + 32-byte key).
/// For `public_key_request`, the payload is empty (clients ask the server to
/// broadcast its public key).
/// For `bulletin_request`, `bulletin`, and `bulletin_list`, the payload uses a
/// structured binary encoding (see the per-type files).
/// `bulletin_response`, `bulletin_response_list`, and
/// `bulletin_response_request` carry threaded replies to a bulletin.
/// `registration` carries a client's handle, callsign, and public key.
/// `registration_ack` is the server's reply with the assigned author id.
pub const Payload = union(MessageType) {
    public_key: PublicKeyPayload,
    bulletin_list_request: BulletinListRequest,
    bulletin: Bulletin,
    bulletin_list: BulletinList,
    public_key_request: void,
    bulletin_request: BulletinRequest,
    registration: Registration,
    registration_ack: RegistrationAck,
    bulletin_response: BulletinResponse,
    bulletin_response_list: BulletinResponseList,
    bulletin_response_request: BulletinResponseRequest,
    user_info: UserInfo,
    user_info_request: UserInfoRequest,
    request_status: RequestStatus,
    packet_request: PacketRequest,
    motd_request: void,
    motd: Motd,
    chat: Chat,
    chat_history_request: ChatHistoryRequest,
    avatar_update: AvatarUpdate,
    user_info_list: UserInfoList,
};

/// Serialize a `Payload` into a flat byte buffer suitable for the
/// `MessageFrame` payload field. Returns the number of bytes written, or
/// `null` if the serialized form exceeds `max_encode_len` or `buf` is too
/// small. Dispatches to the per-type `encode` function.
pub fn encodePayload(buf: []u8, payload: Payload) ?usize {
    if (buf.len < max_encode_len) return null;
    return switch (payload) {
        .public_key => |pkp| pkp.encode(buf),
        .public_key_request => public_key_request.encode(buf),
        .bulletin_list_request => |req| req.encode(buf),
        .bulletin_request => |req| req.encode(buf),
        .bulletin => |bul| bul.encode(buf),
        .bulletin_list => |bl| bl.encode(buf),
        .registration => |reg| reg.encode(buf),
        .registration_ack => |ack| ack.encode(buf),
        .bulletin_response => |r| r.encode(buf),
        .bulletin_response_list => |rl| rl.encode(buf),
        .bulletin_response_request => |rr| rr.encode(buf),
        .user_info => |ui| ui.encode(buf),
        .user_info_request => |uir| uir.encode(buf),
        .request_status => |rs| rs.encode(buf),
        .packet_request => |pr| pr.encode(buf),
        .motd_request => 0,
        .motd => |m| m.encode(buf),
        .chat => |c| c.encode(buf),
        .chat_history_request => |r| r.encode(buf),
        .avatar_update => |au| au.encode(buf),
        .user_info_list => |uil| uil.encode(buf),
    };
}

/// Deserialize raw payload bytes into a `Payload`. Allocates slices for types
/// that contain variable-length data (`bulletin`,
/// `bulletin_list`, `bulletin_response`, `bulletin_response_list`). The
/// caller must call `deinitPayload` to free. Returns `null` for unknown
/// message types or malformed data.
pub fn decodePayload(allocator: std.mem.Allocator, msg_type: MessageType, data: []const u8) !?Payload {
    return switch (msg_type) {
        .public_key => blk: {
            const d = public_key.PublicKeyPayload.decode(data) orelse break :blk null;
            break :blk Payload{ .public_key = d };
        },

        .public_key_request => Payload{ .public_key_request = {} },

        .bulletin_list_request => blk: {
            const d = bulletin_request_mod.BulletinListRequest.decode(data) orelse break :blk null;
            break :blk Payload{ .bulletin_list_request = d };
        },

        .bulletin_request => blk: {
            const d = bulletin_request_mod.BulletinRequest.decode(data) orelse break :blk null;
            break :blk Payload{ .bulletin_request = d };
        },

        .bulletin => blk: {
            const d = (try bulletin.Bulletin.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .bulletin = d };
        },

        .bulletin_list => blk: {
            const d = (try bulletin_list.BulletinList.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .bulletin_list = d };
        },

        .registration => blk: {
            const d = (try registration.Registration.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .registration = d };
        },

        .registration_ack => blk: {
            const d = registration_ack.RegistrationAck.decode(data) orelse break :blk null;
            break :blk Payload{ .registration_ack = d };
        },

        .bulletin_response => blk: {
            const d = (try bulletin_response.BulletinResponse.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .bulletin_response = d };
        },

        .bulletin_response_list => blk: {
            const d = (try bulletin_response.BulletinResponseList.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .bulletin_response_list = d };
        },

        .bulletin_response_request => blk: {
            const d = bulletin_response.BulletinResponseRequest.decode(data) orelse break :blk null;
            break :blk Payload{ .bulletin_response_request = d };
        },

        .user_info => blk: {
            const d = (try user_info.UserInfo.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .user_info = d };
        },

        .user_info_request => blk: {
            const d = (try user_info.UserInfoRequest.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .user_info_request = d };
        },

        .request_status => blk: {
            const d = (try request_status.RequestStatus.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .request_status = d };
        },

        .packet_request => blk: {
            const d = (try packet_request.PacketRequest.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .packet_request = d };
        },

        .motd_request => Payload{ .motd_request = {} },

        .motd => blk: {
            const d = (try motd.Motd.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .motd = d };
        },

        .chat => blk: {
            const d = (try chat_mod.Chat.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .chat = d };
        },

        .chat_history_request => blk: {
            const d = chat_history_request_mod.ChatHistoryRequest.decode(data) orelse break :blk null;
            break :blk Payload{ .chat_history_request = d };
        },

        .avatar_update => blk: {
            const d = (try avatar_update_mod.AvatarUpdate.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .avatar_update = d };
        },

        .user_info_list => blk: {
            const d = (try user_info_list_mod.UserInfoList.decode(allocator, data)) orelse break :blk null;
            break :blk Payload{ .user_info_list = d };
        },

        _ => null,
    };
}

/// Free all heap-allocated slices inside a `Payload`. Safe to call on
/// payloads that own no allocations (e.g. `public_key`, `bulletin_request`).
pub fn deinitPayload(allocator: std.mem.Allocator, payload: Payload) void {
    switch (payload) {
        .public_key => {},
        .public_key_request => {},
        .bulletin_request => {},
        .bulletin_list_request => {},
        .bulletin => |bul| bul.deinit(allocator),
        .bulletin_list => |bl| bl.deinit(allocator),
        .registration => |reg| reg.deinit(allocator),
        .registration_ack => {},
        .bulletin_response => |r| r.deinit(allocator),
        .bulletin_response_list => |rl| rl.deinit(allocator),
        .bulletin_response_request => {},
        .user_info => |ui| ui.deinit(allocator),
        .user_info_request => |uir| uir.deinit(allocator),
        .request_status => |rs| rs.deinit(allocator),
        .packet_request => |pr| pr.deinit(allocator),
        .motd_request => {},
        .motd => |m| m.deinit(allocator),
        .chat => |c| c.deinit(allocator),
        .chat_history_request => {},
        .avatar_update => |au| au.deinit(allocator),
        .user_info_list => |uil| uil.deinit(allocator),
    }
}

// ---------------------------------------------------------------------------
// Tests — dispatch round trips (per-type round trips live in each per-type
// file; these verify the dispatcher wires everything together correctly).
// ---------------------------------------------------------------------------

test "encodePayload/decodePayload public_key round trip" {
    const allocator = std.testing.allocator;
    const pk = [_]u8{0x42} ** 32;
    const payload: Payload = .{ .public_key = .{ .role = .server, .public_key = pk } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 33), n);
    try std.testing.expectEqual(@as(u8, 1), buf[0]);

    const decoded = (try decodePayload(allocator, .public_key, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqual(PublicKeyRole.server, decoded.public_key.role);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.public_key.public_key);
}

test "encodePayload/decodePayload public_key_request round trip" {
    const allocator = std.testing.allocator;
    const payload: Payload = .{ .public_key_request = {} };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 0), n);

    const decoded = (try decodePayload(allocator, .public_key_request, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    // Nothing to check for void
}

test "encodePayload/decodePayload bulletin_list_request round trip" {
    const allocator = std.testing.allocator;
    const payload: Payload = .{ .bulletin_list_request = .{ .page = 3, .page_size = 10 } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 3), n);

    const decoded = (try decodePayload(allocator, .bulletin_list_request, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u16, 3), decoded.bulletin_list_request.page);
    try std.testing.expectEqual(@as(u8, 10), decoded.bulletin_list_request.page_size);
}

test "encodePayload/decodePayload bulletin round trip" {
    const allocator = std.testing.allocator;
    const title = "Net Minutes 2026-08-18";
    const body = "The minutes of the net for today.";

    const payload: Payload = .{ .bulletin = .{
        .id = 1,
        .user_id = 42,
        .created_at = 1724022400,
        .title = title,
        .body = body,
    } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;

    const decoded = (try decodePayload(allocator, .bulletin, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u16, 42), decoded.bulletin.user_id);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.bulletin.created_at);
    try std.testing.expectEqualStrings(title, decoded.bulletin.title);
    try std.testing.expectEqualStrings(body, decoded.bulletin.body);
}

test "encodePayload/decodePayload bulletin_list round trip" {
    const allocator = std.testing.allocator;
    const summaries = [_]BulletinSummary{
        .{ .id = 1, .user_id = 10, .title = "Net Minutes" },
        .{ .id = 2, .user_id = 20, .title = "Weather Report" },
    };
    const payload: Payload = .{ .bulletin_list = .{
        .page = 0,
        .total_pages = 3,
        .bulletins = &summaries,
    } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;

    const decoded = (try decodePayload(allocator, .bulletin_list, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u16, 0), decoded.bulletin_list.page);
    try std.testing.expectEqual(@as(u16, 3), decoded.bulletin_list.total_pages);
    try std.testing.expectEqual(@as(usize, 2), decoded.bulletin_list.bulletins.len);
    try std.testing.expectEqual(@as(u32, 1), decoded.bulletin_list.bulletins[0].id);
    try std.testing.expectEqual(@as(u16, 10), decoded.bulletin_list.bulletins[0].user_id);
    try std.testing.expectEqualStrings("Net Minutes", decoded.bulletin_list.bulletins[0].title);
    try std.testing.expectEqual(@as(u32, 2), decoded.bulletin_list.bulletins[1].id);
    try std.testing.expectEqualStrings("Weather Report", decoded.bulletin_list.bulletins[1].title);
}

test "encodePayload rejects bulletin with title > max_title_len bytes" {
    // The uncompressed title length is checked before compression; a title
    // exceeding limits.max_title_len (80) is rejected regardless of how well
    // it would compress.
    const long_title = [_]u8{'x'} ** 81;
    const payload: Payload = .{ .bulletin = .{
        .id = 1,
        .user_id = 0,
        .created_at = 0,
        .title = &long_title,
        .body = &.{},
    } };
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect(encodePayload(&buf, payload) == null);
}

test "encodePayload rejects bulletin with body > max_body_len bytes" {
    const long_body = [_]u8{'x'} ** 2049;
    const payload: Payload = .{ .bulletin = .{
        .id = 1,
        .user_id = 0,
        .created_at = 0,
        .title = "x",
        .body = &long_body,
    } };
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect(encodePayload(&buf, payload) == null);
}

test "encodePayload rejects bulletin_list with > 255 entries" {
    var many: [256]BulletinSummary = undefined;
    for (&many) |*e| e.* = .{ .id = 0, .user_id = 0, .title = "" };
    const payload: Payload = .{ .bulletin_list = .{
        .page = 0,
        .total_pages = 0,
        .bulletins = &many,
    } };
    var buf: [max_encode_len]u8 = undefined;
    try std.testing.expect(encodePayload(&buf, payload) == null);
}

test "decodePayload rejects malformed bulletin (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02 };
    const result = try decodePayload(allocator, .bulletin, &short);
    try std.testing.expect(result == null);
}

test "decodePayload rejects malformed bulletin_list (too short)" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x02 };
    const result = try decodePayload(allocator, .bulletin_list, &short);
    try std.testing.expect(result == null);
}

test "decodePayload returns null for unknown message type" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0x00, 0x01 };
    const unknown: MessageType = @enumFromInt(63);
    const result = try decodePayload(allocator, unknown, &data);
    try std.testing.expect(result == null);
}

test "deinitPayload is safe for non-allocating variants" {
    const allocator = std.testing.allocator;
    deinitPayload(allocator, .{ .public_key = .{ .role = .client, .public_key = [_]u8{0} ** 32 } });
    deinitPayload(allocator, .{ .public_key_request = {} });
    deinitPayload(allocator, .{ .bulletin_list_request = .{ .page = 0, .page_size = 10 } });
    deinitPayload(allocator, .{ .bulletin_request = .{ .mode = .tail_after, .after_id = 123 } });
    deinitPayload(allocator, .{ .registration_ack = .{ .ok = true, .user_id = 5 } });
    deinitPayload(allocator, .{ .bulletin_response_request = .{ .bulletin_id = 1, .mode = .tail_after, .after_id = 0 } });
    deinitPayload(allocator, .{ .user_info_request = .{ .user_ids = &.{} } });
}

test "deinitPayload is safe for empty bulletin_list" {
    const allocator = std.testing.allocator;
    const payload: Payload = .{ .bulletin_list = .{
        .page = 0,
        .total_pages = 0,
        .bulletins = &.{},
    } };
    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    const decoded = (try decodePayload(allocator, .bulletin_list, buf[0..n])) orelse return error.DecodeFailed;
    deinitPayload(allocator, decoded);
}

test "encodePayload/decodePayload registration round trip" {
    const allocator = std.testing.allocator;
    const pk = [_]u8{0xAB} ** 32;
    const payload: Payload = .{ .registration = .{
        .handle = "brad",
        .public_key = pk,
    } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;

    const decoded = (try decodePayload(allocator, .registration, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqualStrings("brad", decoded.registration.handle);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.registration.public_key);
}

test "encodePayload/decodePayload registration_ack round trip" {
    const allocator = std.testing.allocator;
    const payload: Payload = .{ .registration_ack = .{ .ok = true, .user_id = 42 } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 3), n);

    const decoded = (try decodePayload(allocator, .registration_ack, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expect(decoded.registration_ack.ok);
    try std.testing.expectEqual(@as(u16, 42), decoded.registration_ack.user_id);
}

test "encodePayload/decodePayload user_info round trip" {
    const allocator = std.testing.allocator;
    const pk = [_]u8{0xCD} ** 32;
    const payload: Payload = .{ .user_info = .{
        .id = 7,
        .registered_datetime = 1724022400,
        .handle = "brad",
        .callsign = "KE8WIF",
        .public_key = pk,
        .avatar = "█ █\n █ \n█ █",
    } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;

    const decoded = (try decodePayload(allocator, .user_info, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u16, 7), decoded.user_info.id);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.user_info.registered_datetime);
    try std.testing.expectEqualStrings("brad", decoded.user_info.handle);
    try std.testing.expectEqualStrings("KE8WIF", decoded.user_info.callsign);
    try std.testing.expectEqualSlices(u8, &pk, &decoded.user_info.public_key);
    try std.testing.expectEqualStrings("█ █\n █ \n█ █", decoded.user_info.avatar);
}

test "encodePayload/decodePayload user_info_request round trip" {
    const allocator = std.testing.allocator;
    const ids = [_]u16{ 3, 7, 42 };
    const payload: Payload = .{ .user_info_request = .{ .user_ids = &ids } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;

    const decoded = (try decodePayload(allocator, .user_info_request, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 3), decoded.user_info_request.user_ids.len);
    try std.testing.expectEqual(@as(u16, 3), decoded.user_info_request.user_ids[0]);
    try std.testing.expectEqual(@as(u16, 7), decoded.user_info_request.user_ids[1]);
    try std.testing.expectEqual(@as(u16, 42), decoded.user_info_request.user_ids[2]);
}

test "encodePayload/decodePayload bulletin_request tail_after round trip" {
    const payload: Payload = .{ .bulletin_request = .{
        .mode = .tail_after,
        .after_id = 42,
    } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 5), n);

    const decoded = (try decodePayload(std.testing.allocator, .bulletin_request, buf[0..n])) orelse return error.DecodeFailed;
    try std.testing.expectEqual(@as(u32, 42), decoded.bulletin_request.after_id);
}

test "encodePayload/decodePayload bulletin_request range round trip" {
    const payload: Payload = .{ .bulletin_request = .{
        .mode = .range,
        .start_id = 5,
        .end_id = 10,
    } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 9), n);

    const decoded = (try decodePayload(std.testing.allocator, .bulletin_request, buf[0..n])) orelse return error.DecodeFailed;
    try std.testing.expectEqual(@as(u32, 5), decoded.bulletin_request.start_id);
    try std.testing.expectEqual(@as(u32, 10), decoded.bulletin_request.end_id);
}

test "encodePayload/decodePayload request_status round trip" {
    const payload: Payload = .{ .request_status = .{
        .request_id = 42,
        .outcome = .success,
        .detail = "OK",
    } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;

    const decoded = (try decodePayload(std.testing.allocator, .request_status, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(u16, 42), decoded.request_status.request_id);
    try std.testing.expectEqual(RequestOutcome.success, decoded.request_status.outcome);
    try std.testing.expectEqualStrings("OK", decoded.request_status.detail);
}

test "encodePayload/decodePayload packet_request round trip" {
    const missing = [_]u8{ 1, 3 };
    const payload: Payload = .{ .packet_request = .{ .packet_numbers = &missing } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 3), n);

    const decoded = (try decodePayload(std.testing.allocator, .packet_request, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(std.testing.allocator, decoded);
    try std.testing.expectEqual(@as(usize, 2), decoded.packet_request.packet_numbers.len);
    try std.testing.expectEqual(@as(u8, 1), decoded.packet_request.packet_numbers[0]);
    try std.testing.expectEqual(@as(u8, 3), decoded.packet_request.packet_numbers[1]);
}

test "encodePayload/decodePayload chat round trip" {
    const allocator = std.testing.allocator;
    const payload: Payload = .{ .chat = .{
        .timestamp = 1724022400,
        .user_id = 42,
        .text = "Hello from the chat!",
    } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;

    const decoded = (try decodePayload(allocator, .chat, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.chat.timestamp);
    try std.testing.expectEqual(@as(u16, 42), decoded.chat.user_id);
    try std.testing.expectEqualStrings("Hello from the chat!", decoded.chat.text);
}

test "encodePayload/decodePayload chat_history_request round trip" {
    const allocator = std.testing.allocator;
    const payload: Payload = .{ .chat_history_request = .{ .count = 20 } };

    var buf: [max_encode_len]u8 = undefined;
    const n = encodePayload(&buf, payload) orelse return error.EncodeFailed;
    try std.testing.expectEqual(@as(usize, 1), n);

    const decoded = (try decodePayload(allocator, .chat_history_request, buf[0..n])) orelse return error.DecodeFailed;
    defer deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u8, 20), decoded.chat_history_request.count);
}
