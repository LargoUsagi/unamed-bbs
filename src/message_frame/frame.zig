//! `MessageFrame` — the wire-format struct carried inside an AGWPE data frame.
//!
//! Combines an Ed25519 signature and a typed payload into a struct backed by a
//! fixed byte array. The callsign is NOT included — it comes from the AGWPE
//! frame header (AX.25 source address) on the receive side, and is supplied by
//! the application on the send side.
//!
//! Layout for **packet 0** (the first packet of a logical message, always carries
//! the signature):
//!   offset 0      version+msg_type (2 bytes: version u4 + msg_type u6 + group_id u4)
//!   offset 2      packet_number  (u8)
//!   offset 3      packet_count   (u8)
//!   offset 4..5   payload_len    (u16, little-endian)
//!   offset 6..69  signature      (64 bytes, Ed25519 — present on packet 0 only)
//!   offset 70+    payload        (up to 256 bytes)
//!
//! Layout for **packet 1+** (continuation packets, no signature):
//!   offset 0      version+msg_type (same 2-byte packing)
//!   offset 2      packet_number  (u8)
//!   offset 3      packet_count   (u8)
//!   offset 4..5   payload_len    (u16, little-endian)
//!   offset 6+     payload        (up to 256 bytes)
//!
//! The signature is over the **full reassembled payload** (not per-packet).
//! Single-packet messages use packet_number=0, packet_count=1.

const std = @import("std");
const message_type = @import("message_type.zig");

const MessageType = message_type.MessageType;
const Payload = message_type.Payload;
const encodePayload = message_type.encodePayload;

/// Current protocol version (hardcoded; reserved for future protocol changes).
/// Stored as a u4 (values 0–15).
pub const protocol_version: u4 = 0;

/// Length of the Ed25519 signature field (present on packet 0 only).
pub const signature_len: usize = 64;

/// Maximum payload per packet that fits in a `MessageFrame`.
pub const max_payload_len: usize = 256;

/// Maximum number of packets in one multipart message.
/// `packet_number` and `packet_count` are u8 fields in the wire header, so
/// the index space is 0..255 (256 slots). Senders must not split a payload
/// into more than this many chunks.
pub const max_packets_per_message: usize = std.math.maxInt(u8) + 1;

/// Maximum size of a fully encoded payload before multipart splitting.
/// Encode functions check against this (not `max_payload_len`) so that
/// payloads larger than a single frame can be split by the sender.
pub const max_encode_len: usize = 4096;

/// Header size (6 bytes): version+msg_type(2) + packet_number(1) + packet_count(1) + payload_len(2).
const header_len: usize = 6;

/// Offset of the group_id field (packed into byte 1, bits [5:2]).
const group_id_off: usize = 1;
/// Offset of the packet_number field.
const packet_number_off: usize = 2;
/// Offset of the packet_count field.
const packet_count_off: usize = 3;
/// Offset of the payload_len field.
const payload_len_off: usize = 4;
/// Offset of the signature field (only present when packet_number == 0).
const signature_off: usize = header_len;
/// Offset of the payload when packet_number == 0 (after signature).
const payload_off_p0: usize = header_len + signature_len;
/// Offset of the payload when packet_number > 0 (no signature).
const payload_off_p1: usize = header_len;

/// Total size of a `MessageFrame` backing array in bytes (worst case: packet 0
/// with max payload + signature).
pub const message_frame_size: usize = payload_off_p0 + max_payload_len;

/// Deprecated alias for `max_payload_len`.
pub const max_compressed_len: usize = max_payload_len;

/// Wire format carried inside an AGWPE data frame.
pub const MessageFrame = struct {
    bytes: [message_frame_size]u8 = std.mem.zeroes([message_frame_size]u8),

    /// Build a frame from a raw payload slice and Ed25519 signature.
    ///
    /// For packet 0 (first packet): the signature is written at offset 6 and
    /// the payload at offset 70.
    /// For packets 1+ (continuation): no signature field; the payload starts
    /// at offset 6. Pass an empty signature slice for continuation packets.
    ///
    /// `group_id` identifies the logical message (0–15), `packet_number` is the
    /// 0-based index, `packet_count` is the total number of packets (1 for
    /// single-packet messages).
    pub fn init(
        msg_type: MessageType,
        payload: []const u8,
        signature: []const u8,
        group_id: u4,
        packet_number: u8,
        packet_count: u8,
    ) MessageFrame {
        var f: MessageFrame = .{};

        // Pack version (u4) + msg_type (u6) + group_id (u4) into bytes[0..2].
        // Byte 0: [version:4 | msg_type[5:2]:4]
        // Byte 1: [msg_type[1:0]:2 | group_id:4 | 0:2]
        const mt_val: u8 = @intCast(@intFromEnum(msg_type));
        f.bytes[0] = (@as(u8, protocol_version) << 4) | (mt_val >> 2);
        f.bytes[1] = ((mt_val & 0x03) << 6) | (@as(u8, group_id) << 2);

        f.bytes[packet_number_off] = packet_number;
        f.bytes[packet_count_off] = packet_count;

        const pn: u16 = @intCast(@min(payload.len, max_payload_len));
        std.mem.writeInt(u16, f.bytes[payload_len_off..][0..2], pn, .little);

        if (packet_number == 0) {
            // Packet 0: signature at offset 6, payload at offset 70.
            const sn = @min(signature.len, signature_len);
            @memcpy(f.bytes[signature_off..][0..sn], signature[0..sn]);
            @memcpy(f.bytes[payload_off_p0..][0..pn], payload[0..pn]);
        } else {
            // Continuation: payload at offset 6, no signature.
            @memcpy(f.bytes[payload_off_p1..][0..pn], payload[0..pn]);
        }

        return f;
    }

    /// Build a frame from a typed `Payload` and Ed25519 signature.
    /// Uses group_id=0, packet_number=0, packet_count=1 (single-packet).
    /// Returns `null` if the serialized payload exceeds `max_payload_len`.
    pub fn fromPayload(payload: Payload, signature: []const u8) ?MessageFrame {
        var buf: [max_encode_len]u8 = undefined;
        const n = encodePayload(&buf, payload) orelse return null;
        const tag: MessageType = std.meta.activeTag(payload);
        // If the encoded payload fits in a single frame, return it directly.
        if (n <= max_payload_len) {
            return MessageFrame.init(tag, buf[0..n], signature, 0, 0, 1);
        }
        // Payload too large for a single frame — caller must use multipart splitting.
        return null;
    }

    /// Returns the protocol version (u4).
    pub fn version(self: *const MessageFrame) u4 {
        return @truncate(self.bytes[0] >> 4);
    }

    /// Returns the message type.
    pub fn messageType(self: *const MessageFrame) MessageType {
        const mt_val: u6 = @truncate(((self.bytes[0] & 0x0F) << 2) | (self.bytes[1] >> 6));
        return @enumFromInt(mt_val);
    }

    /// Returns the group ID (u4) — identifies the logical message for reassembly.
    pub fn groupId(self: *const MessageFrame) u4 {
        return @truncate((self.bytes[group_id_off] >> 2) & 0x0F);
    }

    /// Returns the packet number (0-based index within a multi-packet message).
    pub fn packetNumber(self: *const MessageFrame) u8 {
        return self.bytes[packet_number_off];
    }

    /// Returns the packet count (total packets in the logical message).
    pub fn packetCount(self: *const MessageFrame) u8 {
        return self.bytes[packet_count_off];
    }

    /// Returns the number of valid bytes in the payload.
    pub fn payloadLen(self: *const MessageFrame) u16 {
        return std.mem.readInt(u16, self.bytes[payload_len_off..][0..2], .little);
    }

    /// Returns the offset where the payload starts in the backing array.
    pub fn payloadOffset(self: *const MessageFrame) usize {
        return if (self.packetNumber() == 0) payload_off_p0 else payload_off_p1;
    }

    /// Returns the 64-byte Ed25519 signature field (packet 0 only).
    /// Returns zeroes for continuation packets.
    pub fn signatureBytes(self: *const MessageFrame) [signature_len]u8 {
        if (self.packetNumber() != 0) return std.mem.zeroes([signature_len]u8);
        return self.bytes[signature_off..][0..signature_len].*;
    }

    /// Returns true if this is packet 0 with a non-zero signature.
    pub fn hasSignature(self: *const MessageFrame) bool {
        if (self.packetNumber() != 0) return false;
        for (self.bytes[signature_off..][0..signature_len]) |b| {
            if (b != 0) return true;
        }
        return false;
    }

    /// Returns the valid portion of the payload.
    pub fn payloadBytes(self: *const MessageFrame) []const u8 {
        const n = @min(self.payloadLen(), max_payload_len);
        const off = self.payloadOffset();
        return self.bytes[off..][0..n];
    }

    /// Returns only the meaningful bytes for transmission. For packet 0 this
    /// includes the 64-byte signature; for continuation packets it does not.
    /// No zero-padding is sent over the air.
    pub fn wireBytes(self: *const MessageFrame) []const u8 {
        const n = @min(self.payloadLen(), max_payload_len);
        const off = self.payloadOffset();
        return self.bytes[0 .. off + n];
    }

    /// Returns the full backing array (including zero padding).
    /// Prefer `wireBytes` for transmission to avoid sending empty data.
    pub fn asBytes(self: *const MessageFrame) []const u8 {
        return &self.bytes;
    }

    /// Minimum wire size for a packet 0 frame (header + signature, empty payload).
    pub const min_wire_size: usize = header_len + signature_len;

    /// Minimum wire size for a continuation packet (header only, empty payload).
    pub const min_wire_size_cont: usize = header_len;

    /// Parse a received byte slice into a `MessageFrame` (copies into the
    /// struct's backing array). Accepts trimmed frames. Returns `null` if the
    /// slice is too small or the embedded length doesn't match the available data.
    pub fn fromBytes(data: []const u8) ?MessageFrame {
        // Need at least the 6-byte header to read packet_number.
        if (data.len < header_len) return null;
        var f: MessageFrame = .{};

        // Copy the header first so we can read packet_number.
        @memcpy(f.bytes[0..header_len], data[0..header_len]);

        const pl = f.payloadLen();
        if (pl > max_payload_len) return null;

        const is_p0 = (f.packetNumber() == 0);
        const wire_len = if (is_p0)
            payload_off_p0 + pl
        else
            payload_off_p1 + pl;

        if (data.len < wire_len) return null;

        // Copy the rest of the meaningful bytes.
        const copy_len = @min(data.len, message_frame_size);
        @memcpy(f.bytes[0..copy_len], data[0..copy_len]);

        return f;
    }
};

// ---------------------------------------------------------------------------
// Tests — MessageFrame basics and wire-format round trips
// ---------------------------------------------------------------------------

test "MessageFrame default is empty and unsigned" {
    const f: MessageFrame = .{};
    try std.testing.expectEqual(@as(u16, 0), f.payloadLen());
    try std.testing.expectEqualSlices(u8, &.{}, f.payloadBytes());
    try std.testing.expect(!f.hasSignature());
}

test "MessageFrame init packet 0 with payload and signature" {
    const data = [_]u8{ 0x87, 0x67, 0xC7, 0x14, 0x83 };
    const sig = [_]u8{0xAB} ** 64;
    const f = MessageFrame.init(.public_key, &data, &sig, 5, 0, 1);
    try std.testing.expectEqual(MessageType.public_key, f.messageType());
    try std.testing.expectEqual(@as(u4, 0), f.version());
    try std.testing.expectEqual(@as(u4, 5), f.groupId());
    try std.testing.expectEqual(@as(u8, 0), f.packetNumber());
    try std.testing.expectEqual(@as(u8, 1), f.packetCount());
    try std.testing.expectEqual(@as(u16, 5), f.payloadLen());
    try std.testing.expectEqualSlices(u8, &data, f.payloadBytes());
    try std.testing.expect(f.hasSignature());
    try std.testing.expectEqualSlices(u8, &sig, &f.signatureBytes());
}

test "MessageFrame init continuation packet (no signature)" {
    const chunk = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const f = MessageFrame.init(.bulletin, &chunk, &.{}, 3, 1, 4);
    try std.testing.expectEqual(@as(u4, 3), f.groupId());
    try std.testing.expectEqual(@as(u8, 1), f.packetNumber());
    try std.testing.expectEqual(@as(u8, 4), f.packetCount());
    try std.testing.expectEqualSlices(u8, &chunk, f.payloadBytes());
    try std.testing.expect(!f.hasSignature());
    // Wire should be header(6) + payload(4) = 10 bytes (no signature).
    try std.testing.expectEqual(@as(usize, 10), f.wireBytes().len);
}

test "MessageFrame init public_key type" {
    const pk = [_]u8{0xAB} ** 32;
    var pk_payload: [33]u8 = undefined;
    pk_payload[0] = @intCast(@intFromEnum(message_type.PublicKeyRole.client));
    @memcpy(pk_payload[1..33], &pk);
    const f = MessageFrame.init(.public_key, &pk_payload, &.{}, 0, 0, 1);
    try std.testing.expectEqual(MessageType.public_key, f.messageType());
    try std.testing.expectEqual(@as(u16, 33), f.payloadLen());
    try std.testing.expectEqualSlices(u8, &pk_payload, f.payloadBytes());
}

test "MessageFrame wireBytes packet 0 includes signature" {
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const sig = [_]u8{0xFF} ** 64;
    const f = MessageFrame.init(.public_key, &payload, &sig, 0, 0, 1);
    // header(6) + sig(64) + payload(4) = 74
    try std.testing.expectEqual(@as(usize, 74), f.wireBytes().len);
}

test "MessageFrame wireBytes continuation excludes signature" {
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const f = MessageFrame.init(.public_key, &payload, &.{}, 0, 1, 2);
    // header(6) + payload(4) = 10
    try std.testing.expectEqual(@as(usize, 10), f.wireBytes().len);
}

test "MessageFrame wireBytes / fromBytes round trip (packet 0, signed)" {
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const sig = [_]u8{ 0x01, 0x02, 0x03 } ++ [_]u8{0xFF} ** 61;
    const original = MessageFrame.init(.public_key, &payload, &sig, 7, 0, 1);
    const wire = original.wireBytes();
    try std.testing.expectEqual(@as(usize, 74), wire.len);

    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;
    try std.testing.expectEqual(MessageType.public_key, parsed.messageType());
    try std.testing.expectEqual(@as(u4, 7), parsed.groupId());
    try std.testing.expectEqual(@as(u8, 0), parsed.packetNumber());
    try std.testing.expectEqual(@as(u8, 1), parsed.packetCount());
    try std.testing.expectEqual(@as(u16, 4), parsed.payloadLen());
    try std.testing.expectEqualSlices(u8, &payload, parsed.payloadBytes());
    try std.testing.expect(parsed.hasSignature());
    try std.testing.expectEqualSlices(u8, &sig, &parsed.signatureBytes());
}

test "MessageFrame wireBytes / fromBytes round trip (continuation, no sig)" {
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const original = MessageFrame.init(.public_key, &payload, &.{}, 7, 1, 3);
    const wire = original.wireBytes();
    try std.testing.expectEqual(@as(usize, 10), wire.len);

    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u4, 7), parsed.groupId());
    try std.testing.expectEqual(@as(u8, 1), parsed.packetNumber());
    try std.testing.expectEqual(@as(u8, 3), parsed.packetCount());
    try std.testing.expectEqualSlices(u8, &payload, parsed.payloadBytes());
    try std.testing.expect(!parsed.hasSignature());
}

test "MessageFrame wireBytes / fromBytes round trip (public_key type)" {
    const pk = [_]u8{0x42} ** 32;
    var pk_payload: [33]u8 = undefined;
    pk_payload[0] = @intCast(@intFromEnum(message_type.PublicKeyRole.server));
    @memcpy(pk_payload[1..33], &pk);
    const sig = [_]u8{0xCD} ** 64;
    const original = MessageFrame.init(.public_key, &pk_payload, &sig, 0, 0, 1);
    const wire = original.wireBytes();
    try std.testing.expectEqual(@as(usize, 103), wire.len);

    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;
    try std.testing.expectEqual(MessageType.public_key, parsed.messageType());
    try std.testing.expectEqualSlices(u8, &pk_payload, parsed.payloadBytes());
    try std.testing.expect(parsed.hasSignature());
}

test "MessageFrame wireBytes with empty payload (packet 0)" {
    const f = MessageFrame.init(.public_key, &.{}, &.{}, 0, 0, 1);
    const wire = f.wireBytes();
    try std.testing.expectEqual(@as(usize, 70), wire.len);
    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u16, 0), parsed.payloadLen());
}

test "MessageFrame wireBytes with empty payload (continuation)" {
    const f = MessageFrame.init(.public_key, &.{}, &.{}, 0, 1, 2);
    const wire = f.wireBytes();
    try std.testing.expectEqual(@as(usize, 6), wire.len);
    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u16, 0), parsed.payloadLen());
    try std.testing.expectEqual(@as(u8, 1), parsed.packetNumber());
}

test "MessageFrame asBytes / fromBytes round trip (full)" {
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const original = MessageFrame.init(.public_key, &payload, &.{}, 0, 0, 1);
    const bytes = original.asBytes();
    try std.testing.expectEqual(message_frame_size, bytes.len);

    const parsed = MessageFrame.fromBytes(bytes) orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u16, 4), parsed.payloadLen());
    try std.testing.expectEqualSlices(u8, &payload, parsed.payloadBytes());
}

test "MessageFrame fromBytes rejects too-small slice" {
    const short: [5]u8 = .{0} ** 5;
    try std.testing.expect(MessageFrame.fromBytes(&short) == null);
}

test "MessageFrame fromBytes rejects inconsistent length (packet 0)" {
    var bad: [70]u8 = .{0} ** 70;
    std.mem.writeInt(u16, bad[payload_len_off..][0..2], 100, .little);
    try std.testing.expect(MessageFrame.fromBytes(&bad) == null);
}

test "MessageFrame fromBytes handles unknown message type" {
    var bad: [70]u8 = .{0} ** 70;
    const parsed = MessageFrame.fromBytes(&bad) orelse return error.ParseFailed;
    try std.testing.expect(parsed.messageType() != .public_key);
}

// ---------------------------------------------------------------------------
// Tests — MessageFrame.fromPayload integration (end-to-end through wire)
// ---------------------------------------------------------------------------

test "MessageFrame.fromPayload bulletin_list_request round trip" {
    const payload: Payload = .{ .bulletin_list_request = .{ .page = 7, .page_size = 25 } };
    const frame = MessageFrame.fromPayload(payload, &.{}) orelse return error.EncodeFailed;

    try std.testing.expectEqual(MessageType.bulletin_list_request, frame.messageType());
    try std.testing.expectEqual(@as(u16, 3), frame.payloadLen());

    const wire = frame.wireBytes();
    try std.testing.expectEqual(@as(usize, 73), wire.len);

    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;
    const allocator = std.testing.allocator;
    const decoded = (try message_type.decodePayload(allocator, parsed.messageType(), parsed.payloadBytes())) orelse return error.DecodeFailed;
    defer message_type.deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u16, 7), decoded.bulletin_list_request.page);
    try std.testing.expectEqual(@as(u8, 25), decoded.bulletin_list_request.page_size);
}

test "MessageFrame.fromPayload bulletin round trip through wire" {
    const allocator = std.testing.allocator;
    const title = "Test Bulletin";
    const body = "This is the body of the test bulletin.";

    const payload: Payload = .{ .bulletin = .{
        .id = 1,
        .user_id = 42,
        .created_at = 1724022400,
        .title = title,
        .body = body,
    } };

    const sig = [_]u8{0xFF} ** 64;
    const frame = MessageFrame.fromPayload(payload, &sig) orelse return error.EncodeFailed;

    try std.testing.expectEqual(MessageType.bulletin, frame.messageType());
    try std.testing.expect(frame.hasSignature());

    const wire = frame.wireBytes();
    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;
    try std.testing.expectEqual(MessageType.bulletin, parsed.messageType());

    const decoded = (try message_type.decodePayload(allocator, parsed.messageType(), parsed.payloadBytes())) orelse return error.DecodeFailed;
    defer message_type.deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u16, 42), decoded.bulletin.user_id);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.bulletin.created_at);
    try std.testing.expectEqualStrings(title, decoded.bulletin.title);
    try std.testing.expectEqualStrings(body, decoded.bulletin.body);
}

test "MessageFrame.fromPayload bulletin_response round trip through wire" {
    const allocator = std.testing.allocator;
    const body = "This is a response body.";
    const payload: Payload = .{ .bulletin_response = .{
        .bulletin_id = 42,
        .response_id = 7,
        .user_id = 3,
        .create_datetime = 1724022400,
        .body = body,
    } };

    const frame = MessageFrame.fromPayload(payload, &.{}) orelse return error.EncodeFailed;
    const wire = frame.wireBytes();
    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;

    try std.testing.expectEqual(MessageType.bulletin_response, parsed.messageType());

    const decoded = (try message_type.decodePayload(allocator, parsed.messageType(), parsed.payloadBytes())) orelse return error.DecodeFailed;
    defer message_type.deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u32, 42), decoded.bulletin_response.bulletin_id);
    try std.testing.expectEqual(@as(u16, 7), decoded.bulletin_response.response_id);
    try std.testing.expectEqual(@as(u16, 3), decoded.bulletin_response.user_id);
    try std.testing.expectEqual(@as(u64, 1724022400), decoded.bulletin_response.create_datetime);
    try std.testing.expectEqualStrings(body, decoded.bulletin_response.body);
}

test "MessageFrame.fromPayload bulletin_response_request round trip through wire (tail_after)" {
    const allocator = std.testing.allocator;
    const payload: Payload = .{ .bulletin_response_request = .{
        .bulletin_id = 42,
        .mode = .tail_after,
        .after_id = 5,
    } };

    const frame = MessageFrame.fromPayload(payload, &.{}) orelse return error.EncodeFailed;
    const wire = frame.wireBytes();
    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;

    try std.testing.expectEqual(MessageType.bulletin_response_request, parsed.messageType());

    const decoded = (try message_type.decodePayload(allocator, parsed.messageType(), parsed.payloadBytes())) orelse return error.DecodeFailed;
    defer message_type.deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u32, 42), decoded.bulletin_response_request.bulletin_id);
    try std.testing.expectEqual(message_type.ResponseRequestMode.tail_after, decoded.bulletin_response_request.mode);
    try std.testing.expectEqual(@as(u16, 5), decoded.bulletin_response_request.after_id);
}

test "MessageFrame.fromPayload bulletin_list round trip through wire" {
    const allocator = std.testing.allocator;
    const summaries = [_]message_type.BulletinSummary{
        .{ .id = 10, .user_id = 1, .title = "Test Bulletin" },
        .{ .id = 20, .user_id = 2, .title = "Another One" },
    };
    const payload: Payload = .{ .bulletin_list = .{
        .page = 1,
        .total_pages = 5,
        .bulletins = &summaries,
    } };

    const sig = [_]u8{0xEE} ** 64;
    const frame = MessageFrame.fromPayload(payload, &sig) orelse return error.EncodeFailed;
    try std.testing.expectEqual(MessageType.bulletin_list, frame.messageType());
    try std.testing.expect(frame.hasSignature());

    const wire = frame.wireBytes();
    const parsed = MessageFrame.fromBytes(wire) orelse return error.ParseFailed;
    try std.testing.expectEqual(MessageType.bulletin_list, parsed.messageType());

    const decoded = (try message_type.decodePayload(allocator, parsed.messageType(), parsed.payloadBytes())) orelse return error.DecodeFailed;
    defer message_type.deinitPayload(allocator, decoded);
    try std.testing.expectEqual(@as(u16, 1), decoded.bulletin_list.page);
    try std.testing.expectEqual(@as(u16, 5), decoded.bulletin_list.total_pages);
    try std.testing.expectEqual(@as(usize, 2), decoded.bulletin_list.bulletins.len);
    try std.testing.expectEqual(@as(u32, 10), decoded.bulletin_list.bulletins[0].id);
    try std.testing.expectEqualStrings("Test Bulletin", decoded.bulletin_list.bulletins[0].title);
    try std.testing.expectEqual(@as(u16, 1), decoded.bulletin_list.bulletins[0].user_id);
    try std.testing.expectEqual(@as(u32, 20), decoded.bulletin_list.bulletins[1].id);
    try std.testing.expectEqualStrings("Another One", decoded.bulletin_list.bulletins[1].title);
}

test "MessageFrame multipart round trip (packet 0 + continuation)" {
    // Simulate a 2-packet multipart message.
    const chunk0 = [_]u8{ 0xAA, 0xBB, 0xCC };
    const chunk1 = [_]u8{ 0xDD, 0xEE };
    const sig = [_]u8{0x42} ** 64;

    // Packet 0: signed, group_id=5, packet_number=0, packet_count=2.
    const p0 = MessageFrame.init(.bulletin, &chunk0, &sig, 5, 0, 2);
    const wire0 = p0.wireBytes();
    try std.testing.expectEqual(@as(usize, 70 + 3), wire0.len); // header(6)+sig(64)+payload(3)

    const parsed0 = MessageFrame.fromBytes(wire0) orelse return error.ParseFailed;
    try std.testing.expectEqual(MessageType.bulletin, parsed0.messageType());
    try std.testing.expectEqual(@as(u4, 5), parsed0.groupId());
    try std.testing.expectEqual(@as(u8, 0), parsed0.packetNumber());
    try std.testing.expectEqual(@as(u8, 2), parsed0.packetCount());
    try std.testing.expectEqualSlices(u8, &chunk0, parsed0.payloadBytes());
    try std.testing.expect(parsed0.hasSignature());
    try std.testing.expectEqualSlices(u8, &sig, &parsed0.signatureBytes());

    // Packet 1: unsigned, group_id=5, packet_number=1, packet_count=2.
    const p1 = MessageFrame.init(.bulletin, &chunk1, &.{}, 5, 1, 2);
    const wire1 = p1.wireBytes();
    try std.testing.expectEqual(@as(usize, 6 + 2), wire1.len); // header(6)+payload(2), no sig

    const parsed1 = MessageFrame.fromBytes(wire1) orelse return error.ParseFailed;
    try std.testing.expectEqual(MessageType.bulletin, parsed1.messageType());
    try std.testing.expectEqual(@as(u4, 5), parsed1.groupId());
    try std.testing.expectEqual(@as(u8, 1), parsed1.packetNumber());
    try std.testing.expectEqual(@as(u8, 2), parsed1.packetCount());
    try std.testing.expectEqualSlices(u8, &chunk1, parsed1.payloadBytes());
    try std.testing.expect(!parsed1.hasSignature());
}
