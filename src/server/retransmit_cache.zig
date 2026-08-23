//! Retransmission cache for the bulletin server.
//!
//! Stores recently sent multipart frames so the server can retransmit a
//! specific frame via `sendFrameTo` on NAK. 64 entries, 30s TTL, 5s dedup
//! window. The `retransmitObserver` callback is wired into `agwpe.Connection`
//! send options so every transmitted frame is automatically cached.

const std = @import("std");
const Io = std.Io;

const kiss = @import("bbs");
const transport_mod = kiss.transport;
const message_frame = kiss.message_frame;

/// Entry in the retransmission cache. Stores per-packet params so the server
/// can rebuild and retransmit a specific frame via `sendFrameTo` on NAK.
pub const RetransmitEntry = struct {
    active: bool = false,
    msg_type: message_frame.MessageType = @enumFromInt(0),
    group_id: u4 = 0,
    packet_number: u8 = 0,
    packet_count: u8 = 0,
    chunk: [message_frame.max_payload_len]u8 = std.mem.zeroes([message_frame.max_payload_len]u8),
    chunk_len: u16 = 0,
    has_signature: bool = false,
    signature: [message_frame.signature_len]u8 = std.mem.zeroes([message_frame.signature_len]u8),
    timestamp: u64 = 0,
    last_retransmit: u64 = 0,
};

/// Cache of recently sent multipart frames for retransmission on NAK.
/// 64 entries, 30s TTL, 5s dedup window.
pub const RetransmissionCache = struct {
    entries: [64]RetransmitEntry = std.mem.zeroes([64]RetransmitEntry),
    io: Io = undefined,

    fn nowSec(io: Io) u64 {
        return @intCast(@max(0, std.Io.Timestamp.now(io, .real).toSeconds()));
    }

    /// Insert a sent frame into the cache, using info from the FrameObserver.
    pub fn insertFrame(self: *RetransmissionCache, io: Io, info: transport_mod.FrameInfo) void {
        const now = nowSec(io);
        for (&self.entries) |*e| {
            if (!e.active) {
                e.active = true;
                e.msg_type = info.msg_type;
                e.group_id = info.group_id;
                e.packet_number = info.packet_number;
                e.packet_count = info.packet_count;
                const cl = @min(info.chunk.len, message_frame.max_payload_len);
                @memcpy(e.chunk[0..cl], info.chunk[0..cl]);
                e.chunk_len = @intCast(cl);
                e.has_signature = info.signature.len > 0;
                if (e.has_signature) {
                    const sl = @min(info.signature.len, message_frame.signature_len);
                    @memcpy(e.signature[0..sl], info.signature[0..sl]);
                }
                e.timestamp = now;
                e.last_retransmit = 0;
                return;
            }
        }
    }

    /// Look up a frame for retransmission. Returns null if not found, expired,
    /// or within the dedup window.
    pub fn lookup(self: *RetransmissionCache, io: Io, group_id: u4, packet_number: u8) ?*RetransmitEntry {
        const now = nowSec(io);
        for (&self.entries) |*e| {
            if (!e.active) continue;
            if (e.group_id != group_id or e.packet_number != packet_number) continue;
            // TTL check (30 seconds).
            if (now - e.timestamp > 30) {
                e.active = false;
                continue;
            }
            // Dedup check (5 seconds).
            if (e.last_retransmit != 0 and now - e.last_retransmit < 5) {
                return null;
            }
            e.last_retransmit = now;
            return e;
        }
        return null;
    }
};

/// FrameObserver callback that populates the retransmission cache.
pub fn retransmitObserver(ctx: *anyopaque, info: transport_mod.FrameInfo) void {
    const cache: *RetransmissionCache = @ptrCast(@alignCast(ctx));
    cache.insertFrame(cache.io, info);
}

test "RetransmissionCache insert and lookup" {
    const io = std.testing.io;
    var cache: RetransmissionCache = .{ .io = io };

    const chunk = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const sig = [_]u8{0xFE} ** message_frame.signature_len;
    cache.insertFrame(io, .{
        .msg_type = .bulletin,
        .group_id = 3,
        .packet_number = 0,
        .packet_count = 1,
        .chunk = &chunk,
        .signature = &sig,
    });

    const result = cache.lookup(io, 3, 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &chunk, result.?.chunk[0..result.?.chunk_len]);
    try std.testing.expect(result.?.has_signature);
}

test "RetransmissionCache dedup window" {
    const io = std.testing.io;
    var cache: RetransmissionCache = .{ .io = io };

    const chunk = [_]u8{ 0xAA, 0xBB };
    cache.insertFrame(io, .{
        .msg_type = .bulletin,
        .group_id = 1,
        .packet_number = 2,
        .packet_count = 3,
        .chunk = &chunk,
        .signature = &.{},
    });

    // First lookup succeeds.
    try std.testing.expect(cache.lookup(io, 1, 2) != null);
    // Second lookup within dedup window returns null.
    try std.testing.expect(cache.lookup(io, 1, 2) == null);
}

test "RetransmissionCache miss returns null" {
    const io = std.testing.io;
    var cache: RetransmissionCache = .{ .io = io };
    try std.testing.expect(cache.lookup(io, 0, 0) == null);
}
