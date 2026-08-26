//! Multipart message reassembly — shared by the TUI client and the server.
//!
//! Both sides receive `IncomingMessage` packets that may be one slice of a
//! larger multipart message (identified by `group_id` + `source_callsign`,
//! with `packet_number`/`packet_count` from the message-frame header). This
//! module stores the chunks and, once all are received, concatenates them
//! into a single heap-allocated payload returned to the caller.
//!
//! Reassembly is **MTU-agnostic**: it stores whatever chunk sizes a sender
//! emits, indexed by the u8 `packet_number`. The per-transport MTU only
//! matters on the send side (see `transport.sendMultipart`); here we just
//! collect and concatenate by frame ID.

const std = @import("std");

const incoming_mod = @import("incoming.zig");
const frame = @import("frame.zig");
const message_type = @import("../message_frame/message_type.zig");

const MessageType = message_type.MessageType;
const IncomingMessage = incoming_mod.IncomingMessage;
const callsign_len = incoming_mod.callsign_len;
const signature_len = frame.signature_len;
const max_packets_per_message = frame.max_packets_per_message;

/// Maximum concurrent reassembly groups (the u4 group_id space is 0–15).
pub const max_groups: usize = 16;

/// One in-progress multipart reassembly, keyed by (source_callsign, group_id).
pub const Entry = struct {
    active: bool = false,
    source_callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8),
    callsign_len: u8 = 0,
    group_id: u4 = 0,
    msg_type: MessageType = @enumFromInt(0),
    packet_count: u8 = 0,
    signature: [signature_len]u8 = std.mem.zeroes([signature_len]u8),
    has_signature: bool = false,
    /// Payload chunks indexed by `packet_number` (u8 → 0..255). Each slot
    /// holds a heap-allocated slice of whatever length the sender emitted;
    /// null until that packet has been received.
    packets: [max_packets_per_message]?[]u8 = @splat(null),
    received_count: u8 = 0,
    last_received_ts: u64 = 0,

    // --- Client-only NAK tracking (unused by the server) -----------------
    /// Next time (ms) the client should send a NAK for missing packets.
    /// 0 when no NAK is pending. Managed by the client's NAK controller
    /// in `app.zig`; the server simply ignores these fields.
    next_nak_ts: u64 = 0,
    /// Number of NAK attempts already sent for this entry.
    nak_attempts: u8 = 0,
};

/// The reassembled payload returned to the caller when all packets arrive.
/// `payload` is heap-allocated; release it with `Reassembler.freePayload`.
pub const ReassembledMsg = struct {
    msg_type: MessageType,
    group_id: u4,
    /// Copied from the entry so it remains valid after the entry is reset.
    callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8),
    callsign_len: u8 = 0,
    signature: ?[signature_len]u8 = null,
    /// Heap-allocated; ownership passes to the caller.
    payload: []u8,
};

/// Fixed-capacity reassembly buffer (16 concurrent groups). Both the TUI
/// client and the server own one instance.
pub const Reassembler = struct {
    entries: [max_groups]Entry = @splat(.{}),

    /// Feed one incoming packet. Stores its payload chunk; when all packets
    /// for the group have arrived, heap-allocates the concatenation, resets
    /// the entry, and returns the reassembled message. Returns null when
    /// more packets are still needed (or on error/overflow).
    pub fn feed(self: *Reassembler, im: IncomingMessage, now_ms: u64) ?ReassembledMsg {
        // Callsigns are optional (only AGWPE provides link-layer identity);
        // an empty slice keys the entry like any other. Identity-less links
        // rely on group_id alone, so two stations concurrently sending
        // multipart with the same group id can collide — a known limit of
        // identity-less media.
        const callsign = if (im.has_callsign)
            im.callsign[0..@min(im.callsign_str_len, callsign_len)]
        else
            im.callsign[0..0];

        const entry = self.findOrCreate(callsign, im.group_id) orelse return null;

        // Initialize on first packet.
        if (entry.received_count == 0) {
            entry.packet_count = im.packet_count;
            entry.msg_type = im.msg_type;
        }

        const pn = im.packet_number;
        if (pn >= max_packets_per_message) return null;
        if (entry.packets[pn] != null) return null; // already have this packet

        // Store the payload chunk (any length the sender chose).
        const allocator = std.heap.page_allocator;
        const chunk = allocator.dupe(u8, im.frame_payload[0..im.frame_payload_len]) catch return null;
        entry.packets[pn] = chunk;
        entry.received_count += 1;
        entry.last_received_ts = now_ms;

        // Capture signature from packet 0.
        if (pn == 0 and im.signed) {
            entry.signature = im.signature;
            entry.has_signature = true;
        }

        // Not yet complete?
        if (entry.received_count < entry.packet_count) return null;

        return self.completeReassembly(entry);
    }

    /// Expose all entries (active and inactive) so the client's NAK
    /// controller can scan for timed-out / incomplete groups. The server
    /// has no NAK controller and simply ignores inactive entries.
    pub fn entriesSlice(self: *Reassembler) []Entry {
        return &self.entries;
    }

    /// Free all chunks and deactivate an entry (used on timeout/eviction
    /// by the client NAK controller).
    pub fn freeEntry(_: *Reassembler, entry: *Entry) void {
        const allocator = std.heap.page_allocator;
        for (&entry.packets) |*p| {
            if (p.*) |chunk| {
                allocator.free(chunk);
                p.* = null;
            }
        }
        entry.active = false;
        entry.received_count = 0;
        entry.has_signature = false;
        entry.nak_attempts = 0;
        entry.next_nak_ts = 0;
    }

    /// Free a reassembled payload returned by `feed`. Convenience wrapper so
    /// callers above the session core never touch the allocator directly.
    pub fn freePayload(payload: []u8) void {
        std.heap.page_allocator.free(payload);
    }

    fn findOrCreate(self: *Reassembler, callsign: []const u8, group_id: u4) ?*Entry {
        // Try to find an existing entry.
        for (&self.entries) |*e| {
            if (e.active and e.group_id == group_id and e.callsign_len == callsign.len) {
                if (std.mem.eql(u8, e.source_callsign[0..e.callsign_len], callsign)) {
                    return e;
                }
            }
        }
        // Create a new entry.
        for (&self.entries) |*e| {
            if (!e.active) {
                e.* = .{ .active = true };
                e.group_id = group_id;
                e.callsign_len = @intCast(@min(callsign.len, callsign_len));
                @memcpy(e.source_callsign[0..e.callsign_len], callsign[0..e.callsign_len]);
                return e;
            }
        }
        return null;
    }

    fn completeReassembly(self: *Reassembler, entry: *Entry) ?ReassembledMsg {
        const allocator = std.heap.page_allocator;
        // Calculate total reassembled payload size.
        var total: usize = 0;
        var i: u8 = 0;
        while (i < entry.packet_count) : (i += 1) {
            if (entry.packets[i]) |chunk| total += chunk.len;
        }

        // Concatenate chunks in order.
        const reassembled = allocator.alloc(u8, total) catch {
            self.freeEntry(entry);
            return null;
        };
        var pos: usize = 0;
        i = 0;
        while (i < entry.packet_count) : (i += 1) {
            if (entry.packets[i]) |chunk| {
                @memcpy(reassembled[pos..][0..chunk.len], chunk);
                pos += chunk.len;
            }
        }

        // Snapshot metadata before resetting the entry.
        const msg_type = entry.msg_type;
        const group_id = entry.group_id;
        const sig: ?[signature_len]u8 = if (entry.has_signature) entry.signature else null;
        var callsign: [callsign_len]u8 = std.mem.zeroes([callsign_len]u8);
        const cs_len: u8 = entry.callsign_len;
        @memcpy(callsign[0..cs_len], entry.source_callsign[0..cs_len]);

        self.freeEntry(entry);

        return .{
            .msg_type = msg_type,
            .group_id = group_id,
            .callsign = callsign,
            .callsign_len = cs_len,
            .signature = sig,
            .payload = reassembled,
        };
    }
};

// ---------------------------------------------------------------------------
// Integration tests — burst reassembly simulating the client inbox draining
// a coalesced multipart burst 16 packets at a time across ticks.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Build a synthetic multipart `IncomingMessage` for one packet of a logical
/// message. `payload` is the chunk bytes for this packet; packet 0 is marked
/// signed and carries `sig`.
fn makePacket(
    pn: u8,
    packet_count: u8,
    chunk: []const u8,
    sig: [signature_len]u8,
) IncomingMessage {
    var im: IncomingMessage = .{};
    im.is_message_frame = true;
    im.msg_type = .bulletin;
    im.has_callsign = true;
    im.callsign = std.mem.zeroes([callsign_len]u8);
    im.callsign[0] = 'S';
    im.callsign[1] = 'R';
    im.callsign[2] = 'V';
    im.callsign_str_len = 3;
    im.group_id = 0; // all messages share group_id 0, like the server outbox
    im.packet_number = pn;
    im.packet_count = packet_count;
    @memcpy(im.frame_payload[0..chunk.len], chunk);
    im.frame_payload_len = @intCast(chunk.len);
    if (pn == 0) {
        im.signed = true;
        im.signature = sig;
    }
    return im;
}

test "Reassembler: 10 multipart messages (group_id=0) drained 16 packets per tick" {
    const allocator = testing.allocator;
    var reassembler: Reassembler = .{};

    const n_msgs: usize = 10;
    const packets_per_msg: u8 = 5;
    const total_packets: usize = n_msgs * packets_per_msg; // 50

    // Each logical message has a distinct payload so reassembly correctness
    // can be checked: message m's full payload is m*100 repeated 256 times,
    // split into 5 chunks of 256,256,256,256,? (last shorter).
    const chunk_size: usize = 256;
    const full_len: usize = chunk_size * (packets_per_msg - 1) + 100; // 4*256 + 100 = 1124
    var full_payloads: [10][]u8 = undefined;
    var chunks: [50][]u8 = undefined;
    var sigs: [10][signature_len]u8 = undefined;
    for (0..n_msgs) |m| {
        full_payloads[m] = try allocator.alloc(u8, full_len);
        @memset(full_payloads[m], @intCast((m + 1) % 256));
        sigs[m] = .{0} ** signature_len;
        sigs[m][0] = @intCast(m + 1); // distinguish signatures
        for (0..packets_per_msg) |p| {
            const start = p * chunk_size;
            const end = @min(start + chunk_size, full_len);
            chunks[m * packets_per_msg + p] = full_payloads[m][start..end];
        }
    }
    defer for (0..n_msgs) |m| allocator.free(full_payloads[m]);

    // Build all 50 packet IncomingMessages in wire order (message 0 packets 0..4,
    // then message 1 packets 0..4, ...).
    var ims: [50]IncomingMessage = undefined;
    for (0..n_msgs) |m| {
        for (0..packets_per_msg) |p| {
            ims[m * packets_per_msg + p] = makePacket(
                @intCast(p),
                packets_per_msg,
                chunks[m * packets_per_msg + p],
                sigs[m],
            );
        }
    }

    // Drain 16 packets per "tick" (exactly how the client inbox drains), feeding
    // each through the reassembler. Completed messages are collected.
    var completed: usize = 0;
    var seen: [10]bool = .{false} ** 10;
    var i: usize = 0;
    while (i < total_packets) {
        const end = @min(i + 16, total_packets);
        for (i..end) |j| {
            if (reassembler.feed(ims[j], 1000)) |msg| {
                completed += 1;
                // The reassembled payload must equal the original full payload.
                const m = msg.payload[0] - 1;
                try testing.expectEqual(@as(usize, full_len), msg.payload.len);
                try testing.expectEqualSlices(u8, full_payloads[m], msg.payload);
                // The signature captured from packet 0 must survive.
                try testing.expect(msg.signature != null);
                try testing.expectEqual(sigs[m], msg.signature.?);
                seen[m] = true;
                std.heap.page_allocator.free(msg.payload);
            }
        }
        i = end;
    }

    try testing.expectEqual(n_msgs, completed);
    for (seen) |s| try testing.expect(s);
}

test "Reassembler: straddled message completes on the next drain batch" {
    const allocator = testing.allocator;
    var reassembler: Reassembler = .{};

    // 3 messages, 3 packets each (9 packets). Drain 4 at a time: batch 1 =
    // msg0(3) + msg1.p0; batch 2 = msg1.p1,p2 + msg2(3) + ...; every message
    // must complete even when it straddles a drain boundary, all with
    // group_id=0.
    const n_msgs: usize = 3;
    const pp: u8 = 3;
    var full: [3][]u8 = undefined;
    var chunks: [9][]u8 = undefined;
    var sigs: [3][signature_len]u8 = undefined;
    for (0..n_msgs) |m| {
        full[m] = try allocator.alloc(u8, 700); // 3 chunks: 256+256+188
        @memset(full[m], @intCast((m + 1) % 256));
        sigs[m] = .{0} ** signature_len;
        sigs[m][0] = @intCast(m + 100);
        for (0..pp) |p| {
            const s = p * 256;
            const e = @min(s + 256, 700);
            chunks[m * pp + p] = full[m][s..e];
        }
    }
    defer for (0..n_msgs) |m| allocator.free(full[m]);

    var ims: [9]IncomingMessage = undefined;
    for (0..n_msgs) |m| {
        for (0..pp) |p| {
            ims[m * pp + p] = makePacket(@intCast(p), pp, chunks[m * pp + p], sigs[m]);
        }
    }

    var completed: usize = 0;
    var i: usize = 0;
    while (i < 9) {
        const end = @min(i + 4, 9);
        for (i..end) |j| {
            if (reassembler.feed(ims[j], 1000)) |msg| {
                completed += 1;
                const m = msg.payload[0] - 1;
                try testing.expectEqualSlices(u8, full[m], msg.payload);
                std.heap.page_allocator.free(msg.payload);
            }
        }
        i = end;
    }
    try testing.expectEqual(@as(usize, 3), completed);
}

test "Reassembler concatenates mixed-size chunks (MTU-agnostic)" {
    var reassembler: Reassembler = .{};
    const sig = [_]u8{0x71} ** signature_len;

    var c0: [1000]u8 = @splat('A');
    const c1 = "tail!";

    var im0 = makePacket(0, 2, &c0, sig);
    im0.group_id = 9;
    var im1 = makePacket(1, 2, c1, sig);
    im1.group_id = 9;

    try testing.expect(reassembler.feed(im0, 1000) == null);
    const msg = reassembler.feed(im1, 1100) orelse return error.Incomplete;

    defer Reassembler.freePayload(msg.payload);
    try testing.expectEqual(@as(usize, c0.len + c1.len), msg.payload.len);
    for (msg.payload[0..c0.len]) |b| try testing.expectEqual(@as(u8, 'A'), b);
    try testing.expectEqualSlices(u8, c1, msg.payload[c0.len..]);
    try testing.expectEqual(sig, msg.signature.?);
}

test "Reassembler: callsign-less packets (identity-less links) reassemble" {
    var reassembler: Reassembler = .{};

    const c0 = "identity-less chunk one ";
    const c1 = "chunk two";
    var sig: [signature_len]u8 = undefined;
    @memset(&sig, 0xAB);

    for ([_]u8{ 0, 1 }) |pn| {
        var im: IncomingMessage = .{};
        im.is_message_frame = true;
        im.msg_type = .bulletin;
        im.has_callsign = false; // MeshCore RAW packets carry no identity
        im.group_id = 4;
        im.packet_number = pn;
        im.packet_count = 2;
        const chunk = if (pn == 0) c0 else c1;
        @memcpy(im.frame_payload[0..chunk.len], chunk);
        im.frame_payload_len = @intCast(chunk.len);
        if (pn == 0) {
            im.signed = true;
            im.signature = sig;
        }

        if (pn == 0) {
            try testing.expect(reassembler.feed(im, 1000) == null);
        } else {
            const msg = reassembler.feed(im, 1001) orelse return error.TestUnexpectedResult;
            // The reassembler allocates payloads from the page allocator.
            defer std.heap.page_allocator.free(msg.payload);
            try testing.expectEqual(@as(usize, 0), msg.callsign_len);
            try testing.expectEqualSlices(u8, c0 ++ c1, msg.payload);
        }
    }
}
