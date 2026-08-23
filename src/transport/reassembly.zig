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
const message_frame = @import("../message_frame.zig");

const MessageType = message_frame.MessageType;
const IncomingMessage = message_frame.IncomingMessage;

/// Maximum concurrent reassembly groups (the u4 group_id space is 0–15).
pub const max_groups: usize = 16;

/// One in-progress multipart reassembly, keyed by (source_callsign, group_id).
pub const Entry = struct {
    active: bool = false,
    source_callsign: [message_frame.callsign_len]u8 = std.mem.zeroes([message_frame.callsign_len]u8),
    callsign_len: u8 = 0,
    group_id: u4 = 0,
    msg_type: MessageType = @enumFromInt(0),
    packet_count: u8 = 0,
    signature: [message_frame.signature_len]u8 = std.mem.zeroes([message_frame.signature_len]u8),
    has_signature: bool = false,
    /// Payload chunks indexed by `packet_number` (u8 → 0..255). Each slot
    /// holds a heap-allocated slice of whatever length the sender emitted;
    /// null until that packet has been received.
    packets: [message_frame.max_packets_per_message]?[]u8 = @splat(null),
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
/// `payload` is heap-allocated; the **caller owns it and must free it**
/// (e.g. with `std.heap.page_allocator.free(msg.payload)`).
pub const ReassembledMsg = struct {
    msg_type: MessageType,
    group_id: u4,
    /// Copied from the entry so it remains valid after the entry is reset.
    callsign: [message_frame.callsign_len]u8 = std.mem.zeroes([message_frame.callsign_len]u8),
    callsign_len: u8 = 0,
    signature: ?[message_frame.signature_len]u8 = null,
    /// Heap-allocated, caller-owned.
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
        if (!im.has_callsign) return null;
        const callsign = im.callsign[0..@min(im.callsign_str_len, message_frame.callsign_len)];

        const entry = self.findOrCreate(callsign, im.group_id) orelse return null;

        // Initialize on first packet.
        if (entry.received_count == 0) {
            entry.packet_count = im.packet_count;
            entry.msg_type = im.msg_type;
        }

        const pn = im.packet_number;
        if (pn >= message_frame.max_packets_per_message) return null;
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
                e.callsign_len = @intCast(@min(callsign.len, message_frame.callsign_len));
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
        const sig: ?[message_frame.signature_len]u8 = if (entry.has_signature) entry.signature else null;
        var callsign: [message_frame.callsign_len]u8 = std.mem.zeroes([message_frame.callsign_len]u8);
        const callsign_len = entry.callsign_len;
        @memcpy(callsign[0..callsign_len], entry.source_callsign[0..callsign_len]);

        self.freeEntry(entry);

        return .{
            .msg_type = msg_type,
            .group_id = group_id,
            .callsign = callsign,
            .callsign_len = callsign_len,
            .signature = sig,
            .payload = reassembled,
        };
    }
};
