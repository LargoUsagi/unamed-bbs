//! TCP/IP direct link transport — a length-delimited TCP connection that
//! carries message packets between client and server without an AGWPE TNC /
//! AX.25 radio layer.
//!
//! The wire format is a simple length-delimited envelope:
//!
//!   [magic: u8 = 0x4B]            — 'K' for kiss-test
//!   [port: u8]                    — radio channel (low 4 bits; kept for
//!                                    compatibility with the AGWPE path)
//!   [src_callsign_len: u8]        — 0..10
//!   [src_callsign: N bytes]       — sender callsign (no null padding)
//!   [dest_callsign_len: u8]       — 0..10
//!   [dest_callsign: N bytes]      — destination callsign ("CQ" = broadcast)
//!   [frame_len: u16 LE]           — message-frame wire bytes length
//!   [frame_bytes: frame_len]      — the `MessageFrame` wire bytes
//!
//! This is a bottom-layer link implementation: `sendWire` wraps packet wire
//! bytes in the envelope, and the reader thread parses incoming envelopes,
//! populates `IncomingMessage` with the callsigns + decoded frame, and hands
//! them to the generic layers above (`transport.zig`, `messaging.zig`).
//!
//! Two construction paths:
//!   * `connect()`     — client side: open a TCP connection to a server.
//!   * `acceptStream()` — server side: wrap an already-accepted `net.Stream`
//!     from a `net.Server.accept()` call.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

/// Shared transport abstraction (`Transport` vtable + multipart splitting).
pub const transport = @import("../transport.zig");
const incoming_mod = transport.incoming;

const IncomingMessage = incoming_mod.IncomingMessage;
const decodePacket = incoming_mod.decodePacket;
pub const callsign_len = incoming_mod.callsign_len;

/// Maximum frame payload the parser will accept (matches AGWPE).
pub const max_frame_payload: usize = 4096;

/// Maximum payload bytes per packet chunk for the TCP transport. Set to
/// `frame.max_chunk_len` (1024) — the wire has no radio MTU constraint, so
/// TCP links use full-size chunks while radio links split smaller.
pub const mtu_payload: usize = 1024;

/// Magic byte at the start of every TCP transport envelope.
const magic: u8 = 0x4B;

// ---------------------------------------------------------------------------
// Envelope read/write
// ---------------------------------------------------------------------------

/// Maximum size of a complete envelope: magic(1) + port(1) +
/// src_len(1) + src(10) + dest_len(1) + dest(10) + frame_len(2) + frame.
const max_envelope_overhead: usize = 1 + 1 + 1 + callsign_len + 1 + callsign_len + 2;
const max_envelope_size: usize = max_envelope_overhead + max_frame_payload;

/// Write a TCP transport envelope into `buf`. Returns the number of bytes
/// written, or `null` if the frame is too large.
fn writeEnvelope(
    buf: []u8,
    port: u4,
    src_callsign: []const u8,
    dest_callsign: []const u8,
    frame: []const u8,
) ?usize {
    if (src_callsign.len > callsign_len) return null;
    if (dest_callsign.len > callsign_len) return null;
    const total = 1 + 1 + 1 + src_callsign.len + 1 + dest_callsign.len + 2 + frame.len;
    if (buf.len < total) return null;

    var pos: usize = 0;
    buf[pos] = magic;
    pos += 1;
    buf[pos] = @intCast(port & 0x0F);
    pos += 1;
    buf[pos] = @intCast(src_callsign.len);
    pos += 1;
    @memcpy(buf[pos..][0..src_callsign.len], src_callsign);
    pos += src_callsign.len;
    buf[pos] = @intCast(dest_callsign.len);
    pos += 1;
    @memcpy(buf[pos..][0..dest_callsign.len], dest_callsign);
    pos += dest_callsign.len;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(frame.len), .little);
    pos += 2;
    @memcpy(buf[pos..][0..frame.len], frame);
    pos += frame.len;
    return pos;
}

// ---------------------------------------------------------------------------
// Streaming envelope parser
// ---------------------------------------------------------------------------

/// Streaming TCP envelope parser. Feed it raw bytes from the TCP stream and
/// it calls `onEnvelope` for each complete envelope.
pub const EnvelopeParser = struct {
    buf: [max_envelope_size]u8 = undefined,
    pos: usize = 0,
    /// Total bytes needed for the current envelope (0 = not yet known).
    needed: usize = 0,

    pub fn feed(
        self: *EnvelopeParser,
        data: []const u8,
        ctx: anytype,
        comptime onEnvelope: fn (@TypeOf(ctx), u8, []const u8, []const u8, []const u8) void,
    ) void {
        var i: usize = 0;
        // Continue looping while there is either more input data to consume, or
        // a complete envelope (or enough header to compute one) already sitting
        // in the buffer from a prior read. This prevents coalesced envelopes
        // from being stranded in the buffer when no further data arrives to
        // trigger another `feed` call.
        while (i < data.len or
            (self.needed == 0 and self.pos >= 3 + 1) or
            (self.needed > 0 and self.pos >= self.needed))
        {
            const available = data.len - i;
            // When needed == 0 we haven't determined the envelope size yet,
            // so copy all available bytes (up to buffer capacity) to
            // accumulate enough header bytes to compute `needed`.
            const to_copy = if (self.needed == 0)
                @min(available, max_envelope_size - self.pos)
            else if (self.needed > self.pos)
                @min(available, self.needed - self.pos)
            else
                0;

            if (to_copy > 0) {
                @memcpy(self.buf[self.pos..][0..to_copy], data[i..][0..to_copy]);
                self.pos += to_copy;
                i += to_copy;
            }

            if (self.needed == 0 and self.pos >= 3 + 1) {
                // We have magic + port + src_len + src_callsign (at least).
                self.computeNeeded() orelse {
                    // Bad magic or overflow — reset and resync.
                    self.pos = 0;
                    self.needed = 0;
                    continue;
                };
            }

            if (self.needed > 0 and self.pos >= self.needed) {
                self.emit(ctx, onEnvelope);
                // Preserve any trailing bytes (the next envelope(s)) that
                // arrived in the same read. Previously this reset `pos = 0`,
                // silently discarding every envelope coalesced into one TCP
                // read beyond the first.
                const leftover = self.pos - self.needed;
                if (leftover > 0) {
                    std.mem.copyForwards(u8, self.buf[0..leftover], self.buf[self.needed..self.pos]);
                }
                self.pos = leftover;
                self.needed = 0;
            }
        }
    }

    fn computeNeeded(self: *EnvelopeParser) ?void {
        if (self.buf[0] != magic) return null;
        const src_len: usize = self.buf[2];
        // Need at least: magic(1) + port(1) + src_len(1) + src + dest_len(1)
        const dest_len_offset = 3 + src_len;
        if (self.pos < dest_len_offset + 1) {
            // Not enough bytes yet — set a partial needed to pull more.
            self.needed = dest_len_offset + 1;
            return {};
        }
        const dest_len: usize = self.buf[dest_len_offset];
        const frame_len_offset = dest_len_offset + 1 + dest_len;
        if (self.pos < frame_len_offset + 2) {
            self.needed = frame_len_offset + 2;
            return {};
        }
        const frame_len: usize = std.mem.readInt(u16, self.buf[frame_len_offset..][0..2], .little);
        if (frame_len > max_frame_payload) return null;
        self.needed = frame_len_offset + 2 + frame_len;
    }

    fn emit(
        self: *EnvelopeParser,
        ctx: anytype,
        comptime onEnvelope: fn (@TypeOf(ctx), u8, []const u8, []const u8, []const u8) void,
    ) void {
        const port = self.buf[1];
        const src_len: usize = self.buf[2];
        const src = self.buf[3 .. 3 + src_len];
        const dest_len_offset = 3 + src_len;
        const dest_len: usize = self.buf[dest_len_offset];
        const dest = self.buf[dest_len_offset + 1 .. dest_len_offset + 1 + dest_len];
        const frame_len_offset = dest_len_offset + 1 + dest_len;
        const frame_len: usize = std.mem.readInt(u16, self.buf[frame_len_offset..][0..2], .little);
        const frame = self.buf[frame_len_offset + 2 .. frame_len_offset + 2 + frame_len];
        onEnvelope(ctx, port, src, dest, frame);
    }
};

// ---------------------------------------------------------------------------
// Tests for the parser
// ---------------------------------------------------------------------------

test "EnvelopeParser parses a single envelope" {
    const Ctx = struct {
        port: u8 = 0,
        src: []const u8 = "",
        dest: []const u8 = "",
        frame: []const u8 = "",
        called: bool = false,
        fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
            self.called = true;
            self.port = port;
            self.src = src;
            self.dest = dest;
            self.frame = frame;
        }
    };
    var parser: EnvelopeParser = .{};
    var ctx: Ctx = .{};

    var buf: [64]u8 = undefined;
    const n = writeEnvelope(&buf, 3, "KE8WIF", "CQ", "hello") orelse return error.EncodeFailed;
    parser.feed(buf[0..n], &ctx, Ctx.cb);

    try std.testing.expect(ctx.called);
    try std.testing.expectEqual(@as(u8, 3), ctx.port);
    try std.testing.expectEqualStrings("KE8WIF", ctx.src);
    try std.testing.expectEqualStrings("CQ", ctx.dest);
    try std.testing.expectEqualStrings("hello", ctx.frame);
}

test "EnvelopeParser handles split data" {
    const Ctx = struct {
        frame: []const u8 = "",
        called: bool = false,
        fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
            _ = port;
            _ = src;
            _ = dest;
            self.called = true;
            self.frame = frame;
        }
    };
    var parser: EnvelopeParser = .{};
    var ctx: Ctx = .{};

    var buf: [64]u8 = undefined;
    const n = writeEnvelope(&buf, 0, "A", "B", "payload") orelse return error.EncodeFailed;

    // Feed first 3 bytes, then the rest.
    parser.feed(buf[0..3], &ctx, Ctx.cb);
    try std.testing.expect(!ctx.called);
    parser.feed(buf[3..n], &ctx, Ctx.cb);
    try std.testing.expect(ctx.called);
    try std.testing.expectEqualStrings("payload", ctx.frame);
}

test "EnvelopeParser parses multiple envelopes coalesced into one feed" {
    // TCP coalesces multiple server sends into a single read; the parser must
    // emit every envelope, not just the first. The callback copies each
    // frame's bytes immediately because the parser reuses its buffer.
    const Ctx = struct {
        out: [128]u8 = [_]u8{0} ** 128,
        out_len: usize = 0,
        fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
            _ = port;
            _ = src;
            _ = dest;
            const space = self.out.len - self.out_len;
            const n = @min(frame.len, space);
            @memcpy(self.out[self.out_len..][0..n], frame[0..n]);
            self.out_len += n;
        }
    };
    var parser: EnvelopeParser = .{};
    var ctx: Ctx = .{};

    var buf: [128]u8 = undefined;
    const n1 = writeEnvelope(&buf, 0, "A", "B", "first") orelse return error.EncodeFailed;
    const n2 = writeEnvelope(buf[n1..], 0, "A", "B", "second") orelse return error.EncodeFailed;
    const n3 = writeEnvelope(buf[n1 + n2 ..], 0, "A", "B", "third") orelse return error.EncodeFailed;
    const total = n1 + n2 + n3;

    // Feed all three envelopes in one call (simulating a coalesced TCP read).
    parser.feed(buf[0..total], &ctx, Ctx.cb);

    try std.testing.expectEqual(@as(usize, 5 + 6 + 5), ctx.out_len);
    try std.testing.expectEqualStrings("firstsecondthird", ctx.out[0..ctx.out_len]);
}

test "EnvelopeParser parses a coalesced batch followed by more data" {
    const Ctx = struct {
        out: [128]u8 = [_]u8{0} ** 128,
        out_len: usize = 0,
        fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
            _ = port;
            _ = src;
            _ = dest;
            const space = self.out.len - self.out_len;
            const n = @min(frame.len, space);
            @memcpy(self.out[self.out_len..][0..n], frame[0..n]);
            self.out_len += n;
        }
    };
    var parser: EnvelopeParser = .{};
    var ctx: Ctx = .{};

    var buf: [128]u8 = undefined;
    const n1 = writeEnvelope(&buf, 0, "A", "B", "one") orelse return error.EncodeFailed;
    const n2 = writeEnvelope(buf[n1..], 0, "A", "B", "two") orelse return error.EncodeFailed;
    const batch = n1 + n2;

    // First read: two coalesced envelopes.
    parser.feed(buf[0..batch], &ctx, Ctx.cb);

    // Second read: one more envelope, arriving split across a read boundary.
    const n3 = writeEnvelope(buf[0..], 0, "A", "B", "three") orelse return error.EncodeFailed;
    parser.feed(buf[0..n3], &ctx, Ctx.cb);

    try std.testing.expectEqual(@as(usize, 3 + 3 + 5), ctx.out_len);
    try std.testing.expectEqualStrings("onetwothree", ctx.out[0..ctx.out_len]);
}

// ---------------------------------------------------------------------------
// Full-path integration: encode → sign → split into multipart frames → TCP
// envelopes → EnvelopeParser (fed in readVec-sized chunks) → drain 16 packets
// per tick → Reassembler → signature verify → decode. Mirrors the runtime
// receive path for a coalesced multipart burst with group_id=0 (as the server
// outbox sends).
// ---------------------------------------------------------------------------

const FullPathCtx = struct {
    items: *[128]IncomingMessage,
    len: *usize,
    fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
        _ = port;
        _ = src;
        _ = dest;
        if (self.len.* >= self.items.len) return;
        var msg: IncomingMessage = .{};
        _ = decodePacket(frame, &msg);
        self.items[self.len.*] = msg;
        self.len.* += 1;
    }
};


test "EnvelopeParser rejects bad magic" {
    const Ctx = struct {
        called: bool = false,
        fn cb(self: *@This(), port: u8, src: []const u8, dest: []const u8, frame: []const u8) void {
            _ = self;
            _ = port;
            _ = src;
            _ = dest;
            _ = frame;
        }
    };
    var parser: EnvelopeParser = .{};
    var ctx: Ctx = .{};

    // Bad magic byte.
    var bad = [_]u8{ 0x00, 0, 0, 0, 0, 0, 0 };
    parser.feed(&bad, &ctx, Ctx.cb);
    try std.testing.expect(!ctx.called);
}

// ---------------------------------------------------------------------------
// Connection — persistent TCP connection built on the shared
// `connection.Core` scaffolding (reader thread, incoming queue, FIFO drain,
// lifecycle). Only the TCP specifics live here: the length-delimited
// envelope parser and the envelope transmit wrapper.
// ---------------------------------------------------------------------------

const connection_mod = @import("../connection.zig");

/// Persistent TCP connection for the direct TCP transport. Mirrors
/// `agwpe.Connection`: keeps the socket open, sends framed envelopes on
/// demand from the main thread, and runs a background reader thread that
/// parses incoming envelopes and decodes their message frames.
///
/// The Connection must be initialised with `connect()` (client) or
/// `acceptStream()` (server) before use and cleaned up with `disconnect()` /
/// `deinit()`. The struct must not be moved after connection because the
/// embedded core's `Stream.Writer` holds a pointer to its `write_buf` field.
pub const Connection = struct {
    /// Shared scaffolding — lifecycle, writer, reader thread, incoming queue.
    core: connection_mod.Core = .{ .link = &tcp_link },
    /// Streaming envelope parser (owns partial-envelope state across reads).
    parser: EnvelopeParser = .{},

    pub fn isConnected(self: *const Connection) bool {
        return self.core.isConnected();
    }

    /// Open a TCP connection to `address` (client side).
    pub fn connect(
        self: *Connection,
        io: std.Io,
        address: std.Io.net.IpAddress,
        allocator: std.mem.Allocator,
        port: u4,
        callsign: []const u8,
    ) !void {
        return self.core.connect(io, address, allocator, port, callsign);
    }

    /// Wrap an already-accepted TCP stream (server side). The caller obtains
    /// the stream from `net.Server.accept()`.
    pub fn acceptStream(
        self: *Connection,
        io: std.Io,
        stream: std.Io.net.Stream,
        allocator: std.mem.Allocator,
        port: u4,
        callsign: []const u8,
    ) !void {
        return self.core.acceptStream(io, stream, allocator, port, callsign);
    }

    pub fn disconnect(self: *Connection) void {
        self.core.disconnect();
    }

    pub fn deinit(self: *Connection) void {
        self.core.deinit();
    }

    pub fn drainIncoming(self: *Connection, dest: []IncomingMessage) usize {
        return self.core.drainIncoming(dest);
    }

    /// Return a `Transport` handle backed by this connection. The handle
    /// borrows the connection and is valid as long as it lives.
    pub fn asTransport(self: *Connection) transport.Transport {
        return .{ .ctx = @ptrCast(self), .vtable = &tcp_transport_vtable };
    }
};

const tcp_link: connection_mod.Link = .{
    .dispatch = dispatch,
    .sendWire = sendWireFrame,
};

/// Link.dispatch: feed one batch of freshly-read stream bytes through the
/// envelope parser.
fn dispatch(core: *connection_mod.Core, data: []const u8) void {
    const conn: *Connection = @fieldParentPtr("core", core);
    conn.parser.feed(data, conn, onTcpEnvelope);
}

/// EnvelopeParser callback: dispatched for each complete envelope.
fn onTcpEnvelope(conn: *Connection, port: u8, src: []const u8, dest: []const u8, frame_bytes: []const u8) void {
    var msg: IncomingMessage = .{ .port = @intCast(port & 0x0F) };

    if (src.len > 0) {
        @memcpy(msg.callsign[0..src.len], src);
        msg.callsign_str_len = @intCast(src.len);
        msg.has_callsign = true;
    }
    if (dest.len > 0) {
        @memcpy(msg.dest_callsign[0..dest.len], dest);
        msg.dest_callsign_str_len = @intCast(dest.len);
        msg.has_dest_callsign = true;
    }

    _ = decodePacket(frame_bytes, &msg);

    conn.core.enqueueIncoming(msg);
}

/// Link.sendWire: low-level send of pre-built wire bytes wrapped in a TCP
/// envelope.
fn sendWireFrame(core: *connection_mod.Core, port: u4, call_to: []const u8, payload: []const u8) !void {
    const call_from: []const u8 = core.callsign[0..core.callsign_len];

    var buf: [max_envelope_size]u8 = undefined;
    const n = writeEnvelope(&buf, port, call_from, call_to, payload) orelse return error.PayloadTooLarge;

    const w = core.writerInterface().?;
    try w.writeAll(buf[0..n]);
    try w.flush();
}

// ---------------------------------------------------------------------------
// Transport vtable
// ---------------------------------------------------------------------------

const tcp_transport_vtable: transport.Transport.VTable = .{
    .mtu_payload = mtu_payload,
    .high_bandwidth = true,
    .requires_beacon = false,
    .isConnected = transportIsConnected,
    .sendWire = transportSendWire,
    .drainIncoming = transportDrainIncoming,
    .disconnect = transportDisconnect,
};

fn transportIsConnected(ctx: *anyopaque) bool {
    const self: *Connection = @ptrCast(@alignCast(ctx));
    return self.isConnected();
}

fn transportSendWire(ctx: *anyopaque, port: u4, call_to: []const u8, wire: []const u8) anyerror!void {
    const self: *Connection = @ptrCast(@alignCast(ctx));
    return self.core.sendWire(port, call_to, wire);
}

fn transportDrainIncoming(ctx: *anyopaque, dest: []transport.IncomingMessage) usize {
    const self: *Connection = @ptrCast(@alignCast(ctx));
    return self.drainIncoming(dest);
}

fn transportDisconnect(ctx: *anyopaque) void {
    const self: *Connection = @ptrCast(@alignCast(ctx));
    self.disconnect();
}
