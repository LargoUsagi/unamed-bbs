//! AGWPE TNC link transport — framing, parser, and connection.
//!
//! This is the bottom-layer link implementation of the transport stack: it
//! speaks the AGW Packet Engine (AGWPE) TCP protocol used by ham radio TNCs
//! such as Direwolf (AGWPE enabled, default port 8000), wraps packet wire
//! bytes in UI frames on send, and parses raw AX.25 'K' frames on receive,
//! yielding decoded `transport.incoming.IncomingMessage` packets. It knows
//! nothing about message payloads or signatures — those are handled by the
//! generic layers above it (`transport.zig`, `messaging.zig`).
//!
//! AGWPE provides source/destination callsigns in the frame header, so the
//! application can display the sender's callsign without embedding it in the
//! payload.
//!
//! Header layout (36 bytes, matching Direwolf's `struct agwpe_s`):
//!   [0]     portx (u8)
//!   [1..4]  reserved (3 bytes, zero)
//!   [4]     datakind (u8) — command letter
//!   [5]     reserved (zero)
//!   [6]     pid (u8) — AX.25 Layer 3 PID
//!   [7]     reserved (zero)
//!   [8..18]  call_from (10 bytes, null-padded ASCII)
//!   [18..28] call_to (10 bytes, null-padded ASCII)
//!   [28..32] data_len (u32 LE) — payload bytes following header
//!   [32..36] user_reserved (u32 LE, zero)
//!
//! Commands used (client → TNC):
//!   'R' — Request version number (reply: 'R' with major/minor)
//!   'k' — Toggle raw AX.25 frame reception (enables 'K' from TNC)
//!   'V' — Transmit UI data frame (data = [ndigi] + digi*10 + payload)
//!   'G' — Ask about radio ports (reply: 'G' with port descriptions)
//!
//! Commands from TNC → client:
//!   'K' — Received raw AX.25 frame (call_from/call_to in header, data = [chan<<4] + raw frame)
//!   'R' — Version number reply
//!   'G' — Port information reply

const std = @import("std");
const Io = std.Io;
const net = Io.net;

/// Shared transport abstraction (`Transport` vtable + multipart splitting).
pub const transport = @import("transport.zig");
const incoming_mod = transport.incoming;

const IncomingMessage = incoming_mod.IncomingMessage;
const decodePacket = incoming_mod.decodePacket;
const SendOptions = transport.SendOptions;
const FrameObserver = transport.FrameObserver;

/// Size of the AGWPE callsign field in the header (CallFrom/CallTo).
pub const agw_callsign_len: usize = incoming_mod.callsign_len;

/// Size of the fixed AGWPE header.
pub const agw_header_size: usize = 36;

/// AX.25 PID for "no Layer 3 protocol" — used for UI frames.
const ax25_pid_no_l3: u8 = 0xF0;

/// Maximum payload size the parser will accept.
pub const max_frame_payload: usize = 4096;

// ---------------------------------------------------------------------------
// Header read/write
// ---------------------------------------------------------------------------

/// Write an AGWPE header into `buf`.
fn writeHeader(
    buf: *[agw_header_size]u8,
    port: u8,
    kind: u8,
    pid: u8,
    call_from: []const u8,
    call_to: []const u8,
    data_len: u32,
) void {
    @memset(buf, 0);
    buf[0] = port;
    buf[4] = kind;
    buf[6] = pid;
    const cf = @min(call_from.len, agw_callsign_len);
    @memcpy(buf[8..][0..cf], call_from[0..cf]);
    const ct = @min(call_to.len, agw_callsign_len);
    @memcpy(buf[18..][0..ct], call_to[0..ct]);
    std.mem.writeInt(u32, buf[28..32], data_len, .little);
    // user_reserved at [32..36] left as zero
}

/// Extract a null-padded callsign from a 10-byte AGWPE field.
fn parseAgwCallsign(field: []const u8) ?[]const u8 {
    var len: usize = @min(field.len, agw_callsign_len);
    while (len > 0 and field[len - 1] == 0) len -= 1;
    if (len == 0) return null;
    return field[0..len];
}

// ---------------------------------------------------------------------------
// AX.25 info field extraction from raw frames
// ---------------------------------------------------------------------------

/// Extract the information field from a raw AX.25 frame.
///
/// Raw frame format (without start/end flags, with optional FCS):
///   [0..7]   destination address (7 bytes)
///   [7..14]  source address (7 bytes)
///   [14..]   digipeater addresses (7 bytes each, optional)
///   [n]      control field (1 byte for U/I-mod8 frames)
///   [n+1]    PID (1 byte, for UI and I frames)
///   [n+2..]  information field
///   [end-2..end] FCS (2 bytes, may or may not be present)
///
/// The last address has bit 0 of its 6th byte (offset 6 within the address)
/// set to 1 (the "address extension" bit).
///
/// We do NOT strip FCS — some TNCs include it, others don't. Callers that
/// parse structured data (e.g. MessageFrame) use length fields that ignore
/// trailing bytes, so extra FCS bytes are harmless.
fn extractAx25Info(raw: []const u8) ?[]const u8 {
    if (raw.len < 15) return null; // minimum: 2 addresses + control + PID

    // Scan address field: each address is 7 bytes.
    var pos: usize = 0;
    while (pos + 7 <= raw.len) {
        const ext_bit = raw[pos + 6] & 0x01;
        pos += 7;
        if (ext_bit != 0) break;
    }

    // pos now points past the last address to the control field.
    if (pos + 2 > raw.len) return null;

    // For UI frames: control is 1 byte (0x03), PID is 1 byte (0xF0).
    // For I frames (modulo 8): control is 1 byte, PID is 1 byte.
    // Skip control + PID.
    pos += 2;

    // Info field = everything after control+PID. FCS (if present) is trailing
    // and will be ignored by structured parsers (MessageFrame uses payload_len).
    return raw[pos..];
}

test "extractAx25Info with no digipeaters" {
    // Build a minimal AX.25 UI frame: dest(7) + src(7) + control(1) + PID(1) + info(5)
    var frame: [21]u8 = undefined;
    // Destination address (6 bytes + ssid byte, extension bit clear — the
    // source follows so this is NOT the last address).
    @memset(frame[0..6], 'C');
    frame[6] = 0x60; // SSID byte with extension bit (bit 0) clear
    // Source address (6 bytes + ssid byte, extension bit set — last address).
    @memset(frame[7..13], 'K');
    frame[13] = 0x61; // SSID byte with extension bit set
    // Control + PID
    frame[14] = 0x03; // UI frame
    frame[15] = 0xF0; // No Layer 3
    // Info
    @memcpy(frame[16..21], "hello");

    const info = extractAx25Info(&frame).?;
    try std.testing.expectEqualStrings("hello", info);
}

test "extractAx25Info with one digipeater" {
    // dest(7) + src(7) + digi(7) + control(1) + PID(1) + info(3) = 26
    var frame: [26]u8 = undefined;
    @memset(frame[0..6], 'C');
    frame[6] = 0x60; // extension bit NOT set (more addresses follow)
    @memset(frame[7..13], 'K');
    frame[13] = 0x60; // extension bit NOT set
    @memset(frame[14..20], 'W');
    frame[20] = 0x61; // extension bit set (last address)
    frame[21] = 0x03; // UI
    frame[22] = 0xF0; // PID
    @memcpy(frame[23..26], "hi!");

    const info = extractAx25Info(&frame).?;
    try std.testing.expectEqualStrings("hi!", info);
}

test "extractAx25Info returns null for too-short frame" {
    var short: [10]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), extractAx25Info(&short));
}

// ---------------------------------------------------------------------------
// Frame parser — streaming length-delimited AGWPE frame parser
// ---------------------------------------------------------------------------

/// Streaming AGWPE frame parser. Feed it raw bytes from the TCP stream and it
/// calls `onFrame` for each complete 36-byte header + payload pair.
pub const FrameParser = struct {
    header_buf: [agw_header_size]u8 = undefined,
    header_pos: usize = 0,
    data_buf: [max_frame_payload]u8 = undefined,
    data_pos: usize = 0,
    data_len: u32 = 0,
    state: State = .reading_header,
    overflow: bool = false,

    const State = enum { reading_header, reading_data };

    pub fn feed(
        self: *FrameParser,
        data: []const u8,
        ctx: anytype,
        comptime onFrame: fn (@TypeOf(ctx), *const [agw_header_size]u8, []const u8) void,
    ) void {
        var i: usize = 0;
        while (i < data.len) {
            switch (self.state) {
                .reading_header => {
                    const remaining = agw_header_size - self.header_pos;
                    const available = data.len - i;
                    const to_copy = @min(remaining, available);
                    @memcpy(self.header_buf[self.header_pos..][0..to_copy], data[i..][0..to_copy]);
                    self.header_pos += to_copy;
                    i += to_copy;

                    if (self.header_pos == agw_header_size) {
                        self.data_len = std.mem.readInt(u32, self.header_buf[28..32], .little);
                        self.data_pos = 0;
                        self.overflow = false;

                        if (self.data_len == 0) {
                            self.emit(ctx, onFrame);
                            self.resetHeader();
                        } else if (self.data_len > max_frame_payload) {
                            self.overflow = true;
                            self.resetHeader();
                        } else {
                            self.state = .reading_data;
                        }
                    }
                },
                .reading_data => {
                    const remaining = self.data_len - self.data_pos;
                    const available: u32 = @intCast(data.len - i);
                    const to_copy = @min(remaining, available);
                    @memcpy(self.data_buf[self.data_pos..][0..to_copy], data[i..][0..to_copy]);
                    self.data_pos += to_copy;
                    i += to_copy;

                    if (self.data_pos == self.data_len) {
                        if (!self.overflow) {
                            self.emit(ctx, onFrame);
                        }
                        self.resetHeader();
                    }
                },
            }
        }
    }

    fn emit(self: *FrameParser, ctx: anytype, comptime onFrame: fn (@TypeOf(ctx), *const [agw_header_size]u8, []const u8) void) void {
        onFrame(ctx, &self.header_buf, self.data_buf[0..self.data_pos]);
    }

    fn resetHeader(self: *FrameParser) void {
        self.header_pos = 0;
        self.state = .reading_header;
    }
};

test "FrameParser parses a single frame with data" {
    const Ctx = struct {
        kind: u8 = 0,
        data: []const u8 = "",
        called: bool = false,
        fn cb(self: *@This(), header: *const [agw_header_size]u8, data: []const u8) void {
            self.called = true;
            self.kind = header[4];
            self.data = data;
        }
    };
    var parser: FrameParser = .{};
    var ctx: Ctx = .{};

    var hdr: [agw_header_size]u8 = std.mem.zeroes([agw_header_size]u8);
    hdr[4] = 'K';
    std.mem.writeInt(u32, hdr[28..32], 5, .little);

    parser.feed(&hdr, &ctx, Ctx.cb);
    try std.testing.expect(!ctx.called);

    parser.feed("hello", &ctx, Ctx.cb);
    try std.testing.expect(ctx.called);
    try std.testing.expectEqual(@as(u8, 'K'), ctx.kind);
    try std.testing.expectEqualStrings("hello", ctx.data);
}

test "FrameParser handles split header" {
    const Ctx = struct {
        kind: u8 = 0,
        data: []const u8 = "",
        called: bool = false,
        fn cb(self: *@This(), header: *const [agw_header_size]u8, data: []const u8) void {
            self.called = true;
            self.kind = header[4];
            self.data = data;
        }
    };
    var parser: FrameParser = .{};
    var ctx: Ctx = .{};

    var hdr: [agw_header_size]u8 = std.mem.zeroes([agw_header_size]u8);
    hdr[4] = 'R';
    std.mem.writeInt(u32, hdr[28..32], 1, .little);

    parser.feed(hdr[0..20], &ctx, Ctx.cb);
    try std.testing.expect(!ctx.called);
    parser.feed(hdr[20..36], &ctx, Ctx.cb);
    try std.testing.expect(!ctx.called);
    parser.feed(&.{0x42}, &ctx, Ctx.cb);
    try std.testing.expect(ctx.called);
    try std.testing.expectEqual(@as(u8, 'R'), ctx.kind);
    try std.testing.expectEqualSlices(u8, &.{0x42}, ctx.data);
}

test "FrameParser handles frame with no data" {
    const Ctx = struct {
        kind: u8 = 0,
        called: bool = false,
        fn cb(self: *@This(), header: *const [agw_header_size]u8, data: []const u8) void {
            self.called = true;
            self.kind = header[4];
            _ = data;
        }
    };
    var parser: FrameParser = .{};
    var ctx: Ctx = .{};

    var hdr: [agw_header_size]u8 = std.mem.zeroes([agw_header_size]u8);
    hdr[4] = 'k';
    std.mem.writeInt(u32, hdr[28..32], 0, .little);

    parser.feed(&hdr, &ctx, Ctx.cb);
    try std.testing.expect(ctx.called);
    try std.testing.expectEqual(@as(u8, 'k'), ctx.kind);
}

test "FrameParser extracts callsign from header" {
    const Ctx = struct {
        call_from: [agw_callsign_len]u8 = std.mem.zeroes([agw_callsign_len]u8),
        call_from_len: u8 = 0,
        fn cb(self: *@This(), header: *const [agw_header_size]u8, data: []const u8) void {
            _ = data;
            if (parseAgwCallsign(header[8..18])) |cs| {
                @memcpy(self.call_from[0..cs.len], cs);
                self.call_from_len = @intCast(cs.len);
            }
        }
    };
    var parser: FrameParser = .{};
    var ctx: Ctx = .{};

    var hdr: [agw_header_size]u8 = std.mem.zeroes([agw_header_size]u8);
    hdr[4] = 'K';
    @memcpy(hdr[8..][0..6], "KE8WIF");
    std.mem.writeInt(u32, hdr[28..32], 0, .little);

    parser.feed(&hdr, &ctx, Ctx.cb);
    try std.testing.expectEqualStrings("KE8WIF", ctx.call_from[0..ctx.call_from_len]);
}

test "writeHeader produces correct layout" {
    var hdr: [agw_header_size]u8 = undefined;
    writeHeader(&hdr, 3, 'V', 0xF0, "KE8WIF", "CQ", 42);

    try std.testing.expectEqual(@as(u8, 3), hdr[0]);    // portx
    try std.testing.expectEqual(@as(u8, 'V'), hdr[4]);  // datakind
    try std.testing.expectEqual(@as(u8, 0xF0), hdr[6]); // pid
    try std.testing.expectEqualStrings("KE8WIF", hdr[8..14]); // call_from
    try std.testing.expectEqual(@as(u8, 0), hdr[14]);   // null terminator
    try std.testing.expectEqualStrings("CQ", hdr[18..20]); // call_to
    try std.testing.expectEqual(@as(u32, 42), std.mem.readInt(u32, hdr[28..32], .little)); // data_len
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, hdr[32..36], .little)); // user_reserved
}

// ---------------------------------------------------------------------------
// Incoming packet decoding
// ---------------------------------------------------------------------------

// `IncomingMessage` and `decodePacket` come from `transport.incoming` —
// see the imports at the top of this file.

// ---------------------------------------------------------------------------
// Connection — persistent TCP connection to an AGWPE TNC, built on the
// shared `connection.Core` scaffolding (reader thread, incoming queue,
// FIFO drain, lifecycle). Only the AGWPE specifics live here: frame
// parsing ('K' raw AX.25 frames), the 'V' UI transmit wrapper, and the
// 'R' + 'k' post-connect handshake.
// ---------------------------------------------------------------------------

const connection_mod = @import("connection.zig");

/// Persistent TCP connection to an AGWPE TNC (e.g. Direwolf). Keeps the socket
/// open, sends UI frames on demand from the main thread, and runs a background
/// reader thread that parses incoming AGWPE 'K' frames (raw AX.25 received
/// frames) and decodes their payloads. On connect, it sends 'R' (version
/// request) and 'k' (enable raw frame reception).
///
/// The Connection must be initialised with `connect()` before use and cleaned
/// up with `disconnect()` / `deinit()`. The struct must not be moved after
/// `connect()` because the embedded core's `Stream.Writer` holds a pointer to
/// its `write_buf` field.
pub const Connection = struct {
    /// Shared scaffolding — lifecycle, writer, reader thread, incoming queue.
    core: connection_mod.Core = .{ .link = &agwpe_link },
    /// AGWPE streaming frame parser (owns partial-frame state across reads).
    parser: FrameParser = .{},

    pub fn isConnected(self: *const Connection) bool {
        return self.core.isConnected();
    }

    /// Open the TCP connection to the TNC, send 'R' (version) and 'k' (enable
    /// raw RX), and start the reader thread.
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
        return .{ .ctx = @ptrCast(self), .vtable = &agwpe_transport_vtable };
    }
};

const agwpe_link: connection_mod.Link = .{
    .dispatch = dispatch,
    .sendWire = sendWireFrame,
    .postConnect = postConnect,
};

fn postConnect(core: *connection_mod.Core) anyerror!void {
    // Send 'R' — Request version number.
    var ver_hdr: [agw_header_size]u8 = std.mem.zeroes([agw_header_size]u8);
    ver_hdr[4] = 'R';
    try core.writerInterface().?.writeAll(&ver_hdr);

    // Send 'k' — Enable raw AX.25 frame reception.
    var raw_hdr: [agw_header_size]u8 = std.mem.zeroes([agw_header_size]u8);
    raw_hdr[4] = 'k';
    try core.writerInterface().?.writeAll(&raw_hdr);
    try core.writerInterface().?.flush();
}

/// Link.dispatch: feed one batch of freshly-read stream bytes through the
/// AGWPE frame parser.
fn dispatch(core: *connection_mod.Core, data: []const u8) void {
    const conn: *Connection = @fieldParentPtr("core", core);
    conn.parser.feed(data, conn, onAgwpeFrame);
}

/// FrameParser callback: dispatched for each complete AGWPE frame.
fn onAgwpeFrame(conn: *Connection, header: *const [agw_header_size]u8, data: []const u8) void {
    const kind = header[4];

    switch (kind) {
        'K' => {
            // Raw AX.25 frame received — extract callsign from AGWPE header.
            const frame_port: u4 = @intCast(header[0] & 0x0F);

            var msg: IncomingMessage = .{ .port = frame_port };

            if (parseAgwCallsign(header[8..18])) |cs| {
                @memcpy(msg.callsign[0..cs.len], cs);
                msg.callsign_str_len = @intCast(cs.len);
                msg.has_callsign = true;
            }

            // Extract the destination callsign (call_to) from the AGWPE
            // header so directed messages can be filtered by callsign.
            if (parseAgwCallsign(header[18..28])) |cs| {
                @memcpy(msg.dest_callsign[0..cs.len], cs);
                msg.dest_callsign_str_len = @intCast(cs.len);
                msg.has_dest_callsign = true;
            }

            // Extract the AX.25 info field, then decode the message frame.
            // data is: [channel_byte] + [raw AX.25 frame].
            if (data.len >= 2) {
                const raw_frame = data[1..];
                const payload = extractAx25Info(raw_frame) orelse raw_frame;
                _ = decodePacket(payload, &msg);
            }

            conn.core.enqueueIncoming(msg);
        },
        else => {}, // Ignore 'R', 'G', 'g', 'X', etc.
    }
}

/// Link.sendWire: low-level send of pre-built wire bytes as a UI frame via 'V'.
fn sendWireFrame(core: *connection_mod.Core, port: u4, call_to: []const u8, payload: []const u8) !void {
    const call_from: []const u8 = core.callsign[0..core.callsign_len];
    const data_len: u32 = @intCast(1 + payload.len); // 1 byte ndigi + payload

    var hdr: [agw_header_size]u8 = undefined;
    writeHeader(&hdr, @as(u8, port), 'V', ax25_pid_no_l3, call_from, call_to, data_len);

    const w = core.writerInterface().?;
    try w.writeAll(&hdr);
    try w.writeAll(&.{0x00}); // zero digipeaters
    try w.writeAll(payload);
    try w.flush();
}

// ---------------------------------------------------------------------------
// Transport vtable — lets `Connection` satisfy the `transport.Transport`
// interface so shared send-side logic (multipart splitting) can consult the
// transport's MTU instead of hardcoding `frame.max_chunk_len`.
// ---------------------------------------------------------------------------

/// Operational payload bytes per packet chunk for the AGWPE transport.
/// Direwolf and modern TNCs accept AX.25 UI info fields up to 512 bytes;
/// receivers tolerate any chunk up to `frame.max_chunk_len` (1024) regardless
/// of this value, so mixed-MTU networks interoperate as long as all stations
/// run a build with the raised ceiling.
pub const mtu_payload: usize = 512;

const agwpe_transport_vtable: transport.Transport.VTable = .{
    .mtu_payload = mtu_payload,
    .high_bandwidth = false,
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
