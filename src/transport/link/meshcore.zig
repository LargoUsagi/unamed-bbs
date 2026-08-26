//! MeshCore link transport — a LoRa radio running stock companion firmware,
//! attached to a local serial port (USB CDC / hardware UART, 8N1 no flow
//! control). End users keep their radios exactly as they carry them; this
//! link only needs the companion app's serial interface.
//!
//! Companion serial framing (firmware `ArduinoSerialInterface`): every
//! direction exchanges length-prefixed binary frames —
//!
//!   host → radio:  '<' + len u16 LE + payload   (commands)
//!   radio → host:  '>' + len u16 LE + payload   (responses + pushes)
//!
//! Frames are capped at MAX_FRAME_SIZE (176 bytes) by current firmware;
//! larger inbound frames are truncated, larger outbound ones rejected.
//!
//! Raw packet exchange (companion firmware v1.12+):
//!   * TX: `CMD_SEND_RAW_PACKET` (65) — `[0x41][priority][raw packet…]`.
//!     The firmware runs its own packet parser on the raw bytes, so we
//!     construct the MeshCore v1 header ourselves: RAW_CUSTOM payload type
//!     (0xF), DIRECT route, version 1 → `0x3E`, followed by a zero-hop
//!     path_length byte. (Direct is mandatory — the firmware dispatcher
//!     drops flood-routed RAW packets before they reach the app.) The reply
//!     (`OK`/`ERR`) is skipped on RX; the send queue is firmware-managed
//!     (no KISS-style TxDone pacing), with a full queue surfacing as
//!     `ERR_CODE_TABLE_FULL`.
//!   * RX: `PUSH_CODE_RAW_DATA` (0x84) —
//!     `[0x84][snr×4][rssi][reserved][payload…]`, pushed asynchronously.
//!     The firmware strips the MeshCore header/path before delivery, so the
//!     body is exactly our `MessageFrame` wire bytes and feeds directly
//!     into `decodePacket`.
//!
//! All traffic is sent as zero-hop direct RAW packets: one transmission
//! heard by every station in range. The BBS model is broadcast-oriented and
//! directed callsigns already ride inside signed payloads, so no contact
//! sync or direct-path management is needed in this cut.
//!
//! Chunk budget (why `mtu_payload` is 98): stock companion firmware caps
//! every serial command frame at MAX_FRAME_SIZE (176), so
//!
//!   176 − cmd(1) − priority(1)                    = 174 raw packet bytes
//!   174 − meshcore header(1) − path_len(1)        = 172 MessageFrame bytes
//!   172 − identity tag(4)                         = 168 MessageFrame bytes
//!   168 − MessageFrame header(6) − signature(64)  =  98 chunk bytes
//!
//! Continuation packets could carry more (no signature field), but
//! `sendMultipart` splits uniformly. Receivers accept chunks up to
//! `frame.max_chunk_len` regardless of their own link's MTU, so mixed-MTU
//! networks interoperate.

const std = @import("std");
const Io = std.Io;

/// Serial port configuration library (ZigEmbeddedGroup/serial).
const serial = @import("serial");

/// Shared transport abstraction (`Transport` vtable + multipart splitting).
pub const transport = @import("../transport.zig");
const connection_mod = @import("../connection.zig");

const incoming_mod = transport.incoming;

const IncomingMessage = incoming_mod.IncomingMessage;
const decodePacket = incoming_mod.decodePacket;

/// Operational payload bytes per packet chunk for this transport. See the
/// module doc comment for the full derivation against the companion
/// firmware's 176-byte serial frame cap — including the 4-byte sender
/// identity tag that rides inside every radio payload.
pub const mtu_payload: usize = 98;

/// Default baud rate — MeshCore companion firmware standard (115200 8N1).
pub const default_baud: u32 = 115200;

// --- Station identity --------------------------------------------------------

/// Sender-identity tag: the first `identity_tag_len` bytes of THIS STATION'S
/// RADIO PUBLIC KEY (the Ed25519 identity companion firmware generates and
/// reports in its SELF_INFO frame), prepended to every transmitted radio
/// payload. RAW_CUSTOM packets carry no on-air sender identity, so this tag
/// is the only station identifier a receiver has; it is rendered as uppercase
/// hex (8 chars) and surfaces as the session-layer callsign — spoofable like
/// an AX.25 callsign, which is the existing trust model.
pub const identity_tag_len: usize = 4;

/// Length of the hex-rendered identity callsign.
pub const identity_callsign_len: usize = 2 * identity_tag_len;

/// `RESP_CODE_SELF_INFO` — reply to APP_START; carries the radio's public key.
const RESP_CODE_SELF_INFO: u8 = 0x05;
const self_info_min_len: usize = 1 + 3 + 32; // type + adv/tx/max + pubkey

/// Render a raw identity tag as uppercase hex callsign characters.
fn identityHex(buf: *[identity_callsign_len]u8, tag: [identity_tag_len]u8) []const u8 {
    const hex = "0123456789ABCDEF";
    for (tag, 0..) |b, i| {
        buf[i * 2] = hex[b >> 4];
        buf[i * 2 + 1] = hex[b & 0x0F];
    }
    return buf;
}

// --- Companion protocol codes ---------------------------------------------

/// `CMD_APP_START` — first command after opening the port; identifies the
/// host application to the firmware.
const CMD_APP_START: u8 = 0x01;
/// `CMD_SEND_RAW_PACKET` (firmware v1.12+): queue one raw packet for TX.
const CMD_SEND_RAW_PACKET: u8 = 0x41;
/// `RESP_CODE_OK` / `RESP_CODE_ERR` replies — parsed and ignored.
const RESP_CODE_OK: u8 = 0x00;
const RESP_CODE_ERR: u8 = 0x01;
/// `PUSH_CODE_RAW_DATA`: an asynchronously delivered raw packet payload.
const PUSH_CODE_RAW_DATA: u8 = 0x84;

/// Host app name reported in the APP_START handshake.
const app_name = "unamed-bbs";

// --- Companion serial framing constants ------------------------------------

/// Marker byte starting a host → radio frame (commands).
const tx_marker: u8 = '<';
/// Marker byte starting a radio → host frame (responses + pushes).
const rx_marker: u8 = '>';
/// Firmware-side cap (`MAX_FRAME_SIZE`); larger frames never cross the wire.
pub const max_serial_frame_size: usize = 176;

// --- Raw packet construction ------------------------------------------------

/// MeshCore v1 packet header byte for DIRECT-routed RAW_CUSTOM payloads:
/// bits 6-7 version (v1 = 00) | bits 2-5 payload type (RAW_CUSTOM = 1111)
/// | bits 0-1 route type (direct = 10).
///
/// Direct is required: companion firmware's dispatcher only delivers
/// RAW_CUSTOM packets to the app when `pkt->isRouteDirect()` — flood-routed
/// raw packets are silently dropped (`src/Mesh.cpp`). A zero-hop direct
/// packet is a one-shot transmission heard by everyone in range, which is
/// the semantics this link wants; receiving firmware additionally dedups
/// repeats via its seen-table.
pub const raw_custom_direct_header: u8 = 0b00_1111_10;

/// Priority byte passed to `CMD_SEND_RAW_PACKET` (0 = normal).
const default_tx_priority: u8 = 0;

/// Largest command payload this link ever builds: cmd(1) + priority(1) +
/// meshcore header(1) + path_len(1) + identity_tag(4) + a fully-signed
/// packet-0 MessageFrame (header 6 + signature 64 + chunk mtu_payload).
/// Asserted ≤ the firmware's serial frame cap at compile time below.
pub const max_command_payload: usize =
    4 + identity_tag_len + 6 + transport.frame.signature_len + mtu_payload;

comptime {
    if (max_command_payload > max_serial_frame_size) {
        @compileError("MeshCore MTU exceeds the companion firmware serial frame cap");
    }
}

// ---------------------------------------------------------------------------
// Command frame builder (host → radio)
// ---------------------------------------------------------------------------

/// Write `'<' + len16 LE + [CMD_SEND_RAW_PACKET][priority]
/// + [raw_custom_direct_header][path_len=0] + identity_tag + wire` into
/// `buf`. Returns the total byte count, or null when `wire` would overflow
/// the firmware's serial frame cap.
pub fn writeTxCommand(buf: []u8, tag: [identity_tag_len]u8, wire: []const u8) ?usize {
    const payload_len = 4 + identity_tag_len + wire.len;
    if (payload_len > max_serial_frame_size) return null;
    const total = 3 + payload_len;
    if (buf.len < total) return null;

    buf[0] = tx_marker;
    std.mem.writeInt(u16, buf[1..3], @intCast(payload_len), .little);
    buf[3] = CMD_SEND_RAW_PACKET;
    buf[4] = default_tx_priority;
    buf[5] = raw_custom_direct_header;
    buf[6] = 0x00; // path_length: zero hops (heard by every station in range)
    @memcpy(buf[7..][0..identity_tag_len], &tag);
    @memcpy(buf[7 + identity_tag_len .. total], wire);
    return total;
}

/// Build and write the `CMD_APP_START` handshake frame. Reserved bytes 1-7
/// are zeros; the trailing app name is informational.
fn postConnect(core: *connection_mod.Core) anyerror!void {
    var buf: [3 + 8 + app_name.len]u8 = undefined;
    const payload_len = 8 + app_name.len;

    buf[0] = tx_marker;
    std.mem.writeInt(u16, buf[1..3], @intCast(payload_len), .little);
    buf[3] = CMD_APP_START;
    @memset(buf[4..11], 0);
    @memcpy(buf[11..][0..app_name.len], app_name);

    const w = core.writerInterface() orelse return error.NotConnected;
    try w.writeAll(buf[0 .. 3 + payload_len]);
    try w.flush();
}

// ---------------------------------------------------------------------------
// Response frame parser (radio → host)
// ---------------------------------------------------------------------------

/// Streaming parser for `<`-framed companion responses. Feed it raw serial
/// bytes in arbitrarily-sized chunks; it delivers each complete frame's
/// payload. Mirrors the firmware side: declared lengths beyond the frame
/// cap are still consumed but truncated (the firmware truncates too), so
/// the stream stays in sync even around oversized frames.
pub const RxParser = struct {
    state: State = .idle,
    declared: u16 = 0,
    have: u16 = 0,
    buf: [max_serial_frame_size]u8 = undefined,

    const State = enum { idle, got_marker, got_len_lo, payload };

    pub fn feed(
        self: *RxParser,
        data: []const u8,
        ctx: anytype,
        comptime handleFrame: fn (@TypeOf(ctx), []const u8) void,
    ) void {
        for (data) |c| {
            switch (self.state) {
                .idle => {
                    if (c == rx_marker) self.state = .got_marker;
                },
                .got_marker => {
                    self.declared = c;
                    self.state = .got_len_lo;
                },
                .got_len_lo => {
                    self.declared |= @as(u16, c) << 8;
                    self.have = 0;
                    // Zero-length frame: nothing to deliver, resync.
                    self.state = if (self.declared == 0) .idle else .payload;
                },
                .payload => {
                    if (self.have < self.buf.len) {
                        self.buf[self.have] = c;
                    }
                    self.have += 1;
                    if (self.have >= self.declared) {
                        const n: usize = @min(self.declared, self.buf.len);
                        handleFrame(ctx, self.buf[0..n]);
                        self.state = .idle;
                    }
                },
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Connection — embeds connection.Core like every other link
// ---------------------------------------------------------------------------

/// Persistent serial-port connection to a MeshCore companion radio. Mirrors
/// `agwpe.Connection` / `tcp.Connection`: opened once via `connect()`,
/// sends framed commands on demand from the main thread, runs a background
/// reader thread that parses response frames and decodes pushed raw packets.
///
/// The struct must not be moved after `connect()` because the embedded
/// core's file writer holds a pointer to its `write_buf` field.
pub const Connection = struct {
    /// Shared scaffolding — lifecycle, writer, reader thread, incoming queue.
    core: connection_mod.Core = .{ .link = &meshcore_link },
    /// Streaming response-frame parser (owns partial-frame state across reads).
    parser: RxParser = .{},
    /// Station radio public key + availability flag (from the SELF_INFO
    /// handshake reply). Written once by the reader thread; read on the TX
    /// path. Guarded by `pubkey_mutex` (uses `core.io` when locked).
    pubkey_mutex: Io.Mutex = .init,
    radio_pubkey: [32]u8 = std.mem.zeroes([32]u8),
    have_pubkey: bool = false,

    /// Snapshot of this station's identity tag (first bytes of the radio
    /// public key), or null before SELF_INFO has arrived.
    pub fn identityTag(self: *Connection) ?[identity_tag_len]u8 {
        self.pubkey_mutex.lockUncancelable(self.core.io);
        defer self.pubkey_mutex.unlock(self.core.io);
        if (!self.have_pubkey) return null;
        return self.radio_pubkey[0..identity_tag_len].*;
    }

    /// Block up to `timeout_ms` for the SELF_INFO handshake to deliver the
    /// station's identity. Returns the tag, or null on timeout.
    pub fn waitIdentityTag(self: *Connection, io: Io, timeout_ms: u64) ?[identity_tag_len]u8 {
        const deadline = std.Io.Timestamp.now(io, .awake).toMilliseconds() +
            @as(i64, @intCast(timeout_ms));
        while (true) {
            if (self.identityTag()) |tag| return tag;
            if (std.Io.Timestamp.now(io, .awake).toMilliseconds() >= deadline) return null;
            std.Io.sleep(io, .fromMilliseconds(5), .real) catch {};
        }
    }

    pub fn isConnected(self: *const Connection) bool {
        return self.core.isConnected();
    }

    /// Open and configure the serial port at `device_path` (e.g.
    /// `/dev/ttyUSB0`, `COM5`, `\\.\COM12`) and start the reader thread.
    /// Bare Windows `COM<n>` names are auto-translated to the Win32 device
    /// namespace, which is the only form that resolves reliably for port
    /// numbers ≥ 10 (and works for all of them).
    pub fn connect(
        self: *Connection,
        io: Io,
        device_path: []const u8,
        baud: u32,
        allocator: std.mem.Allocator,
        port: u4,
        callsign: []const u8,
    ) !void {
        self.core.setup(io, allocator, port, callsign);

        var win_buf: [64]u8 = undefined;
        const dev = translateWindowsComPort(&win_buf, device_path) orelse device_path;
        // Device paths are absolute (/dev/ttyUSB0, \\.\COM6); the absolute
        // open skips working-directory resolution, which is what breaks
        // bare Windows COM names. Relative paths fall back to a cwd open.
        const file = if (std.fs.path.isAbsolute(dev))
            try std.Io.Dir.openFileAbsolute(io, dev, .{ .mode = .read_write })
        else
            try std.Io.Dir.cwd().openFile(io, dev, .{ .mode = .read_write });
        errdefer file.close(io);

        try serial.configureSerialPort(file, .{
            .baud_rate = baud,
            .word_size = .eight,
            .parity = .none,
            .stop_bits = .one,
            .handshake = .none,
        });
        // Windows comm timeouts + queued-byte read gating are applied
        // centrally by `connection.Core.attachFile`.
        try self.core.attachFile(file);

        // The SELF_INFO reply to our APP_START carries this station's radio
        // public key — required before any transmission (identity tag).
        // Brief wait; a radio that never answers identity will surface as
        // NoIdentity errors on send rather than a failed connect.
        _ = self.waitIdentityTag(io, 750);
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
        return .{ .ctx = @ptrCast(self), .vtable = &meshcore_transport_vtable };
    }
};

const meshcore_link: connection_mod.Link = .{
    .dispatch = dispatch,
    .sendWire = sendWireFrame,
    .postConnect = postConnect,
};

/// Translate a bare Windows COM port name (`COM6`) into the Win32 device
/// namespace form (`\\.\COM6`). Plain names stop resolving as devices for
/// port numbers ≥ 10, while the namespace form works for every port — so
/// users can simply write `meshcore://COM6` on any Windows port. Explicit
/// `\\.\…` paths and POSIX device paths pass through unchanged. No-op
/// (returns null) on non-Windows targets.
fn translateWindowsComPort(buf: []u8, device_path: []const u8) ?[]const u8 {
    if (@import("builtin").os.tag != .windows) return null;
    if (!std.ascii.startsWithIgnoreCase(device_path, "COM")) return null;
    const digits = device_path[3..];
    if (digits.len == 0) return null;
    for (digits) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    if (buf.len < 4 + device_path.len) return null;
    @memcpy(buf[0..4], "\\\\.\\");
    @memcpy(buf[4..][0..device_path.len], device_path);
    return buf[0 .. 4 + device_path.len];
}

/// Link.dispatch: feed one batch of freshly-read serial bytes through the
/// response-frame parser.
fn dispatch(core: *connection_mod.Core, data: []const u8) void {
    const conn: *Connection = @fieldParentPtr("core", core);
    conn.parser.feed(data, conn, onFrame);
}

/// One complete companion frame arrived. Only `PUSH_CODE_RAW_DATA` matters:
/// `[0x84][snr][rssi][reserved][payload…]`. The firmware has already
/// stripped the MeshCore header/path, leaving our MessageFrame wire bytes.
/// Every other code (OK/ERR replies, adverts, message-waiting tickles, …)
/// is consumed and ignored.
fn onFrame(conn: *Connection, frame: []const u8) void {
    if (frame.len < 5) return; // type + 3 metadata + ≥1 payload byte

    if (frame[0] == RESP_CODE_SELF_INFO) {
        storeSelfInfo(conn, frame);
        return;
    }
    if (frame[0] != PUSH_CODE_RAW_DATA) return;

    // Raw push body: [snr][rssi][reserved][identity_tag][frame…]. The tag
    // (first bytes of the sender's radio public key) renders as the
    // session-layer callsign; the rest is our MessageFrame wire bytes.
    const body = frame[4..];
    if (body.len <= identity_tag_len) return;

    var msg: IncomingMessage = .{};
    var cs_buf: [identity_callsign_len]u8 = undefined;
    const cs = identityHex(&cs_buf, body[0..identity_tag_len].*);
    msg.has_callsign = true;
    @memcpy(msg.callsign[0..cs.len], cs);
    msg.callsign_str_len = @intCast(cs.len);

    if (!decodePacket(body[identity_tag_len..], &msg)) return;
    conn.core.enqueueIncoming(msg);
}

/// Capture this station's radio public key from a SELF_INFO frame:
/// `[type][adv_type][tx_power][max_power][pubkey 32…]`.
fn storeSelfInfo(conn: *Connection, frame: []const u8) void {
    if (frame.len < self_info_min_len) return;
    conn.pubkey_mutex.lockUncancelable(conn.core.io);
    defer conn.pubkey_mutex.unlock(conn.core.io);
    @memcpy(&conn.radio_pubkey, frame[4 .. 4 + 32]);
    conn.have_pubkey = true;
}

/// Link.sendWire: wrap one packet's wire bytes in a `CMD_SEND_RAW_PACKET`
/// serial frame — prefixed with this station's identity tag — and transmit.
/// Zero-hop direct: `port`/`call_to` have no meaning on the MeshCore air
/// interface here.
fn sendWireFrame(
    core: *connection_mod.Core,
    port: u4,
    call_to: []const u8,
    wire: []const u8,
) anyerror!void {
    _ = port;
    _ = call_to;
    const conn: *Connection = @fieldParentPtr("core", core);
    const tag = conn.identityTag() orelse return error.NoIdentity;

    var buf: [max_serial_frame_size + 3]u8 = undefined;
    const n = writeTxCommand(&buf, tag, wire) orelse return error.PayloadTooLarge;

    const w = core.writerInterface() orelse return error.NotConnected;
    try w.writeAll(buf[0..n]);
    try w.flush();
}

// ---------------------------------------------------------------------------
// Transport vtable — satisfies `transport.Transport`
// ---------------------------------------------------------------------------

const meshcore_transport_vtable: transport.Transport.VTable = .{
    .mtu_payload = mtu_payload,
    .high_bandwidth = false,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "raw_custom_direct_header packs version, payload type, and route" {
    const hdr = raw_custom_direct_header;
    try testing.expectEqual(@as(u2, 0b00), @as(u2, @truncate(hdr >> 6))); // v1
    try testing.expectEqual(@as(u4, 0xF), @as(u4, @truncate(hdr >> 2))); // RAW_CUSTOM
    try testing.expectEqual(@as(u2, 0b10), @as(u2, @truncate(hdr))); // direct
}

comptime {
    if (raw_custom_direct_header != 0x3E) @compileError("unexpected header encoding");
}

test "max_command_payload fits the firmware serial frame cap" {
    try testing.expectEqual(@as(usize, 176), max_command_payload);
    try testing.expect(max_command_payload <= max_serial_frame_size);
}

test "writeTxCommand wraps wire bytes in a length-prefixed SEND_RAW_PACKET frame" {
    const wire = [_]u8{ 0xAA, 0xBB, 0xCC };
    const tag = [identity_tag_len]u8{ 0x95, 0x1A, 0x1B, 0xC7 };
    var buf: [max_serial_frame_size + 3]u8 = undefined;

    const n = writeTxCommand(&buf, tag, &wire) orelse return error.TestUnexpectedResult;

    try testing.expectEqual(@as(usize, 3 + 4 + identity_tag_len + wire.len), n);
    try testing.expectEqual(@as(u8, '<'), buf[0]);
    try testing.expectEqual(@as(u16, 11), std.mem.readInt(u16, buf[1..3], .little));
    try testing.expectEqual(CMD_SEND_RAW_PACKET, buf[3]);
    try testing.expectEqual(default_tx_priority, buf[4]);
    try testing.expectEqual(raw_custom_direct_header, buf[5]);
    try testing.expectEqual(@as(u8, 0x00), buf[6]); // zero-hop path_length
    try testing.expectEqualSlices(u8, &tag, buf[7 .. 7 + identity_tag_len]);
    try testing.expectEqualSlices(u8, &wire, buf[7 + identity_tag_len .. n]);
}

test "writeTxCommand rejects wire bytes beyond the serial frame cap" {
    var wire: [max_serial_frame_size - 4]u8 = undefined;
    @memset(&wire, 0);
    var buf: [max_serial_frame_size + 3]u8 = undefined;
    try testing.expect(writeTxCommand(&buf, .{0} ** identity_tag_len, &wire) == null);
}

test "identityHex renders uppercase callsign characters" {
    var cs: [identity_callsign_len]u8 = undefined;
    const s = identityHex(&cs, .{ 0x95, 0x1A, 0x0B, 0x07 });
    try testing.expectEqualStrings("951A0B07", s);
}

test "RxParser handles fragmented and coalesced frames" {
    const Collector = struct {
        frames: [8][]const u8 = undefined,
        lens: [8]usize = @splat(0),
        count: usize = 0,

        fn onFrame(self: *@This(), frame: []const u8) void {
            self.frames[self.count] = frame;
            self.lens[self.count] = frame.len;
            self.count += 1;
        }
    };

    var p: RxParser = .{};
    var c: Collector = .{};

    // Frame A split across three reads; frame B coalesced into one read.
    const payload_a = [_]u8{ 0x84, 0x10, 0xE0, 0xFF, 0x01, 0x02 };
    const frame_b = [_]u8{ 0x00, 0x2A }; // OK reply with a value

    var a_framed: [3 + payload_a.len]u8 = undefined;
    a_framed[0] = rx_marker;
    std.mem.writeInt(u16, a_framed[1..3], payload_a.len, .little);
    @memcpy(a_framed[3..], &payload_a);

    p.feed(a_framed[0..2], &c, Collector.onFrame);
    try testing.expectEqual(@as(usize, 0), c.count);
    p.feed(a_framed[2..], &c, Collector.onFrame);
    try testing.expectEqual(@as(usize, 1), c.count);
    try testing.expectEqualSlices(u8, &payload_a, c.frames[0][0..c.lens[0]]);

    var combined: [64]u8 = undefined;
    const b_total = 3 + frame_b.len;
    combined[0] = rx_marker;
    std.mem.writeInt(u16, combined[1..3], frame_b.len, .little);
    @memcpy(combined[3..b_total], &frame_b);
    combined[b_total] = rx_marker; // stray marker for the next header
    combined[b_total + 1] = 0x05; // len lo
    p.feed(combined[0 .. b_total + 2], &c, Collector.onFrame);

    try testing.expectEqual(@as(usize, 2), c.count);
    try testing.expectEqualSlices(u8, &frame_b, c.frames[1][0..c.lens[1]]);
}

test "translateWindowsComPort rewrites bare COM names on Windows, passes through elsewhere" {
    var buf: [64]u8 = undefined;
    if (@import("builtin").os.tag == .windows) {
        try testing.expectEqualStrings("\\\\.\\COM6", translateWindowsComPort(&buf, "COM6").?);
        try testing.expectEqualStrings("\\\\.\\com12", translateWindowsComPort(&buf, "com12").?);
        // Non-COM paths pass through untouched.
        try testing.expect(translateWindowsComPort(&buf, "/dev/ttyUSB0") == null);
        try testing.expect(translateWindowsComPort(&buf, "\\\\.\\COM7") == null);
        // A name with trailing non-digits is not a COM port.
        try testing.expect(translateWindowsComPort(&buf, "COMBO1") == null);
    } else {
        try testing.expect(translateWindowsComPort(&buf, "COM6") == null);
    }
}

test "raw data push becomes a decoded IncomingMessage; other frames are skipped" {
    const io = testing.io;
    const allocator = testing.allocator;

    var conn: Connection = .{};
    conn.core.setup(io, allocator, 0, "TEST");
    defer conn.core.deinit();

    // Build a real single-packet MessageFrame (signed layout with empty sig).
    const MessageFrame = transport.frame.MessageFrame;
    const chunk = "hello meshcore";
    const frame_pkt = MessageFrame.init(.motd, chunk, &[_]u8{}, 3, 0, 1);
    const wire = frame_pkt.wireBytes();

    // Wrap it in a PUSH_CODE_RAW_DATA frame with a sender identity tag.
    const sender_tag = [identity_tag_len]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var push: [4 + identity_tag_len + 128]u8 = undefined;
    push[0] = PUSH_CODE_RAW_DATA;
    push[1] = 0x28; // snr × 4
    push[2] = 0xC4; // rssi dBm (signed)
    push[3] = 0xFF; // reserved
    @memcpy(push[4..][0..identity_tag_len], &sender_tag);
    @memcpy(push[4 + identity_tag_len ..][0..wire.len], wire);

    var framed: [3 + 4 + identity_tag_len + 128]u8 = undefined;
    const framed_len = 3 + 4 + identity_tag_len + wire.len;
    framed[0] = rx_marker;
    std.mem.writeInt(u16, framed[1..3], @intCast(4 + identity_tag_len + wire.len), .little);
    @memcpy(framed[3..framed_len], push[0 .. 4 + identity_tag_len + wire.len]);

    // Prepend an OK reply that must be skipped silently.
    var stream: [4 + framed.len]u8 = undefined;
    var pos: usize = 0;
    stream[pos] = rx_marker;
    std.mem.writeInt(u16, stream[pos + 1 ..][0..2], 1, .little);
    stream[pos + 3] = RESP_CODE_OK;
    pos += 4;
    @memcpy(stream[pos..][0..framed_len], framed[0..framed_len]);
    pos += framed_len;

    conn.parser.feed(stream[0..pos], &conn, onFrame);

    var dest: [4]IncomingMessage = undefined;
    const n = conn.core.drainIncoming(&dest);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(dest[0].is_message_frame);
    try testing.expect(dest[0].has_callsign);
    try testing.expectEqualStrings("DEADBEEF", dest[0].callsign[0..dest[0].callsign_str_len]);
    try testing.expectEqualSlices(u8, chunk, dest[0].frame_payload[0..chunk.len]);
}

test "SELF_INFO frame captures the station radio public key" {
    const io = testing.io;
    const allocator = testing.allocator;

    var conn: Connection = .{};
    conn.core.setup(io, allocator, 0, "TEST");
    defer conn.core.deinit();
    try testing.expect(!conn.have_pubkey);

    var self_info: [self_info_min_len]u8 = undefined;
    self_info[0] = RESP_CODE_SELF_INFO;
    self_info[1] = 0x01; // adv type
    self_info[2] = 22; // tx power
    self_info[3] = 30; // max power
    for (0..32) |i| self_info[4 + i] = @intCast(i);

    onFrame(&conn, &self_info);

    try testing.expect(conn.have_pubkey);
    for (0..32) |i| try testing.expectEqual(@as(u8, @intCast(i)), conn.radio_pubkey[i]);
    const tag = conn.identityTag().?;
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3 }, &tag);
}
