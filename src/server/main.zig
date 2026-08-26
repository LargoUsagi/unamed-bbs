//! Bulletin server executable.
//!
//! Connects to one or more AGWPE TNCs (e.g. Direwolf) via `--connect` and/or
//! listens for direct TCP client connections via `--listen`. Broadcasts
//! (chat, bulletins, MOTD, user info) are sent to ALL connected transports
//! so every listener can cache them. Directed responses
//! (registration acks, request_status, chat rejects) and NAK retransmits go
//! only to the source transport.
//!
//! The heartbeat is a per-link beacon: only transports whose vtable declares
//! `requires_beacon = true` (ham radio links where listeners depend on
//! periodic unsolicited traffic) are beaconed, and only when THAT link's own
//! last successful transmission falls outside the current 10-minute
//! wall-clock window. Direct TCP links are never beaconed.
//!
//! This file owns only lifecycle: arg parsing, key/store/MOTD setup, transport
//! pool setup, connect/reconnect, TCP accept, and the heartbeat timer. All
//! data flow is delegated to the two abstractions — `inbox.zig` (receive:
//! drain, reassemble, dispatch) and `outbox.zig` (send: encode, sign, route).
//!
//! Usage:
//!   kiss_server --connect agwpe://127.0.0.1:8000:0 \
//!               --listen tcp://0.0.0.0:9000 \
//!               --callsign KE8WIF --key mypassphrase --store bulletins.kblt

const std = @import("std");
const Io = std.Io;

const kiss = @import("bbs");
const agwpe = kiss.agwpe;
const tcp_mod = kiss.tcp;
const signing = kiss.signing;
const bulletin_store = @import("bulletin_store.zig");
const cli = @import("cli.zig");
const context = @import("context.zig");
const outbox = @import("outbox.zig");
const routing = @import("routing.zig");
const transports = @import("transports.zig");
const inbox_mod = @import("inbox.zig");

const ServerCtx = context.ServerCtx;
const TransportPool = transports.TransportPool;
const TransportSpec = cli.TransportSpec;
const TransportId = routing.TransportId;
const Route = routing.Route;
const max_transports = transports.max_transports;

/// Default Message of the Day used when the database has no persisted MOTD.
const default_motd = "Welcome to the BBS.";

/// Seconds between reconnection attempts for a dropped transport.
const retry_delay_sec: u64 = 5;

/// Length of the heartbeat beacon window, in seconds. A transport whose
/// vtable declares `requires_beacon` is beaconed once per wall-clock window
/// (:00/:10/:20…) in which it has not transmitted anything itself. Windows
/// are synchronized to the hour so beacons from different stations line up
/// on the same schedule.
const beacon_window_sec: u64 = 600;

/// Pending accepted TCP stream + the listener index it came from. The accept
/// thread pushes these; the main loop drains them and wraps them into the pool.
const PendingAccept = struct {
    stream: Io.net.Stream,
    listener_idx: usize,
};

/// Thread-safe queue of pending TCP accepts. The accept thread(s) push; the
/// main loop drains.
const PendingAcceptQueue = struct {
    mutex: std.Io.Mutex = .init,
    items: std.array_list.Managed(PendingAccept) = undefined,

    fn init(allocator: std.mem.Allocator) PendingAcceptQueue {
        return .{ .items = std.array_list.Managed(PendingAccept).init(allocator) };
    }

    fn deinit(self: *PendingAcceptQueue, io: Io) void {
        // Close any unclaimed streams.
        for (self.items.items) |*pa| pa.stream.close(io);
        self.items.deinit();
    }

    fn push(self: *PendingAcceptQueue, io: Io, pa: PendingAccept) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.items.append(pa) catch {};
    }

    fn drain(self: *PendingAcceptQueue, io: Io) []PendingAccept {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const result = self.items.toOwnedSlice() catch return &.{};
        return @constCast(result);
    }
};

/// Per-listener accept thread state.
const ListenerState = struct {
    io: Io,
    server: *Io.net.Server,
    listener_idx: usize,
    queue: *PendingAcceptQueue,
    stop: *std.atomic.Value(bool),
};

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;

    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer: Io.File.Writer = .init(.stderr(), io, &stderr_buf);
    const stderr = &stderr_writer.interface;

    const argv = try init.minimal.args.toSlice(arena);
    const parsed = cli.parseArgs(arena, argv[1..]) catch |err| {
        try stderr.writeAll(cli.usage);
        try stderr.print("\nerror: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return;
    };
    if (parsed == .help) {
        try stderr.writeAll(cli.usage);
        try stderr.flush();
        return;
    }
    const o = parsed.run;

    // Set up signing key. The key is either derived from a passphrase
    // (`--key`) or loaded from a file (`--key-file`) in PEM (PKCS#8),
    // OpenSSH, or raw 64-byte format; the two flags are mutually exclusive
    // (enforced in cli.parseArgs).
    const kp: ?signing.KeyPair = if (o.key_file) |path|
        signing.loadSecretKey(io, path) catch |err| {
            const hint = switch (err) {
                error.EncryptedKeyNotSupported => " (encrypted keys are not supported)",
                error.NotAnEd25519Key => " (not an Ed25519 key)",
                else => "",
            };
            try stderr.print("error: failed to load key file '{s}': {s}{s}\n", .{ path, @errorName(err), hint });
            try stderr.flush();
            return;
        }
    else if (o.key_passphrase) |passphrase|
        signing.KeyPair.fromPassphrase(passphrase) catch |err| {
            try stderr.print("error: key derivation failed: {s}\n", .{@errorName(err)});
            try stderr.flush();
            return;
        }
    else
        null;

    if (kp) |k| {
        const pk = k.publicKeyBytes();
        try stderr.print("server public key: {x:0>2}{x:0>2}{x:0>2}{x:0>2}\u{2026}{x:0>2}{x:0>2}{x:0>2}{x:0>2}\n", .{
            pk[0], pk[1], pk[2], pk[3],
            pk[28], pk[29], pk[30], pk[31],
        });
    }

    // Load persisted bulletins.
    var store = bulletin_store.Store.init(arena);
    store.load(io, o.store_path) catch |err| {
        try stderr.print("note: could not load store '{s}': {s} (starting empty)\n", .{ o.store_path, @errorName(err) });
    };
    try stderr.print("loaded {d} bulletins from {s}\n", .{ store.count(), o.store_path });

    // Load persisted MOTD from the database, falling back to the default.
    const initial_motd: []const u8 = blk: {
        if (store.getMotd()) |saved| {
            break :blk saved;
        }
        break :blk default_motd;
    };
    try stderr.print("MOTD: \"{s}\"\n", .{initial_motd});

    // --- Parse outbound connect endpoints ---
    const num_connects = @min(o.connects.items.len, max_transports);
    var connect_addresses: [max_transports]Io.net.IpAddress = undefined;
    for (o.connects.items[0..num_connects], 0..) |spec, i| {
        const host_str = if (std.mem.eql(u8, spec.host, "localhost")) "127.0.0.1" else spec.host;
        connect_addresses[i] = Io.net.IpAddress.parse(host_str, spec.port) catch |err| {
            try stderr.print("error: invalid host '{s}': {s}\n", .{ spec.host, @errorName(err) });
            try stderr.flush();
            return;
        };
        try stderr.print("connect {d}: {s}://{s}:{d} kport={d}\n", .{
            i, @tagName(spec.kind), spec.host, spec.port, spec.kport,
        });
    }

    // --- Parse inbound listen endpoints ---
    const num_listens = @min(o.listens.items.len, max_transports);
    var listen_servers: [max_transports]Io.net.Server = undefined;
    var listen_count: usize = 0;
    for (o.listens.items[0..num_listens]) |spec| {
        const host_str = if (std.mem.eql(u8, spec.host, "localhost")) "127.0.0.1" else spec.host;
        const addr = Io.net.IpAddress.parse(host_str, spec.port) catch |err| {
            try stderr.print("error: invalid listen host '{s}': {s}\n", .{ spec.host, @errorName(err) });
            try stderr.flush();
            return;
        };
        listen_servers[listen_count] = addr.listen(io, .{ .reuse_address = true }) catch |err| {
            try stderr.print("error: failed to listen on {s}:{d}: {s}\n", .{ spec.host, spec.port, @errorName(err) });
            try stderr.flush();
            return;
        };
        try stderr.print("listen {d}: tcp://{s}:{d}\n", .{ listen_count, spec.host, spec.port });
        listen_count += 1;
    }
    try stderr.flush();

    if (num_connects == 0 and listen_count == 0) {
        try stderr.writeAll("error: no transports specified\n");
        try stderr.flush();
        return;
    }

    // --- Connection objects ---
    // AGWPE connections for outbound AGWPE connects.
    // Each must be default-initialized so mutexes/atomics start in a valid
    // state; `undefined` would leave incoming_mutex as garbage, deadlocking
    // the reader thread.
    var agwpe_conns: [max_transports]agwpe.Connection = undefined;
    for (&agwpe_conns) |*c| c.* = .{};
    // TCP connections for outbound TCP connects AND inbound TCP accepts.
    var tcp_conns: [max_transports]tcp_mod.Connection = undefined;
    for (&tcp_conns) |*c| c.* = .{};
    // Track which tcp_conns slots are in use (for accept reuse).
    var tcp_slots_used: [max_transports]bool = .{false} ** max_transports;

    var pool: TransportPool = .{};

    // Pre-add outbound AGWPE transports to the pool (disconnected; pool skips them).
    var agwpe_slot_map: [max_transports]usize = .{0} ** max_transports;
    var agwpe_pool_count: usize = 0;
    for (o.connects.items[0..num_connects], 0..) |spec, i| {
        if (spec.kind == .agwpe) {
            const name = std.fmt.allocPrint(arena, "agwpe:{s}:{d}", .{ spec.host, spec.port }) catch "agwpe";
            const pool_id = pool.add(transports.wrapAgwpe(
                @intCast(agwpe_pool_count), i, name, &agwpe_conns[i], io, spec.kport,
            )) orelse break;
            agwpe_slot_map[agwpe_pool_count] = i;
            agwpe_pool_count += 1;
            _ = pool_id;
        }
    }

    // Pre-add outbound TCP transports to the pool (disconnected).
    var tcp_connect_slot_map: [max_transports]usize = .{0} ** max_transports;
    var tcp_connect_pool_count: usize = agwpe_pool_count;
    for (o.connects.items[0..num_connects], 0..) |spec, i| {
        if (spec.kind == .tcp) {
            const name = std.fmt.allocPrint(arena, "tcp-connect:{s}:{d}", .{ spec.host, spec.port }) catch "tcp-connect";
            const pool_id = pool.add(transports.wrapTcp(
                @intCast(tcp_connect_pool_count), .tcp_connect, i, name, &tcp_conns[i], io, 0,
            )) orelse break;
            tcp_connect_slot_map[tcp_connect_pool_count - agwpe_pool_count] = i;
            tcp_slots_used[i] = true;
            tcp_connect_pool_count += 1;
            _ = pool_id;
        }
    }

    // --- TCP listener accept threads ---
    var pending_accepts = PendingAcceptQueue.init(arena);
    var stop_flag = std.atomic.Value(bool).init(false);
    var listener_threads: [max_transports]?std.Thread = .{null} ** max_transports;
    for (0..listen_count) |li| {
        const ls = arena.create(ListenerState) catch break;
        ls.* = .{
            .io = io,
            .server = &listen_servers[li],
            .listener_idx = li,
            .queue = &pending_accepts,
            .stop = &stop_flag,
        };
        listener_threads[li] = std.Thread.spawn(.{}, acceptLoop, .{ls}) catch null;
    }

    // Per-AGWPE-transport reconnection timestamps.
    var last_reconnect: [max_transports]u64 = .{0} ** max_transports;
    // Per-TCP-connect reconnection timestamps.
    var last_tcp_reconnect: [max_transports]u64 = .{0} ** max_transports;

    // Mutable MOTD — sysop can update it at runtime via a `motd` message.
    var current_motd: []const u8 = initial_motd;

    // Receive-side inbox.
    var inbox: inbox_mod.Inbox = .{};

    const base_ctx: ServerCtx = .{
        .io = io,
        .stderr = stderr,
        .pool = &pool,
        .source_transport_id = 0,
        .store = &store,
        .kp = kp,
        .store_path = o.store_path,
        .motd_text = &current_motd,
    };

    // Main loop: connect/reconnect, accept, drain, process, heartbeat.
    while (true) {
        // --- Connect / reconnect outbound AGWPE transports ---
        for (o.connects.items[0..num_connects], 0..) |spec, i| {
            if (spec.kind != .agwpe) continue;
            _ = blk: {
                for (agwpe_slot_map[0..agwpe_pool_count], 0..) |conn_idx, pi| {
                    if (conn_idx == i) break :blk pi;
                }
                continue;
            };
            if (agwpe_conns[i].isConnected()) continue;

            const now: u64 = @intCast(@max(0, std.Io.Timestamp.now(io, .real).toSeconds()));
            if (now - last_reconnect[i] < retry_delay_sec) continue;
            last_reconnect[i] = now;

            const host_str = if (std.mem.eql(u8, spec.host, "localhost")) "127.0.0.1" else spec.host;
            try stderr.print("connect {d}: connecting to agwpe://{s}:{d} as {s}...\n", .{ i, host_str, spec.port, o.callsign });
            try stderr.flush();
            agwpe_conns[i].connect(io, connect_addresses[i], arena, spec.kport, o.callsign) catch |err| {
                try stderr.print("connect {d}: failed: {s} — retry in {d}s\n", .{ i, @errorName(err), retry_delay_sec });
                try stderr.flush();
                continue;
            };
            try stderr.print("connect {d}: connected\n", .{i});
            try stderr.flush();
        }

        // --- Connect / reconnect outbound TCP transports ---
        for (o.connects.items[0..num_connects], 0..) |spec, i| {
            if (spec.kind != .tcp) continue;
            if (tcp_conns[i].isConnected()) continue;

            const now: u64 = @intCast(@max(0, std.Io.Timestamp.now(io, .real).toSeconds()));
            if (now - last_tcp_reconnect[i] < retry_delay_sec) continue;
            last_tcp_reconnect[i] = now;

            const host_str = if (std.mem.eql(u8, spec.host, "localhost")) "127.0.0.1" else spec.host;
            const addr = Io.net.IpAddress.parse(host_str, spec.port) catch continue;
            try stderr.print("connect: connecting to tcp://{s}:{d}...\n", .{ host_str, spec.port });
            try stderr.flush();
            tcp_conns[i].connect(io, addr, arena, 0, o.callsign) catch |err| {
                try stderr.print("connect: tcp failed: {s} — retry in {d}s\n", .{ @errorName(err), retry_delay_sec });
                try stderr.flush();
                continue;
            };
            try stderr.print("connect: tcp connected\n", .{});
            try stderr.flush();
        }

        // --- Drain pending TCP accepts ---
        {
            const accepted = pending_accepts.drain(io);
            defer arena.free(accepted);
            for (accepted) |pa| {
                // Find a free TCP connection slot.
                var slot: ?usize = null;
                for (0..max_transports) |si| {
                    if (!tcp_slots_used[si]) {
                        slot = si;
                        break;
                    }
                }
                if (slot == null) {
                    try stderr.print("listen: pool full, rejecting connection\n", .{});
                    try stderr.flush();
                    pa.stream.close(io);
                    continue;
                }
                const si = slot.?;
                tcp_conns[si] = .{};
                tcp_conns[si].acceptStream(io, pa.stream, arena, 0, o.callsign) catch |err| {
                    try stderr.print("listen: acceptStream failed: {s}\n", .{@errorName(err)});
                    try stderr.flush();
                    pa.stream.close(io);
                    continue;
                };
                tcp_slots_used[si] = true;
                const name = std.fmt.allocPrint(arena, "tcp-listen:{d}", .{si}) catch "tcp-listen";
                const free_id = pool.findFreeSlot() orelse {
                    try stderr.print("listen: pool full after accept\n", .{});
                    try stderr.flush();
                    tcp_conns[si].disconnect();
                    tcp_slots_used[si] = false;
                    continue;
                };
                _ = pool.addAt(free_id, transports.wrapTcp(free_id, .tcp_listen, si, name, &tcp_conns[si], io, 0));
                try stderr.print("listen: accepted connection → slot {d}, pool id {d}\n", .{ si, free_id });
                try stderr.flush();
            }
        }

        // --- Clean up disconnected TCP-listen transports ---
        // Scan the pool for disconnected transports that came from TCP listens
        // and free their slots so new clients can connect.
        {
            var id: TransportId = 0;
            while (id < pool.count) : (id += 1) {
                if (pool.transports[id]) |*t| {
                    if (!t.isConnected() and t.kind == .tcp_listen) {
                        if (t.slot_idx < max_transports) {
                            tcp_conns[t.slot_idx].deinit();
                            tcp_slots_used[t.slot_idx] = false;
                        }
                        pool.remove(id);
                    }
                }
            }
        }

        if (!pool.anyConnected() and listen_count == 0) {
            std.Io.sleep(io, .fromMilliseconds(1000), .real) catch {};
            continue;
        }

        // --- Drain and process incoming messages through the inbox ---
        _ = inbox.drain(&base_ctx);

        // Evict stale multipart reassembly entries (30s timeout).
        inbox.processTimeouts(&base_ctx);

        // --- Heartbeat: per-link beacon for silent beacon-capable radios ---
        {
            const now: u64 = @intCast(@max(0, std.Io.Timestamp.now(io, .real).toSeconds()));
            const seconds_into_hour = now % 3600;
            const window_start = now - (seconds_into_hour % beacon_window_sec);
            var id: TransportId = 0;
            while (id < pool.count) : (id += 1) {
                const t = pool.get(id) orelse continue;
                if (!t.isConnected()) continue;
                if (!t.transport.requiresBeacon()) continue;
                if (t.last_tx_sec >= window_start) continue;
                try stderr.print("heartbeat: no TX on {s} in current {d}-minute window, sending bulletin list\n", .{ t.name, beacon_window_sec / 60 });
                try stderr.flush();
                outbox.sendHeartbeat(&base_ctx, Route.onTransport(id)) catch {};
                // Stamp even if the send failed so a dead link retries on
                // the next window instead of every loop iteration.
                t.last_tx_sec = now;
            }
        }

        std.Io.sleep(io, .fromMilliseconds(100), .real) catch {};
    }
}

/// Accept thread loop: blocks on `server.accept()` and pushes accepted
/// streams to the pending-accept queue. Exits when `stop` is set.
fn acceptLoop(ls: *ListenerState) void {
    while (!ls.stop.load(.acquire)) {
        const conn = ls.server.accept(ls.io) catch break;
        ls.queue.push(ls.io, .{ .stream = conn, .listener_idx = ls.listener_idx });
    }
}

test {
    std.testing.refAllDecls(bulletin_store);
    std.testing.refAllDecls(@import("retransmit_cache.zig"));
    std.testing.refAllDecls(@import("routing.zig"));
    std.testing.refAllDecls(@import("transports.zig"));
    std.testing.refAllDecls(@import("inbox.zig"));
}
