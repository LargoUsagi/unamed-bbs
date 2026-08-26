//! Server-side transport pool built on the shared `transport.Transport`
//! vtable (from the `bbs` package).
//!
//! `ServerTransport` composes a `transport.Transport` — the single
//! transport abstraction shared by the client and server. It adds the
//! server-specific concerns: a per-transport `RetransmissionCache`, a KISS
//! radio channel (`port`), and pool metadata (`id`, `name`). The `send`
//! method calls `transport.sendMultipart` with the cache observer auto-wired;
//! `sendRaw` calls it without the observer (for NAK retransmits that are
//! already cached).
//!
//! `TransportPool` holds up to `max_transports` connected transports and
//! fills transmit targets (`fillTargets`) for the shared `bbs.messaging`
//! `txSend` loop per a `Route` decision: broadcast to all transports,
//! broadcast to the source transport only, or direct to a single callsign on
//! the source transport.
//!
//! `wrapAgwpe` creates a `ServerTransport` from an `agwpe.Connection` by
//! calling `conn.asTransport()`. Future meshcore support adds a second
//! factory function without touching the pool, the outbox, or any handler.

const std = @import("std");
const Io = std.Io;

const transport_mod = @import("bbs").transport;
const agwpe = @import("bbs").agwpe;
const tcp_mod = @import("bbs").tcp;
const message_frame = @import("bbs").message_frame;
const messaging = @import("bbs").messaging;

const routing = @import("routing.zig");
const retransmit_cache_mod = @import("retransmit_cache.zig");

const TransportId = routing.TransportId;
const Route = routing.Route;
const RetransmissionCache = retransmit_cache_mod.RetransmissionCache;

/// Maximum number of simultaneously connected transports. With TCP listeners
/// each accepted client occupies a slot, so this is larger than the original 4.
pub const max_transports: usize = 16;

/// Identifies the role of a transport in the server's connection pool.
/// Used by the cleanup loop in `main.zig` to distinguish dynamically-accepted
/// TCP listeners (which need slot recycling) from static outbound connects.
pub const TransportKind = enum {
    /// Outbound AGWPE TNC connection.
    agwpe,
    /// Outbound TCP connection (client-style connect to a remote TCP endpoint).
    tcp_connect,
    /// Inbound TCP connection (accepted from a `--listen` socket).
    tcp_listen,
};

// ---------------------------------------------------------------------------
// ServerTransport — composes transport.Transport + retransmission cache
// ---------------------------------------------------------------------------

/// A server-side transport: a shared `transport.Transport` (the vtable-based
/// abstraction from the `bbs` package) plus a per-transport retransmission
/// cache, KISS radio channel, and pool metadata. Callers interact through
/// `send` / `sendRaw` / `isConnected` / `drainIncoming` / `deinit`.
pub const ServerTransport = struct {
    id: TransportId,
    kind: TransportKind,
    /// Index into `main.zig`'s `agwpe_conns` or `tcp_conns` array. Used by
    /// the cleanup loop to recycle TCP-listen slots without parsing names.
    slot_idx: usize,
    name: []const u8,
    /// Default KISS port (radio channel) for this transport. Used when
    /// routing broadcasts to all radios — each transport transmits on its
    /// own channel. For single-radio routing (responses to a request), the
    /// port from the incoming message is used instead.
    port: u4,
    /// The shared transport vtable handle. Obtained from a concrete transport
    /// (e.g. `agwpe.Connection.asTransport()`).
    transport: transport_mod.Transport,
    cache: RetransmissionCache,

    pub inline fn isConnected(self: *const ServerTransport) bool {
        return self.transport.isConnected();
    }

    pub inline fn drainIncoming(self: *ServerTransport, dest: []transport_mod.IncomingMessage) usize {
        return self.transport.drainIncoming(dest);
    }

    /// Send with the retransmission-cache observer auto-wired. Used for all
    /// normal transmissions so every sent frame is cached for NAK retransmit.
    pub fn send(
        self: *ServerTransport,
        port: u4,
        call_to: []const u8,
        msg_type: message_frame.MessageType,
        payload: []const u8,
        sig: []const u8,
        opts: transport_mod.SendOptions,
    ) void {
        transport_mod.sendMultipart(self.transport, port, call_to, msg_type, payload, sig, opts, self.cacheObserver()) catch {};
    }

    /// Frame observer that populates this transport's retransmission cache.
    /// The returned observer borrows `&self.cache`, whose address is stable
    /// for as long as the transport occupies its pool slot — safe because
    /// every transmission through it happens synchronously within one call.
    pub fn cacheObserver(self: *ServerTransport) transport_mod.FrameObserver {
        return .{
            .ctx = @ptrCast(&self.cache),
            .observe = retransmit_cache_mod.retransmitObserver,
        };
    }

    /// Send without the cache observer. Used for NAK retransmits where the
    /// frame is already cached and re-caching would reset the dedup window.
    pub fn sendRaw(
        self: *ServerTransport,
        port: u4,
        call_to: []const u8,
        msg_type: message_frame.MessageType,
        payload: []const u8,
        sig: []const u8,
        opts: transport_mod.SendOptions,
    ) void {
        transport_mod.sendMultipart(self.transport, port, call_to, msg_type, payload, sig, opts, null) catch {};
    }

    pub fn deinit(self: *ServerTransport) void {
        self.transport.disconnect();
    }
};

// ---------------------------------------------------------------------------
// TransportPool — holds multiple transports, routes based on Route
// ---------------------------------------------------------------------------

/// A drained incoming message tagged with the transport it arrived on.
pub const DrainedMessage = struct {
    msg: transport_mod.IncomingMessage,
    transport_id: TransportId,
};

/// Holds up to `max_transports` connected transports and fills transmit
/// targets (`fillTargets`) for `bbs.messaging.txSend` per a `Route` decision.
pub const TransportPool = struct {
    transports: [max_transports]?ServerTransport = .{null} ** max_transports,
    count: usize = 0,

    /// Add a transport to the pool. Returns the assigned `TransportId` or
    /// `null` if the pool is full.
    pub fn add(self: *TransportPool, transport: ServerTransport) ?TransportId {
        if (self.count >= max_transports) return null;
        const id: TransportId = @intCast(self.count);
        self.transports[self.count] = transport;
        self.count += 1;
        return id;
    }

    /// Get a mutable pointer to the transport with the given ID.
    pub fn get(self: *TransportPool, id: TransportId) ?*ServerTransport {
        if (id >= self.count) return null;
        if (self.transports[id]) |*t| return @constCast(t);
        return null;
    }

    /// Fill `dest` with transmit targets per a `Route` decision, ready for
    /// `bbs.messaging.txSend`. Broadcast scope (`RadioScope.all`) yields one
    /// target per connected transport, each on its own configured radio
    /// channel; single-radio scope yields at most one target on the source
    /// transport using the given `port` (from the incoming message). Every
    /// target carries this transport's retransmit-cache observer. Disconnected
    /// transports are skipped. Returns the filled count.
    pub fn fillTargets(
        self: *TransportPool,
        decision: Route,
        source_id: TransportId,
        port: u4,
        opts: transport_mod.SendOptions,
        dest: []messaging.TxTarget,
    ) usize {
        const call_to = decision.callTo();
        var n: usize = 0;

        switch (decision.radios) {
            .all => {
                for (self.transports[0..self.count]) |*t_opt| {
                    if (t_opt.*) |*t| {
                        if (!t.isConnected()) continue;
                        if (n >= dest.len) break;
                        dest[n] = .{
                            .transport = t.transport,
                            .port = t.port,
                            .call_to = call_to,
                            .opts = opts,
                            .observer = t.cacheObserver(),
                        };
                        n += 1;
                    }
                }
            },
            .single => {
                if (self.get(source_id)) |t| {
                    if (t.isConnected() and dest.len > 0) {
                        dest[0] = .{
                            .transport = t.transport,
                            .port = port,
                            .call_to = call_to,
                            .opts = opts,
                            .observer = t.cacheObserver(),
                        };
                        n = 1;
                    }
                }
            },
        }
        return n;
    }

    /// Drain one incoming message from any connected transport. Returns
    /// `null` when all queues are empty. Call this in a loop to drain all.
    pub fn drainOne(self: *TransportPool, buf: []transport_mod.IncomingMessage) ?DrainedMessage {
        for (self.transports[0..self.count], 0..) |*t_opt, i| {
            if (t_opt.*) |*t| {
                if (!t.isConnected()) continue;
                const n = t.drainIncoming(buf);
                if (n > 0) {
                    return .{ .msg = buf[0], .transport_id = @intCast(i) };
                }
            }
        }
        return null;
    }

    /// Returns true if at least one transport is connected.
    pub fn anyConnected(self: *const TransportPool) bool {
        for (self.transports[0..self.count]) |t_opt| {
            if (t_opt) |t| {
                if (t.isConnected()) return true;
            }
        }
        return false;
    }

    /// Deinit all transports.
    pub fn deinitAll(self: *TransportPool) void {
        for (self.transports[0..self.count]) |*t_opt| {
            if (t_opt.*) |*t| t.deinit();
            t_opt.* = null;
        }
        self.count = 0;
    }

    /// Remove a transport from the pool by ID, freeing its slot for reuse.
    /// The transport is deinit'd. Used when a TCP client disconnects so a
    /// new client can take its slot.
    pub fn remove(self: *TransportPool, id: TransportId) void {
        if (id >= self.count) return;
        if (self.transports[id]) |*t| {
            t.deinit();
        }
        self.transports[id] = null;
    }

    /// Find the first free (null) slot in the pool, or null if full.
    pub fn findFreeSlot(self: *TransportPool) ?TransportId {
        for (self.transports[0..self.count], 0..) |*t_opt, i| {
            if (t_opt.* == null) return @intCast(i);
        }
        if (self.count < max_transports) {
            const id: TransportId = @intCast(self.count);
            return id;
        }
        return null;
    }

    /// Add a transport to a specific slot (used when reusing a freed slot).
    /// Returns the assigned `TransportId` or null if the slot is invalid.
    pub fn addAt(self: *TransportPool, id: TransportId, t: ServerTransport) ?TransportId {
        if (id >= max_transports) return null;
        self.transports[id] = t;
        if (id >= self.count) self.count = id + 1;
        return id;
    }
};

// ---------------------------------------------------------------------------
// Factory — create a ServerTransport from an agwpe.Connection
// ---------------------------------------------------------------------------

/// Create a `ServerTransport` wrapping an `agwpe.Connection`. The caller
/// retains ownership of the connection; the transport borrows it via
/// `conn.asTransport()`. `port` is the KISS radio channel this transport
/// transmits on.
pub fn wrapAgwpe(
    id: TransportId,
    slot_idx: usize,
    name: []const u8,
    conn: *agwpe.Connection,
    io: Io,
    port: u4,
) ServerTransport {
    return .{
        .id = id,
        .kind = .agwpe,
        .slot_idx = slot_idx,
        .name = name,
        .port = port,
        .transport = conn.asTransport(),
        .cache = .{ .io = io },
    };
}

/// Create a `ServerTransport` wrapping a `tcp.Connection`. The caller retains
/// ownership of the connection; the transport borrows it via
/// `conn.asTransport()`. `port` is the radio channel (always 0 for TCP).
pub fn wrapTcp(
    id: TransportId,
    kind: TransportKind,
    slot_idx: usize,
    name: []const u8,
    conn: *tcp_mod.Connection,
    io: Io,
    port: u4,
) ServerTransport {
    return .{
        .id = id,
        .kind = kind,
        .slot_idx = slot_idx,
        .name = name,
        .port = port,
        .transport = conn.asTransport(),
        .cache = .{ .io = io },
    };
}
