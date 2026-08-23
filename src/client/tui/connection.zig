//! ConnectionManager — transport connection state and connection-parameter
//! text inputs.
//!
//! Owns both an `agwpe.Connection` (for the AGWPE TNC radio path) and a
//! `tcp.Connection` (for direct TCP/IP to the server). Only one transport is
//! active at a time; `active_kind` tracks which. The connect lifecycle
//! (`startConnect`, `handleConnectResult`, the background `connectTask`) lives
//! here so `app.zig` is free of socket plumbing.
//!
//! On successful connect, the current transport configuration is persisted to
//! the client-side SQLite store as a single `tc_connect_uri` string so the
//! client can auto-reconnect on restart. CLI `--connect` always takes priority
//! over saved DB values and locks the transport fields for the session.
//!
//! The functions take `*AppContext` (defined in `app.zig`) because they need
//! app-wide fields (`io`, `async_runner`, `status`, `store`) that remain on
//! the root context. This mirrors the pattern used by `outbox.zig`.

const std = @import("std");
const zz = @import("zigzag");

const types = @import("types.zig");
const cli = @import("cli.zig");
const agwpe = types.agwpe;
const tcp_mod = @import("bbs").tcp;
const endpoint = @import("bbs").endpoint;

const ConnectArgs = types.ConnectArgs;
const ConnectResult = types.ConnectResult;
const Msg = types.Msg;

const AppContext = @import("app.zig").AppContext;

/// Which transport is currently active (or should be attempted on connect).
pub const ActiveTransport = endpoint.TransportKind;

/// Connection state for both transport kinds plus the connection-parameter
/// text inputs. Exposed as `ctx.connection`; screens call
/// `ctx.connection.isConnected()` for rendering and
/// `connection.startConnect(ctx)` to trigger a connect.
pub const ConnectionManager = struct {
    /// AGWPE connection (used when active_kind == .agwpe).
    conn: agwpe.Connection = .{},
    /// TCP direct connection (used when active_kind == .tcp).
    tcp_conn: tcp_mod.Connection = .{},
    /// Which transport kind is currently active / should be connected.
    active_kind: ActiveTransport = .agwpe,
    /// True when the AGWPE connection has been initialized and needs cleanup
    /// before a reconnect.
    agwpe_conn_initialized: bool = false,
    /// True when the TCP connection has been initialized and needs cleanup
    /// before a reconnect.
    tcp_conn_initialized: bool = false,
    connecting: bool = false,
    /// True when `--connect` was passed on the CLI. Transport params are
    /// immutable for the session; the settings screen shows them read-only
    /// and hides the tab switcher.
    connect_locked: bool = false,
    /// True when `--callsign` was passed on the CLI. The callsign field is
    /// immutable for the session.
    callsign_locked: bool = false,
    /// True when the active transport has a valid configuration (from CLI or
    /// DB) and can be auto-connected on startup.
    active_configured: bool = false,

    // AGWPE inputs
    host_input: zz.TextInput,
    port_input: zz.TextInput,
    kport_input: zz.TextInput,
    // TCP inputs
    tcp_host_input: zz.TextInput,
    tcp_port_input: zz.TextInput,
    // Shared
    callsign_input: zz.TextInput,

    pub fn isConnected(self: *const ConnectionManager) bool {
        return switch (self.active_kind) {
            .agwpe => self.conn.isConnected(),
            .tcp => self.tcp_conn.isConnected(),
        };
    }

    /// Return the active transport handle for the inbox.
    pub fn activeTransport(self: *ConnectionManager) types.transport.Transport {
        return switch (self.active_kind) {
            .agwpe => self.conn.asTransport(),
            .tcp => self.tcp_conn.asTransport(),
        };
    }

    /// True when the active transport has a valid configuration and can be
    /// auto-connected on startup.
    pub fn activeConfigured(self: *const ConnectionManager) bool {
        return self.active_configured;
    }

    /// Disconnect the active transport.
    pub fn disconnect(self: *ConnectionManager) void {
        switch (self.active_kind) {
            .agwpe => {
                if (self.agwpe_conn_initialized) {
                    self.conn.disconnect();
                }
            },
            .tcp => {
                if (self.tcp_conn_initialized or self.tcp_conn.initialized) {
                    self.tcp_conn.disconnect();
                }
            },
        }
    }
};

/// Initialise the connection-parameter inputs.
///
/// Resolution order for each field: CLI override → saved DB value → default.
/// A non-null `overrides.connect` locks the transport fields for the session.
/// A non-null `overrides.callsign` locks the callsign field for the session.
/// The `active_configured` flag is set when the CLI provided a connect
/// endpoint or the DB has a previously-saved `tc_connect_uri`.
pub fn init(mgr: *ConnectionManager, allocator: std.mem.Allocator, store: *@import("../client_store.zig").Store, overrides: cli.TuiOverrides) void {
    // --- Determine the connect endpoint: CLI > DB > none ---
    const connect_ep: ?endpoint.TransportEndpoint = blk: {
        if (overrides.connect) |ep| break :blk ep;
        // Fall back to the saved connect URI in the DB.
        if (store.getConnectUri()) |saved_uri| {
            defer store.allocator.free(saved_uri);
            break :blk endpoint.parseEndpoint(saved_uri) catch null;
        }
        break :blk null;
    };

    // --- Set transport inputs from the resolved connect endpoint ---
    mgr.host_input = zz.TextInput.init(allocator);
    mgr.host_input.placeholder = "TNC host IP (e.g. 127.0.0.1)";
    mgr.port_input = zz.TextInput.init(allocator);
    mgr.port_input.placeholder = "TCP port (e.g. 8000)";
    mgr.kport_input = zz.TextInput.init(allocator);
    mgr.kport_input.placeholder = "Radio port 0-15";
    mgr.tcp_host_input = zz.TextInput.init(allocator);
    mgr.tcp_host_input.placeholder = "Server host IP (e.g. 127.0.0.1)";
    mgr.tcp_port_input = zz.TextInput.init(allocator);
    mgr.tcp_port_input.placeholder = "Server TCP port (e.g. 9000)";

    if (connect_ep) |ep| {
        mgr.active_kind = ep.kind;
        mgr.active_configured = true;
        var port_buf: [8]u8 = undefined;
        switch (ep.kind) {
            .agwpe => {
                mgr.host_input.setValue(ep.host) catch {};
                mgr.port_input.setValue(std.fmt.bufPrint(&port_buf, "{d}", .{ep.port}) catch types.default_tcp_port) catch {};
                mgr.kport_input.setValue(std.fmt.bufPrint(&port_buf, "{d}", .{ep.kport}) catch types.default_radio_port) catch {};
                // TCP fields get defaults (not used for this transport).
                mgr.tcp_host_input.setValue(types.default_host) catch {};
                mgr.tcp_port_input.setValue(types.default_tcp_server_port) catch {};
            },
            .tcp => {
                mgr.tcp_host_input.setValue(ep.host) catch {};
                mgr.tcp_port_input.setValue(std.fmt.bufPrint(&port_buf, "{d}", .{ep.port}) catch types.default_tcp_server_port) catch {};
                // AGWPE fields get defaults (not used for this transport).
                mgr.host_input.setValue(types.default_host) catch {};
                mgr.port_input.setValue(types.default_tcp_port) catch {};
                mgr.kport_input.setValue(types.default_radio_port) catch {};
            },
        }
    } else {
        // No connect endpoint from CLI or DB — use defaults, no auto-connect.
        mgr.active_kind = .agwpe;
        mgr.active_configured = false;
        mgr.host_input.setValue(types.default_host) catch {};
        mgr.port_input.setValue(types.default_tcp_port) catch {};
        mgr.kport_input.setValue(types.default_radio_port) catch {};
        mgr.tcp_host_input.setValue(types.default_host) catch {};
        mgr.tcp_port_input.setValue(types.default_tcp_server_port) catch {};
    }

    // --- Callsign: CLI > DB > default ---
    mgr.callsign_input = zz.TextInput.init(allocator);
    mgr.callsign_input.placeholder = "Your callsign (e.g. KE8WIF)";
    if (overrides.callsign) |c| {
        mgr.callsign_input.setValue(c) catch {};
        mgr.callsign_locked = true;
    } else if (store.getTransportString("tc_callsign")) |saved| {
        defer store.allocator.free(saved);
        mgr.callsign_input.setValue(saved) catch {};
        mgr.callsign_locked = false;
    } else {
        mgr.callsign_input.setValue(types.default_callsign) catch {};
        mgr.callsign_locked = false;
    }

    // --- Lock flags ---
    // connect_locked is true only when the CLI explicitly passed --connect.
    // A DB-restored endpoint is editable in the settings screen.
    mgr.connect_locked = overrides.connect != null;

    mgr.conn = .{};
    mgr.tcp_conn = .{};
    mgr.agwpe_conn_initialized = false;
    mgr.tcp_conn_initialized = false;
    mgr.connecting = false;

    // --- If --connect was passed, persist the URI to the DB immediately ---
    if (overrides.connect) |ep| {
        saveConnectUri(store, ep);
    }
}

pub fn deinit(mgr: *ConnectionManager) void {
    // Only deinit connections that were initialized (connect() sets up the
    // incoming_queue). Calling deinit on a never-connected Connection would
    // crash on the uninitialized queue.
    if (mgr.agwpe_conn_initialized) {
        mgr.conn.deinit();
    }
    if (mgr.tcp_conn_initialized or mgr.tcp_conn.initialized) {
        mgr.tcp_conn.deinit();
    }
    mgr.host_input.deinit();
    mgr.port_input.deinit();
    mgr.kport_input.deinit();
    mgr.tcp_host_input.deinit();
    mgr.tcp_port_input.deinit();
    mgr.callsign_input.deinit();
}

/// Disconnect the active transport. Called from the Settings screen's
/// Disconnect button.
pub fn disconnectActive(ctx: *AppContext) void {
    const mgr = &ctx.connection;
    mgr.disconnect();
    ctx.inbox.transport = null;
    ctx.status = "Disconnected.";
}

/// Spawn a background connect attempt using the active transport kind.
/// Tears down the other transport first so only one is active at a time.
/// For AGWPE (AX.25 radio) the callsign is required — it is used for
/// AX.25 header routing on the air. The default "NOCALL" placeholder is
/// rejected so the user must set a real callsign (via `--callsign` CLI
/// flag or in Settings) before connecting over AGWPE.
pub fn startConnect(ctx: *AppContext) void {
    const mgr = &ctx.connection;
    if (mgr.connecting) {
        ctx.status = "Already connecting...";
        return;
    }
    if (mgr.isConnected()) return;

    // AGWPE requires a real callsign for AX.25 routing.
    if (mgr.active_kind == .agwpe) {
        const callsign = mgr.callsign_input.value.items;
        if (callsign.len == 0 or std.mem.eql(u8, callsign, "NOCALL")) {
            ctx.status = "Callsign is required for AGWPE — set it in Settings (Ctrl+R).";
            return;
        }
    }

    // Tear down the other transport so only one is active at a time.
    switch (mgr.active_kind) {
        .agwpe => {
            if (mgr.tcp_conn.isConnected()) {
                mgr.tcp_conn.disconnect();
                ctx.inbox.transport = null;
            }
        },
        .tcp => {
            if (mgr.conn.isConnected()) {
                mgr.conn.disconnect();
                ctx.inbox.transport = null;
            }
        },
    }

    const callsign = mgr.callsign_input.value.items;
    const page = std.heap.page_allocator;

    switch (mgr.active_kind) {
        .agwpe => startAgwpeConnect(ctx, mgr, callsign, page),
        .tcp => startTcpConnect(ctx, mgr, callsign, page),
    }
}

fn startAgwpeConnect(ctx: *AppContext, mgr: *ConnectionManager, callsign: []const u8, page: std.mem.Allocator) void {
    const host_raw = mgr.host_input.value.items;
    const host_str = if (std.mem.eql(u8, host_raw, "localhost")) "127.0.0.1" else host_raw;
    const port = std.fmt.parseInt(u16, mgr.port_input.value.items, 10) catch {
        ctx.status = "Invalid TCP port — edit in Settings (Ctrl+R).";
        return;
    };
    const kport = std.fmt.parseInt(u4, mgr.kport_input.value.items, 10) catch 0;

    const address = std.Io.net.IpAddress.parse(host_str, port) catch {
        ctx.status = "Invalid host address — edit in Settings (Ctrl+R).";
        return;
    };

    if (mgr.agwpe_conn_initialized) {
        mgr.conn.deinit();
        mgr.conn = .{};
        mgr.agwpe_conn_initialized = false;
    }

    const callsign_copy = page.dupe(u8, callsign) catch {
        ctx.status = "Out of memory.";
        return;
    };
    const host_copy = page.dupe(u8, host_str) catch {
        page.free(callsign_copy);
        ctx.status = "Out of memory.";
        return;
    };

    const args = ConnectArgs{
        .connection = &mgr.conn,
        .io = ctx.io,
        .address = address,
        .allocator = page,
        .port = kport,
        .callsign = callsign_copy,
        .tcp_port = port,
        .host = host_copy,
    };

    mgr.connecting = true;
    ctx.status = "Connecting (AGWPE)...";
    _ = ctx.async_runner.spawnWithArg(ConnectArgs, args, &connectTask);
}

fn startTcpConnect(ctx: *AppContext, mgr: *ConnectionManager, callsign: []const u8, page: std.mem.Allocator) void {
    const host_raw = mgr.tcp_host_input.value.items;
    const host_str = if (std.mem.eql(u8, host_raw, "localhost")) "127.0.0.1" else host_raw;
    const port = std.fmt.parseInt(u16, mgr.tcp_port_input.value.items, 10) catch {
        ctx.status = "Invalid TCP port — edit in Settings (Ctrl+R).";
        return;
    };

    const address = std.Io.net.IpAddress.parse(host_str, port) catch {
        ctx.status = "Invalid host address — edit in Settings (Ctrl+R).";
        return;
    };

    if (mgr.tcp_conn_initialized or mgr.tcp_conn.initialized) {
        mgr.tcp_conn.deinit();
        mgr.tcp_conn = .{};
        mgr.tcp_conn_initialized = false;
    }

    const callsign_copy = page.dupe(u8, callsign) catch {
        ctx.status = "Out of memory.";
        return;
    };
    const host_copy = page.dupe(u8, host_str) catch {
        page.free(callsign_copy);
        ctx.status = "Out of memory.";
        return;
    };

    const args = TcpConnectArgs{
        .connection = &mgr.tcp_conn,
        .io = ctx.io,
        .address = address,
        .allocator = page,
        .callsign = callsign_copy,
        .tcp_port = port,
        .host = host_copy,
    };

    mgr.connecting = true;
    ctx.status = "Connecting (TCP)...";
    _ = ctx.async_runner.spawnWithArg(TcpConnectArgs, args, &tcpConnectTask);
}

/// Arguments for the background TCP connect task.
pub const TcpConnectArgs = struct {
    connection: *tcp_mod.Connection,
    io: std.Io,
    address: std.Io.net.IpAddress,
    allocator: std.mem.Allocator,
    callsign: []const u8,
    tcp_port: u16 = 0,
    host: []const u8 = "",
};

/// Background task: attempt TCP connection (AGWPE transport).
fn connectTask(args: ConnectArgs) ?Msg {
    defer std.heap.page_allocator.free(args.callsign);
    defer std.heap.page_allocator.free(args.host);

    const host = copyHost(args.host);
    const host_len: u8 = @intCast(@min(args.host.len, 64));

    args.connection.connect(args.io, args.address, args.allocator, args.port, args.callsign) catch |err| {
        var err_buf: [64]u8 = std.mem.zeroes([64]u8);
        const err_name = @errorName(err);
        const en = @min(err_name.len, 63);
        @memcpy(err_buf[0..en], err_name[0..en]);
        return .{ .connect_done = .{
            .ok = false,
            .err = err_buf,
            .err_len = @intCast(en),
            .kport = args.port,
            .host = host,
            .host_len = host_len,
            .port = args.tcp_port,
        } };
    };

    return .{ .connect_done = .{
        .ok = true,
        .kport = args.port,
        .host = host,
        .host_len = host_len,
        .port = args.tcp_port,
    } };
}

/// Background task: attempt direct TCP connection.
fn tcpConnectTask(args: TcpConnectArgs) ?Msg {
    defer std.heap.page_allocator.free(args.callsign);
    defer std.heap.page_allocator.free(args.host);

    const host = copyHost(args.host);
    const host_len: u8 = @intCast(@min(args.host.len, 64));

    args.connection.connect(args.io, args.address, args.allocator, 0, args.callsign) catch |err| {
        var err_buf: [64]u8 = std.mem.zeroes([64]u8);
        const err_name = @errorName(err);
        const en = @min(err_name.len, 63);
        @memcpy(err_buf[0..en], err_name[0..en]);
        return .{ .connect_done = .{
            .ok = false,
            .err = err_buf,
            .err_len = @intCast(en),
            .kport = 0,
            .host = host,
            .host_len = host_len,
            .port = args.tcp_port,
        } };
    };

    return .{ .connect_done = .{
        .ok = true,
        .kport = 0,
        .host = host,
        .host_len = host_len,
        .port = args.tcp_port,
    } };
}

/// Copy a host string into a fixed 64-byte buffer (for `ConnectResult`).
fn copyHost(host: []const u8) [64]u8 {
    var buf: [64]u8 = std.mem.zeroes([64]u8);
    const n = @min(host.len, 64);
    @memcpy(buf[0..n], host[0..n]);
    return buf;
}

/// Process a `ConnectResult` from the background connect task.
pub fn handleConnectResult(ctx: *AppContext, cr: ConnectResult) void {
    const mgr = &ctx.connection;
    mgr.connecting = false;
    if (cr.ok) {
        // Mark the appropriate connection as initialized.
        switch (mgr.active_kind) {
            .agwpe => mgr.agwpe_conn_initialized = true,
            .tcp => mgr.tcp_conn_initialized = true,
        }
        ctx.status = "Connected.";
        // Hand the transport handle to the inbox so receive-side logic is
        // transport-neutral.
        ctx.inbox.setTransport(mgr.activeTransport());
        // Capture the TX-side connection params into the outbox.
        ctx.outbox.setParams(cr.kport, cr.host[0..cr.host_len], cr.port);
        // Persist the current configuration so the client can auto-reconnect
        // on restart. CLI flags always take priority over these saved values.
        saveTransportConfig(ctx);
    } else {
        const err = cr.err[0..cr.err_len];
        ctx.status = std.fmt.allocPrint(
            std.heap.page_allocator,
            "Connection failed: {s} — Ctrl+R for settings.",
            .{err},
        ) catch "Connection failed — Ctrl+R for settings.";
    }
}

/// Format the active transport's configuration as a connect URI string.
/// Returns an owned slice (caller must free).
fn formatConnectUri(mgr: *const ConnectionManager, allocator: std.mem.Allocator) ![]u8 {
    return switch (mgr.active_kind) {
        .agwpe => std.fmt.allocPrint(allocator, "agwpe://{s}:{s}:{s}", .{
            mgr.host_input.value.items,
            mgr.port_input.value.items,
            mgr.kport_input.value.items,
        }),
        .tcp => std.fmt.allocPrint(allocator, "tcp://{s}:{s}", .{
            mgr.tcp_host_input.value.items,
            mgr.tcp_port_input.value.items,
        }),
    };
}

/// Persist the active transport endpoint as a `tc_connect_uri` string and
/// the callsign so the client can auto-reconnect on restart. Called after a
/// successful connect.
fn saveTransportConfig(ctx: *AppContext) void {
    const mgr = &ctx.connection;
    const store = &ctx.store;

    // Save the connect URI.
    const uri = formatConnectUri(mgr, store.allocator) catch return;
    defer store.allocator.free(uri);
    store.setConnectUri(uri) catch {};

    // Save callsign.
    store.setTransportString("tc_callsign", mgr.callsign_input.value.items) catch {};
}

/// Save the connect URI from a CLI-provided endpoint to the DB so it persists
/// for the next session. Called during init when --connect is used.
fn saveConnectUri(store: *@import("../client_store.zig").Store, ep: endpoint.TransportEndpoint) void {
    const uri = std.fmt.allocPrint(store.allocator, "{s}://{s}:{d}", .{
        switch (ep.kind) {
            .agwpe => "agwpe",
            .tcp => "tcp",
        },
        ep.host,
        ep.port,
    }) catch return;
    defer store.allocator.free(uri);
    // For AGWPE, append the kport if non-zero.
    if (ep.kind == .agwpe and ep.kport != 0) {
        const full = std.fmt.allocPrint(store.allocator, "{s}:{d}", .{ uri, ep.kport }) catch return;
        defer store.allocator.free(full);
        store.setConnectUri(full) catch {};
    } else {
        store.setConnectUri(uri) catch {};
    }
}
