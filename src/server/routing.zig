//! Routing types for multi-transport message dispatch.
//!
//! The server can connect to multiple transports (AGWPE TNCs today, meshcore
//! radios in the future). Every outgoing message is routed through a
//! `Route` that answers two independent questions:
//!
//!   1. **Which radio(s)?** — `RadioScope`
//!      - `.all` — send on every connected transport (e.g. chat broadcasts,
//!        heartbeats, new bulletins — anything useful for all listeners to
//!        cache).
//!      - `.single` — send only on the transport that received the triggering
//!        request (e.g. NAK retransmits that are only relevant to clients on
//!        that radio).
//!
//!   2. **Which client(s)?** — `ClientScope`
//!      - `.all` — broadcast to CQ (all listeners on the radio).
//!      - `.single` — directed to a specific callsign (e.g. registration
//!        acks, request_status rejections, chat rejects).
//!
//! The three useful combinations are:
//!
//!   | radios  | clients | Use case |
//!   |---------|---------|----------|
//!   | all     | all     | Chat, heartbeat, new bulletins, MOTD, user info |
//!   | single  | all     | NAK retransmits (same radio, CQ) |
//!   | single  | single  | Registration acks, request_status, chat rejects |

const std = @import("std");

/// Identifies a transport within the server's `TransportPool`. Assigned
/// sequentially as transports are added (0, 1, 2, …).
pub const TransportId = u8;

/// Which radio(s) a message should be transmitted on.
pub const RadioScope = enum {
    /// Send on every connected transport.
    all,
    /// Send only on the transport that received the triggering request.
    single,
};

/// Which client(s) a message should be addressed to.
pub const ClientScope = union(enum) {
    /// Broadcast to CQ (all listeners on the radio).
    all,
    /// Directed to a specific callsign.
    single: []const u8,
};

/// Composed routing decision: which radios × which clients.
///
/// Convenience constants/factory are provided for the three common patterns:
///   - `Route.broadcast_all`           — all radios, all clients (CQ)
///   - `Route.broadcast_source`        — source radio, all clients (CQ)
///   - `Route.directed(callsign)`      — source radio, single client
pub const Route = struct {
    radios: RadioScope,
    clients: ClientScope,

    /// All radios, all clients — the default for CQ broadcasts that distribute
    /// content useful for every listener to cache (chat, bulletins, heartbeat,
    /// MOTD, user info, public key).
    pub const broadcast_all: Route = .{
        .radios = .all,
        .clients = .all,
    };

    /// Source radio only, all clients — used for NAK retransmits where the
    /// retransmitted packet is only relevant to clients on the same radio.
    pub const broadcast_source: Route = .{
        .radios = .single,
        .clients = .all,
    };

    /// Source radio only, single client — used for directed responses like
    /// registration acks, request_status, and chat rejects.
    pub fn directed(callsign: []const u8) Route {
        return .{
            .radios = .single,
            .clients = .{ .single = callsign },
        };
    }

    /// Resolve the destination callsign for the wire layer ("CQ" for
    /// broadcast, or the specific callsign for directed).
    pub fn callTo(self: Route) []const u8 {
        return switch (self.clients) {
            .all => "CQ",
            .single => |cs| cs,
        };
    }
};
