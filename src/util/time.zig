//! Wall-clock time helper shared by the client and server.
//!
//! The single canonical source for "current epoch seconds" across the code
//! base. The server stamps event times with it (user registration/login
//! updates, bulletin / response / chat creation, reconnect backoff, heartbeat
//! windows, retransmit-cache TTL) and the client uses it for deadlines and
//! countdowns (pending-registration timeout, MOTD staleness, packet-stats
//! bucket rotation). Centralizing the clamp-and-cast keeps every timestamp
//! site consistent (never negative, always u64 seconds).

const std = @import("std");

/// Wall-clock seconds since the unix epoch, clamped to >= 0 and cast to u64.
pub fn nowSecs(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Timestamp.now(io, .real).toSeconds()));
}
