//! Shared context passed to every server message handler. Bundles the
//! transport pool, store, signing key, and MOTD state so handlers don't
//! need many separate parameters.
//!
//! `source_transport_id` identifies which transport the current message
//! arrived on — handlers use it when routing directed or single-radio
//! responses back through the same transport.

const std = @import("std");
const Io = std.Io;

const kiss = @import("bbs");
const signing = kiss.signing;

const bulletin_store = @import("bulletin_store.zig");
const retransmit_cache = @import("retransmit_cache.zig");
const transports = @import("transports.zig");
const routing = @import("routing.zig");

pub const ServerCtx = struct {
    io: Io,
    stderr: *Io.Writer,
    pool: *transports.TransportPool,
    /// Which transport the current message arrived on. Used by `Route`
    /// decisions with `RadioScope.single` to target the source transport.
    source_transport_id: routing.TransportId,
    store: *bulletin_store.Store,
    kp: ?signing.KeyPair,
    store_path: []const u8,
    motd_text: *[]const u8,
};
