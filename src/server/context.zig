//! Shared context passed to every server message handler. Bundles the
//! transport pool, store, signing key, and MOTD state so handlers don't
//! need many separate parameters.
//!
//! `source_transport_id` identifies which transport the current message
//! arrived on — handlers use it when routing directed or single-radio
//! responses back through the same transport.
//!
//! `RequestMeta` is the per-message metadata the inbox extracts from a
//! received `messaging.Message` before dispatching to a handler: link-layer
//! identity (callsign), signature material for sender verification, and the
//! port/group_id needed to route responses. Handlers receive it in place of
//! the raw `messaging.Message` so they never import the transport layer.

const std = @import("std");
const Io = std.Io;

const kiss = @import("bbs");
const signing = kiss.signing;

const bulletin_store = @import("bulletin_store.zig");
const retransmit_cache = @import("retransmit_cache.zig");
const transports = @import("transports.zig");
const routing = @import("routing.zig");

/// Per-message metadata extracted from a received `messaging.Message` by the
/// inbox and handed to each handler alongside the decoded request fields.
/// Replaces the `messaging.Message` parameter in handler signatures so
/// handlers stay free of `transport`/`message_frame` imports.
pub const RequestMeta = struct {
    /// Source callsign slice (empty when the link surfaces no identity).
    callsign: []const u8,
    /// Radio channel / port the message arrived on.
    port: u4,
    /// True when the message carried a signature.
    signed: bool,
    /// The signature bytes (valid when `signed` is true).
    signature: [signing.signature_len]u8,
    /// Logical message id (0-15), used by `packet_request` to address cached
    /// packets for retransmission.
    group_id: u4,
    /// The raw payload bytes the signature covers. Handlers verify signatures
    /// over this slice; it stays alive for the duration of the handler call
    /// (the inbox frees the decoded payload after the handler returns).
    payload_bytes: []const u8,
};

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
