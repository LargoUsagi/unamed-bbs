//! Handler for `packet_request` — retransmits previously-cached packets (by
//! packet number) to the requester. Verifies the requester's signature
//! against their stored key before serving the cache.

const std = @import("std");

const kiss = @import("bbs");

const context = @import("../context.zig");
const ServerCtx = context.ServerCtx;
const RequestMeta = context.RequestMeta;

pub fn handle(ctx: *const ServerCtx, meta: RequestMeta, packet_numbers: []const u8) !void {
    try ctx.stderr.print("RX packet_request from {s} (group_id={d})\n", .{ meta.callsign, meta.group_id });
    try ctx.stderr.flush();

    // Verify the requester's signature against their stored key.
    // The sender is identified by their signing key, not by callsign.
    if (!meta.signed) {
        try ctx.stderr.writeAll("  ignoring: packet_request not signed\n");
        try ctx.stderr.flush();
        return;
    }
    var requester = ctx.store.findUserBySignature(meta.signature, meta.payload_bytes) orelse {
        try ctx.stderr.writeAll("  ignoring: signature does not match any registered user\n");
        try ctx.stderr.flush();
        return;
    };
    defer requester.deinit(ctx.store.allocator);

    try ctx.stderr.print("  requesting {d} packet(s): ", .{packet_numbers.len});
    for (packet_numbers) |pn| {
        try ctx.stderr.print("{d} ", .{pn});
    }
    try ctx.stderr.writeAll("\n");

    // Retransmit each requested packet from the source transport's cache.
    var retransmitted: usize = 0;
    for (packet_numbers) |pn| {
        if (ctx.pool.get(ctx.source_transport_id)) |t| {
            if (t.cache.lookup(ctx.io, meta.group_id, pn)) |entry| {
                const sig_slice = if (entry.has_signature) &entry.signature else &.{};
                t.sendRaw(meta.port, "CQ", entry.msg_type, entry.chunk[0..entry.chunk_len], sig_slice, .{
                    .group_id = entry.group_id,
                    .packet_override = .{ .packet_number = entry.packet_number, .packet_count = entry.packet_count },
                });
                retransmitted += 1;
                try ctx.stderr.print("  retransmitted packet {d}\n", .{pn});
                continue;
            }
        }
        try ctx.stderr.print("  packet {d} not in cache (expired or dedup)\n", .{pn});
    }
    try ctx.stderr.print("  retransmitted {d}/{d} packets\n", .{ retransmitted, packet_numbers.len });
    try ctx.stderr.flush();
}
