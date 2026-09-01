//! TopBar widget — the two-line header shared by every non-modal screen.
//!
//! Line 1: connection indicator + packet stats + status message.
//! Line 2: BBS key indicator (omitted when `show_bbs` is false).
//!
//! Follows the zigzag component pattern: `init()` to create, `view()` to
//! render. Stateless — reads from `AppContext` on each `view` call.

const std = @import("std");
const zz = @import("zigzag");

const app = @import("../app.zig");
const render = @import("../render.zig");
const time = @import("bbs").time;

pub const TopBar = struct {
    /// When true, the BBS key indicator is rendered on a second line.
    /// Settings and avatar_edit set this to false (they don't show the key).
    show_bbs: bool = true,

    pub fn init(show_bbs: bool) TopBar {
        return .{ .show_bbs = show_bbs };
    }

    pub fn deinit(self: *TopBar) void {
        _ = self;
    }

    /// Render the top bar. Caller frees the returned string.
    pub fn view(self: *const TopBar, alloc: std.mem.Allocator, ctx: *const app.AppContext) ![]const u8 {
        const styled_conn = try render.renderConnIndicator(alloc, ctx.connection.isConnected(), ctx.connection.active_kind);
        defer alloc.free(styled_conn);
        const styled_stats = try render.renderPacketStats(alloc, ctx.packet_stats.txRecent(), ctx.packet_stats.rxRecent(), ctx.packet_stats.sparklineData());
        defer alloc.free(styled_stats);
        const styled_status = try render.renderStatusLine(alloc, ctx.status, ctx.outbox.busy);
        defer alloc.free(styled_status);

        if (self.show_bbs) {
            const styled_bbs = try render.renderBbsIndicator(alloc, ctx.identity.bbs_key, ctx.identity.bbs_key_locked);
            defer alloc.free(styled_bbs);
            return std.fmt.allocPrint(alloc, "{s} {s}  {s}\n{s}", .{ styled_conn, styled_stats, styled_status, styled_bbs });
        }
        return std.fmt.allocPrint(alloc, "{s} {s}  {s}", .{ styled_conn, styled_stats, styled_status });
    }
};

/// Styled "Waiting for server key... Ns" countdown line, or an empty string
/// when no pending registration is in flight. Shared by the login and
/// register screens.
pub fn renderWaitingLine(alloc: std.mem.Allocator, ctx: *const app.AppContext) anyerror![]const u8 {
    if (ctx.pending_registration == null) return try alloc.dupe(u8, "");
    const now: u64 = time.nowSecs(ctx.io);
    const remaining: i64 = @as(i64, @intCast(ctx.pending_registration.?.deadline_secs)) - @as(i64, @intCast(now));
    const secs: u64 = if (remaining > 0) @intCast(remaining) else 0;
    const waiting_line = try std.fmt.allocPrint(alloc, "Waiting for server key... {d}s", .{secs});
    defer alloc.free(waiting_line);
    return render.yellow.render(alloc, waiting_line);
}
