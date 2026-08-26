//! Store record types — the application-level data model shared by the
//! server and client stores.
//!
//! These are the persistent, memory-owning structs that mirror the replicated
//! SQLite tables. Each owns its heap-allocated slices (`handle`, `callsign`,
//! `body`, `title`, `avatar`, `text`) and provides a `deinit` to free them.
//! They are distinct from the wire-payload structs in `message_frame/`: the
//! wire types (`message_frame.Bulletin`, `message_frame.BulletinResponse`,
//! …) are transient decoded payloads, while the records here are the
//! canonical form the app holds in its database and renders in the UI.
//!
//! `BulletinSummary` is the store-native projection used by the paginated
//! `listPage` / `listAllBulletins` query helpers — same field shape as
//! `message_frame.BulletinSummary` but owned by this module so the store does
//! not re-export wire types.

const std = @import("std");

/// Maximum number of responses a single bulletin may have. The id space is
/// 0..1023 inclusive (a u10). When a bulletin reaches this count the reply
/// UI on the client is hidden — no more responses can be added.
pub const max_response_id: u16 = @import("../message_frame/bulletin_response.zig").max_response_id;

/// A registered user: a handle (display name), a callsign, and the
/// Ed25519 public key they registered with. `id` is the server-assigned
/// u16 reference stored in `bulletins.user_id`. Shared by server and client
/// stores — on the client this is a cache of users learned from the server.
/// `registered_datetime` is the server-set Unix epoch timestamp (seconds)
/// set at registration time.
pub const User = struct {
    id: u16,
    handle: []u8,
    callsign: []u8,
    public_key: [32]u8,
    registered_datetime: u64,
    is_sysop: bool = false,
    /// 11×7 ASCII art avatar (7 lines joined by '\n', '█'/' ' cells). The
    /// server computes this once at registration (from the public key) and
    /// replicates it verbatim to clients via `user_info`. Empty for legacy
    /// rows that predate the column.
    avatar: []u8 = &.{},

    pub fn deinit(self: *User, allocator: std.mem.Allocator) void {
        allocator.free(self.handle);
        allocator.free(self.callsign);
        if (self.avatar.len != 0) allocator.free(self.avatar);
    }
};

/// A stored chat message. The BBS uses `epoch_time` (the Unix epoch time at
/// which the server received the message) as the primary key; clients cache
/// received chat messages here so the chat window can be assembled and sorted
/// by timestamp. Owns its `text` slice (plain text — compressed only on the
/// wire). Shared by server and client stores.
pub const ChatRecord = struct {
    /// Unix epoch seconds (server-set at receipt time). Primary key.
    epoch_time: u64,
    /// Server-assigned user id of the author (references the `users` table).
    user_id: u16,
    /// Plain chat text (decompressed; up to 256 chars before compression).
    text: []u8,

    pub fn deinit(self: *ChatRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.text);
    }
};

/// A stored bulletin with a server-assigned id. Owns its title and body
/// slices. Shared by server and client stores.
pub const BulletinRecord = struct {
    id: u32,
    user_id: u16,
    created_at: u64,
    title: []u8,
    body: []u8,

    pub fn deinit(self: *BulletinRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.title);
        allocator.free(self.body);
    }
};

/// A stored bulletin response with a per-bulletin sequential id. Owns its
/// body slice (plain UTF-8 text — compressed only on the wire). Shared by
/// server and client stores.
pub const BulletinResponseRecord = struct {
    bulletin_id: u32,
    response_id: u16,
    user_id: u16,
    /// Server-set creation timestamp (Unix epoch seconds).
    create_datetime: u64,
    body: []u8,

    pub fn deinit(self: *const BulletinResponseRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }
};

/// Metadata for a single bulletin in a paginated list (no body). This is the
/// store-native projection returned by `listPage` / `listAllBulletins`; it
/// mirrors the columns selected by those queries. Distinct from
/// `message_frame.BulletinSummary` (the wire payload) — the outbox converts
/// between the two at the transport boundary. The caller owns the returned
/// slice and each `title`; free with `freeBulletinSummaryList`.
pub const BulletinSummary = struct {
    id: u32,
    /// Server-assigned user id (references the `users` table).
    user_id: u16,
    title: []const u8,
};
