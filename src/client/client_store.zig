//! Client-side store.
//!
//! Backed by SQLite. Uses the shared (replicated) `bulletins` and `users`
//! table schemas from `src/store.zig` so that a seed bundle produced from
//! those tables on the server can be imported here verbatim. The `users`
//! table is created on the client even though it is currently unused for
//! queries — it exists so a future server seed bundle can be copied in
//! without a schema migration.
//!
//! The client also keeps two **client-private** tables that are never shared
//! with the server:
//!
//!   - `known_keys`  — callsign → Ed25519 public key cache, used to verify
//!     signatures on messages from peers whose key was learned over the air.
//!     Replaces the in-memory `known_keys` array the TUI previously kept.
//!   - `client_config` — key/value store for client-only state such as the
//!     server-assigned `my_user_id` and the learned (soft-trusted) `bbs_key`,
//!     so they survive restarts. (When `--bbs-key` is passed the key is
//!     hard-locked from the CLI and the DB value is not consulted.)
//!
//! Server-private data (operator statuses, email addresses, server config)
//! never appears here — it lives only in `server/bulletin_store.zig`.

const std = @import("std");
const sqlite = @import("sqlite");

const store = @import("bbs").store;

pub const User = store.User;
pub const BulletinRecord = store.BulletinRecord;
pub const BulletinResponseRecord = store.BulletinResponseRecord;
pub const ChatRecord = store.ChatRecord;

/// Client store backed by SQLite. The `bulletins` and `users` tables share
/// their schema with the server store via `src/store.zig`.
pub const Store = struct {
    allocator: std.mem.Allocator,
    db: sqlite.Db,

    pub fn init(allocator: std.mem.Allocator) Store {
        var db = sqlite.Db.init(.{
            .mode = sqlite.Db.Mode{ .Memory = {} },
            .open_flags = .{ .write = true, .create = true },
            .threading_mode = .MultiThread,
        }) catch unreachable;

        store.createSchema(&db);
        createClientTables(&db);

        return .{
            .allocator = allocator,
            .db = db,
        };
    }

    pub fn deinit(self: *Store) void {
        self.db.deinit();
    }

    // -----------------------------------------------------------------------
    // Bulletins (shared schema) — cache of bulletins learned from the server.
    // -----------------------------------------------------------------------

    /// Add a bulletin with a specific ID. Used to cache bulletins received
    /// from the server (which assigns the id). Returns the assigned id.
    pub fn addWithId(self: *Store, id: u32, user_id: u16, created_at: u64, title: []const u8, body: []const u8) !u32 {
        return store.addBulletinWithId(&self.db, id, user_id, created_at, title, body);
    }

    /// Add a bulletin. Returns the assigned id.
    pub fn add(self: *Store, user_id: u16, created_at: u64, title: []const u8, body: []const u8) !u32 {
        return store.addBulletin(&self.db, user_id, created_at, title, body);
    }

    /// Number of bulletins cached.
    pub fn count(self: *Store) usize {
        return store.countBulletins(&self.db);
    }

    /// Returns a cached bulletin by ID. Caller owns the record and must call deinit().
    pub fn getById(self: *Store, id: u32) ?BulletinRecord {
        return store.getBulletinById(&self.db, self.allocator, id);
    }

    /// Returns a page of bulletin summaries sorted by `created_at` ascending.
    /// Caller owns the returned slice and the titles inside it.
    pub fn listPage(self: *Store, page: u16, page_size: u8) ![]store.BulletinSummary {
        return store.listBulletinPage(&self.db, self.allocator, page, page_size);
    }

    /// Total number of pages given a page size.
    pub fn totalPages(self: *Store, page_size: u8) u16 {
        return store.totalBulletinPages(&self.db, page_size);
    }

    /// Returns all cached bulletin summaries sorted newest-first. The caller
    /// owns the returned slice and the titles inside it. Used by the Bulletins
    /// screen to render a scrollable list of every cached bulletin.
    pub fn listAll(self: *Store) ![]store.BulletinSummary {
        return store.listAllBulletins(&self.db, self.allocator);
    }

    // -----------------------------------------------------------------------
    // Bulletin responses (shared schema) — cache of responses learned from
    // the server. The client stores them by their server-assigned
    // `(bulletin_id, response_id)` pair.
    // -----------------------------------------------------------------------

    /// Insert (or replace) a cached response received from the server.
    pub fn addResponseWithId(self: *Store, bulletin_id: u32, response_id: u16, user_id: u16, create_datetime: u64, body: []const u8) !void {
        return store.addBulletinResponseWithId(&self.db, bulletin_id, response_id, user_id, create_datetime, body);
    }

    /// Count of cached responses for a single bulletin.
    pub fn countResponses(self: *Store, bulletin_id: u32) usize {
        return store.countBulletinResponses(&self.db, bulletin_id);
    }

    /// Next missing response id for a bulletin (max cached id + 1, or 0 if
    /// no cached responses). Returns null when the client has cached all
    /// 1024 responses — i.e. the id space is exhausted.
    pub fn nextResponseId(self: *Store, bulletin_id: u32) ?u16 {
        return store.nextBulletinResponseId(&self.db, bulletin_id);
    }

    /// Look up a single cached response by `(bulletin_id, response_id)`.
    pub fn getResponse(self: *Store, bulletin_id: u32, response_id: u16) ?BulletinResponseRecord {
        return store.getBulletinResponse(&self.db, self.allocator, bulletin_id, response_id);
    }

    /// All cached responses for a bulletin, sorted by response_id ascending.
    pub fn listResponses(self: *Store, bulletin_id: u32) ![]BulletinResponseRecord {
        return store.listBulletinResponses(&self.db, self.allocator, bulletin_id);
    }

    /// Free a slice of `BulletinResponseRecord` returned by `listResponses`.
    pub fn freeResponseList(self: *Store, list: []const BulletinResponseRecord) void {
        store.freeBulletinResponseList(self.allocator, list);
    }

    // -----------------------------------------------------------------------
    // Chat messages (shared schema) — cache of chat lines received from the
    // BBS, keyed by the server-set epoch time. The chat window is assembled
    // and sorted by `epoch_time` from this cache.
    // -----------------------------------------------------------------------

    /// Insert (or replace) a cached chat message with a specific `epoch_time`.
    pub fn addChatMessage(self: *Store, epoch_time: u64, user_id: u16, text: []const u8) !void {
        return store.addChatMessage(&self.db, epoch_time, user_id, text);
    }

    /// Number of chat messages cached.
    pub fn countChatMessages(self: *Store) usize {
        return store.countChatMessages(&self.db);
    }

    /// Return up to `n` most recent cached chat messages, newest first. The
    /// caller owns the returned slice and each record's `text`; call
    /// `freeChatRecordList` to free.
    pub fn listRecentChatMessages(self: *Store, n: u8) ![]ChatRecord {
        return store.listRecentChatMessages(&self.db, self.allocator, n);
    }

    /// Free a slice of `ChatRecord` returned by `listRecentChatMessages`.
    pub fn freeChatRecordList(self: *Store, list: []const ChatRecord) void {
        store.freeChatRecordList(self.allocator, list);
    }

    // -----------------------------------------------------------------------
    // Users (shared schema, currently unused for queries on the client —
    // present so a server seed bundle can be imported). Helpers delegate to
    // the common module in case the client needs them later.
    // -----------------------------------------------------------------------

    pub fn getUserByCallsign(self: *Store, callsign: []const u8) ?User {
        return store.getUserByCallsign(&self.db, self.allocator, callsign);
    }

    pub fn getUserByHandle(self: *Store, handle: []const u8) ?User {
        return store.getUserByHandle(&self.db, self.allocator, handle);
    }

    pub fn getUserById(self: *Store, id: u16) ?User {
        return store.getUserById(&self.db, self.allocator, id);
    }

    /// Insert or replace a user by id. Used to cache user info received from
    /// the server (via `user_info` broadcasts). The client does not own the
    /// `registered_datetime` or `avatar` — the server is authoritative.
    pub fn upsertUserWithId(self: *Store, id: u16, handle: []const u8, callsign: []const u8, public_key: [32]u8, registered_datetime: u64, is_sysop: bool, avatar: []const u8) !void {
        return store.upsertUserWithId(&self.db, id, handle, callsign, public_key, registered_datetime, is_sysop, avatar);
    }

    /// Count of registered users in the cache.
    pub fn countUsers(self: *Store) usize {
        return store.countUsers(&self.db);
    }

    /// All cached users sorted by id ascending. Caller owns the returned
    /// slice and each `User`'s handle/callsign; call `freeUserList` to free.
    pub fn listUsers(self: *Store) ![]User {
        return store.listAllUsers(&self.db, self.allocator);
    }

    /// Free a slice of `User` returned by `listUsers`.
    pub fn freeUserList(self: *Store, list: []const User) void {
        store.freeUserList(self.allocator, list);
    }

    // -----------------------------------------------------------------------
    // Known keys (client-private) — callsign → public key cache.
    // -----------------------------------------------------------------------

    /// Insert or update a known callsign → public key mapping.
    pub fn upsertKnownKey(self: *Store, callsign: []const u8, public_key: [32]u8) !void {
        var stmt = try self.db.prepare(
            "INSERT OR REPLACE INTO known_keys (callsign, public_key) VALUES (?, ?)",
        );
        defer stmt.deinit();
        try stmt.exec(.{}, .{ callsign, sqlite.Blob{ .data = &public_key } });
    }

    /// Look up a public key by callsign. Returns null if not cached.
    pub fn lookupPublicKey(self: *Store, callsign: []const u8) ?[32]u8 {
        const Row = struct { public_key: [32]u8 };
        var stmt = self.db.prepare("SELECT public_key FROM known_keys WHERE callsign = ?") catch return null;
        defer stmt.deinit();
        const row = stmt.one(Row, .{}, .{callsign}) catch return null;
        if (row) |r| return r.public_key;
        return null;
    }

    /// Number of known keys cached.
    pub fn countKnownKeys(self: *Store) usize {
        var stmt = self.db.prepare("SELECT COUNT(*) FROM known_keys") catch return 0;
        defer stmt.deinit();
        const row = stmt.one(usize, .{}, .{}) catch return 0;
        return row orelse 0;
    }

    // -----------------------------------------------------------------------
    // Client config (client-private) — key/value store for client-only state.
    // -----------------------------------------------------------------------

    /// Read a config value as a blob. Caller owns the returned slice.
    /// Uses `sqlite3_column_blob` (not `sqlite3_column_text`) so binary
    /// values like secret keys round-trip without text-encoding side effects.
    pub fn getConfigBlob(self: *Store, key: []const u8) ?[]u8 {
        const Row = struct { value: sqlite.Blob };
        var stmt = self.db.prepare("SELECT value FROM client_config WHERE key = ?") catch return null;
        defer stmt.deinit();
        const row = stmt.oneAlloc(Row, self.allocator, .{}, .{key}) catch return null;
        if (row) |r| return @constCast(r.value.data);
        return null;
    }

    /// Write a config value as a blob, replacing any existing value.
    pub fn setConfigBlob(self: *Store, key: []const u8, value: []const u8) !void {
        var stmt = try self.db.prepare(
            "INSERT OR REPLACE INTO client_config (key, value) VALUES (?, ?)",
        );
        defer stmt.deinit();
        try stmt.exec(.{}, .{ key, sqlite.Blob{ .data = value } });
    }

    /// The server-assigned user id for this client, learned from a signed
    /// `registration_ack`. Null until the client has registered.
    pub fn getMyUserId(self: *Store) ?u16 {
        const blob = self.getConfigBlob("my_user_id") orelse return null;
        defer self.allocator.free(blob);
        if (blob.len != 2) return null;
        return @intCast(std.mem.readInt(u16, blob[0..2], .little));
    }

    /// Persist the server-assigned user id so it survives restarts.
    pub fn setMyUserId(self: *Store, id: u16) !void {
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, id, .little);
        try self.setConfigBlob("my_user_id", &buf);
    }

    /// The learned (soft-trusted) BBS public key, if any. Note: when the
    /// client is launched with `--bbs-key` the key is hard-locked from the
    /// CLI and this DB value is not consulted.
    pub fn getBbsKey(self: *Store) ?[32]u8 {
        const blob = self.getConfigBlob("bbs_key") orelse return null;
        defer self.allocator.free(blob);
        if (blob.len != 32) return null;
        var key: [32]u8 = undefined;
        @memcpy(&key, blob[0..32]);
        return key;
    }

    /// Persist a learned BBS public key so it survives restarts.
    pub fn setBbsKey(self: *Store, key: [32]u8) !void {
        try self.setConfigBlob("bbs_key", &key);
    }

    /// Retrieve the persisted Ed25519 secret key (64 bytes), if "remember
    /// credentials" was checked. Returns null if not stored.
    pub fn getSecretKey(self: *Store) ?[64]u8 {
        const blob = self.getConfigBlob("secret_key") orelse return null;
        defer self.allocator.free(blob);
        if (blob.len != 64) return null;
        var key: [64]u8 = undefined;
        @memcpy(&key, blob[0..64]);
        return key;
    }

    /// Persist the Ed25519 secret key (64 bytes) so the user doesn't need to
    /// re-enter their password on restart.
    pub fn setSecretKey(self: *Store, key: [64]u8) !void {
        try self.setConfigBlob("secret_key", &key);
    }

    /// Clear any persisted secret key (used on logout).
    pub fn clearSecretKey(self: *Store) void {
        var stmt = self.db.prepare("DELETE FROM client_config WHERE key = 'secret_key'") catch return;
        defer stmt.deinit();
        stmt.exec(.{}, .{}) catch return;
    }

    /// The last known MOTD text received from the server. Caller owns the
    /// returned slice and must free it. Null if never received.
    pub fn getMotd(self: *Store) ?[]u8 {
        return self.getConfigBlob("motd_text");
    }

    /// Persist the MOTD text so it survives restarts.
    pub fn setMotd(self: *Store, text: []const u8) !void {
        try self.setConfigBlob("motd_text", text);
    }

    /// The Unix epoch timestamp (seconds) when the MOTD was last received.
    /// Returns 0 if never set.
    pub fn getMotdTimestamp(self: *Store) u64 {
        const blob = self.getConfigBlob("motd_timestamp") orelse return 0;
        defer self.allocator.free(blob);
        if (blob.len != 8) return 0;
        return std.mem.readInt(u64, blob[0..8], .little);
    }

    /// Persist the MOTD timestamp so the client doesn't re-request a fresh
    /// MOTD on every restart.
    pub fn setMotdTimestamp(self: *Store, ts: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, ts, .little);
        try self.setConfigBlob("motd_timestamp", &buf);
    }

    // -----------------------------------------------------------------------
    // Read bulletin tracking (client-private) — tracks which bulletins have
    // been opened by the user so the list can show "[New]" for unread ones.
    // -----------------------------------------------------------------------

    /// Mark a bulletin as read (opened in the detail screen). Idempotent —
    /// if already marked, this is a no-op.
    pub fn markBulletinRead(self: *Store, bulletin_id: u32) void {
        var stmt = self.db.prepare(
            "INSERT OR IGNORE INTO read_bulletins (bulletin_id) VALUES (?)",
        ) catch return;
        defer stmt.deinit();
        stmt.exec(.{}, .{bulletin_id}) catch return;
    }

    /// Check whether a bulletin has been read. Returns true if the bulletin
    /// id is in the `read_bulletins` table.
    pub fn isBulletinRead(self: *Store, bulletin_id: u32) bool {
        var stmt = self.db.prepare("SELECT 1 FROM read_bulletins WHERE bulletin_id = ?") catch return false;
        defer stmt.deinit();
        const row = stmt.one(i32, .{}, .{bulletin_id}) catch return false;
        return row != null;
    }

    // -----------------------------------------------------------------------
    // Transport configuration (client-private) — saves the last successfully
    // connected transport endpoint as a URI string so the client can
    // auto-reconnect on restart. CLI --connect takes priority over the saved
    // value. The URI format mirrors the server CLI:
    //   agwpe://host:port[:kport]  or  tcp://host:port
    // -----------------------------------------------------------------------

    /// The saved connect URI (e.g. "agwpe://127.0.0.1:8000:0" or
    /// "tcp://127.0.0.1:9000"). Caller owns the returned slice. Returns
    /// null if never saved.
    pub fn getConnectUri(self: *Store) ?[]u8 {
        return self.getConfigBlob("tc_connect_uri");
    }

    /// Persist the connect URI so the client can auto-reconnect on restart.
    pub fn setConnectUri(self: *Store, uri: []const u8) !void {
        try self.setConfigBlob("tc_connect_uri", uri);
    }

    /// Get a stored transport string (callsign). Caller owns the returned
    /// slice. Returns null if not saved.
    pub fn getTransportString(self: *Store, key: []const u8) ?[]u8 {
        return self.getConfigBlob(key);
    }

    /// Store a transport string (callsign).
    pub fn setTransportString(self: *Store, key: []const u8, value: []const u8) !void {
        try self.setConfigBlob(key, value);
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    /// No-op for sqlite as it writes automatically.
    pub fn save(self: *Store, io: std.Io, path: []const u8) !void {
        _ = self;
        _ = io;
        _ = path;
    }

    /// Open a database file, replacing any in-memory db. Creates the shared
    /// and client-private tables and runs shared migrations.
    pub fn load(self: *Store, io: std.Io, path: []const u8) !void {
        _ = io;
        self.db.deinit();

        const path_z = try self.allocator.dupeZ(u8, path);
        defer self.allocator.free(path_z);

        self.db = try sqlite.Db.init(.{
            .mode = sqlite.Db.Mode{ .File = path_z },
            .open_flags = .{ .write = true, .create = true },
            .threading_mode = .MultiThread,
        });

        store.createSchema(&self.db);
        store.migrateSchema(&self.db);
        createClientTables(&self.db);
    }
};

// ---------------------------------------------------------------------------
// Client-private schema
// ---------------------------------------------------------------------------

/// Create the client-private tables (`known_keys`, `client_config`). These
/// are never shared with the server and have no counterpart in
/// `server/bulletin_store.zig`.
fn createClientTables(db: *sqlite.Db) void {
    db.exec(
        "CREATE TABLE IF NOT EXISTS known_keys (" ++
            "callsign TEXT PRIMARY KEY, public_key BLOB NOT NULL" ++
            ")",
        .{},
        .{},
    ) catch unreachable;
    db.exec(
        "CREATE TABLE IF NOT EXISTS client_config (" ++
            "key TEXT PRIMARY KEY, value BLOB" ++
            ")",
        .{},
        .{},
    ) catch unreachable;
    db.exec(
        "CREATE TABLE IF NOT EXISTS read_bulletins (" ++
            "bulletin_id INTEGER PRIMARY KEY" ++
            ")",
        .{},
        .{},
    ) catch unreachable;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Store bulletins cache add and get" {
    const allocator = std.testing.allocator;
    var s = Store.init(allocator);
    defer s.deinit();

    try std.testing.expectEqual(@as(usize, 0), s.count());
    _ = try s.addWithId(5, 1, 1000, "Hello", &.{ 0x01 });
    try std.testing.expectEqual(@as(usize, 1), s.count());

    var rec = s.getById(5).?;
    defer rec.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 5), rec.id);
    try std.testing.expectEqualStrings("Hello", rec.title);
}

test "Store known keys upsert and lookup" {
    const allocator = std.testing.allocator;
    var s = Store.init(allocator);
    defer s.deinit();

    try std.testing.expectEqual(@as(usize, 0), s.countKnownKeys());
    try std.testing.expect(s.lookupPublicKey("KE8WIF") == null);

    const pk1 = [_]u8{0xAA} ** 32;
    try s.upsertKnownKey("KE8WIF", pk1);
    try std.testing.expectEqual(@as(usize, 1), s.countKnownKeys());

    const got = s.lookupPublicKey("KE8WIF").?;
    try std.testing.expectEqualSlices(u8, &pk1, &got);

    // Upsert updates an existing callsign in place.
    const pk2 = [_]u8{0xBB} ** 32;
    try s.upsertKnownKey("KE8WIF", pk2);
    try std.testing.expectEqual(@as(usize, 1), s.countKnownKeys());
    const got2 = s.lookupPublicKey("KE8WIF").?;
    try std.testing.expectEqualSlices(u8, &pk2, &got2);

    // Case-sensitive: distinct callsigns are distinct rows.
    try s.upsertKnownKey("N0CALL", pk1);
    try std.testing.expectEqual(@as(usize, 2), s.countKnownKeys());
}

test "Store my_user_id round trip" {
    const allocator = std.testing.allocator;
    var s = Store.init(allocator);
    defer s.deinit();

    try std.testing.expect(s.getMyUserId() == null);
    try s.setMyUserId(42);
    try std.testing.expectEqual(@as(?u16, 42), s.getMyUserId());
}

test "Store bbs_key round trip" {
    const allocator = std.testing.allocator;
    var s = Store.init(allocator);
    defer s.deinit();

    try std.testing.expect(s.getBbsKey() == null);
    const key = [_]u8{0xCD} ** 32;
    try s.setBbsKey(key);
    const got = s.getBbsKey().?;
    try std.testing.expectEqualSlices(u8, &key, &got);
}

test "Store secret_key round trip" {
    const allocator = std.testing.allocator;
    var s = Store.init(allocator);
    defer s.deinit();

    try std.testing.expect(s.getSecretKey() == null);
    const sk = [_]u8{0xAB} ** 64;
    try s.setSecretKey(sk);
    const got = s.getSecretKey().?;
    try std.testing.expectEqualSlices(u8, &sk, &got);

    s.clearSecretKey();
    try std.testing.expect(s.getSecretKey() == null);
}

test "Store load persists known keys and config" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test_client_store.sqlite";

    {
        var s = Store.init(allocator);
        defer s.deinit();
        try s.load(io, path);

        try s.upsertKnownKey("KE8WIF", [_]u8{0xAA} ** 32);
        try s.setMyUserId(7);
        try s.setBbsKey([_]u8{0x11} ** 32);
        _ = try s.addWithId(1, 1, 100, "Cached", &.{ 0x01 });
    }

    {
        var s = Store.init(allocator);
        defer s.deinit();
        try s.load(io, path);

        try std.testing.expectEqual(@as(usize, 1), s.count());
        try std.testing.expectEqual(@as(usize, 1), s.countKnownKeys());
        const got = s.lookupPublicKey("KE8WIF").?;
        try std.testing.expectEqual(@as(u8, 0xAA), got[0]);
        try std.testing.expectEqual(@as(?u16, 7), s.getMyUserId());
        const bbs = s.getBbsKey().?;
        try std.testing.expectEqual(@as(u8, 0x11), bbs[0]);
    }

    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

test "Store read bulletin tracking" {
    const allocator = std.testing.allocator;
    var s = Store.init(allocator);
    defer s.deinit();

    // Initially no bulletins are read.
    try std.testing.expect(!s.isBulletinRead(1));
    try std.testing.expect(!s.isBulletinRead(42));

    // Mark one as read.
    s.markBulletinRead(42);
    try std.testing.expect(!s.isBulletinRead(1));
    try std.testing.expect(s.isBulletinRead(42));

    // Marking again is a no-op (idempotent).
    s.markBulletinRead(42);
    try std.testing.expect(s.isBulletinRead(42));
}

test "Store read bulletin tracking persists across load" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test_client_read_tracking.sqlite";

    {
        var s = Store.init(allocator);
        defer s.deinit();
        try s.load(io, path);

        _ = try s.addWithId(1, 1, 100, "Hello", &.{ 0x01 });
        s.markBulletinRead(1);
        try std.testing.expect(s.isBulletinRead(1));
    }

    {
        var s = Store.init(allocator);
        defer s.deinit();
        try s.load(io, path);

        try std.testing.expect(s.isBulletinRead(1));
        try std.testing.expect(!s.isBulletinRead(2));
    }

    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}
