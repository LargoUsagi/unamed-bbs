//! Server-side bulletin store.
//!
//! Wraps the shared (replicated) `bulletins` and `users` tables defined in
//! `src/store/` and exposes the server's high-level `Store` API. The
//! server is free to add server-private tables here (e.g. operator
//! statuses, email addresses, server config) — those are never shared with
//! clients and stay out of the common schema so a seed bundle generated from
//! the replicated tables remains compatible with the client store.

const std = @import("std");
const sqlite = @import("sqlite");

const kiss = @import("bbs");
const store = kiss.store;
const signing = kiss.signing;

pub const User = store.User;
pub const BulletinRecord = store.BulletinRecord;
pub const BulletinResponseRecord = store.BulletinResponseRecord;
pub const ChatRecord = store.ChatRecord;

/// Server bulletin store backed by SQLite. The `bulletins` and `users`
/// tables share their schema with the client store via `src/store/`.
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
        createServerConfigTable(&db);

        return .{
            .allocator = allocator,
            .db = db,
        };
    }

    pub fn deinit(self: *Store) void {
        self.db.deinit();
    }

    // -----------------------------------------------------------------------
    // Server config (server-private key/value store)
    // -----------------------------------------------------------------------

    /// Create the `server_config` table if it doesn't exist. Called during
    /// `init` and after `load`.
    fn createServerConfigTable(db: *sqlite.Db) void {
        db.exec(
            "CREATE TABLE IF NOT EXISTS server_config (" ++
                "key TEXT PRIMARY KEY, value BLOB" ++
                ")",
            .{},
            .{},
        ) catch unreachable;
    }

    /// Read the persisted MOTD text. Caller owns the returned slice.
    /// Returns `null` if no MOTD has been set.
    pub fn getMotd(self: *Store) ?[]u8 {
        const Row = struct { value: []u8 };
        var stmt = self.db.prepare("SELECT value FROM server_config WHERE key = 'motd'") catch return null;
        defer stmt.deinit();
        const row = stmt.oneAlloc(Row, self.allocator, .{}, .{}) catch return null;
        if (row) |r| return r.value;
        return null;
    }

    /// Persist the MOTD text so it survives server restarts.
    pub fn setMotd(self: *Store, text: []const u8) !void {
        var stmt = try self.db.prepare(
            "INSERT OR REPLACE INTO server_config (key, value) VALUES ('motd', ?)",
        );
        defer stmt.deinit();
        try stmt.exec(.{}, .{sqlite.Blob{ .data = text }});
    }

    /// Add a bulletin with a specific ID. Returns the assigned id.
    pub fn addWithId(self: *Store, id: u32, user_id: u16, created_at: u64, title: []const u8, body: []const u8) !u32 {
        return store.addBulletinWithId(&self.db, id, user_id, created_at, title, body);
    }

    /// Add a bulletin. Returns the assigned id.
    pub fn add(self: *Store, user_id: u16, created_at: u64, title: []const u8, body: []const u8) !u32 {
        return store.addBulletin(&self.db, user_id, created_at, title, body);
    }

    /// Number of bulletins stored.
    pub fn count(self: *Store) usize {
        return store.countBulletins(&self.db);
    }

    /// Returns a bulletin by ID. The caller owns the returned record and must call deinit().
    pub fn getById(self: *Store, id: u32) ?BulletinRecord {
        return store.getBulletinById(&self.db, self.allocator, id);
    }

    /// List bulletins with `id > after_id`, ordered by id ascending. Caller
    /// owns the returned slice and each record's title/body.
    pub fn listBulletinsAfter(self: *Store, after_id: u32) ![]BulletinRecord {
        return store.listBulletinsAfter(&self.db, self.allocator, after_id);
    }

    /// List bulletins with `start_id <= id <= end_id`, ordered by id ascending.
    /// Caller owns the returned slice and each record's title/body.
    pub fn listBulletinsRange(self: *Store, start_id: u32, end_id: u32) ![]BulletinRecord {
        return store.listBulletinsRange(&self.db, self.allocator, start_id, end_id);
    }

    /// Free a slice of `BulletinRecord` returned by `listBulletinsAfter` or
    /// `listBulletinsRange`.
    pub fn freeBulletinRecordList(self: *Store, list: []const BulletinRecord) void {
        store.freeBulletinRecordList(self.allocator, list);
    }

    /// Returns a page of bulletin summaries sorted newest-first. The caller
    /// owns the returned slice and the titles inside it, and must free them.
    pub fn listPage(self: *Store, page: u16, page_size: u8) ![]store.BulletinSummary {
        return store.listBulletinPage(&self.db, self.allocator, page, page_size);
    }

    /// Total number of pages given a page size.
    pub fn totalPages(self: *Store, page_size: u8) u16 {
        return store.totalBulletinPages(&self.db, page_size);
    }

    // -----------------------------------------------------------------------
    // Bulletin responses (shared schema)
    // -----------------------------------------------------------------------

    /// Insert (or replace) a response with a specific id. Used by the server
    /// when assigning the next id and by the client when caching received
    /// responses.
    pub fn addResponseWithId(self: *Store, bulletin_id: u32, response_id: u16, user_id: u16, create_datetime: u64, body: []const u8) !void {
        return store.addBulletinResponseWithId(&self.db, bulletin_id, response_id, user_id, create_datetime, body);
    }

    /// Count of responses for a single bulletin.
    pub fn countResponses(self: *Store, bulletin_id: u32) usize {
        return store.countBulletinResponses(&self.db, bulletin_id);
    }

    /// Next response id for a bulletin, or null if the bulletin is full
    /// (1024 responses, ids 0..1023).
    pub fn nextResponseId(self: *Store, bulletin_id: u32) ?u16 {
        return store.nextBulletinResponseId(&self.db, bulletin_id);
    }

    /// Look up a single response by `(bulletin_id, response_id)`.
    pub fn getResponse(self: *Store, bulletin_id: u32, response_id: u16) ?BulletinResponseRecord {
        return store.getBulletinResponse(&self.db, self.allocator, bulletin_id, response_id);
    }

    /// All responses for a bulletin, sorted by response_id ascending.
    pub fn listResponses(self: *Store, bulletin_id: u32) ![]BulletinResponseRecord {
        return store.listBulletinResponses(&self.db, self.allocator, bulletin_id);
    }

    /// Responses for a bulletin with `response_id > after_id`.
    pub fn listResponsesAfter(self: *Store, bulletin_id: u32, after_id: u16) ![]BulletinResponseRecord {
        return store.listBulletinResponsesAfter(&self.db, self.allocator, bulletin_id, after_id);
    }

    /// Responses for a bulletin with `start_id <= response_id <= end_id`.
    pub fn listResponsesRange(self: *Store, bulletin_id: u32, start_id: u16, end_id: u16) ![]BulletinResponseRecord {
        return store.listBulletinResponsesRange(&self.db, self.allocator, bulletin_id, start_id, end_id);
    }

    /// Free a slice of `BulletinResponseRecord` returned by the list methods.
    pub fn freeResponseList(self: *Store, list: []const BulletinResponseRecord) void {
        store.freeBulletinResponseList(self.allocator, list);
    }

    // -----------------------------------------------------------------------
    // Chat messages (shared schema) — the BBS stores every received chat
    // keyed by the epoch time of receipt, and re-broadcasts it to CQ.
    // -----------------------------------------------------------------------

    /// Insert (or replace) a chat message with a specific `epoch_time` (the
    /// server-set Unix epoch seconds at receipt time, used as the primary key).
    pub fn addChatMessage(self: *Store, epoch_time: u64, user_id: u16, text: []const u8) !void {
        return store.addChatMessage(&self.db, epoch_time, user_id, text);
    }

    /// Number of chat messages stored.
    pub fn countChatMessages(self: *Store) usize {
        return store.countChatMessages(&self.db);
    }

    /// Return up to `n` most recent chat messages, newest first. The
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
    // Users
    // -----------------------------------------------------------------------

    /// Register a new user. Returns the assigned u16 id.
    pub fn addUser(self: *Store, handle: []const u8, callsign: []const u8, public_key: [32]u8, registered_datetime: u64, is_sysop: bool, avatar: []const u8) !u16 {
        return store.addUser(&self.db, handle, callsign, public_key, registered_datetime, is_sysop, avatar);
    }

    /// Update an existing user's callsign, public key, registered_datetime, and avatar by id.
    pub fn updateUser(self: *Store, id: u16, callsign: []const u8, public_key: [32]u8, registered_datetime: u64, is_sysop: bool, avatar: []const u8) !void {
        return store.updateUser(&self.db, id, callsign, public_key, registered_datetime, is_sysop, avatar);
    }

    /// Update only the avatar column for a user (used by the `avatar_update`
    /// handler).
    pub fn updateAvatar(self: *Store, id: u16, avatar: []const u8) !void {
        return store.updateUserAvatar(&self.db, id, avatar);
    }

    /// Look up a user by handle. Caller owns the result and must call deinit().
    pub fn getUserByHandle(self: *Store, handle: []const u8) ?User {
        return store.getUserByHandle(&self.db, self.allocator, handle);
    }

    /// Look up a user by callsign (first match).
    pub fn getUserByCallsign(self: *Store, callsign: []const u8) ?User {
        return store.getUserByCallsign(&self.db, self.allocator, callsign);
    }

    /// List all users sorted by `id` ascending. Caller owns the returned
    /// slice and each `User`'s `handle`/`callsign`; call `freeUserList` to free.
    pub fn listAllUsers(self: *Store) ![]User {
        return try store.listAllUsers(&self.db, self.allocator);
    }

    /// Free a slice of `User` returned by `listAllUsers`.
    pub fn freeUserList(self: *Store, list: []const User) void {
        store.freeUserList(self.allocator, list);
    }

    /// Identify the sender of a signed message by trying to verify the
    /// signature against every registered user's public key. Returns the
    /// first matching user (owned — caller must `deinit`), or null if no
    /// stored key verifies the signature.
    ///
    /// This replaces the old `getUserByCallsign` + verify pattern, which
    /// broke when multiple users shared a callsign (e.g. the default
    /// "NOCALL") — the first match's key was used, causing false
    /// "signature INVALID" rejections for all other users with that
    /// callsign. Identifying by signing key is correct because the
    /// signature cryptographically proves which key pair sent the message.
    pub fn findUserBySignature(
        self: *Store,
        signature: [signing.signature_len]u8,
        payload: []const u8,
    ) ?User {
        const users = self.listAllUsers() catch return null;
        defer self.freeUserList(users);
        for (users) |u| {
            if (signing.verify(signature, payload, u.public_key)) {
                // Return a copy that the caller owns (re-allocate
                // handle/callsign/avatar so the caller can deinit independently).
                const handle_copy = self.allocator.dupe(u8, u.handle) catch return null;
                const callsign_copy = self.allocator.dupe(u8, u.callsign) catch {
                    self.allocator.free(handle_copy);
                    return null;
                };
                const avatar_copy = self.allocator.dupe(u8, u.avatar) catch {
                    self.allocator.free(handle_copy);
                    self.allocator.free(callsign_copy);
                    return null;
                };
                return .{
                    .id = u.id,
                    .handle = handle_copy,
                    .callsign = callsign_copy,
                    .public_key = u.public_key,
                    .registered_datetime = u.registered_datetime,
                    .is_sysop = u.is_sysop,
                    .avatar = avatar_copy,
                };
            }
        }
        return null;
    }

    /// Look up a user by id. Caller owns the result and must call deinit().
    pub fn getUserById(self: *Store, id: u16) ?User {
        return store.getUserById(&self.db, self.allocator, id);
    }

    /// Count the total number of registered users.
    pub fn countUsers(self: *Store) usize {
        return store.countUsers(&self.db);
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

    /// Load bulletins from a file, replacing any existing records by switching the database.
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
        createServerConfigTable(&self.db);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Store add and count" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    try std.testing.expectEqual(@as(usize, 0), store_inst.count());

    const id1 = try store_inst.add(1, 100, "First", &.{ 0x01, 0x02 });
    try std.testing.expectEqual(@as(u32, 1), id1);
    try std.testing.expectEqual(@as(usize, 1), store_inst.count());

    const id2 = try store_inst.add(1, 200, "Second", &.{ 0x03, 0x04, 0x05 });
    try std.testing.expectEqual(@as(u32, 2), id2);
    try std.testing.expectEqual(@as(usize, 2), store_inst.count());
}

test "Store listPage returns summaries" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    _ = try store_inst.add(1, 100, "First", &.{});
    _ = try store_inst.add(1, 200, "Second", &.{});
    _ = try store_inst.add(1, 300, "Third", &.{});

    // DESC by created_at: page 0 → Third(3), Second(2); page 1 → First(1)
    const page0 = try store_inst.listPage(0, 2);
    defer {
        for (page0) |s| allocator.free(s.title);
        allocator.free(page0);
    }
    try std.testing.expectEqual(@as(usize, 2), page0.len);
    try std.testing.expectEqual(@as(u32, 3), page0[0].id);
    try std.testing.expectEqualStrings("Third", page0[0].title);
    try std.testing.expectEqual(@as(u32, 2), page0[1].id);
    try std.testing.expectEqualStrings("Second", page0[1].title);

    const page1 = try store_inst.listPage(1, 2);
    defer {
        for (page1) |s| allocator.free(s.title);
        allocator.free(page1);
    }
    try std.testing.expectEqual(@as(usize, 1), page1.len);
    try std.testing.expectEqual(@as(u32, 1), page1[0].id);
    try std.testing.expectEqualStrings("First", page1[0].title);
}

test "Store listPage out of range returns empty" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    _ = try store_inst.add(0, 0, "Only", &.{});
    const empty = try store_inst.listPage(5, 10);
    defer {
        for (empty) |s| allocator.free(s.title);
        allocator.free(empty);
    }
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "Store totalPages" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    try std.testing.expectEqual(@as(u16, 0), store_inst.totalPages(10));

    _ = try store_inst.add(0, 0, "A", &.{});
    _ = try store_inst.add(0, 0, "B", &.{});
    _ = try store_inst.add(0, 0, "C", &.{});

    try std.testing.expectEqual(@as(u16, 1), store_inst.totalPages(10));
    try std.testing.expectEqual(@as(u16, 2), store_inst.totalPages(2));
    try std.testing.expectEqual(@as(u16, 3), store_inst.totalPages(1));
}

test "Store sorts bulletins by created_at descending" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    _ = try store_inst.add(1, 300, "C", &.{});
    _ = try store_inst.add(1, 100, "A", &.{});
    _ = try store_inst.add(1, 200, "B", &.{});

    const page = try store_inst.listPage(0, 10);
    defer {
        for (page) |s| allocator.free(s.title);
        allocator.free(page);
    }
    try std.testing.expectEqual(@as(usize, 3), page.len);
    try std.testing.expectEqualStrings("C", page[0].title);
    try std.testing.expectEqualStrings("B", page[1].title);
    try std.testing.expectEqualStrings("A", page[2].title);
}

test "Store save and load round trip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test_server_bulletin_store.sqlite";

    {
        var store_inst = Store.init(allocator);
        defer store_inst.deinit();
        try store_inst.load(io, path);

        _ = try store_inst.add(1, 1000, "First Post", &.{ 0xDE, 0xAD });
        _ = try store_inst.add(2, 2000, "Second Post", &.{ 0xBE, 0xEF, 0x00 });
    }

    {
        var store_inst = Store.init(allocator);
        defer store_inst.deinit();
        try store_inst.load(io, path);
        try std.testing.expectEqual(@as(usize, 2), store_inst.count());

        var rec1 = store_inst.getById(1).?;
        defer rec1.deinit(allocator);
        try std.testing.expectEqualStrings("First Post", rec1.title);
        try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD }, rec1.body);
        try std.testing.expectEqual(@as(u32, 1), rec1.id);
        try std.testing.expectEqual(@as(u64, 1000), rec1.created_at);

        var rec2 = store_inst.getById(2).?;
        defer rec2.deinit(allocator);
        try std.testing.expectEqualStrings("Second Post", rec2.title);
        try std.testing.expectEqualSlices(u8, &.{ 0xBE, 0xEF, 0x00 }, rec2.body);
        try std.testing.expectEqual(@as(u32, 2), rec2.id);
        try std.testing.expectEqual(@as(u64, 2000), rec2.created_at);
    }

    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

test "Store load continues id sequence" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test_server_bulletin_id.sqlite";

    {
        var store_inst = Store.init(allocator);
        defer store_inst.deinit();
        try store_inst.load(io, path);
        _ = try store_inst.add(0, 0, "A", &.{});
        _ = try store_inst.add(0, 0, "B", &.{});
        _ = try store_inst.add(0, 0, "C", &.{});
    }

    {
        var store_inst = Store.init(allocator);
        defer store_inst.deinit();
        try store_inst.load(io, path);
        const new_id = try store_inst.add(0, 0, "D", &.{});
        try std.testing.expectEqual(@as(u32, 4), new_id);
    }

    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

test "Store addUser inserts and getUserByHandle retrieves" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    const pk = [_]u8{0xAA} ** 32;
    const id = try store_inst.addUser("brad", "KE8WIF", pk, 1000, false, "");
    try std.testing.expect(id >= 1);

    var u = store_inst.getUserByHandle("brad").?;
    defer u.deinit(allocator);
    try std.testing.expectEqual(id, u.id);
    try std.testing.expectEqualStrings("brad", u.handle);
    try std.testing.expectEqualStrings("KE8WIF", u.callsign);
    try std.testing.expectEqualSlices(u8, &pk, &u.public_key);
    try std.testing.expectEqual(@as(u64, 1000), u.registered_datetime);
}

test "Store updateUser changes callsign and public key" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    const pk1 = [_]u8{0x11} ** 32;
    const id = try store_inst.addUser("brad", "KE8WIF", pk1, 1000, false, "");

    const pk2 = [_]u8{0x22} ** 32;
    try store_inst.updateUser(id, "N0CALL", pk2, 2000, false, "");

    var u = store_inst.getUserByHandle("brad").?;
    defer u.deinit(allocator);
    try std.testing.expectEqual(id, u.id);
    try std.testing.expectEqualStrings("N0CALL", u.callsign);
    try std.testing.expectEqualSlices(u8, &pk2, &u.public_key);
}

test "Store addUser allows distinct handles with same callsign" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    const pk = [_]u8{0x33} ** 32;
    const id1 = try store_inst.addUser("brad", "KE8WIF", pk, 1000, false, "");
    const id2 = try store_inst.addUser("op", "KE8WIF", pk, 2000, false, "");
    try std.testing.expect(id1 != id2);
}

test "Store getUserByCallsign returns first match" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    const pk = [_]u8{0x44} ** 32;
    _ = try store_inst.addUser("brad", "KE8WIF", pk, 1000, false, "");
    _ = try store_inst.addUser("op", "KE8WIF", pk, 2000, false, "");

    var u = store_inst.getUserByCallsign("KE8WIF").?;
    defer u.deinit(allocator);
    try std.testing.expectEqualStrings("KE8WIF", u.callsign);
}

test "Store getUserById" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    const pk = [_]u8{0x55} ** 32;
    const id = try store_inst.addUser("op", "N0CALL", pk, 1000, false, "");

    var u = store_inst.getUserById(id).?;
    defer u.deinit(allocator);
    try std.testing.expectEqual(id, u.id);
    try std.testing.expectEqualStrings("op", u.handle);
    try std.testing.expectEqualStrings("N0CALL", u.callsign);
}

test "Store responses add/count/next/get/list" {
    const allocator = std.testing.allocator;
    var store_inst = Store.init(allocator);
    defer store_inst.deinit();

    try std.testing.expectEqual(@as(usize, 0), store_inst.countResponses(1));
    try std.testing.expectEqual(@as(u16, 0), store_inst.nextResponseId(1).?);

    try store_inst.addResponseWithId(1, 0, 7, 1000, &.{0xAA});
    try store_inst.addResponseWithId(1, 1, 8, 2000, &.{0xBB});
    try std.testing.expectEqual(@as(usize, 2), store_inst.countResponses(1));
    try std.testing.expectEqual(@as(u16, 2), store_inst.nextResponseId(1).?);

    var rec = store_inst.getResponse(1, 1).?;
    defer rec.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 8), rec.user_id);
    try std.testing.expectEqualSlices(u8, &.{0xBB}, rec.body);

    // listResponsesAfter(after_id=0) returns just id 1.
    const after = try store_inst.listResponsesAfter(1, 0);
    defer store.freeBulletinResponseList(allocator, after);
    try std.testing.expectEqual(@as(usize, 1), after.len);
    try std.testing.expectEqual(@as(u16, 1), after[0].response_id);

    // listResponsesRange(0, 1) returns both responses.
    const range = try store_inst.listResponsesRange(1, 0, 1);
    defer store.freeBulletinResponseList(allocator, range);
    try std.testing.expectEqual(@as(usize, 2), range.len);
}

test "Store nextResponseId returns null when full" {
    var store_inst = Store.init(std.testing.allocator);
    defer store_inst.deinit();

    for (0..@as(u32, store.max_response_id + 1)) |i| {
        try store_inst.addResponseWithId(1, @intCast(i), 1, 0, &.{});
    }
    try std.testing.expect(store_inst.nextResponseId(1) == null);
}
