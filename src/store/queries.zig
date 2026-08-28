//! Shared query helpers over the replicated tables.
//!
//! These free functions take a `*sqlite.Db` and an allocator, and return
//! owned record slices (from `records.zig`) that the caller must free with
//! the matching `free*List` helper. Both the server store
//! (`server/bulletin_store.zig`) and the client store
//! (`client/client_store.zig`) wrap these to expose their `Store` methods.

const std = @import("std");
const sqlite = @import("sqlite");
const records = @import("records.zig");

pub const User = records.User;
pub const ChatRecord = records.ChatRecord;
pub const BulletinRecord = records.BulletinRecord;
pub const BulletinResponseRecord = records.BulletinResponseRecord;
pub const BulletinSummary = records.BulletinSummary;
pub const max_response_id = records.max_response_id;

// ---------------------------------------------------------------------------
// Bulletins — shared query helpers
// ---------------------------------------------------------------------------

/// Add a bulletin with a specific ID. Returns the assigned id.
pub fn addBulletinWithId(
    db: *sqlite.Db,
    id: u32,
    user_id: u16,
    created_at: u64,
    title: []const u8,
    body: []const u8,
) !u32 {
    const query = "INSERT OR REPLACE INTO bulletins (id, user_id, created_at, title, body) VALUES (?, ?, ?, ?, ?)";
    var stmt = try db.prepare(query);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ id, user_id, created_at, title, sqlite.Blob{ .data = body } });
    return id;
}

/// Add a bulletin. Returns the assigned id.
pub fn addBulletin(
    db: *sqlite.Db,
    user_id: u16,
    created_at: u64,
    title: []const u8,
    body: []const u8,
) !u32 {
    const query = "INSERT INTO bulletins (user_id, created_at, title, body) VALUES (?, ?, ?, ?)";
    var stmt = try db.prepare(query);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ user_id, created_at, title, sqlite.Blob{ .data = body } });
    return @intCast(db.getLastInsertRowID());
}

/// Number of bulletins stored.
pub fn countBulletins(db: *sqlite.Db) usize {
    var stmt = db.prepare("SELECT COUNT(*) FROM bulletins") catch return 0;
    defer stmt.deinit();
    const row = stmt.one(usize, .{}, .{}) catch return 0;
    return row orelse 0;
}

/// Returns a bulletin by ID. The caller owns the returned record and must
/// call deinit().
pub fn getBulletinById(db: *sqlite.Db, allocator: std.mem.Allocator, id: u32) ?BulletinRecord {
    var stmt = db.prepare("SELECT id, user_id, created_at, title, body FROM bulletins WHERE id = ?") catch return null;
    defer stmt.deinit();
    return stmt.oneAlloc(BulletinRecord, allocator, .{}, .{id}) catch null;
}

/// List bulletins with `id > after_id`, ordered by id ascending. The caller
/// owns the returned slice and each record's title/body; call
/// `freeBulletinRecordList` to free.
pub fn listBulletinsAfter(
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    after_id: u32,
) ![]BulletinRecord {
    var stmt = try db.prepare(
        "SELECT id, user_id, created_at, title, body FROM bulletins WHERE id > ? ORDER BY id ASC",
    );
    defer stmt.deinit();
    return try stmt.all(BulletinRecord, allocator, .{}, .{after_id});
}

/// List bulletins with `start_id <= id <= end_id`, ordered by id ascending.
/// The caller owns the returned slice and each record's title/body; call
/// `freeBulletinRecordList` to free.
pub fn listBulletinsRange(
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    start_id: u32,
    end_id: u32,
) ![]BulletinRecord {
    var stmt = try db.prepare(
        "SELECT id, user_id, created_at, title, body FROM bulletins WHERE id >= ? AND id <= ? ORDER BY id ASC",
    );
    defer stmt.deinit();
    return try stmt.all(BulletinRecord, allocator, .{}, .{ start_id, end_id });
}

/// Free a slice of `BulletinRecord` returned by `listBulletinsAfter` or
/// `listBulletinsRange`.
pub fn freeBulletinRecordList(allocator: std.mem.Allocator, list: []const BulletinRecord) void {
    for (list) |*r| {
        var mut: BulletinRecord = r.*;
        mut.deinit(allocator);
    }
    allocator.free(list);
}

/// Returns a page of bulletin summaries sorted by `created_at` descending
/// (newest first). The caller owns the returned slice and the titles inside it.
pub fn listBulletinPage(
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    page: u16,
    page_size: u8,
) ![]BulletinSummary {
    var stmt = try db.prepare(
        "SELECT id, user_id, title FROM bulletins ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
    );
    defer stmt.deinit();
    const limit: usize = page_size;
    const offset: usize = @as(usize, page) * limit;
    return try stmt.all(BulletinSummary, allocator, .{}, .{ limit, offset });
}

/// Returns all bulletin summaries sorted by `created_at` descending (newest
/// first). The caller owns the returned slice and the titles inside it.
/// Used by the client Bulletins screen to render a scrollable list of every
/// cached bulletin, rather than a single fixed-size page.
pub fn listAllBulletins(db: *sqlite.Db, allocator: std.mem.Allocator) ![]BulletinSummary {
    var stmt = try db.prepare(
        "SELECT id, user_id, title FROM bulletins ORDER BY created_at DESC, id DESC",
    );
    defer stmt.deinit();
    return try stmt.all(BulletinSummary, allocator, .{}, .{});
}

/// Free a slice of `BulletinSummary` returned by `listBulletinPage` or
/// `listAllBulletins`. Frees each `title` (owned slice) and the slice itself.
pub fn freeBulletinSummaryList(allocator: std.mem.Allocator, list: []const BulletinSummary) void {
    for (list) |s| allocator.free(@constCast(s.title));
    allocator.free(list);
}

/// Total number of pages given a page size.
pub fn totalBulletinPages(db: *sqlite.Db, page_size: u8) u16 {
    if (page_size == 0) return 0;
    const c = countBulletins(db);
    const ps: usize = page_size;
    return @intCast((c + ps - 1) / ps);
}

// ---------------------------------------------------------------------------
// Bulletin responses — shared query helpers
// ---------------------------------------------------------------------------

/// Insert (or replace) a bulletin response with a specific
/// `(bulletin_id, response_id)` pair. Used by both the server (when assigning
/// the next id) and the client (when caching a response received over the air).
/// `body` is the already-Compressed bytes (Unishox2). `create_datetime` is the
/// server-set epoch timestamp. The caller is responsible for ensuring
/// `response_id <= max_response_id` (0..1023) and that the
/// `(bulletin_id, response_id)` pair is unique.
pub fn addBulletinResponseWithId(
    db: *sqlite.Db,
    bulletin_id: u32,
    response_id: u16,
    user_id: u16,
    create_datetime: u64,
    body: []const u8,
) !void {
    const query = "INSERT OR REPLACE INTO bulletin_responses (bulletin_id, response_id, user_id, create_datetime, body) VALUES (?, ?, ?, ?, ?)";
    var stmt = try db.prepare(query);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ bulletin_id, response_id, user_id, create_datetime, sqlite.Blob{ .data = body } });
}

/// Count the number of responses stored for a single bulletin.
pub fn countBulletinResponses(db: *sqlite.Db, bulletin_id: u32) usize {
    var stmt = db.prepare("SELECT COUNT(*) FROM bulletin_responses WHERE bulletin_id = ?") catch return 0;
    defer stmt.deinit();
    const row = stmt.one(usize, .{}, .{bulletin_id}) catch return 0;
    return row orelse 0;
}

/// Get the next response id for a bulletin (one greater than the current
/// maximum, or 0 if the bulletin has no responses yet). Returns `null` when
/// the bulletin is full (1024 responses, ids 0..1023 all used).
pub fn nextBulletinResponseId(db: *sqlite.Db, bulletin_id: u32) ?u16 {
    const Row = struct { max_id: ?u16 };
    var stmt = db.prepare("SELECT MAX(response_id) AS max_id FROM bulletin_responses WHERE bulletin_id = ?") catch return 0;
    defer stmt.deinit();
    const row = stmt.one(Row, .{}, .{bulletin_id}) catch return null;
    if (row == null) return 0;
    const max_id = row.?.max_id orelse return 0;
    if (max_id >= max_response_id) return null;
    return max_id + 1;
}

/// Look up a single response by `(bulletin_id, response_id)`. Returns null
/// when no such response exists. The caller owns the returned record and must
/// call `deinit()`.
pub fn getBulletinResponse(
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    bulletin_id: u32,
    response_id: u16,
) ?BulletinResponseRecord {
    var stmt = db.prepare(
        "SELECT bulletin_id, response_id, user_id, create_datetime, body FROM bulletin_responses WHERE bulletin_id = ? AND response_id = ?",
    ) catch return null;
    defer stmt.deinit();
    return stmt.oneAlloc(BulletinResponseRecord, allocator, .{}, .{ bulletin_id, response_id }) catch null;
}

/// List all responses for a bulletin sorted by `response_id` ascending.
/// The caller owns the returned slice and each record's `body`; call
/// `freeBulletinResponseList` to free.
pub fn listBulletinResponses(
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    bulletin_id: u32,
) ![]BulletinResponseRecord {
    var stmt = try db.prepare(
        "SELECT bulletin_id, response_id, user_id, create_datetime, body FROM bulletin_responses WHERE bulletin_id = ? ORDER BY response_id ASC",
    );
    defer stmt.deinit();
    return try stmt.all(BulletinResponseRecord, allocator, .{}, .{bulletin_id});
}

/// List responses for a bulletin with `response_id > after_id`, sorted by
/// `response_id` ascending. The caller owns the returned slice; call
/// `freeBulletinResponseList` to free.
pub fn listBulletinResponsesAfter(
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    bulletin_id: u32,
    after_id: u16,
) ![]BulletinResponseRecord {
    var stmt = try db.prepare(
        "SELECT bulletin_id, response_id, user_id, create_datetime, body FROM bulletin_responses WHERE bulletin_id = ? AND response_id > ? ORDER BY response_id ASC",
    );
    defer stmt.deinit();
    return try stmt.all(BulletinResponseRecord, allocator, .{}, .{ bulletin_id, after_id });
}

/// List responses for a bulletin with `start_id <= response_id <= end_id`,
/// sorted by `response_id` ascending. The caller owns the returned slice;
/// call `freeBulletinResponseList` to free.
pub fn listBulletinResponsesRange(
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    bulletin_id: u32,
    start_id: u16,
    end_id: u16,
) ![]BulletinResponseRecord {
    var stmt = try db.prepare(
        "SELECT bulletin_id, response_id, user_id, create_datetime, body FROM bulletin_responses WHERE bulletin_id = ? AND response_id >= ? AND response_id <= ? ORDER BY response_id ASC",
    );
    defer stmt.deinit();
    return try stmt.all(BulletinResponseRecord, allocator, .{}, .{ bulletin_id, start_id, end_id });
}

/// Free a slice of `BulletinResponseRecord` returned by `listBulletinResponses`,
/// `listBulletinResponsesAfter`, or `listBulletinResponsesRange`.
pub fn freeBulletinResponseList(allocator: std.mem.Allocator, list: []const BulletinResponseRecord) void {
    for (list) |*r| r.deinit(allocator);
    allocator.free(list);
}

// ---------------------------------------------------------------------------
// Chat messages — shared query helpers
// ---------------------------------------------------------------------------

/// Insert (or replace) a chat message with a specific `epoch_time` (the
/// server-set Unix epoch seconds at receipt time, used as the primary key).
/// `text` is the plain (decompressed) chat body. Used by both the server
/// (when storing a received chat) and the client (when caching a chat
/// received over the air).
pub fn addChatMessage(
    db: *sqlite.Db,
    epoch_time: u64,
    user_id: u16,
    text: []const u8,
) !void {
    const query = "INSERT OR REPLACE INTO chat_messages (epoch_time, user_id, text) VALUES (?, ?, ?)";
    var stmt = try db.prepare(query);
    defer stmt.deinit();
    try stmt.exec(.{}, .{ epoch_time, user_id, text });
}

/// Number of chat messages stored.
pub fn countChatMessages(db: *sqlite.Db) usize {
    var stmt = db.prepare("SELECT COUNT(*) FROM chat_messages") catch return 0;
    defer stmt.deinit();
    const row = stmt.one(usize, .{}, .{}) catch return 0;
    return row orelse 0;
}

/// Return up to `count` most recent chat messages, newest first (ordered by
/// `epoch_time` DESC). The caller owns the returned slice and each record's
/// `text`; call `freeChatRecordList` to free.
pub fn listRecentChatMessages(
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    count: u8,
) ![]ChatRecord {
    var stmt = try db.prepare(
        "SELECT epoch_time, user_id, text FROM chat_messages ORDER BY epoch_time DESC LIMIT ?",
    );
    defer stmt.deinit();
    return try stmt.all(ChatRecord, allocator, .{}, .{@as(usize, count)});
}

/// Free a slice of `ChatRecord` returned by `listRecentChatMessages`.
pub fn freeChatRecordList(allocator: std.mem.Allocator, list: []const ChatRecord) void {
    for (list) |*r| {
        var mut: ChatRecord = r.*;
        mut.deinit(allocator);
    }
    allocator.free(list);
}

// ---------------------------------------------------------------------------
// Users — shared query helpers
// ---------------------------------------------------------------------------

/// Register a new user. Returns the assigned u16 id. Errors if a user with
/// the same handle already exists (unique index enforces this).
/// `registered_datetime` is the server-set Unix epoch timestamp (seconds).
/// `avatar` is the server-computed ASCII art avatar string (may be empty).
pub fn addUser(
    db: *sqlite.Db,
    handle: []const u8,
    callsign: []const u8,
    public_key: [32]u8,
    registered_datetime: u64,
    is_sysop: bool,
    avatar: []const u8,
) !u16 {
    var stmt = try db.prepare("INSERT INTO users (handle, callsign, public_key, registered_datetime, is_sysop, avatar) VALUES (?, ?, ?, ?, ?, ?)");
    defer stmt.deinit();
    try stmt.exec(.{}, .{ handle, callsign, sqlite.Blob{ .data = &public_key }, registered_datetime, if (is_sysop) @as(u8, 1) else @as(u8, 0), avatar });
    return @intCast(db.getLastInsertRowID());
}

/// Update an existing user's callsign, public key, registered_datetime, and
/// avatar by id.
pub fn updateUser(
    db: *sqlite.Db,
    id: u16,
    callsign: []const u8,
    public_key: [32]u8,
    registered_datetime: u64,
    is_sysop: bool,
    avatar: []const u8,
) !void {
    var stmt = try db.prepare("UPDATE users SET callsign = ?, public_key = ?, registered_datetime = ?, is_sysop = ?, avatar = ? WHERE id = ?");
    defer stmt.deinit();
    try stmt.exec(.{}, .{ callsign, sqlite.Blob{ .data = &public_key }, registered_datetime, if (is_sysop) @as(u8, 1) else @as(u8, 0), avatar, id });
}

/// Insert or replace a user by id (used by the client to cache user info
/// received from the server).
pub fn upsertUserWithId(
    db: *sqlite.Db,
    id: u16,
    handle: []const u8,
    callsign: []const u8,
    public_key: [32]u8,
    registered_datetime: u64,
    is_sysop: bool,
    avatar: []const u8,
) !void {
    var stmt = try db.prepare(
        "INSERT OR REPLACE INTO users (id, handle, callsign, public_key, registered_datetime, is_sysop, avatar) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    defer stmt.deinit();
    try stmt.exec(.{}, .{ id, handle, callsign, sqlite.Blob{ .data = &public_key }, registered_datetime, if (is_sysop) @as(u8, 1) else @as(u8, 0), avatar });
}

/// Update only the avatar column for a user (used by the `avatar_update`
/// handler). Cheaper than a full `updateUser` when only the avatar changed.
pub fn updateUserAvatar(db: *sqlite.Db, id: u16, avatar: []const u8) !void {
    var stmt = try db.prepare("UPDATE users SET avatar = ? WHERE id = ?");
    defer stmt.deinit();
    try stmt.exec(.{}, .{ avatar, id });
}

/// Look up a user by handle. Caller owns the result and must call deinit().
pub fn getUserByHandle(db: *sqlite.Db, allocator: std.mem.Allocator, handle: []const u8) ?User {
    var stmt = db.prepare("SELECT id, handle, callsign, public_key, registered_datetime, is_sysop, avatar FROM users WHERE handle = ? COLLATE NOCASE") catch return null;
    defer stmt.deinit();
    return stmt.oneAlloc(User, allocator, .{}, .{handle}) catch null;
}

/// Look up a user by callsign (first match; callsign is not unique).
pub fn getUserByCallsign(db: *sqlite.Db, allocator: std.mem.Allocator, callsign: []const u8) ?User {
    var stmt = db.prepare("SELECT id, handle, callsign, public_key, registered_datetime, is_sysop, avatar FROM users WHERE callsign = ? LIMIT 1") catch return null;
    defer stmt.deinit();
    return stmt.oneAlloc(User, allocator, .{}, .{callsign}) catch null;
}

/// Look up a user by id. Caller owns the result and must call deinit().
pub fn getUserById(db: *sqlite.Db, allocator: std.mem.Allocator, id: u16) ?User {
    var stmt = db.prepare("SELECT id, handle, callsign, public_key, registered_datetime, is_sysop, avatar FROM users WHERE id = ?") catch return null;
    defer stmt.deinit();
    return stmt.oneAlloc(User, allocator, .{}, .{id}) catch null;
}

/// Count the total number of registered users.
pub fn countUsers(db: *sqlite.Db) usize {
    var stmt = db.prepare("SELECT COUNT(*) FROM users") catch return 0;
    defer stmt.deinit();
    const row = stmt.one(usize, .{}, .{}) catch return 0;
    return row orelse 0;
}

/// List all users sorted by `id` ascending. The caller owns the returned
/// slice and each `User`'s `handle`/`callsign`; call `freeUserList` to free.
pub fn listAllUsers(db: *sqlite.Db, allocator: std.mem.Allocator) ![]User {
    var stmt = try db.prepare(
        "SELECT id, handle, callsign, public_key, registered_datetime, is_sysop, avatar FROM users ORDER BY id ASC",
    );
    defer stmt.deinit();
    return try stmt.all(User, allocator, .{}, .{});
}

/// Free a slice of `User` returned by `listAllUsers`.
pub fn freeUserList(allocator: std.mem.Allocator, list: []const User) void {
    for (list) |*u| {
        var mut: User = u.*;
        mut.deinit(allocator);
    }
    allocator.free(list);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "shared addBulletin and countBulletins" {
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    try std.testing.expectEqual(@as(usize, 0), countBulletins(&db));
    const id1 = try addBulletin(&db, 1, 100, "First", &.{ 0x01, 0x02 });
    try std.testing.expectEqual(@as(u32, 1), id1);
    try std.testing.expectEqual(@as(usize, 1), countBulletins(&db));
}

test "shared listAllBulletins returns summaries sorted newest-first" {
    const allocator = std.testing.allocator;
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    try std.testing.expectEqual(@as(usize, 0), (try listAllBulletins(&db, allocator)).len);
    {
        const summaries = try listAllBulletins(&db, allocator);
        defer allocator.free(summaries);
    }

    // created_at ascending: older first inserted, but the query returns
    // newest-first, so the highest created_at comes first.
    _ = try addBulletin(&db, 1, 100, "Oldest", &.{});
    _ = try addBulletin(&db, 2, 200, "Middle", &.{});
    _ = try addBulletin(&db, 3, 300, "Newest", &.{});

    const summaries = try listAllBulletins(&db, allocator);
    defer freeBulletinSummaryList(allocator, summaries);
    try std.testing.expectEqual(@as(usize, 3), summaries.len);
    // Sorted by created_at DESC, id DESC — newest inserted (created_at 300) first.
    try std.testing.expectEqualStrings("Newest", summaries[0].title);
    try std.testing.expectEqualStrings("Middle", summaries[1].title);
    try std.testing.expectEqualStrings("Oldest", summaries[2].title);
}

test "shared addUser and getUserByHandle" {
    const allocator = std.testing.allocator;
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    const pk = [_]u8{0xAA} ** 32;
    const id = try addUser(&db, "brad", "KE8WIF", pk, 1000, false, "");
    try std.testing.expect(id >= 1);

    var u = getUserByHandle(&db, allocator, "brad").?;
    defer u.deinit(allocator);
    try std.testing.expectEqualStrings("brad", u.handle);
    try std.testing.expectEqualSlices(u8, &pk, &u.public_key);
    try std.testing.expectEqual(@as(u64, 1000), u.registered_datetime);
    try std.testing.expectEqual(@as(usize, 0), u.avatar.len);
}

test "shared listAllUsers returns users sorted by id ascending" {
    const allocator = std.testing.allocator;
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    try std.testing.expectEqual(@as(usize, 0), countUsers(&db));

    const pk_a = [_]u8{0xAA} ** 32;
    const pk_b = [_]u8{0xBB} ** 32;
    const pk_c = [_]u8{0xCC} ** 32;
    _ = try addUser(&db, "brad", "KE8WIF", pk_a, 1000, true, "");
    _ = try addUser(&db, "nina", "N0CALL", pk_b, 2000, false, "");
    _ = try addUser(&db, "zoe", "W1ABC", pk_c, 3000, false, "");
    try std.testing.expectEqual(@as(usize, 3), countUsers(&db));

    const users = try listAllUsers(&db, allocator);
    defer freeUserList(allocator, users);
    try std.testing.expectEqual(@as(usize, 3), users.len);
    // Sorted by id ascending.
    try std.testing.expect(users[0].id < users[1].id);
    try std.testing.expect(users[1].id < users[2].id);
    // Fields round-trip.
    try std.testing.expectEqualStrings("brad", users[0].handle);
    try std.testing.expectEqualStrings("KE8WIF", users[0].callsign);
    try std.testing.expectEqual(true, users[0].is_sysop);
    try std.testing.expectEqual(@as(u64, 1000), users[0].registered_datetime);
    try std.testing.expectEqualSlices(u8, &pk_a, &users[0].public_key);
    try std.testing.expectEqualStrings("zoe", users[2].handle);
    try std.testing.expectEqual(false, users[2].is_sysop);
}

test "shared bulletin_responses add/get/count" {
    const allocator = std.testing.allocator;
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    // Empty — count is 0, next id is 0.
    try std.testing.expectEqual(@as(usize, 0), countBulletinResponses(&db, 1));
    try std.testing.expectEqual(@as(u16, 0), nextBulletinResponseId(&db, 1).?);

    // Add a response for bulletin 1 with id 0.
    try addBulletinResponseWithId(&db, 1, 0, 7, 1000, &.{ 0x01, 0x02 });
    try std.testing.expectEqual(@as(usize, 1), countBulletinResponses(&db, 1));
    try std.testing.expectEqual(@as(u16, 1), nextBulletinResponseId(&db, 1).?);

    // Add a response for bulletin 1 with id 1.
    try addBulletinResponseWithId(&db, 1, 1, 8, 2000, &.{ 0x03 });
    try std.testing.expectEqual(@as(usize, 2), countBulletinResponses(&db, 1));
    try std.testing.expectEqual(@as(u16, 2), nextBulletinResponseId(&db, 1).?);

    // A different bulletin has its own id space.
    try std.testing.expectEqual(@as(usize, 0), countBulletinResponses(&db, 2));
    try std.testing.expectEqual(@as(u16, 0), nextBulletinResponseId(&db, 2).?);

    // Get a specific response.
    var rec = getBulletinResponse(&db, allocator, 1, 0).?;
    defer rec.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), rec.bulletin_id);
    try std.testing.expectEqual(@as(u16, 0), rec.response_id);
    try std.testing.expectEqual(@as(u16, 7), rec.user_id);
    try std.testing.expectEqual(@as(u64, 1000), rec.create_datetime);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, rec.body);
}

test "shared bulletin_responses listAll/after/range" {
    const allocator = std.testing.allocator;
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    for (0..5) |i| {
        try addBulletinResponseWithId(&db, 1, @intCast(i), @intCast(i + 1), @intCast(i * 100), &.{@intCast(i)});
    }
    try std.testing.expectEqual(@as(usize, 5), countBulletinResponses(&db, 1));

    // listBulletinResponses returns all 5 in ascending id order.
    {
        const all = try listBulletinResponses(&db, allocator, 1);
        defer freeBulletinResponseList(allocator, all);
        try std.testing.expectEqual(@as(usize, 5), all.len);
        for (all, 0..) |r, i| {
            try std.testing.expectEqual(@as(u16, @intCast(i)), r.response_id);
        }
    }

    // listBulletinResponsesAfter(after_id=2) returns ids 3..4.
    {
        const after = try listBulletinResponsesAfter(&db, allocator, 1, 2);
        defer freeBulletinResponseList(allocator, after);
        try std.testing.expectEqual(@as(usize, 2), after.len);
        try std.testing.expectEqual(@as(u16, 3), after[0].response_id);
        try std.testing.expectEqual(@as(u16, 4), after[1].response_id);
    }

    // listBulletinResponsesRange(1, 3) returns ids 1..3.
    {
        const range = try listBulletinResponsesRange(&db, allocator, 1, 1, 3);
        defer freeBulletinResponseList(allocator, range);
        try std.testing.expectEqual(@as(usize, 3), range.len);
        try std.testing.expectEqual(@as(u16, 1), range[0].response_id);
        try std.testing.expectEqual(@as(u16, 3), range[2].response_id);
    }
}

test "shared nextBulletinResponseId returns null when full" {
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    // Fill the bulletin with the maximum number of responses (0..1023).
    for (0..@as(u32, max_response_id + 1)) |i| {
        try addBulletinResponseWithId(&db, 5, @intCast(i), 1, 0, &.{});
    }
    try std.testing.expectEqual(@as(usize, max_response_id + 1), countBulletinResponses(&db, 5));
    // Next id should be null — no room for another response.
    try std.testing.expect(nextBulletinResponseId(&db, 5) == null);
}

test "shared addBulletinResponseWithId replaces on duplicate id" {
    const allocator = std.testing.allocator;
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    // Insert, then insert a different body at the same (bulletin_id, response_id).
    try addBulletinResponseWithId(&db, 1, 0, 7, 100, &.{ 0xAA });
    try addBulletinResponseWithId(&db, 1, 0, 9, 200, &.{ 0xBB });
    try std.testing.expectEqual(@as(usize, 1), countBulletinResponses(&db, 1));
    var rec = getBulletinResponse(&db, allocator, 1, 0).?;
    defer rec.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 9), rec.user_id);
    try std.testing.expectEqual(@as(u64, 200), rec.create_datetime);
    try std.testing.expectEqualSlices(u8, &.{0xBB}, rec.body);
}

test "shared chat_messages add/count/listRecent" {
    const allocator = std.testing.allocator;
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    try std.testing.expectEqual(@as(usize, 0), countChatMessages(&db));

    // Insert three chat messages with increasing epoch times.
    try addChatMessage(&db, 1000, 1, "first");
    try addChatMessage(&db, 2000, 2, "second");
    try addChatMessage(&db, 3000, 3, "third");
    try std.testing.expectEqual(@as(usize, 3), countChatMessages(&db));

    // listRecent returns newest first.
    {
        const recent = try listRecentChatMessages(&db, allocator, 2);
        defer freeChatRecordList(allocator, recent);
        try std.testing.expectEqual(@as(usize, 2), recent.len);
        try std.testing.expectEqual(@as(u64, 3000), recent[0].epoch_time);
        try std.testing.expectEqual(@as(u16, 3), recent[0].user_id);
        try std.testing.expectEqualStrings("third", recent[0].text);
        try std.testing.expectEqual(@as(u64, 2000), recent[1].epoch_time);
        try std.testing.expectEqualStrings("second", recent[1].text);
    }

    // Asking for more than available returns all of them.
    {
        const recent = try listRecentChatMessages(&db, allocator, 20);
        defer freeChatRecordList(allocator, recent);
        try std.testing.expectEqual(@as(usize, 3), recent.len);
        try std.testing.expectEqual(@as(u64, 3000), recent[0].epoch_time);
        try std.testing.expectEqual(@as(u64, 1000), recent[2].epoch_time);
    }
}

test "shared chat_messages addChatMessage replaces on duplicate epoch_time" {
    const allocator = std.testing.allocator;
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();
    @import("schema.zig").createSchema(&db);

    // The epoch time is the primary key; re-inserting at the same time
    // replaces the row (used by the server when it re-stamps a chat at the
    // same second — collisions are extremely unlikely but handled).
    try addChatMessage(&db, 1000, 1, "original");
    try addChatMessage(&db, 1000, 2, "replaced");
    try std.testing.expectEqual(@as(usize, 1), countChatMessages(&db));

    const recent = try listRecentChatMessages(&db, allocator, 1);
    defer freeChatRecordList(allocator, recent);
    try std.testing.expectEqual(@as(usize, 1), recent.len);
    try std.testing.expectEqual(@as(u16, 2), recent[0].user_id);
    try std.testing.expectEqualStrings("replaced", recent[0].text);
}
