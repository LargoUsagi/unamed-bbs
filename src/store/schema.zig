//! Shared store schema (the replicated tables) and migration helpers.
//!
//! Tables declared here (`bulletins`, `users`, `bulletin_responses`,
//! `chat_messages`) are **replicated tables**: their schema is identical on
//! both sides so that a seed bundle (a sqlite db copy of these tables)
//! produced by the server can be imported verbatim by a client, and
//! vice-versa. Server-private data (e.g. operator statuses, email addresses,
//! server-side config) and client-private data (e.g. cached known keys,
//! client config) live in separate, side-specific tables created by
//! `server/bulletin_store.zig` and `client/client_store.zig` respectively and
//! are never shared.
//!
//! Each bulletin has a server-assigned id, a u16 reference to a user row,
//! a creation timestamp (Unix epoch), a title, and a body. Both title and
//! body are stored as plain UTF-8 text (uncompressed) — they are compressed
//! only on the wire. Records are queried sorted by `created_at` ascending so
//! `listPage` returns bulletins in chronological order.
//!
//! Users are registered via the `registration` message type and stored in
//! the `users` table. The `users.id` (a u16) is what `bulletins.user_id`
//! references. Uniqueness is enforced on `handle` — re-registering the same
//! handle updates the callsign and public key and returns the existing id.

const std = @import("std");
const sqlite = @import("sqlite");

/// Create the `bulletins`, `users`, `bulletin_responses`, and `chat_messages`
/// tables (with their indexes) if they don't already exist. Both sides call
/// this so the schema is identical.
pub fn createSchema(db: *sqlite.Db) void {
    createBulletinsTable(db);
    createUsersTable(db);
    createBulletinResponsesTable(db);
    createChatMessagesTable(db);
}

/// `bulletins` table — shared/replicated schema.
pub fn createBulletinsTable(db: *sqlite.Db) void {
    db.exec(
        "CREATE TABLE IF NOT EXISTS bulletins (" ++
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " ++
            "user_id INTEGER, created_at INTEGER, title TEXT, body BLOB" ++
            ")",
        .{},
        .{},
    ) catch unreachable;
    db.exec(
        "CREATE INDEX IF NOT EXISTS idx_bulletins_created_at ON bulletins(created_at)",
        .{},
        .{},
    ) catch unreachable;
}

/// `users` table — shared/replicated schema.
pub fn createUsersTable(db: *sqlite.Db) void {
    db.exec(
        "CREATE TABLE IF NOT EXISTS users (" ++
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " ++
            "handle TEXT, callsign TEXT, public_key BLOB, " ++
            "registered_datetime INTEGER NOT NULL DEFAULT 0, " ++
            "is_sysop INTEGER NOT NULL DEFAULT 0, " ++
            "avatar TEXT NOT NULL DEFAULT ''" ++
            ")",
        .{},
        .{},
    ) catch unreachable;
    db.exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_handle ON users(handle)",
        .{},
        .{},
    ) catch unreachable;
}

/// `bulletin_responses` table — shared/replicated schema.
///
/// Each row is a reply to a bulletin. Uniqueness is enforced on
/// `(bulletin_id, response_id)` — the server assigns a sequential
/// `response_id` per bulletin, 0..1023. The body is stored as plain UTF-8
/// text in a BLOB column (compressed only on the wire).
/// `create_datetime` is the server-set epoch timestamp (authoritative).
pub fn createBulletinResponsesTable(db: *sqlite.Db) void {
    db.exec(
        "CREATE TABLE IF NOT EXISTS bulletin_responses (" ++
            "bulletin_id INTEGER NOT NULL, " ++
            "response_id INTEGER NOT NULL, " ++
            "user_id INTEGER NOT NULL, " ++
            "create_datetime INTEGER NOT NULL DEFAULT 0, " ++
            "body BLOB NOT NULL, " ++
            "PRIMARY KEY (bulletin_id, response_id)" ++
            ")",
        .{},
        .{},
    ) catch unreachable;
    db.exec(
        "CREATE INDEX IF NOT EXISTS idx_bulletin_responses_bulletin ON bulletin_responses(bulletin_id)",
        .{},
        .{},
    ) catch unreachable;
}

/// `chat_messages` table — shared/replicated schema.
///
/// Each row is a chat line routed through the BBS. The BBS uses
/// `epoch_time` (the Unix epoch seconds at which the server received the
/// message) as the **primary key**. `user_id` references the `users` table.
/// `text` is the plain (decompressed) chat body (the wire form compresses it
/// with Unishox2). Both the server and the client keep this table so a
/// received `chat` frame can be cached locally and the chat window can be
/// assembled and sorted by `epoch_time`.
pub fn createChatMessagesTable(db: *sqlite.Db) void {
    db.exec(
        "CREATE TABLE IF NOT EXISTS chat_messages (" ++
            "epoch_time INTEGER PRIMARY KEY, " ++
            "user_id INTEGER NOT NULL, " ++
            "text TEXT NOT NULL" ++
            ")",
        .{},
        .{},
    ) catch unreachable;
}

/// Migrate older schemas on both sides. Kept here so server and client
/// stores run the same migrations and stay schema-compatible.
pub fn migrateSchema(db: *sqlite.Db) void {
    migrateBulletinsSchema(db);
    migrateUsersSchema(db);
    migrateBulletinResponsesSchema(db);
    // The `chat_messages` table was added after the original schema. Create
    // it here so older databases pick it up on load.
    createChatMessagesTable(db);
}

/// Old `bulletins.author_id` was a 32-byte BLOB (raw public key) or used the
/// `author_id` column name — rebuild with the new `user_id` INTEGER shape.
pub fn migrateBulletinsSchema(db: *sqlite.Db) void {
    const Row = struct { sql: []const u8 };
    var stmt = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'bulletins'") catch return;
    defer stmt.deinit();
    const row = stmt.oneAlloc(Row, std.heap.page_allocator, .{}, .{}) catch return;
    const r = row orelse return;
    defer std.heap.page_allocator.free(r.sql);
    if (std.mem.indexOf(u8, r.sql, "author_id") != null) {
        db.exec("DROP TABLE bulletins", .{}, .{}) catch {};
        db.exec(
            "CREATE TABLE bulletins (" ++
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " ++
                "user_id INTEGER, created_at INTEGER, title TEXT, body BLOB" ++
                ")",
            .{},
            .{},
        ) catch {};
        db.exec(
            "CREATE INDEX IF NOT EXISTS idx_bulletins_created_at ON bulletins(created_at)",
            .{},
            .{},
        ) catch {};
    }
}

/// Drop the legacy `authors` table (renamed to `users`) if it exists, and
/// add the `is_sysop` and `avatar` columns to `users` if they're missing
/// (older schemas).
pub fn migrateUsersSchema(db: *sqlite.Db) void {
    db.exec("DROP TABLE IF EXISTS authors", .{}, .{}) catch {};
    // Add is_sysop column if it doesn't exist.
    const Row = struct { sql: []const u8 };
    var stmt = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'") catch return;
    defer stmt.deinit();
    const row = stmt.oneAlloc(Row, std.heap.page_allocator, .{}, .{}) catch return;
    const r = row orelse return;
    defer std.heap.page_allocator.free(r.sql);
    if (std.mem.indexOf(u8, r.sql, "is_sysop") == null) {
        db.exec("ALTER TABLE users ADD COLUMN is_sysop INTEGER NOT NULL DEFAULT 0", .{}, .{}) catch {};
    }
    if (std.mem.indexOf(u8, r.sql, "avatar") == null) {
        db.exec("ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''", .{}, .{}) catch {};
    }
}

/// Add `create_datetime` column to `bulletin_responses` if it doesn't exist
/// (older schemas lacked this column).
pub fn migrateBulletinResponsesSchema(db: *sqlite.Db) void {
    const Row = struct { sql: []const u8 };
    var stmt = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'bulletin_responses'") catch return;
    defer stmt.deinit();
    const row = stmt.oneAlloc(Row, std.heap.page_allocator, .{}, .{}) catch return;
    const r = row orelse return;
    defer std.heap.page_allocator.free(r.sql);
    if (std.mem.indexOf(u8, r.sql, "create_datetime") == null) {
        db.exec("ALTER TABLE bulletin_responses ADD COLUMN create_datetime INTEGER NOT NULL DEFAULT 0", .{}, .{}) catch {};
    }
}

test "shared schema createSchema is idempotent" {
    var db = sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{ .write = true, .create = true },
        .threading_mode = .MultiThread,
    }) catch unreachable;
    defer db.deinit();

    createSchema(&db);
    createSchema(&db);
    migrateSchema(&db);

    const queries = @import("queries.zig");
    try std.testing.expectEqual(@as(usize, 0), queries.countBulletins(&db));
}
