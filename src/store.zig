//! Shared store module — the replicated schema, record types, and query
//! helpers used by both the server and client stores.
//!
//! This file is the public entry point for the `bbs.store` module. It
//! re-exports the three sub-modules under `src/store/`:
//!   * `records.zig`  — the memory-owning record structs (`User`,
//!     `BulletinRecord`, `BulletinResponseRecord`, `ChatRecord`,
//!     `BulletinSummary`) that mirror the replicated tables.
//!   * `schema.zig`   — `createSchema` and the `migrate*` helpers that
//!     create/upgrade the replicated tables on both sides.
//!   * `queries.zig`  — the shared query helpers (`addBulletin`, `getUserById`,
//!     `listAllBulletins`, …) that the server and client stores wrap.
//!
//! The record types here are the **application data model** — the canonical,
//! memory-owning form persisted in SQLite. They are distinct from the
//! wire-payload structs in `message_frame/` (e.g. `message_frame.Bulletin`),
//! which are transient, decoded payloads. The outbox converts between the two
//! at the transport boundary.

pub const records = @import("store/records.zig");
pub const schema = @import("store/schema.zig");
pub const queries = @import("store/queries.zig");

// Record types (re-exported for `bbs.store.User`, etc.).
pub const User = records.User;
pub const ChatRecord = records.ChatRecord;
pub const BulletinRecord = records.BulletinRecord;
pub const BulletinResponseRecord = records.BulletinResponseRecord;
pub const BulletinSummary = records.BulletinSummary;
pub const max_response_id = records.max_response_id;

// Schema helpers.
pub const createSchema = schema.createSchema;
pub const createBulletinsTable = schema.createBulletinsTable;
pub const createUsersTable = schema.createUsersTable;
pub const createBulletinResponsesTable = schema.createBulletinResponsesTable;
pub const createChatMessagesTable = schema.createChatMessagesTable;
pub const migrateSchema = schema.migrateSchema;
pub const migrateBulletinsSchema = schema.migrateBulletinsSchema;
pub const migrateUsersSchema = schema.migrateUsersSchema;
pub const migrateBulletinResponsesSchema = schema.migrateBulletinResponsesSchema;

// Query helpers.
pub const addBulletinWithId = queries.addBulletinWithId;
pub const addBulletin = queries.addBulletin;
pub const countBulletins = queries.countBulletins;
pub const getBulletinById = queries.getBulletinById;
pub const listBulletinsAfter = queries.listBulletinsAfter;
pub const listBulletinsRange = queries.listBulletinsRange;
pub const freeBulletinRecordList = queries.freeBulletinRecordList;
pub const listBulletinPage = queries.listBulletinPage;
pub const listAllBulletins = queries.listAllBulletins;
pub const freeBulletinSummaryList = queries.freeBulletinSummaryList;
pub const totalBulletinPages = queries.totalBulletinPages;
pub const addBulletinResponseWithId = queries.addBulletinResponseWithId;
pub const countBulletinResponses = queries.countBulletinResponses;
pub const nextBulletinResponseId = queries.nextBulletinResponseId;
pub const getBulletinResponse = queries.getBulletinResponse;
pub const listBulletinResponses = queries.listBulletinResponses;
pub const listBulletinResponsesAfter = queries.listBulletinResponsesAfter;
pub const listBulletinResponsesRange = queries.listBulletinResponsesRange;
pub const freeBulletinResponseList = queries.freeBulletinResponseList;
pub const addChatMessage = queries.addChatMessage;
pub const countChatMessages = queries.countChatMessages;
pub const listRecentChatMessages = queries.listRecentChatMessages;
pub const freeChatRecordList = queries.freeChatRecordList;
pub const addUser = queries.addUser;
pub const updateUser = queries.updateUser;
pub const upsertUserWithId = queries.upsertUserWithId;
pub const updateUserAvatar = queries.updateUserAvatar;
pub const getUserByHandle = queries.getUserByHandle;
pub const getUserByCallsign = queries.getUserByCallsign;
pub const getUserById = queries.getUserById;
pub const countUsers = queries.countUsers;
pub const listAllUsers = queries.listAllUsers;
pub const freeUserList = queries.freeUserList;

test {
    _ = @import("store/records.zig");
    _ = @import("store/schema.zig");
    _ = @import("store/queries.zig");
}
