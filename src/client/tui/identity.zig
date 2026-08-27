//! Identity — signing key pair, trusted BBS key, user id, and known-key cache.
//!
//! Groups the crypto/identity fields that were previously scattered on
//! `AppContext`. The derivation (`deriveKeyFromHandleAndPassword`) and
//! known-key cache accessor (`storePublicKey`) live here so `app.zig` is free
//! of crypto plumbing.
//!
//! Functions take `*AppContext` (defined in `app.zig`) because they need the
//! persistent `store` (which remains on the root context) for persistence
//! and key-cache queries.

const std = @import("std");

const types = @import("types.zig");
const cli = @import("cli.zig");
const signing = types.signing;

const AppContext = @import("app.zig").AppContext;

/// Signing identity, trusted BBS key, and registration state.
/// Exposed as `ctx.identity`; screens read `ctx.identity.bbs_key` /
/// `ctx.identity.bbs_key_locked` for rendering and call
/// `identity.deriveKeyFromHandleAndPassword(ctx, ...)` from the register screen.
pub const Identity = struct {
    /// The Ed25519 signing key pair, or `null` when no key has been derived
    /// / restored yet. NEVER a randomly-generated placeholder — the client
    /// must not sign anything until the user has registered or logged in.
    /// Outbound sends (`outbox.prepareSend` and the direct transport callers)
    /// gate on this being non-null and surface a "register/login first" status
    /// so commands are blocked until a valid key exists.
    keypair: ?signing.KeyPair = null,
    key_has_passphrase: bool,
    /// True when the signing key was loaded from a file via `--key-file`
    /// (never derived from a passphrase). File-sourced keys are never copied
    /// into the SQLite store — the user manages the key file and is expected
    /// to pass `--key-file` again on the next launch.
    key_from_file: bool,
    bbs_key: ?[signing.public_key_len]u8,
    bbs_key_locked: bool,
    my_user_id: ?u16,
    /// True when the key was derived from a handle+password (not random or
    /// CLI-only passphrase). Used to decide whether to persist the secret key
    /// after a successful registration ack.
    key_from_ui: bool,
    /// True when the user checked "Remember credentials" on the register
    /// screen. Gates whether the secret key is persisted to SQLite.
    remember_credentials: bool,
    /// Pre-filled handle from CLI `--handle` flag.
    prefill_handle: ?[]const u8,
    /// Pre-filled password from CLI `--key` passphrase. Used to pre-fill the
    /// password + confirm fields on the Register/Login screen.
    prefill_password: ?[]const u8,
    /// True when `--handle` was passed on the CLI. The handle field in the
    /// register screen is read-only (immutable for the session).
    handle_locked: bool = false,
    /// True if the current user is a sysop (system operator). Set from
    /// registration_ack and user_info broadcasts.
    my_is_sysop: bool,
    /// True if the signing key is available and working on launch — either
    /// restored from the persisted secret key OR derived from the CLI
    /// `--key` passphrase. The user can sign/verify correctly without
    /// re-entering their password. False when the keypair was randomly
    /// generated (no stored secret key and no `--key`). Drives the landing
    /// routing: when `my_user_id` is set but this is false, the user must
    /// re-derive their key (Login) rather than go straight to Account.
    key_restored_from_store: bool,
    /// True when the CLI provided both `--handle` and `--key` but no stored
    /// `my_user_id` exists — the client should auto-register once connected
    /// (and the BBS key is known) without waiting for the user to open the
    /// Register screen and press submit. Cleared after the registration is
    /// sent (or on logout).
    auto_register: bool,
};

/// Initialise identity state from the persistent store and CLI overrides.
/// `ctx.store` must already be loaded before this is called.
pub fn init(ctx: *AppContext, overrides: cli.TuiOverrides) void {
    const id = &ctx.identity;
    const store = &ctx.store;

    // --- Restore client-private state from the store ---
    id.my_user_id = store.getMyUserId();
    id.my_is_sysop = false;
    if (id.my_user_id) |uid| {
        if (store.getUserById(uid)) |user| {
            var mut_user = user;
            id.my_is_sysop = mut_user.is_sysop;
            mut_user.deinit(store.allocator);
        }
    }

    // --- BBS key: hard-locked from CLI, or soft-trusted from the store ---
    if (overrides.bbs_key_hex) |hex| {
        if (types.parseHexKey(hex)) |key| {
            id.bbs_key = key;
            id.bbs_key_locked = true;
        } else {
            id.bbs_key = store.getBbsKey();
            id.bbs_key_locked = false;
        }
    } else {
        id.bbs_key = store.getBbsKey();
        id.bbs_key_locked = false;
    }

    // --- Key derivation ---
    // Never generate a random placeholder key. If no key can be derived
    // (no CLI passphrase, no stored secret key, or derivation failed) the
    // keypair stays `null` and outbound commands are blocked until the user
    // registers or logs in.
    id.key_from_ui = false;
    id.key_from_file = false;
    id.remember_credentials = false;
    id.prefill_handle = overrides.handle;
    id.prefill_password = overrides.key_passphrase;
    id.handle_locked = overrides.handle != null;
    if (overrides.key_file) |path| {
        // Bring-your-own key: load a PEM (PKCS#8), OpenSSH, or raw 64-byte
        // Ed25519 secret key from a file. This is an explicit user action, so
        // a load failure is surfaced rather than silently leaving the keypair
        // null (which would look like "no key configured"). File keys are
        // never persisted to the SQLite store (key_from_file stays true and
        // key_from_ui stays false, so handleRegistrationAck's persistence
        // guard excludes them).
        id.key_from_file = true;
        id.key_has_passphrase = false;
        id.key_restored_from_store = true;
        id.keypair = signing.loadSecretKey(ctx.io, path) catch |err| blk: {
            id.key_restored_from_store = false;
            const msg = switch (err) {
                error.EncryptedKeyNotSupported => std.fmt.allocPrint(
                    std.heap.page_allocator,
                    "Key file '{s}' is encrypted; only unencrypted keys are supported",
                    .{path},
                ) catch "Encrypted key file not supported",
                error.NotAnEd25519Key => std.fmt.allocPrint(
                    std.heap.page_allocator,
                    "Key file '{s}' does not contain an Ed25519 key",
                    .{path},
                ) catch "Key file is not an Ed25519 key",
                else => std.fmt.allocPrint(
                    std.heap.page_allocator,
                    "Failed to load key file '{s}': {s}",
                    .{ path, @errorName(err) },
                ) catch "Failed to load key file",
            };
            ctx.status = msg;
            ctx.startup_notice = msg;
            break :blk null;
        };
    } else if (overrides.key_passphrase) |passphrase| {
        // A CLI-derived key is working/available, so treat it as restored —
        // a returning user with a stored my_user_id auto-logs-in to Account.
        id.key_has_passphrase = true;
        id.key_restored_from_store = true;
        id.keypair = if (overrides.handle) |handle|
            signing.KeyPair.fromHandleAndPassword(handle, passphrase) catch blk: {
                id.key_has_passphrase = false;
                id.key_restored_from_store = false;
                break :blk null;
            }
        else
            signing.KeyPair.fromPassphrase(passphrase) catch blk: {
                id.key_has_passphrase = false;
                id.key_restored_from_store = false;
                break :blk null;
            };
    } else if (store.getSecretKey()) |sk_bytes| {
        id.key_has_passphrase = true;
        id.key_restored_from_store = true;
        id.keypair = signing.KeyPair.fromSecretKeyBytes(sk_bytes) catch blk: {
            id.key_has_passphrase = false;
            id.key_restored_from_store = false;
            break :blk null;
        };
    } else {
        id.key_has_passphrase = false;
        id.key_restored_from_store = false;
        id.keypair = null;
    }

    // --- Auto-register: CLI gave us a handle + key but no stored user id ---
    // The client will fire the registration automatically once connected (and
    // the BBS key is known), via AppContext.tick. The key may come from a
    // passphrase (`--key`) or a pre-generated key file (`--key-file`).
    id.auto_register = (overrides.handle != null and
        (overrides.key_passphrase != null or overrides.key_file != null) and
        id.my_user_id == null);
}

/// Reset identity to a fresh state (used by logout).
pub fn reset(ctx: *AppContext) void {
    const id = &ctx.identity;
    id.my_user_id = null;
    id.key_from_ui = false;
    id.key_from_file = false;
    id.remember_credentials = false;
    id.key_has_passphrase = false;
    id.key_restored_from_store = false;
    id.auto_register = false;
    id.keypair = null;
}

/// Derive the signing key from a handle and password (HKDF-SHA256 with the
/// handle as salt). Called by the register screen before sending the
/// registration. Returns `true` on success, `false` on failure.
pub fn deriveKeyFromHandleAndPassword(ctx: *AppContext, handle: []const u8, password: []const u8) bool {
    const kp = signing.KeyPair.fromHandleAndPassword(handle, password) catch return false;
    ctx.identity.keypair = kp;
    ctx.identity.key_has_passphrase = true;
    ctx.identity.key_from_ui = true;
    return true;
}

fn normalizeCallsign(callsign: []const u8) [types.transport.callsign_len + 1]u8 {
    var buf: [types.transport.callsign_len + 1]u8 = std.mem.zeroes([types.transport.callsign_len + 1]u8);
    const n = @min(callsign.len, types.transport.callsign_len);
    for (0..n) |i| buf[i] = std.ascii.toUpper(callsign[i]);
    buf[n] = 0;
    return buf;
}

pub fn storePublicKey(ctx: *AppContext, callsign: []const u8, public_key: [signing.public_key_len]u8) void {
    const cs = normalizeCallsign(callsign);
    const cs_slice = std.mem.sliceTo(&cs, 0);
    ctx.store.upsertKnownKey(cs_slice, public_key) catch {};
}
