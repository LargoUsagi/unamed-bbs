//! Ed25519 signing and verification for KISS TNC messages.
//!
//! Provides key generation, signing of the compressed message body, and
//! signature verification on the receiving side. Keys can be persisted as
//! raw byte files (secret key: 64 bytes, public key: 32 bytes).
//!
//! A key derivation function (HKDF-SHA256) is provided to deterministically
//! derive an Ed25519 key pair from a simple string passphrase — useful for CLI
//! usage without managing key files.
//!
//! The signature is over the compressed payload only — the callsign is
//! implicitly authenticated through the sender's public key, which is looked
//! up by callsign on the receiving side (key distribution is out of scope).

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// 64-byte Ed25519 signature (matches `MessageFrame.signature_len`).
pub const signature_len: usize = Ed25519.Signature.encoded_length;

/// 32-byte Ed25519 public key.
pub const public_key_len: usize = Ed25519.PublicKey.encoded_length;

/// 64-byte Ed25519 secret key (seed + public key).
pub const secret_key_len: usize = Ed25519.SecretKey.encoded_length;

/// 32-byte seed for deterministic key generation.
pub const seed_len: usize = Ed25519.KeyPair.seed_length;

/// A key pair for signing messages.
pub const KeyPair = struct {
    kp: Ed25519.KeyPair,

    /// Generate a new random key pair.
    pub fn generate(io: std.Io) KeyPair {
        return .{ .kp = Ed25519.KeyPair.generate(io) };
    }

    /// Deterministically derive a key pair from a 32-byte seed.
    pub fn fromSeed(seed: [seed_len]u8) !KeyPair {
        return .{ .kp = try Ed25519.KeyPair.generateDeterministic(seed) };
    }

    /// Derive an Ed25519 key pair from a simple string passphrase using
    /// HKDF-SHA256 as the key derivation function.
    ///
    /// The passphrase is HKDF-extracted with a fixed salt, then HKDF-expanded
    /// to 32 bytes to produce the Ed25519 seed. The same passphrase always
    /// yields the same key pair, so two operators who share a passphrase can
    /// sign and verify without exchanging key files.
    pub fn fromPassphrase(passphrase: []const u8) !KeyPair {
        // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM=passphrase)
        const salt = "kiss-tnc-ed25519-v1";
        const prk = HkdfSha256.extract(salt, passphrase);
        // HKDF-Expand: derive 32 bytes for the Ed25519 seed
        var seed: [seed_len]u8 = undefined;
        HkdfSha256.expand(&seed, "ed25519-key", prk);
        return try fromSeed(seed);
    }

    /// Derive an Ed25519 key pair from a handle and password using
    /// HKDF-SHA256, with the handle as the salt. This ensures the passphrase
    /// is salted by the handle so two users with the same password but
    /// different handles get different keys.
    pub fn fromHandleAndPassword(handle: []const u8, password: []const u8) !KeyPair {
        const prk = HkdfSha256.extract(handle, password);
        var seed: [seed_len]u8 = undefined;
        HkdfSha256.expand(&seed, "ed25519-key", prk);
        return try fromSeed(seed);
    }

    /// Reconstruct a key pair from a stored secret key (64 bytes).
    pub fn fromSecretKeyBytes(secret_bytes: [secret_key_len]u8) !KeyPair {
        const sk = try Ed25519.SecretKey.fromBytes(secret_bytes);
        return .{ .kp = try Ed25519.KeyPair.fromSecretKey(sk) };
    }

    /// Return the secret key as raw bytes (seed + public key, 64 bytes).
    pub fn secretKeyBytes(self: KeyPair) [secret_key_len]u8 {
        return self.kp.secret_key.toBytes();
    }

    /// Return the public key as raw bytes (32 bytes).
    pub fn publicKeyBytes(self: KeyPair) [public_key_len]u8 {
        return self.kp.public_key.toBytes();
    }

    /// Sign a message (the compressed payload). Returns the 64-byte signature.
    /// Uses deterministic signing (no random noise) so the same input always
    /// produces the same signature.
    pub fn sign(self: KeyPair, msg: []const u8) ![signature_len]u8 {
        const sig = try self.kp.sign(msg, null);
        return sig.toBytes();
    }
};

/// Verify a signature against a message and public key.
/// Returns `true` if the signature is valid.
pub fn verify(
    signature: [signature_len]u8,
    msg: []const u8,
    public_key_bytes: [public_key_len]u8,
) bool {
    const pk = Ed25519.PublicKey.fromBytes(public_key_bytes) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);
    sig.verify(msg, pk) catch return false;
    return true;
}

/// Load a secret key from a file (64 raw bytes).
pub fn loadSecretKey(io: std.Io, path: []const u8) !KeyPair {
    var dir = std.Io.Dir.cwd(io);
    const file = try dir.openFile(path, .{});
    defer file.close(io);
    var buf: [secret_key_len]u8 = undefined;
    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(&read_buf);
    try reader.interface.readSliceAll(&buf);
    return try KeyPair.fromSecretKeyBytes(buf);
}

/// Save a secret key to a file as 64 raw bytes.
pub fn saveSecretKey(io: std.Io, path: []const u8, kp: KeyPair) !void {
    var dir = std.Io.Dir.cwd(io);
    const file = try dir.createFile(path, .{});
    defer file.close(io);
    var write_buf: [128]u8 = undefined;
    var writer = file.writer(&write_buf);
    try writer.interface.writeAll(&kp.secretKeyBytes());
    try writer.interface.flush();
}

test "sign and verify round trip" {
    const kp = try KeyPair.fromSeed([_]u8{0x42} ** seed_len);
    const msg = "Hello from the ham radio TNC!";
    const sig = try kp.sign(msg);
    try std.testing.expect(verify(sig, msg, kp.publicKeyBytes()));
}

test "verify rejects wrong message" {
    const kp = try KeyPair.fromSeed([_]u8{0x42} ** seed_len);
    const sig = try kp.sign("original message");
    try std.testing.expect(!verify(sig, "tampered message", kp.publicKeyBytes()));
}

test "verify rejects wrong public key" {
    const kp1 = try KeyPair.fromSeed([_]u8{0x42} ** seed_len);
    const kp2 = try KeyPair.fromSeed([_]u8{0x99} ** seed_len);
    const sig = try kp1.sign("message");
    try std.testing.expect(!verify(sig, "message", kp2.publicKeyBytes()));
}

test "verify rejects garbage signature" {
    const kp = try KeyPair.fromSeed([_]u8{0x42} ** seed_len);
    const bad_sig = [_]u8{0xFF} ** signature_len;
    try std.testing.expect(!verify(bad_sig, "message", kp.publicKeyBytes()));
}

test "fromSeed is deterministic" {
    const seed = [_]u8{0xAB} ** seed_len;
    const kp1 = try KeyPair.fromSeed(seed);
    const kp2 = try KeyPair.fromSeed(seed);
    try std.testing.expectEqualSlices(u8, &kp1.publicKeyBytes(), &kp2.publicKeyBytes());
    try std.testing.expectEqualSlices(u8, &kp1.secretKeyBytes(), &kp2.secretKeyBytes());
}

test "fromPassphrase is deterministic" {
    const kp1 = try KeyPair.fromPassphrase("my secret passphrase");
    const kp2 = try KeyPair.fromPassphrase("my secret passphrase");
    try std.testing.expectEqualSlices(u8, &kp1.publicKeyBytes(), &kp2.publicKeyBytes());
    try std.testing.expectEqualSlices(u8, &kp1.secretKeyBytes(), &kp2.secretKeyBytes());
}

test "fromPassphrase produces different keys for different passphrases" {
    const kp1 = try KeyPair.fromPassphrase("passphrase one");
    const kp2 = try KeyPair.fromPassphrase("passphrase two");
    try std.testing.expect(!std.mem.eql(u8, &kp1.publicKeyBytes(), &kp2.publicKeyBytes()));
}

test "fromPassphrase sign and verify round trip" {
    const kp = try KeyPair.fromPassphrase("ham radio key");
    const msg = "QTH: EM12aj";
    const sig = try kp.sign(msg);
    try std.testing.expect(verify(sig, msg, kp.publicKeyBytes()));
    try std.testing.expect(!verify(sig, "tampered", kp.publicKeyBytes()));
}

test "fromPassphrase produces usable key (not all-zero)" {
    const kp = try KeyPair.fromPassphrase("test");
    const pk = kp.publicKeyBytes();
    var has_nonzero = false;
    for (pk) |b| {
        if (b != 0) {
            has_nonzero = true;
            break;
        }
    }
    try std.testing.expect(has_nonzero);
}

test "fromHandleAndPassword is deterministic" {
    const kp1 = try KeyPair.fromHandleAndPassword("brad", "secret123");
    const kp2 = try KeyPair.fromHandleAndPassword("brad", "secret123");
    try std.testing.expectEqualSlices(u8, &kp1.publicKeyBytes(), &kp2.publicKeyBytes());
    try std.testing.expectEqualSlices(u8, &kp1.secretKeyBytes(), &kp2.secretKeyBytes());
}

test "fromHandleAndPassword differs for different handles" {
    const kp1 = try KeyPair.fromHandleAndPassword("brad", "secret123");
    const kp2 = try KeyPair.fromHandleAndPassword("alice", "secret123");
    try std.testing.expect(!std.mem.eql(u8, &kp1.publicKeyBytes(), &kp2.publicKeyBytes()));
}

test "fromHandleAndPassword differs for different passwords" {
    const kp1 = try KeyPair.fromHandleAndPassword("brad", "secret123");
    const kp2 = try KeyPair.fromHandleAndPassword("brad", "different");
    try std.testing.expect(!std.mem.eql(u8, &kp1.publicKeyBytes(), &kp2.publicKeyBytes()));
}

test "fromHandleAndPassword differs from fromPassphrase" {
    const kp1 = try KeyPair.fromHandleAndPassword("brad", "secret123");
    const kp2 = try KeyPair.fromPassphrase("secret123");
    try std.testing.expect(!std.mem.eql(u8, &kp1.publicKeyBytes(), &kp2.publicKeyBytes()));
}
