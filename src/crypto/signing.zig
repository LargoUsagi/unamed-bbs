//! Ed25519 signing and verification for KISS TNC messages.
//!
//! Provides key generation, signing of the compressed message body, and
//! signature verification on the receiving side. Secret keys can be loaded
//! from a file in three auto-detected formats: PEM PKCS#8 (as produced by
//! `openssl genpkey -algorithm Ed25519`), OpenSSH (as produced by
//! `ssh-keygen -t ed25519`), or raw 64-byte Ed25519 secret key (the native
//! format written by `saveSecretKey`). Public keys are 32 bytes.
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
const asn1 = std.crypto.codecs.asn1;
const der = asn1.der;
const base64 = std.base64;

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

/// DER OID content bytes for Ed25519 (1.3.101.112).
const ed25519_oid = [_]u8{ 0x2B, 0x65, 0x70 };

/// Load an Ed25519 secret key from a file. The format is auto-detected:
///
///   1. PEM PKCS#8 (`-----BEGIN PRIVATE KEY-----`), as produced by
///      `openssl genpkey -algorithm Ed25519`. Only unencrypted keys are
///      supported; `-----BEGIN ENCRYPTED PRIVATE KEY-----` is rejected with
///      `error.EncryptedKeyNotSupported`.
///   2. OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), as produced by
///      `ssh-keygen -t ed25519`. Only unencrypted (`none` cipher) keys are
///      supported; encrypted keys are rejected with `error.EncryptedKeyNotSupported`.
///   3. Raw 64-byte Ed25519 secret key (seed + public key) — the native
///      format written by `saveSecretKey`.
///
/// Returns `error.NotAnEd25519Key` when the file parses but does not contain
/// an Ed25519 key, and `error.InvalidPem` / `error.InvalidOpenSshKey` /
/// `error.InvalidKeyFile` for malformed or unrecognised payloads.
pub fn loadSecretKey(io: std.Io, path: []const u8) !KeyPair {
    var dir = std.Io.Dir.cwd();
    const data = try dir.readFileAlloc(io, path, std.heap.page_allocator, .limited(8192));
    defer std.heap.page_allocator.free(data);
    return try parseKeyFile(data);
}

/// Detect the key file format and dispatch to the right parser.
fn parseKeyFile(data: []const u8) !KeyPair {
    if (std.mem.startsWith(u8, data, "-----BEGIN PRIVATE KEY-----")) {
        return parsePemPkcs8(data);
    }
    if (std.mem.startsWith(u8, data, "-----BEGIN OPENSSH PRIVATE KEY-----")) {
        return parseOpenSsh(data);
    }
    if (std.mem.startsWith(u8, data, "-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
        return error.EncryptedKeyNotSupported;
    }
    if (std.mem.startsWith(u8, data, "-----BEGIN") and std.mem.indexOf(u8, data, "ENCRYPTED") != null) {
        return error.EncryptedKeyNotSupported;
    }
    if (data.len >= secret_key_len) {
        var sk: [secret_key_len]u8 = undefined;
        @memcpy(&sk, data[0..secret_key_len]);
        return KeyPair.fromSecretKeyBytes(sk) catch return error.InvalidKeyFile;
    }
    return error.InvalidKeyFile;
}

/// Extract the base64 body of a PEM-armored message: everything between the
/// `-----BEGIN...` header line and the `-----END...` footer line. Newlines
/// within the body are left in place and stripped by the decoder.
fn pemBody(data: []const u8) ![]const u8 {
    const first_nl = std.mem.indexOfScalar(u8, data, '\n') orelse return error.InvalidPem;
    const rest = data[first_nl + 1 ..];
    const end_idx = std.mem.indexOf(u8, rest, "-----END") orelse return error.InvalidPem;
    return rest[0..end_idx];
}

/// Base64-decode `body` (ignoring whitespace/newlines) into an exactly-sized
/// buffer. Caller frees with `std.heap.page_allocator`.
fn base64Decode(body: []const u8) ![]u8 {
    const compact = try std.heap.page_allocator.alloc(u8, body.len);
    defer std.heap.page_allocator.free(compact);
    var compact_len: usize = 0;
    for (body) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') continue;
        compact[compact_len] = c;
        compact_len += 1;
    }
    const dec = base64.standard.Decoder;
    const out_len = dec.calcSizeForSlice(compact[0..compact_len]) catch return error.InvalidPem;
    const buf = try std.heap.page_allocator.alloc(u8, out_len);
    dec.decode(buf, compact[0..compact_len]) catch {
        std.heap.page_allocator.free(buf);
        return error.InvalidPem;
    };
    return buf;
}

fn parsePemPkcs8(data: []const u8) !KeyPair {
    const body = try pemBody(data);
    const der_bytes = try base64Decode(body);
    defer std.heap.page_allocator.free(der_bytes);
    return parsePkcs8Der(der_bytes);
}

/// Parse a DER-encoded PKCS#8 PrivateKeyInfo and extract the Ed25519 seed.
fn parsePkcs8Der(der_bytes: []const u8) !KeyPair {
    var d = der.Decoder{ .bytes = der_bytes };
    _ = d.sequence() catch return error.InvalidPem;
    _ = d.element(asn1.ExpectedTag.primitive(.integer)) catch return error.InvalidPem; // version
    const alg_seq = d.sequence() catch return error.InvalidPem;
    const oid_ele = d.element(asn1.ExpectedTag.primitive(.oid)) catch return error.InvalidPem;
    if (!std.mem.eql(u8, d.view(oid_ele), &ed25519_oid)) return error.NotAnEd25519Key;
    d.index = alg_seq.slice.end; // skip optional algorithm params
    const pk_ele = d.element(asn1.ExpectedTag.primitive(.octetstring)) catch return error.InvalidPem;
    const pk_bytes = d.view(pk_ele);
    // The privateKey OCTET STRING wraps the CurvePrivateKey, which is itself
    // an OCTET STRING containing the 32-byte seed.
    var inner = der.Decoder{ .bytes = pk_bytes };
    const seed_ele = inner.element(asn1.ExpectedTag.primitive(.octetstring)) catch return error.InvalidPem;
    const seed_bytes = inner.view(seed_ele);
    if (seed_bytes.len != seed_len) return error.NotAnEd25519Key;
    var seed: [seed_len]u8 = undefined;
    @memcpy(&seed, seed_bytes);
    return KeyPair.fromSeed(seed) catch return error.InvalidPem;
}

fn parseOpenSsh(data: []const u8) !KeyPair {
    const body = try pemBody(data);
    const blob = try base64Decode(body);
    defer std.heap.page_allocator.free(blob);
    return parseOpenSshBlob(blob);
}

/// Parse the binary OpenSSH private key blob and extract the Ed25519
/// secret key (seed + public key, 64 bytes).
fn parseOpenSshBlob(blob: []const u8) !KeyPair {
    const magic = "openssh-key-v1\x00";
    if (blob.len < magic.len) return error.InvalidOpenSshKey;
    if (!std.mem.eql(u8, blob[0..magic.len], magic)) return error.InvalidOpenSshKey;
    var pos: usize = magic.len;
    const cipher = takeSshString(blob, &pos) catch return error.InvalidOpenSshKey;
    if (!std.mem.eql(u8, cipher, "none")) return error.EncryptedKeyNotSupported;
    const kdf = takeSshString(blob, &pos) catch return error.InvalidOpenSshKey;
    if (!std.mem.eql(u8, kdf, "none")) return error.EncryptedKeyNotSupported;
    _ = takeSshString(blob, &pos) catch return error.InvalidOpenSshKey; // kdf options
    const nkeys = takeU32(blob, &pos) catch return error.InvalidOpenSshKey;
    if (nkeys != 1) return error.InvalidOpenSshKey;
    _ = takeSshString(blob, &pos) catch return error.InvalidOpenSshKey; // public key blob
    const priv_section = takeSshString(blob, &pos) catch return error.InvalidOpenSshKey;
    var ppos: usize = 0;
    const c1 = takeU32(priv_section, &ppos) catch return error.InvalidOpenSshKey;
    const c2 = takeU32(priv_section, &ppos) catch return error.InvalidOpenSshKey;
    if (c1 != c2) return error.EncryptedKeyNotSupported; // checkint mismatch = encrypted/corrupt
    const ktype = takeSshString(priv_section, &ppos) catch return error.InvalidOpenSshKey;
    if (!std.mem.eql(u8, ktype, "ssh-ed25519")) return error.NotAnEd25519Key;
    _ = takeSshString(priv_section, &ppos) catch return error.InvalidOpenSshKey; // public key
    const priv = takeSshString(priv_section, &ppos) catch return error.InvalidOpenSshKey;
    if (priv.len != secret_key_len) return error.NotAnEd25519Key;
    var sk: [secret_key_len]u8 = undefined;
    @memcpy(&sk, priv);
    return KeyPair.fromSecretKeyBytes(sk) catch return error.InvalidOpenSshKey;
}

/// Read a 4-byte big-endian unsigned integer at `pos`, advancing `pos`.
fn takeU32(data: []const u8, pos: *usize) !u32 {
    if (pos.* + 4 > data.len) return error.EndOfStream;
    const v = std.mem.readInt(u32, data[pos.*..][0..4], .big);
    pos.* += 4;
    return v;
}

/// Read an SSH wire-format string (uint32 length + bytes) at `pos`.
fn takeSshString(data: []const u8, pos: *usize) ![]const u8 {
    const len = try takeU32(data, pos);
    if (pos.* + len > data.len) return error.EndOfStream;
    const s = data[pos.* .. pos.* + len];
    pos.* += len;
    return s;
}

/// Save a secret key to a file as 64 raw bytes (the native format). Use an
/// external tool (`openssl`, `ssh-keygen`) to produce PEM/OpenSSH key files.
pub fn saveSecretKey(io: std.Io, path: []const u8, kp: KeyPair) !void {
    var dir = std.Io.Dir.cwd();
    const file = try dir.createFile(io, path, .{});
    defer file.close(io);
    var write_buf: [128]u8 = undefined;
    var writer = file.writer(io, &write_buf);
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

test "saveSecretKey/loadSecretKey round trip" {
    const t = std.testing;
    const io = t.io;
    const path = "zig-test-key-roundtrip.bin";
    const kp = try KeyPair.fromSeed([_]u8{0x55} ** seed_len);
    try saveSecretKey(io, path, kp);
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
    const loaded = try loadSecretKey(io, path);
    try std.testing.expectEqualSlices(u8, &kp.publicKeyBytes(), &loaded.publicKeyBytes());
    try std.testing.expectEqualSlices(u8, &kp.secretKeyBytes(), &loaded.secretKeyBytes());
}

// --- PKCS#8 DER / PEM tests ---

/// Build a PKCS#8 DER PrivateKeyInfo for a given Ed25519 seed (48 bytes).
fn buildPkcs8Der(out: *[48]u8, seed: [seed_len]u8) void {
    const header = [_]u8{
        0x30, 0x2e, // SEQUENCE (46)
        0x02, 0x01, 0x00, // INTEGER (1) version = 0
        0x30, 0x05, // SEQUENCE (5) AlgorithmIdentifier
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING (34) privateKey
        0x04, 0x20, // OCTET STRING (32) CurvePrivateKey (seed)
    };
    @memcpy(out[0..16], &header);
    @memcpy(out[16..48], &seed);
}

test "parsePkcs8Der extracts Ed25519 seed" {
    const seed = [_]u8{0x55} ** seed_len;
    var der_bytes: [48]u8 = undefined;
    buildPkcs8Der(&der_bytes, seed);
    const kp = try parsePkcs8Der(&der_bytes);
    const expected = try KeyPair.fromSeed(seed);
    try std.testing.expectEqualSlices(u8, &expected.secretKeyBytes(), &kp.secretKeyBytes());
    try std.testing.expectEqualSlices(u8, &expected.publicKeyBytes(), &kp.publicKeyBytes());
}

test "parseKeyFile reads PEM PKCS#8" {
    const seed = [_]u8{0x55} ** seed_len;
    var der_bytes: [48]u8 = undefined;
    buildPkcs8Der(&der_bytes, seed);
    var b64_buf: [64]u8 = undefined;
    const b64 = base64.standard.Encoder.encode(&b64_buf, &der_bytes);
    const pem = try std.fmt.allocPrint(
        std.heap.page_allocator,
        "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----\n",
        .{b64},
    );
    defer std.heap.page_allocator.free(pem);
    const kp = try parseKeyFile(pem);
    const expected = try KeyPair.fromSeed(seed);
    try std.testing.expectEqualSlices(u8, &expected.secretKeyBytes(), &kp.secretKeyBytes());
}

test "parsePkcs8Der rejects a non-Ed25519 OID" {
    // Same structure but with the RSA OID (1.2.840.113549.1.1.1) swapped in.
    var der_bytes: [48]u8 = undefined;
    buildPkcs8Der(&der_bytes, [_]u8{0x55} ** seed_len);
    // Overwrite the OID content bytes (offsets 9..12) with a wrong value.
    der_bytes[9] = 0x2a;
    der_bytes[10] = 0x86;
    der_bytes[11] = 0x48;
    try std.testing.expectError(error.NotAnEd25519Key, parsePkcs8Der(&der_bytes));
}

test "parseKeyFile rejects encrypted PEM header" {
    const pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\n-----END ENCRYPTED PRIVATE KEY-----\n";
    try std.testing.expectError(error.EncryptedKeyNotSupported, parseKeyFile(pem));
}

// --- OpenSSH tests ---

/// Write a 4-byte big-endian uint32 into `buf` at `pos`, advancing `pos`.
fn sshPutU32(buf: []u8, pos: *usize, v: u32) void {
    std.mem.writeInt(u32, buf[pos.*..][0..4], v, .big);
    pos.* += 4;
}

/// Write an SSH wire-format string (uint32 length + bytes) at `pos`.
fn sshPutStr(buf: []u8, pos: *usize, s: []const u8) void {
    sshPutU32(buf, pos, @intCast(s.len));
    @memcpy(buf[pos.*..][0..s.len], s);
    pos.* += s.len;
}

/// Build an unencrypted OpenSSH Ed25519 private key blob (234 bytes) for `kp`.
fn buildOpenSshBlob(out: *[234]u8, kp: KeyPair) void {
    var pos: usize = 0;
    const magic = "openssh-key-v1\x00";
    @memcpy(out[pos..][0..magic.len], magic);
    pos += magic.len;
    sshPutStr(out, &pos, "none"); // cipher
    sshPutStr(out, &pos, "none"); // kdf
    sshPutU32(out, &pos, 0); // kdf options (empty)
    sshPutU32(out, &pos, 1); // number of keys
    // public key blob (content length 51)
    sshPutU32(out, &pos, 51);
    sshPutStr(out, &pos, "ssh-ed25519");
    sshPutU32(out, &pos, 32);
    @memcpy(out[pos..][0..32], &kp.publicKeyBytes());
    pos += 32;
    // private section (content length 136)
    sshPutU32(out, &pos, 136);
    sshPutU32(out, &pos, 0x12345678); // checkint 1
    sshPutU32(out, &pos, 0x12345678); // checkint 2
    sshPutStr(out, &pos, "ssh-ed25519");
    sshPutU32(out, &pos, 32);
    @memcpy(out[pos..][0..32], &kp.publicKeyBytes());
    pos += 32;
    sshPutU32(out, &pos, 64);
    @memcpy(out[pos..][0..64], &kp.secretKeyBytes());
    pos += 64;
    sshPutStr(out, &pos, "test"); // comment
    out[pos] = 0x01; // padding
    pos += 1;
    std.debug.assert(pos == 234);
}

test "parseOpenSshBlob extracts Ed25519 secret key" {
    const expected = try KeyPair.fromSeed([_]u8{0x55} ** seed_len);
    var blob: [234]u8 = undefined;
    buildOpenSshBlob(&blob, expected);
    const kp = try parseOpenSshBlob(&blob);
    try std.testing.expectEqualSlices(u8, &expected.secretKeyBytes(), &kp.secretKeyBytes());
    try std.testing.expectEqualSlices(u8, &expected.publicKeyBytes(), &kp.publicKeyBytes());
}

test "parseKeyFile reads OpenSSH format" {
    const expected = try KeyPair.fromSeed([_]u8{0x42} ** seed_len);
    var blob: [234]u8 = undefined;
    buildOpenSshBlob(&blob, expected);
    var b64_buf: [312]u8 = undefined;
    const b64 = base64.standard.Encoder.encode(&b64_buf, &blob);
    const openssh = try std.fmt.allocPrint(
        std.heap.page_allocator,
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{s}\n-----END OPENSSH PRIVATE KEY-----\n",
        .{b64},
    );
    defer std.heap.page_allocator.free(openssh);
    const kp = try parseKeyFile(openssh);
    try std.testing.expectEqualSlices(u8, &expected.secretKeyBytes(), &kp.secretKeyBytes());
}

test "parseOpenSshBlob rejects mismatched checkint (encrypted/corrupt)" {
    const expected = try KeyPair.fromSeed([_]u8{0x55} ** seed_len);
    var blob: [234]u8 = undefined;
    buildOpenSshBlob(&blob, expected);
    // Corrupt the second checkint (it lives right after the private-section
    // length prefix: offsets 99..102).
    blob[102] = 0x00;
    try std.testing.expectError(error.EncryptedKeyNotSupported, parseOpenSshBlob(&blob));
}

// --- raw 64-byte fallback test ---

test "parseKeyFile reads raw 64-byte secret key" {
    const expected = try KeyPair.fromSeed([_]u8{0x42} ** seed_len);
    const sk = expected.secretKeyBytes();
    const kp = try parseKeyFile(&sk);
    try std.testing.expectEqualSlices(u8, &sk, &kp.secretKeyBytes());
}

test "parseKeyFile rejects too-short non-PEM input" {
    try std.testing.expectError(error.InvalidKeyFile, parseKeyFile("not a key file at all"));
}
