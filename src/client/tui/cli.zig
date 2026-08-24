//! Optional field pre-fill values passed from CLI flags into the TUI.
//!
//! A non-null optional is both the value to use AND the lock signal — when
//! a field is set from the CLI it is immutable for the session (the settings
//! screen shows it read-only). This eliminates the separate `*_configured`
//! booleans that the old multi-flag approach required.

const kiss = @import("bbs");
const endpoint = kiss.endpoint;

pub const TuiOverrides = struct {
    /// Parsed connect endpoint from `--connect <url>`. When non-null, the
    /// transport kind, host, port, and kport are locked for the session and
    /// the settings screen shows them read-only. When null, the client falls
    /// back to the saved `tc_connect_uri` in the SQLite store.
    connect: ?endpoint.TransportEndpoint = null,

    /// Startup notice shown once in a popup (e.g. duplicate `--connect`
    /// warning). Cleared after the user dismisses the popup.
    startup_notice: ?[]const u8 = null,

    /// Source callsign for AX.25 headers. Non-null = locked/immutable.
    callsign: ?[]const u8 = null,

    /// Handle for registration (salts the KDF with `--key`).
    /// Non-null = locked/immutable (register screen handle field is read-only).
    handle: ?[]const u8 = null,

    /// Derive Ed25519 signing key from passphrase (HKDF-SHA256).
    /// Mutually exclusive with `key_file`.
    key_passphrase: ?[]const u8 = null,

    /// Load a pre-generated Ed25519 secret key from a file instead of
    /// deriving one from a passphrase. Accepted formats (auto-detected):
    /// PEM PKCS#8 (`openssl genpkey`), OpenSSH (`ssh-keygen`), or raw 64
    /// bytes. Mutually exclusive with `key_passphrase`. Only unencrypted
    /// keys are supported. The secret is never copied into the SQLite store.
    key_file: ?[]const u8 = null,

    /// Hex-encoded Ed25519 public key (64 hex chars) of the BBS to trust.
    /// Hard-locks the server key; if omitted the client soft-trusts the
    /// public key advertised by any server.
    bbs_key_hex: ?[]const u8 = null,

    /// When true, the client store uses an in-memory SQLite database that is
    /// never persisted to disk. No `client_store.sqlite` file is read or
    /// written, and logout does not delete any file. Triggered by `--in-memory`.
    in_memory: bool = false,
};
