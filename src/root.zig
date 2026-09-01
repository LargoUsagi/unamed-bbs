//! Root of the `bbs` package.
//!
//! Re-exports the shared modules so that the server and client executables
//! (whose root source files live in subdirectories such as `src/server/`)
//! can import shared code through this module instead of reaching outside
//! their own module path with `../`.
//!
//! Layer map (dependencies point downward only):
//!   * `protocol` — wire-protocol contract constants & enums shared across
//!     the stack: `MessageType`, request mode/role enums, request outcome,
//!     `max_response_id`, and the uncompressed string-field size limits.
//!     Imports nothing from `store` or `transport`.
//!   * `store` — replicated SQLite schema, record types, and query helpers
//!     (`store/records.zig`, `store/schema.zig`, `store/queries.zig`)
//!   * `crypto/signing` — Ed25519 signing, key loading, key derivation
//!   * `util/avatar` — ASCII art avatar generation
//!   * `util/time` — wall-clock seconds helper (`nowSecs`)
//!   * `transport.message_frame` — typed application payloads + wire codec
//!     (depends on `transport/message_frame/unishox2.zig` for on-the-wire
//!     compression; re-exports the `protocol` constants via `limits.zig`)
//!   * `transport.frame` / `transport.incoming` — packetization wire format
//!   * `transport.transport` — link-agnostic `Transport` vtable + splitting
//!   * `transport.messaging` — sessions: sign, fan-out, reassembly
//!   * `transport.link.agwpe` / `transport.link.tcp` / `transport.link.meshcore`
//!     — concrete link implementations

const std = @import("std");
const Io = std.Io;

pub const protocol = @import("protocol.zig");
pub const agwpe = @import("transport/link/agwpe.zig");
pub const tcp = @import("transport/link/tcp.zig");
pub const meshcore = @import("transport/link/meshcore.zig");
pub const transport = @import("transport/transport.zig");
pub const connection = @import("transport/connection.zig");
pub const endpoint = @import("transport/endpoint.zig");
pub const reassembly = @import("transport/reassembly.zig");
pub const messaging = @import("transport/messaging.zig");
pub const signing = @import("crypto/signing.zig");
pub const store = @import("store.zig");
pub const avatar = @import("util/avatar.zig");
pub const time = @import("util/time.zig");

// Reference every shared submodule so `zig build test`'s `mod_tests`
// executable (rooted here) compiles and runs their `test {}` blocks.
// Without this block the shared-module test binary compiles 0 tests and
// every test in store.zig, signing.zig, unishox2.zig, avatar.zig,
// transport/*.zig, and message_frame/*.zig is silently skipped.
test {
    _ = @import("protocol.zig");
    _ = @import("transport/link/agwpe.zig");
    _ = @import("transport/link/tcp.zig");
    _ = @import("transport/link/meshcore.zig");
    _ = @import("transport/transport.zig");
    _ = @import("transport/frame.zig");
    _ = @import("transport/incoming.zig");
    _ = @import("transport/endpoint.zig");
    _ = @import("transport/reassembly.zig");
    _ = @import("transport/messaging.zig");
    _ = @import("crypto/signing.zig");
    _ = @import("transport/message_frame.zig");
    _ = @import("store.zig");
    _ = @import("util/avatar.zig");
    _ = @import("transport/message_frame/unishox2.zig");
}
