//! Root of the `bbs` package.
//!
//! Re-exports the shared modules so that the server and client executables
//! (whose root source files live in subdirectories such as `src/server/`)
//! can import shared code through this module instead of reaching outside
//! their own module path with `../`.
//!
//! The AGWPE link layer, transport abstraction, and multipart reassembly
//! live under `src/transport/` and are re-exported below.

const std = @import("std");
const Io = std.Io;

pub const agwpe = @import("transport/agwpe.zig");
pub const tcp = @import("transport/tcp.zig");
pub const transport = @import("transport/transport.zig");
pub const endpoint = @import("transport/endpoint.zig");
pub const reassembly = @import("transport/reassembly.zig");
pub const signing = @import("signing.zig");
pub const message_frame = @import("message_frame.zig");
pub const store = @import("store.zig");
pub const unishox2 = @import("unishox2.zig");
pub const avatar = @import("avatar.zig");

// Reference every shared submodule so `zig build test`'s `mod_tests`
// executable (rooted here) compiles and runs their `test {}` blocks.
// Without this block the shared-module test binary compiles 0 tests and
// every test in store.zig, signing.zig, unishox2.zig, avatar.zig,
// transport/*.zig, and message_frame/*.zig is silently skipped.
test {
    _ = @import("transport/agwpe.zig");
    _ = @import("transport/tcp.zig");
    _ = @import("transport/transport.zig");
    _ = @import("transport/endpoint.zig");
    _ = @import("transport/reassembly.zig");
    _ = @import("signing.zig");
    _ = @import("message_frame.zig");
    _ = @import("store.zig");
    _ = @import("unishox2.zig");
    _ = @import("avatar.zig");
}

