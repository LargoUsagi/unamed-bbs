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

