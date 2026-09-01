//! Interactive TUI for the AGWPE TNC sender/monitor, built on ZigZag.
//!
//! This file is the public entry point for the `tui` module. The actual
//! implementation lives in the `tui/` directory:
//!   - `types.zig` — shared types, constants, and helpers
//!   - `cli.zig` — `TuiOverrides` (CLI flag pre-fill values)
//!   - `render.zig` — shared style presets, styled status indicators, the
//!     key-fingerprint formatters, and the `fillTerminal` / `countLines`
//!     layout helpers
//!   - `widgets/button.zig` — simple `zz.Form`-compatible button widget
//!   - `model.zig` — central `Model` struct (init/update/deinit) and `run()`
//!   - `app.zig` — `AppContext` (shared application state and lifecycle)
//!   - `outbox.zig`, `incoming.zig`, `inbox.zig`, `logs.zig` — send/receive/log
//!     logic extracted from `app.zig` (the inbox owns receive mechanics, the
//!     outbox owns send mechanics — the two data-flow abstractions for the
//!     whole client)
//!   - `screens/` — one file per screen (landing, chat, bulletins, settings, …)
//!
//! Callers should `@import("tui.zig")` and use `tui.run(...)` / `tui.TuiOverrides`.

const model = @import("tui/model.zig");

pub const Model = model.Model;
pub const TuiOverrides = @import("tui/cli.zig").TuiOverrides;
pub const run = model.run;
