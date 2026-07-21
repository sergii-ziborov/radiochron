//! Wi-Fi diagnostics: native collectors and 802.11 beacon analysis.
//!
//! This is the library. It has no notion of MCP, of JSON-RPC, or of any
//! transport — that lives in the `radiochron-mcp` crate, which depends on this
//! one. An IoT agent, a CLI, a metrics exporter or a fleet-management service
//! wants this crate and nothing else.
//!
//! # Design
//!
//! Collectors reach the operating system through hand-written FFI with the DLL
//! resolved at run time, rather than through a binding crate. On Windows that
//! means `wlanapi.dll` and `wevtapi.dll` directly: no PowerShell, no runtime C#
//! compilation, no import library, and no build toolchain beyond a stock
//! `rustup`.
//!
//! Analysis is deliberately separated from collection. [`wlan::analyze`],
//! [`events::detect`], [`wlan::bss::parse_information_elements`] and [`time`]
//! are pure functions over data — they never touch the operating system, which
//! is what makes them testable without a radio and portable to targets whose
//! collectors do not exist yet.
//!
//! # Platform support
//!
//! | | Windows | Linux | macOS |
//! |---|---|---|---|
//! | interface + association | yes | planned (nl80211) | planned (CoreWLAN) |
//! | BSS list with raw IEs | yes | planned | limited by the public API |
//! | connection history | yes | no equivalent | no equivalent |
//!
//! Connection history depends on the WLAN AutoConfig event log, which has no
//! counterpart on Linux or macOS. Callers must treat it as an optional
//! capability rather than assuming it exists.

//! # Selecting capabilities
//!
//! Features are granular so an embedded target compiles only what it calls:
//!
//! ```toml
//! radiochron = { version = "0.2", default-features = false, features = ["status"] }
//! ```
//!
//! `status` (association state) · `scan` (BSS list + IE parsing) · `analyze`
//! (findings) · `sample` (dynamics over a window) · `history` (reading the OS
//! event log) · `record` (writing our own — the [`chronicle`]).
//!
//! Reading history and writing it are deliberately separate features: `history`
//! reads what Windows already recorded, while `record` keeps a chronicle of our
//! own through a pluggable [`chronicle::Sink`] — which is what history will
//! mean on platforms whose OS keeps no log. The chronicle's types, sink and
//! change detector are OS-free; only the recorder loop touches a collector.

pub mod time;

#[cfg(feature = "record")]
pub mod chronicle;

#[cfg(all(windows, any(feature = "status", feature = "history")))]
mod dll;

#[cfg(all(windows, feature = "history"))]
pub mod events;

#[cfg(all(windows, feature = "status"))]
pub mod wlan;
