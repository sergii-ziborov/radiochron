#![cfg_attr(not(feature = "std"), no_std)]

//! Wi-Fi diagnostics: native collectors and 802.11 beacon analysis.
//!
//! This is the library. It has no notion of MCP, of JSON-RPC, or of any
//! transport — that lives in the `radiochron-mcp` crate, which depends on this
//! one. An IoT agent, a CLI, a metrics exporter or a fleet-management service
//! wants this crate and nothing else.
//!
//! # Design
//!
//! Collectors reach the operating system through hand-written native APIs. On
//! Windows that means dynamically resolved `wlanapi.dll` and `wevtapi.dll`; on
//! Linux it means Generic Netlink/nl80211; on macOS it means CoreWLAN. None of
//! the backends shells out or needs a C build step beyond stock `rustup`.
//!
//! Analysis is deliberately separated from collection. With
//! `default-features = false, features = ["embedded"]`, the crate is
//! `no_std + alloc`: firmware supplies association/scan observations through
//! [`embedded::Collector`], while RadioChron supplies the data model, 802.11 IE
//! parser, findings engine and an injected-clock/injected-sink chronicle with
//! heartbeat metrics. Hosted collectors, files, clocks and sockets do not enter
//! that build.
//!
//! # Platform support
//!
//! | | Windows | Linux | macOS | bare-metal MCU |
//! |---|---|---|---|---|
//! | interface + association | native | nl80211 | CoreWLAN | firmware adapter |
//! | BSS list with raw IEs | native | nl80211 | CoreWLAN | firmware adapter |
//! | analysis | yes | yes | yes | yes (`no_std + alloc`) |
//! | connection history | yes | no equivalent | no equivalent | caller-owned |
//!
//! Connection history depends on the WLAN AutoConfig event log, which has no
//! counterpart on Linux or macOS. Callers must treat it as an optional
//! capability rather than assuming it exists.

//! # Selecting capabilities
//!
//! Hosted target:
//!
//! ```toml
//! radiochron = { version = "0.3", default-features = false, features = ["status"] }
//! ```
//!
//! Bare-metal target with a global allocator:
//!
//! ```toml
//! radiochron = { version = "0.3", default-features = false, features = ["embedded"] }
//! ```
//!
//! `std` (host runtime) · `embedded` (`no_std + alloc` firmware adapter, IE
//! parser, analysis, chronicle and metrics) · `status` (association state) · `scan` (BSS list + IE parsing) · `analyze`
//! (findings) · `sample` (dynamics over a window) · `history` (reading the OS
//! event log) · `record` (writing our own — the `chronicle`) · `connectivity`
//! (radio-to-Internet diagnosis with caller-supplied targets).
//!
//! Reading history and writing it are deliberately separate features: `history`
//! reads what Windows already recorded, while `record` keeps a chronicle of our
//! own through a pluggable `chronicle::Sink` — which is what history will
//! mean on platforms whose OS keeps no log. The chronicle's types, sink and
//! change detector and generic recorder are OS-free; only the selected
//! collector touches an operating-system API.

extern crate alloc;

#[cfg(any(feature = "record", feature = "embedded"))]
mod schema;

#[cfg(feature = "std")]
pub mod time;

#[cfg(feature = "embedded")]
pub mod embedded;

#[cfg(all(
    any(windows, target_os = "linux", target_os = "macos"),
    feature = "connectivity"
))]
pub mod connectivity;

#[cfg(all(feature = "std", feature = "record"))]
pub mod chronicle;

#[cfg(all(windows, any(feature = "status", feature = "history")))]
mod dll;

#[cfg(all(windows, feature = "history"))]
pub mod events;

#[cfg(any(feature = "status", feature = "embedded"))]
pub mod wlan;
