//! BeaconTrail — pure-Rust Windows Wi-Fi collectors.
//!
//! This library holds the data-collection engine. It deliberately reaches the
//! native Windows WLAN / Event Log / IP stack through typed FFI (`windows-rs`)
//! rather than by spawning `netsh` / PowerShell or compiling embedded C# at
//! runtime, which is how the original TypeScript/Electron implementation worked.
//!
//! Module status:
//! - [`wlan`] — WLAN interface state + current connection (step 1, implemented).
//!   Next: `WlanGetNetworkBssList` (BSS list + 802.11 IE parse), `wevtapi`
//!   event log, `GetAdaptersAddresses` IP config, `rusqlite` persistence.

#[cfg(windows)]
pub mod wlan;
