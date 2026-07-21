# radiochron

**[radiochron.com](https://radiochron.com)** · the chronicle of your radio.

A pure-Rust Wi-Fi diagnostics library: native WLAN collectors, 802.11 beacon
analysis, connection-history verdicts, and a change-only recorder. No
PowerShell, no `netsh` text scraping, no embedded C#, no `.NET` — and **no build
toolchain beyond a stock [`rustup`](https://rustup.rs)**.

This crate is the engine. It knows nothing about MCP, JSON-RPC, or any
transport — that lives in [`radiochron-mcp`](https://github.com/sergii-ziborov/radiochron-mcp),
which depends on this one. An IoT agent, a CLI, a metrics exporter or a
fleet-management service wants this crate and nothing else.

```toml
[dependencies]
radiochron = "0.2"
```

## Repository family

The IoT/core dependency stays deliberately independent from its delivery
surfaces:

| Repository | Purpose |
|---|---|
| [`radiochron`](https://github.com/sergii-ziborov/radiochron) | this portable Rust engine |
| [`radiochron-mcp`](https://github.com/sergii-ziborov/radiochron-mcp) | Windows MCP server built on the engine |
| [`radiochron-js`](https://github.com/sergii-ziborov/radiochron-js) | npm launcher that ships the prebuilt MCP binary |
| [`radiochron-site`](https://github.com/sergii-ziborov/radiochron-site) | source for [radiochron.com](https://radiochron.com) |

## Why no toolchain

Collectors reach the OS through hand-written FFI with the DLL resolved at run
time via `LoadLibraryExW` restricted to `System32`, rather than through a binding crate. The `windows`
crate would drag in `windows-link`/`raw-dylib`, which needs mingw's `dlltool`
on the GNU target or the multi-gigabyte Visual C++ build tools plus the Windows
SDK on MSVC. Instead, the eight `wlanapi.dll` and four `wevtapi.dll` entry
points are declared by hand with a handful of `#[repr(C)]` structs.

The result: **three direct dependencies** — `serde`, `serde_json`, `anyhow` —
for a 13-crate tree including everything transitive, and a build that needs
nothing but `rustup` (the self-sufficient GNU toolchain works with no Visual
Studio installed). On an embedded target that is the difference between adding
a dependency and rebuilding the image.

## Selecting capabilities

Features are granular so an embedded target compiles only what it calls. A
sensor that only needs association state and link strength takes `status` and
nothing else:

```toml
radiochron = { version = "0.2", default-features = false, features = ["status"] }
```

| Feature | Enables | Depends on |
|---|---|---|
| `status`  | Interface enumeration + current-connection attributes ([`wlan::wifi_status`]) | — |
| `scan`    | Nearby BSS list with raw 802.11 IE parsing ([`wlan::bss`]) | `status` |
| `analyze` | The findings engine ([`wlan::analyze`]) | `scan` |
| `sample`  | Connection dynamics sampled over a window ([`wlan::sample`]) | `status` |
| `history` | Reading the Windows WLAN AutoConfig event log ([`events`]) | — |
| `record`  | Writing our own change log — the [`chronicle`] | — |

`default = ["status", "scan", "analyze", "sample", "history", "record"]`.

Reading history and writing it are separate on purpose: `history` reads what
Windows already recorded; `record` keeps a chronicle of our own through a
pluggable [`chronicle::Sink`] — which is what "history" will mean on platforms
whose OS keeps no such log.

## Collect

```rust
use radiochron::wlan;

// Every WLAN interface and, for the associated one, SSID / BSSID / PHY / dBm.
for status in wlan::wifi_status()? {
    if let Some(c) = status.connection {
        println!("{:?} {} {} dBm (est)", c.ssid, c.phy_type, c.rssi_dbm_estimate);
    }
}

// Nearby APs. Wait for the driver's real completion notification, then retain
// per-interface errors alongside useful entries from other radios.
let refresh = wlan::bss::scan_and_wait(std::time::Duration::from_secs(12))?;
let collection = wlan::bss::bss_list_detailed()?;
# Ok::<(), anyhow::Error>(())
```

## Analyze — findings, not records

`analyze` returns conclusions, not raw evidence: co-channel contention,
crowded-channel association, weak signal, roam and band-steering candidates,
insecure security, hidden SSIDs and scan-quality problems. Every [`Finding`]
carries a caveat stating why it might be wrong — RSSI, for instance, is
reconstructed by most Windows drivers from a 0..100 quality scale, so a
reported −71 dBm may be anywhere in −69..−73.

```rust
use radiochron::wlan::{self, analyze};

let entries = wlan::bss::bss_list()?;
let status = wlan::wifi_status()?;
let connection = status.iter().find_map(|s| s.connection.as_ref());

let analysis = analyze::analyze(&entries, connection);
for finding in &analysis.findings {
    // finding.severity, finding.title, finding.caveat, ...
}
# Ok::<(), anyhow::Error>(())
```

`sample::sample_connection_on(interface_guid, duration_s, interval_ms)` answers
a different question — not "what is the state" but "is it stable": RSSI
min/max/mean and swing, rx-rate range, distinct BSSIDs and roam count over a
window. Collector errors are separate from genuine disconnected samples.

## History — why it dropped earlier

The `history` feature reads the WLAN AutoConfig event log directly through
`wevtapi` and returns a [`events::detect::Verdict`]: reconnect loops, an AP
repeatedly failing key exchange, a suspected credential mismatch.

```rust
use radiochron::events;

let recent = events::recent(200, Some(3600))?; // last hour, up to 200 events
let verdict = events::detect::detect(&recent);
# Ok::<(), anyhow::Error>(())
```

It reads `EvtRenderEventXml` — the raw, **locale-invariant** event XML with
structured `EventData` — not the fully-rendered localized `Message` string.
Every rule keys on numeric event codes, never on prose, so it behaves
identically on a German or Japanese Windows.

## Record — the chronicle

The `record` feature keeps a chronicle of change through a pluggable
[`chronicle::Sink`]. The shipped sink is append-only JSONL with built-in
rotation (zero new dependencies, greppable, and safer across power loss than a
database mid-transaction):

```rust
use radiochron::chronicle::{JsonlSink, Recorder, RecorderOptions, RotationPolicy};

let sink = JsonlSink::open("chronicle.jsonl", RotationPolicy::default())?;
let mut recorder = Recorder::new(sink, RecorderOptions::default());
recorder.run_for(std::time::Duration::from_secs(3600))?; // or own the loop via .step()
# Ok::<(), anyhow::Error>(())
```

The chronicle records **change, not polls**: a stable link produces one
`Associated` entry per interface and then silence, however long you record.
Collector errors never impersonate disconnects; event-log tailing uses
`EventRecordID` and records an explicit `HistoryGap` when a bounded poll loses
records. Its types, sink
([`chronicle::Sink`], [`chronicle::JsonlSink`], [`chronicle::VecSink`]) and
[`chronicle::ChangeDetector`] are OS-free — they are the part that ports to
Linux, macOS and cellular collectors unchanged. Heavy storage backends stay
out of the tree: a SQLite sink is ~30 lines of `impl Sink` in your crate, which
keeps *this* library building on stock `rustup` (`rusqlite`'s bundled C compile
does not).

## Platform support

|  | Windows | Linux | macOS |
|---|---|---|---|
| interface + association | **yes** | planned (nl80211) | planned (CoreWLAN) |
| BSS list with raw IEs | **yes** | planned | limited by the public API |
| connection history | **yes** | no equivalent | no equivalent |

Today the collectors are Windows-only; the analysis, chronicle and time modules
are pure and portable. On non-Windows targets the OS-touching modules are
compiled out, so the crate still builds — treat history and the radio
collectors as optional capabilities, not assumptions.

- **MSRV:** Rust 1.78
- **Edition:** 2021

## Safety and privacy

SSIDs, BSSIDs, MAC addresses and event logs are sensitive. This library is
local-first, has no telemetry, and transmits nothing off the machine. Only run
scans against networks you own or are authorized to test. It is not a packet
sniffer, a geolocation system, or offensive Wi-Fi tooling.

## License

Licensed under either of [Apache-2.0](https://github.com/sergii-ziborov/radiochron/blob/main/LICENSE-APACHE)
or [MIT](https://github.com/sergii-ziborov/radiochron/blob/main/LICENSE-MIT), at
your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
