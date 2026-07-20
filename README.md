# RadioChron

**[radiochron.com](https://radiochron.com)** · the chronicle of your radio.

A pure-Rust Wi-Fi diagnostics **library** and the **MCP server** built on it.
No PowerShell, no `netsh` text scraping, no embedded C#, no .NET, no Node —
and no build toolchain beyond a stock `rustup`.

One engine, four surfaces:

| Surface | Status | For |
|---|---|---|
| `radiochron` — Rust library | this repo | IoT agents, exporters, CLIs — anything embedding collectors, analysis and the chronicle recorder |
| `radiochron-mcp` — MCP server | this repo | AI assistants: six read-only tools + resources over stdio |
| `radiochron` — npm package | **planned** | Node.js apps, via napi-rs prebuilt binaries — no Rust toolchain on the consumer's machine (name verified free) |
| [`radiochron-electron`](https://github.com/sergii-ziborov/radiochron-electron) — desktop | separate repo | evidence timelines and network inventory on the same engine |

> Early release, Windows-first. The collectors are verified on real hardware;
> crates.io/npm publishes, cellular collectors and Linux nl80211 are on the
> [roadmap](https://radiochron.com/#straight).

## Why

Intermittent Wi-Fi failures are hard to explain once the connection recovers.
RadioChron exposes what Windows already knows — interface state, nearby BSSIDs
with real signal strength, security posture — through a protocol an assistant
can drive directly. No screenshots, no copy-pasted `netsh` output.

A snapshot says the link is fine right now. RadioChron keeps the **chronicle** —
what the radio did over time — which is the only thing that can answer why it
was not fine ten minutes ago.

The name is deliberately not Wi-Fi-specific: cellular collectors are the planned
next domain, and for a device in the field the radio that matters may be either.

## The pure-Rust thesis

The predecessor (an Electron/TypeScript app) could not reach `wlanapi.dll` from
Node, so it compiled embedded C# at runtime via PowerShell `Add-Type` for every
scan. Each data path therefore depended on `powershell.exe` plus the .NET CSC
compiler, paid a cold-compile cost, parsed locale-dependent English text, and
tripped AV/WDAC on exactly the managed corporate machines it targeted.

RadioChron calls the same Win32 APIs through hand-written FFI. It does not
depend on the `windows` crate either: seven `wlanapi.dll` entry points and a
handful of `#[repr(C)]` structs are declared directly, and the DLL is resolved
at run time via `LoadLibraryW`. No import library, no `raw-dylib`, no `dlltool`,
no Visual C++ build tools.

| Data source | Native API | Replaces |
|---|---|---|
| Interface + current connection | `WlanQueryInterface` | `netsh wlan show interfaces` |
| Nearby BSS list, dBm, IEs | `WlanGetNetworkBssList` | embedded C# `Add-Type` |
| Scan trigger | `WlanScan` | embedded C# `Add-Type` |
| Connection history | `wevtapi` (`EvtQuery`/`EvtRender`) | `Get-WinEvent` |

The event-log path is worth a note. `Get-WinEvent` returns a fully-rendered
**localized** `Message` string, and the predecessor parsed that text — so it
silently produced nothing on a German or Japanese Windows. `EvtRenderEventXml`
returns the raw event XML with structured `EventData`, which is locale-invariant
and needs neither `EvtFormatMessage` nor publisher metadata. Every rule keys on
numeric codes, never on prose.

The MCP layer is hand-written too: the stdio transport is newline-delimited
JSON-RPC 2.0, so an SDK that pulls an async runtime, a schema generator and a
mandatory `chrono` (whose `clock` feature drags in `windows-link`/`raw-dylib`)
would have reintroduced the exact build requirement this project avoids.

**Total dependency count: three** — `serde`, `serde_json`, `anyhow`, for a
13-crate tree including transitive dependencies. Release binary: **~724 KB**.
Runtime requirements on the target machine: none.

For comparison, the nearest equivalent crate resolves to **51 crates** and does
not build on a stock `rustup` toolchain at all — its transitive dependencies
require mingw or the Visual C++ build tools. On an embedded target that is the
difference between adding a dependency and rebuilding the image.

## Repository layout

Two repositories, because a repository is not a crate — one repo can publish
several crates, and `cargo add` users see crates, not repos:

| Name | What it is | Lives |
|---|---|---|
| `radiochron` | the library: collectors, 802.11 analysis, and the chronicle recorder | this repo, `crates/radiochron` |
| `radiochron-mcp` | the MCP server crate; the installed binary is still named `radiochron` | this repo, `crates/radiochron-mcp` |
| `radiochron-electron` | the desktop app (Node) | [separate repo](https://github.com/sergii-ziborov/radiochron-electron) |

There is deliberately **no `radiochron-history` crate**. Reading history is the
`history` feature (the Windows event log); writing it is the `record` feature —
the `chronicle` module with a pluggable `Sink` trait. The shipped sink is
append-only JSONL with built-in rotation (zero new dependencies, greppable, and
safer across power loss than a database mid-transaction). Heavy backends belong
in the consumer's crate as an `impl Sink` of ~30 lines: a bundled SQLite sink
would drag in a C compile and break the stock-rustup build property this
project is built around.

```rust
use radiochron::chronicle::{JsonlSink, Recorder, RecorderOptions, RotationPolicy};

let sink = JsonlSink::open("chronicle.jsonl", RotationPolicy::default())?;
let mut recorder = Recorder::new(sink, RecorderOptions::default());
recorder.run_for(std::time::Duration::from_secs(3600))?; // or own the loop via .step()
```

The chronicle records **change, not polls**: a stable link produces one
`associated` line and then silence, however long you record. Its types, sink
and change detector are OS-free — they are the part that ports to Linux,
macOS and cellular collectors unchanged.

## Build

Needs nothing but [rustup](https://rustup.rs). No Visual C++ build tools, no
Windows SDK, no mingw, no administrator rights.

The GNU toolchain is self-sufficient — it ships its own linker — so on a machine
without Visual Studio, select it once:

```powershell
rustup default stable-x86_64-pc-windows-gnu
```

Then:

```powershell
cargo test                  # unit tests
cargo build --release       # target\release\radiochron.exe
cargo run --example probe   # human-readable dump against the real adapter
```

The MSVC toolchain works too if you already have the Visual C++ build tools; CI
builds on GNU so that an MSVC-only assumption cannot creep in unnoticed.

## Use it with an MCP client

Register the binary. For Claude Code:

```powershell
claude mcp add radiochron -- "C:\path\to\radiochron.exe"
```

Or add it to a client config directly:

```json
{
  "mcpServers": {
    "radiochron": {
      "command": "C:\\path\\to\\radiochron.exe"
    }
  }
}
```

No arguments, no configuration, no environment variables.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `wifi_status` | — | Every WLAN interface, its state, and for the associated one: SSID, BSSID, PHY type (`ht`/`vht`/`he`/`eht`), signal quality, estimated RSSI in dBm, rx/tx rates |
| `wifi_networks` | `refresh_scan?: boolean`<br>`detail?: "summary" \| "full"` | `{count, refreshed, detail, networks}` — nearby BSS entries with SSID, BSSID, band, channel, real RSSI in dBm, PHY type, security and capability flags |
| `wifi_analyze` | `refresh_scan?: boolean` | **Findings, not records.** Co-channel contention, crowded-channel association, weak signal, band-steering and roam candidates, insecure security, hidden SSIDs, scan-quality problems |
| `wifi_history` | `within_seconds?: number`<br>`max_events?: number`<br>`include_events?: boolean` | **Why it dropped earlier.** Reads the WLAN AutoConfig event log and returns a verdict: reconnect loops, an AP repeatedly failing key exchange, suspected credential mismatch |
| `wifi_sample` | `duration_seconds?: 1..120`<br>`interval_ms?: >=250` | Connection dynamics over a window: RSSI min/max/mean and swing, rx-rate range, distinct BSSIDs, roam count, disconnected samples |
| `wifi_scan` | — | Triggers a driver scan on each interface; returns how many accepted |

All six are read-only.

**Prefer `wifi_analyze`.** On a real 43-BSS environment it answers in 802 bytes
where the full BSS list costs 41 KB — a 98% reduction — because it returns the
conclusion instead of the evidence. Every finding carries a `caveat` field
stating why it might be wrong; that is part of the payload on purpose, since a
bare severity invites over-trust and several of these signals are genuinely
weaker than they look. RSSI, for instance, is reconstructed by most Windows
drivers from a 0..100 quality scale, so a reported −71 dBm may be anywhere in
−69..−73.

`wifi_sample` answers a different question: not "what is the state" but "is it
stable". A mean of −65 dBm looks fine until you see the 40 dB swing behind it.

Two behaviours worth knowing about `wifi_networks`:

- **The driver cache can be empty or sparse.** If the first read returns nothing,
  it is retried once behind a real scan rather than reported as "no networks" —
  an agent would otherwise repeat that as a fact about the environment. The
  `refreshed` field says whether a scan was performed.
- **`summary` is the default** and costs ~150 bytes per network against ~1000 for
  `full`. `full` adds raw IE ids and names, rates, timestamps and capability
  bits; ask for it only when those fields are actually needed.

## Deliberately not exposed

The parent project grew collectors that are unsafe to hand to an autonomous
model. They are not part of this server's tool surface, and calling them returns
`-32601 unknown tool`:

- **plaintext saved Wi-Fi keys** — a model must not be able to read and leak credentials
- **adapter MAC change / adapter restart / computer rename** — privileged, disruptive, can drop the operator off the network
- **active LAN sweeps** — emits probe traffic, trips IDS on managed segments
- **external AI-review shell-out** — arbitrary process execution and off-box data flow

## Verified

Measured on an Intel Wi-Fi 6E AX211 in a dense office environment:

- 64 unit tests green, including C-ABI struct layout assertions
- `wifi_status` — connected, `phy=he`, −58 dBm, 649/432 Mbps
- `wifi_networks` — up to **58 BSS** across 2.4, 5 and 6 GHz; RSSI −91..−54 dBm;
  band and channel resolved for every entry; IE blobs 100–384 bytes
- Latency, excluding the deliberate 4 s post-scan settle: `wifi_status` ~74 ms,
  cached `wifi_networks` and `wifi_scan` under 40 ms. Process start plus
  `initialize` is ~61 ms of that.

Two useful correctness signals fall out of real captures: 6 GHz APs report
`RSN`+`HE` with **no** HT/VHT elements, and a legacy 802.11g printer reports
`phy=erp` with no capability flags at all. Both are exactly what the spec
requires, and neither is what a naive parser would produce.

**Not field-verified:** the EHT (Wi-Fi 7) branch. No 802.11be AP has been in
range, so it is covered only by a synthetic composite-beacon unit test. Legacy
WPA detection has been seen firing on real hardware but is environment-dependent.

## Roadmap

- WLAN AutoConfig event timeline via `wevtapi` (reconnect-loop detection)
- Baseline runs, run comparison and evidence reports over SQLite
- IP configuration via `GetAdaptersAddresses`

## Safety and privacy

SSIDs, BSSIDs, MAC addresses and event logs are sensitive. RadioChron is
local-first, has no telemetry, and transmits nothing off the machine. Only run
scans against networks you own or are authorized to test. This is not a packet
sniffer, a geolocation system, or offensive Wi-Fi tooling.

## License

[MIT](LICENSE)
