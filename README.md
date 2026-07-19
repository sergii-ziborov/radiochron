# BeaconTrail

Local-first Windows Wi-Fi incident recorder and evidence notebook, exposed as a
**Model Context Protocol (MCP) server**. Pure Rust — no PowerShell, no `netsh`
text scraping, no embedded C#.

> Pre-alpha. The collector engine is being ported to native Rust; the surface
> below is the target, not a shipped feature list.

## Why

Intermittent Wi-Fi failures are hard to explain once the connection recovers.
BeaconTrail records what Windows already knows — interface state, nearby BSSIDs
with real dBm and 802.11 capability flags, WLAN AutoConfig events — keeps a
local history, and turns a transient fault into evidence you can attach to a
ticket. Exposed over MCP, an AI assistant can drive that engine directly:
*"why did my Wi-Fi drop at 14:20?"* becomes a tool call, not a screenshot.

Wi-Fi APs broadcast **beacon** frames; BeaconTrail keeps the **trail**.

## The pure-Rust thesis

The predecessor (an Electron/TypeScript app) could not reach `wlanapi.dll` from
Node, so it compiled embedded C# at runtime via PowerShell `Add-Type` for every
scan. That means each data path depended on `powershell.exe` + the .NET CSC
compiler, paid a cold-compile cost, parsed locale-dependent English text, and
tripped AV/WDAC on exactly the managed corporate machines it targets.

BeaconTrail calls the same Win32 APIs directly as typed FFI:

| Data source | Native API (`windows-rs`) | Replaces |
|---|---|---|
| Interface + current connection | `WlanQueryInterface` | `netsh wlan show interfaces` |
| Nearby BSS list, dBm, IEs | `WlanGetNetworkBssList` | embedded C# `Add-Type` |
| Scan trigger | `WlanScan` | embedded C# `Add-Type` |
| WLAN AutoConfig events | `wevtapi` (`EvtQuery`/`EvtRender`) | `Get-WinEvent` |
| IP configuration | `GetAdaptersAddresses` | `Get-NetIPConfiguration` |
| Saved profile metadata | `WlanGetProfile` | `netsh wlan show profile` |
| LAN neighbors | `GetIpNetTable2`, `IcmpSendEcho2` | `arp` / `ping` |
| Persistence | `rusqlite` (bundled) | `node:sqlite` |

Result: a single signed `.exe` with no Node, no PowerShell, no .NET runtime, and
structured values instead of localized text.

## Status

- [x] Project scaffold, MIT, crate layout
- [x] `wlan` module — interfaces + current connection (`WlanOpenHandle` /
      `WlanEnumInterfaces` / `WlanQueryInterface`)
- [ ] First green build + `cargo run --example probe` on real hardware
- [ ] `WlanGetNetworkBssList` + 802.11 Information Element parser
      (RSN/WPA/HT/VHT/HE/EHT, vendor OUIs, rates, center frequency)
- [ ] WLAN AutoConfig event log via `wevtapi`
- [ ] SQLite persistence (`baseline_runs`, events, device inventory)
- [ ] `rmcp` stdio MCP server surface

## Build

Requires the Rust toolchain and a linker for the `windows` crate.

```powershell
cargo run --example probe   # prove the native WLAN path
cargo build --release       # produce the server binary
```

## Planned MCP surface

Read-only diagnostics (safe for an autonomous agent):
`wifi_status`, `wifi_networks`, `wifi_events`, `wifi_timeline`,
`wifi_list_runs`, `wifi_analyze_run`, `wifi_report`, `wifi_compare_runs`,
`wifi_list_diagnostics`, `device_inventory_history`.

State-writing: `wifi_collect` (job-based — start/poll/cancel, never a blocking
call), `wifi_diagnostics_bundle`.

**Deliberately off the default surface.** These are gated behind explicit opt-in
and are never auto-invokable by a model:

- plaintext saved Wi-Fi keys — an agent must not be able to read and leak credentials
- adapter MAC change / adapter restart / computer rename — privileged and disruptive
- active LAN sweeps — emits probe traffic, trips IDS on managed segments
- external AI-review shell-out — arbitrary process execution and off-box data flow

## Architecture

BeaconTrail is the engine. The desktop UI is a *client* of it, speaking the same
MCP protocol an AI assistant does — one engine, one source of truth, no
duplicated collector logic:

```text
        Windows WLAN / Event Log / IP / neighbor APIs
                          |
              BeaconTrail (Rust, windows-rs FFI)
                          |
                    MCP (stdio)
                    /          \
       AI assistant             Electron desktop UI
```

## Safety and privacy

SSIDs, BSSIDs, MAC addresses, IPs, and event logs are sensitive. BeaconTrail is
local-first, has no telemetry, and does not transmit collected data off the
machine. Only run active checks against networks you own or are authorized to
test. This is not a packet sniffer, a geolocation system, or offensive Wi-Fi
tooling.

## License

[MIT](LICENSE)
