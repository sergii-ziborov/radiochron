# radiochron

**[radiochron.com](https://radiochron.com)** · the chronicle of your radio.

Wi-Fi diagnostics as an MCP server: connection-history **verdicts** (reconnect
loops, an AP failing key exchange, credential mismatch), findings instead of
data dumps, a change-only chronicle recorder, and native WLAN collectors —
pure Rust, shipped here as a prebuilt binary. No Rust toolchain, no git, no
build step.

## Install

```sh
claude mcp add radiochron -- npx -y radiochron
```

Or in any MCP client config:

```json
{ "mcpServers": { "radiochron": { "command": "npx", "args": ["-y", "radiochron"] } } }
```

Six read-only tools: `wifi_history`, `wifi_analyze`, `wifi_sample`,
`wifi_status`, `wifi_networks`, `wifi_scan`. Nothing writes, nothing reads
saved passwords, nothing leaves the machine.

**Windows-only today** — the engine talks to `wlanapi.dll` and the WLAN event
log directly. Linux (nl80211) and macOS (CoreWLAN) are on the
[roadmap](https://radiochron.com/#roadmap), as are napi-rs bindings for
importing the library from Node.js.

MIT · [source](https://github.com/sergii-ziborov/radiochron)
