# radiochron-esp-idf

ESP-IDF collector adapter for the `radiochron` Rust diagnostics core. It owns
no global state and adds no ESP dependency to `radiochron` itself.

```toml
[dependencies]
radiochron = { version = "0.3", default-features = false, features = ["embedded"] }
radiochron-esp-idf = "0.1"
```

Wrap the `BlockingWifi<EspWifi>` already created by the application (`EspWifi`
itself is supported too):

```rust,ignore
use radiochron::embedded::Snapshot;
use radiochron_esp_idf::EspIdfCollector;

let mut collector = EspIdfCollector::new(wifi);
let mut snapshot = Snapshot::new();
snapshot.refresh(&mut collector)?;
let analysis = snapshot.analyze();
```

The adapter uses `is_connected`, `get_ap_info` and the blocking ESP-IDF scan.
It maps SSID, BSSID, RSSI, channel, PHY and the SDK-reported authentication
mode. ESP-IDF's high-level scan result does not carry raw beacon Information
Elements, so entries set `ie_data_complete = false`; RadioChron will use the
reported authentication mode but will not invent RSN/PMF details.

Scanning wakes the radio and can interrupt power-saving schedules. Firmware
owns the cadence and should call `Snapshot::refresh` according to its energy
budget.

For the embedded chronicle, subscribe to ESP-IDF's `WifiEvent` on the system
event loop and pass `radiochron_esp_idf::disconnect_reason(&event)` to
`Chronicle::observe_status_with_reason`. This preserves the SDK/IEEE reason code
without coupling the RadioChron core to ESP-IDF's event-loop implementation.
