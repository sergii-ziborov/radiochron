//! Human-readable diagnostic report, exposed as an MCP resource.
//!
//! Resources are application-driven: the host decides whether to pull them into
//! context, with no tool call and no model decision. That makes this the
//! zero-friction path for "here is what my Wi-Fi looks like", while the tools
//! remain the path for model-initiated and parameterised queries.
//!
//! Deliberately serves the CACHED scan. A read must never trigger a four-second
//! scan: clients may read resources speculatively or on every turn, and a hidden
//! multi-second stall on a passive read is bad behaviour. Freshness is made
//! legible in the body instead.

use std::fmt::Write as _;

use serde_json::{json, Value};

use beacontrail::time::now_iso8601;
use beacontrail::wlan::analyze::Analysis;
use beacontrail::wlan::bss::BssEntry;
use beacontrail::wlan::WifiStatus;

/// Render the report as Markdown.
pub fn markdown(status: &[WifiStatus], entries: &[BssEntry], analysis: &Analysis) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "# Wi-Fi Diagnostic Report\n");
    let _ = writeln!(out, "Generated: {}", now_iso8601());
    let _ = writeln!(
        out,
        "Source: cached scan results — call the wifi_scan tool to force a refresh.\n"
    );

    let _ = writeln!(out, "## Adapters\n");
    for entry in status {
        let _ = writeln!(
            out,
            "- **{}** — {}",
            entry.interface.description, entry.interface.state
        );
    }

    match status.iter().find_map(|s| s.connection.as_ref()) {
        Some(connection) => {
            let _ = writeln!(out, "\n## Association\n");
            let _ = writeln!(
                out,
                "| SSID | BSSID | PHY | Quality | RSSI | Rx | Tx |\n|---|---|---|---|---|---|---|"
            );
            let _ = writeln!(
                out,
                "| {} | {} | {} | {}/100 | {} dBm | {} kbps | {} kbps |",
                connection.ssid.as_deref().unwrap_or("—"),
                connection.bssid.as_deref().unwrap_or("—"),
                connection.phy_type,
                connection.signal_quality,
                connection.rssi_dbm_estimate,
                connection.rx_rate_kbps,
                connection.tx_rate_kbps
            );
        }
        None => {
            let _ = writeln!(out, "\n## Association\n\nNot associated.");
        }
    }

    let _ = writeln!(out, "\n## Environment\n");
    let _ = writeln!(out, "{} BSS visible.\n", entries.len());
    if !analysis.bands.is_empty() {
        let _ = writeln!(
            out,
            "| Band | BSS | SSIDs | Channels | Strongest |\n|---|---|---|---|---|"
        );
        for band in &analysis.bands {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} dBm |",
                band.band,
                band.bss_count,
                band.distinct_ssids,
                band.distinct_channels,
                band.strongest_dbm.unwrap_or(0)
            );
        }
    }

    let _ = writeln!(out, "\n## Findings\n");
    if analysis.findings.is_empty() {
        let _ = writeln!(out, "None. Nothing in the environment looks wrong.");
    } else {
        for finding in &analysis.findings {
            let _ = writeln!(out, "### [{}] {}\n", finding.severity, finding.title);
            let _ = writeln!(out, "{}\n", finding.caveat);
        }
    }

    let _ = writeln!(out, "\n## Strongest BSS\n");
    let _ = writeln!(
        out,
        "| SSID | BSSID | Band | Ch | RSSI | RSN |\n|---|---|---|---|---|---|"
    );

    let mut sorted: Vec<&BssEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| -e.rssi_dbm);
    for entry in sorted.iter().take(15) {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            entry.ssid.as_deref().unwrap_or("*hidden*"),
            entry.bssid,
            entry.band,
            entry
                .channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "—".into()),
            entry.rssi_dbm,
            if entry.information_elements.has_rsn {
                "yes"
            } else {
                "no"
            }
        );
    }

    let _ = writeln!(
        out,
        "\n---\n\nThis report lists SSIDs and BSSIDs of nearby networks, including \
         neighbours'. A BSSID can be resolved to a street address through public \
         geolocation databases — treat it as location-identifying before sharing."
    );

    out
}

/// Machine-readable form of the same snapshot.
pub fn json(status: &[WifiStatus], entries: &[BssEntry], analysis: &Analysis) -> Value {
    json!({
        "generated": now_iso8601(),
        "source": "cached scan results",
        "adapters": status,
        "bss_count": entries.len(),
        "analysis": analysis,
    })
}

// Calendar arithmetic and its tests moved to `beacontrail::time`, where the
// event-log parser shares them.
