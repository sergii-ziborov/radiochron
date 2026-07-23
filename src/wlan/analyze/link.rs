use alloc::format;
use alloc::vec::Vec;
use serde_json::json;

use super::Finding;
use crate::wlan::bss::BssEntry;
use crate::wlan::CurrentConnection;

pub(super) fn push_weak_signal(
    findings: &mut Vec<Finding>,
    connection: Option<&CurrentConnection>,
) {
    let Some(connection) = connection else { return };
    let rssi = connection.rssi_dbm_estimate;
    if rssi > -67 {
        return;
    }

    let severity = if rssi <= -83 || (rssi <= -76 && connection.rx_rate_kbps < 50_000) {
        "critical"
    } else if rssi <= -71 {
        "warning"
    } else {
        "info"
    };

    findings.push(Finding {
        id: "weak_signal_link",
        severity,
        title: format!("Associated at {rssi} dBm"),
        detail: json!({
            "rssi_dbm": rssi,
            "signal_quality": connection.signal_quality,
            "rx_rate_kbps": connection.rx_rate_kbps
        }),
        caveat: "On most Windows drivers only the 0..100 quality scale is real and the dBm value is \
                 reconstructed from it, giving ~2 dB quantization. RSSI also says nothing about SNR: \
                 a -75 dBm link in clean spectrum beats a -62 dBm link under interference. Never \
                 treat this as a throughput conclusion on its own.",
    });
}

pub(super) fn push_band_steering(
    findings: &mut Vec<Finding>,
    entries: &[BssEntry],
    connection: Option<&CurrentConnection>,
    connected: Option<&BssEntry>,
) {
    let (Some(connection), Some(current)) = (connection, connected) else {
        return;
    };
    if current.band != "2.4GHz" {
        return;
    }
    let Some(ssid) = connection.ssid.as_deref() else {
        return;
    };

    let baseline = connection.rssi_dbm_estimate;
    let Some(best) = entries
        .iter()
        .filter(|e| {
            e.ssid.as_deref() == Some(ssid)
                && matches!(e.band, "5GHz" | "6GHz")
                && e.rssi_dbm >= baseline + 6
                && e.rssi_dbm >= -70
        })
        .max_by_key(|e| e.rssi_dbm)
    else {
        return;
    };

    let delta = best.rssi_dbm - baseline;
    // Sharing the first three MAC octets is decent evidence of the same hardware.
    let same_vendor = best.bssid.get(..8) == current.bssid.get(..8);

    findings.push(Finding {
        id: "band_steering_opportunity",
        severity: if delta >= 12 || best.rssi_dbm >= -60 {
            "warning"
        } else {
            "info"
        },
        title: format!(
            "The same SSID is {delta} dB stronger on {} (channel {})",
            best.band,
            best.channel.unwrap_or(0)
        ),
        detail: json!({
            "current_band": current.band,
            "current_rssi_dbm": baseline,
            "candidate": {
                "bssid": best.bssid, "band": best.band, "channel": best.channel,
                "rssi_dbm": best.rssi_dbm, "delta_db": delta,
                "has_he": best.information_elements.has_he,
                "same_oui_as_current": same_vendor
            }
        }),
        caveat:
            "An identical SSID does not prove the same network â€” guest and corporate VLANs, or an \
                 unrelated network with a common name, will match. 2.4 GHz also penetrates walls \
                 better, so a stronger 5/6 GHz reading here can vanish one room away. Stationary \
                 clients only.",
    });
}

pub(super) fn push_sticky_client(
    findings: &mut Vec<Finding>,
    entries: &[BssEntry],
    connection: Option<&CurrentConnection>,
    connected: Option<&BssEntry>,
) {
    let (Some(connection), Some(current)) = (connection, connected) else {
        return;
    };
    if connection.rssi_dbm_estimate > -65 {
        return;
    }
    let Some(ssid) = connection.ssid.as_deref() else {
        return;
    };

    let Some(best) = entries
        .iter()
        .filter(|e| {
            e.ssid.as_deref() == Some(ssid)
                && e.bssid != current.bssid
                && e.band == current.band
                && e.rssi_dbm >= connection.rssi_dbm_estimate + 10
        })
        .max_by_key(|e| e.rssi_dbm)
    else {
        return;
    };

    findings.push(Finding {
        id: "sticky_client_roam_candidate",
        severity: if connection.rssi_dbm_estimate <= -75 && best.rssi_dbm >= -60 {
            "warning"
        } else {
            "info"
        },
        title: format!(
            "A closer AP of the same SSID is available at {} dBm",
            best.rssi_dbm
        ),
        detail: json!({
            "current_rssi_dbm": connection.rssi_dbm_estimate,
            "candidate_bssid": best.bssid,
            "candidate_rssi_dbm": best.rssi_dbm,
            "delta_db": best.rssi_dbm - connection.rssi_dbm_estimate
        }),
        caveat: "Roaming is decided by the driver using 802.11k neighbour reports and load data. \
                 RadioChron parses advertised BSS Load when present but cannot see the driver's full \
                 decision inputs, and the stronger BSSID may be another radio of the same physical AP. \
                 This is an observation, never an instruction to force a roam â€” an active transfer \
                 takes a real hit from roaming.",
    });
}
