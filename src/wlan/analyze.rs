//! Turn a BSS list into conclusions.
//!
//! Fifty-eight BSS records are data. "Your AP shares its channel with nine
//! others and the same SSID is 14 dB stronger on 6 GHz" is an answer. This
//! module does that reduction so the caller does not spend tokens deriving it
//! and does not get the arithmetic wrong.
//!
//! Every finding carries a `caveat`: the honest reason it might be wrong. That
//! is deliberately part of the payload rather than a code comment — a model
//! reading a bare severity will over-trust it, and most of these signals are
//! genuinely weaker than they look. RSSI in particular is often reconstructed
//! by the driver from a 0..100 quality scale, so a reported -71 dBm may sit
//! anywhere in -69..-73.
//!
//! Pure over its inputs, so the whole thing is testable without a radio.

use serde::Serialize;
use serde_json::{json, Value};

use super::bss::BssEntry;
use super::CurrentConnection;

/// Below this a BSS is too faint to contribute meaningful contention.
const CONTENTION_FLOOR_DBM: i32 = -85;
/// A BSS at or above this is a strong neighbour.
const STRONG_DBM: i32 = -75;
/// The 2.4 GHz non-overlapping set under FCC/ETSI practice.
const CHANNELS_24: [u16; 3] = [1, 6, 11];

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: &'static str,
    pub title: String,
    pub detail: Value,
    /// Why this finding could be wrong. Always populated.
    pub caveat: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Analysis {
    pub bss_count: usize,
    pub connected: Option<ConnectedSummary>,
    pub bands: Vec<BandSummary>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct ConnectedSummary {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub band: Option<&'static str>,
    pub channel: Option<u16>,
    pub rssi_dbm: i32,
    pub phy_type: String,
    pub rx_rate_kbps: u32,
}

#[derive(Debug, Serialize)]
pub struct BandSummary {
    pub band: &'static str,
    pub bss_count: usize,
    pub distinct_ssids: usize,
    pub distinct_channels: usize,
    pub strongest_dbm: Option<i32>,
}

/// Analyse the environment. `connection` is optional: an unassociated adapter
/// still yields a useful census.
pub fn analyze(entries: &[BssEntry], connection: Option<&CurrentConnection>) -> Analysis {
    let mut findings = Vec::new();

    let connected_bss = connection
        .and_then(|c| c.bssid.as_deref())
        .and_then(|bssid| entries.iter().find(|e| e.bssid == bssid));

    push_staleness(&mut findings, entries);
    push_cochannel(&mut findings, entries, connected_bss);
    push_crowded_channel(&mut findings, entries, connected_bss);
    push_weak_signal(&mut findings, connection);
    push_band_steering(&mut findings, entries, connection, connected_bss);
    push_sticky_client(&mut findings, entries, connection, connected_bss);
    push_security(&mut findings, entries, connected_bss);
    push_hidden(&mut findings, entries);

    // Most severe first: a caller that reads only the head should read the worst.
    findings.sort_by_key(|f| match f.severity {
        "critical" => 0,
        "warning" => 1,
        _ => 2,
    });

    Analysis {
        bss_count: entries.len(),
        connected: connection.map(|c| ConnectedSummary {
            ssid: c.ssid.clone(),
            bssid: c.bssid.clone(),
            band: connected_bss.map(|b| b.band),
            channel: connected_bss.and_then(|b| b.channel),
            rssi_dbm: c.rssi_dbm_estimate,
            phy_type: c.phy_type.clone(),
            rx_rate_kbps: c.rx_rate_kbps,
        }),
        bands: summarize_bands(entries),
        findings,
    }
}

fn summarize_bands(entries: &[BssEntry]) -> Vec<BandSummary> {
    ["2.4GHz", "5GHz", "6GHz"]
        .into_iter()
        .filter_map(|band| {
            let members: Vec<&BssEntry> = entries.iter().filter(|e| e.band == band).collect();
            if members.is_empty() {
                return None;
            }

            let mut ssids: Vec<&str> = members.iter().filter_map(|e| e.ssid.as_deref()).collect();
            ssids.sort_unstable();
            ssids.dedup();

            let mut channels: Vec<u16> = members.iter().filter_map(|e| e.channel).collect();
            channels.sort_unstable();
            channels.dedup();

            Some(BandSummary {
                band,
                bss_count: members.len(),
                distinct_ssids: ssids.len(),
                distinct_channels: channels.len(),
                strongest_dbm: members.iter().map(|e| e.rssi_dbm).max(),
            })
        })
        .collect()
}

/// Emitted first because it governs how much the rest can be trusted.
fn push_staleness(findings: &mut Vec<Finding>, entries: &[BssEntry]) {
    let blind = entries
        .iter()
        .filter(|e| e.information_elements.element_count == 0)
        .count();

    if entries.len() < 5 {
        findings.push(Finding {
            id: "scan_data_sparse",
            severity: "warning",
            title: format!("Only {} BSS visible — the scan may be stale", entries.len()),
            detail: json!({ "bss_count": entries.len() }),
            caveat:
                "A sparse list usually means the driver cache was not refreshed rather than an \
                     empty environment. Re-run with refresh_scan before drawing conclusions.",
        });
    }

    if blind > 0 && blind * 5 > entries.len() {
        findings.push(Finding {
            id: "missing_information_elements",
            severity: "info",
            title: format!("{blind} BSS carry no information elements"),
            detail: json!({ "without_ie": blind, "total": entries.len() }),
            caveat:
                "Every security and capability flag is derived from beacon IEs. Entries without \
                     them are silently treated as having no RSN/HT/VHT/HE, which can look like an \
                     open or legacy network when it is merely a truncated capture.",
        });
    }
}

fn push_cochannel(findings: &mut Vec<Finding>, entries: &[BssEntry], connected: Option<&BssEntry>) {
    let Some(current) = connected else { return };
    if current.band != "2.4GHz" {
        return;
    }

    let neighbours: Vec<&BssEntry> = entries
        .iter()
        .filter(|e| {
            e.band == "2.4GHz"
                && e.bssid != current.bssid
                && e.rssi_dbm >= CONTENTION_FLOOR_DBM
                && e.center_frequency_khz
                    .abs_diff(current.center_frequency_khz)
                    < 2_000
        })
        .collect();

    if neighbours.len() < 3 {
        return;
    }

    let strong = neighbours
        .iter()
        .filter(|e| e.rssi_dbm >= STRONG_DBM)
        .count();
    let severity = match neighbours.len() {
        0..=4 => "info",
        5..=8 => "warning",
        _ => "critical",
    };

    findings.push(Finding {
        id: "cochannel_contention_2g",
        severity,
        title: format!(
            "{} other BSS share your 2.4 GHz channel {}",
            neighbours.len(),
            current.channel.unwrap_or(0)
        ),
        detail: json!({
            "channel": current.channel,
            "neighbours": neighbours.len(),
            "strong_neighbours": strong,
            "associated_ap_channel_utilization_percent": current
                .information_elements
                .bss_load
                .as_ref()
                .map(|load| load.channel_utilization_percent),
            "top": neighbours.iter().take(5).map(|e| json!({
                "ssid": e.ssid, "bssid": e.bssid, "rssi_dbm": e.rssi_dbm
            })).collect::<Vec<_>>()
        }),
        caveat:
            "This measures potential, not observed, contention. Nine idle neighbours cost almost \
                 nothing while one saturated neighbour costs a lot. BSS Load utilization is \
                 reported when advertised, but it is each AP's own view rather than an additive \
                 channel measurement.",
    });
}

fn push_crowded_channel(
    findings: &mut Vec<Finding>,
    entries: &[BssEntry],
    connected: Option<&BssEntry>,
) {
    let Some(current) = connected else { return };
    let Some(channel) = current.channel else {
        return;
    };

    let occupancy = |c: u16| -> usize {
        entries
            .iter()
            .filter(|e| {
                e.band == current.band
                    && e.channel == Some(c)
                    && e.bssid != current.bssid
                    && e.rssi_dbm >= CONTENTION_FLOOR_DBM
            })
            .count()
    };

    let here = occupancy(channel);
    if here < 4 {
        return;
    }

    // On 2.4 GHz only the non-overlapping set is a legitimate alternative.
    let alternatives: Vec<u16> = if current.band == "2.4GHz" {
        CHANNELS_24.to_vec()
    } else {
        let mut seen: Vec<u16> = entries
            .iter()
            .filter(|e| e.band == current.band)
            .filter_map(|e| e.channel)
            .collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    };

    let Some((best, best_occ)) = alternatives
        .into_iter()
        .filter(|c| *c != channel)
        .map(|c| (c, occupancy(c)))
        .min_by_key(|(_, occ)| *occ)
    else {
        return;
    };

    if here < best_occ + 3 {
        return;
    }

    findings.push(Finding {
        id: "connected_on_crowded_channel",
        severity: if here >= 8 && best_occ <= 2 { "critical" } else { "warning" },
        title: format!("Channel {channel} carries {here} BSS; channel {best} carries {best_occ}"),
        detail: json!({
            "band": current.band,
            "connected_channel": channel,
            "connected_occupancy": here,
            "best_alternative": best,
            "best_occupancy": best_occ
        }),
        caveat: "Measured from the client's position, not the AP's — the AP may hear an entirely \
                 different neighbour set, and in a managed deployment the channel was likely chosen \
                 by a controller with global information this tool does not have.",
    });
}

fn push_weak_signal(findings: &mut Vec<Finding>, connection: Option<&CurrentConnection>) {
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

fn push_band_steering(
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
            "An identical SSID does not prove the same network — guest and corporate VLANs, or an \
                 unrelated network with a common name, will match. 2.4 GHz also penetrates walls \
                 better, so a stronger 5/6 GHz reading here can vanish one room away. Stationary \
                 clients only.",
    });
}

fn push_sticky_client(
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
                 This is an observation, never an instruction to force a roam — an active transfer \
                 takes a real hit from roaming.",
    });
}

fn push_security(findings: &mut Vec<Finding>, entries: &[BssEntry], connected: Option<&BssEntry>) {
    // A truncated or out-of-bounds beacon parses as having no RSN; require a
    // complete IE range before judging. The capability Privacy bit prevents a
    // WEP network from being mislabeled as open.
    let classified: Vec<&BssEntry> = entries
        .iter()
        .filter(|e| e.ie_data_complete && e.information_elements.element_count > 0)
        .collect();

    let open = classified
        .iter()
        .filter(|e| {
            !e.information_elements.has_rsn
                && !e.information_elements.has_wpa
                && e.capability_information & 0x0010 == 0
        })
        .count();
    let legacy = classified
        .iter()
        .filter(|e| {
            !e.information_elements.has_rsn
                && (e.information_elements.has_wpa || e.capability_information & 0x0010 != 0)
        })
        .count();

    let connected_insecure = connected.is_some_and(|c| {
        c.ie_data_complete
            && c.information_elements.element_count > 0
            && !c.information_elements.has_rsn
    });

    if open == 0 && legacy == 0 && !connected_insecure {
        return;
    }

    findings.push(Finding {
        id: "insecure_or_legacy_security",
        severity: if connected_insecure {
            "critical"
        } else {
            "info"
        },
        title: if connected_insecure {
            "Your own connection advertises no RSN".to_string()
        } else {
            format!("{open} unprotected and {legacy} legacy-security BSS in range")
        },
        detail: json!({
            "without_rsn": open,
            "legacy_security": legacy,
            "classified": classified.len(),
            "connected_insecure": connected_insecure
        }),
        caveat:
            "RSN AKM, cipher and PMF fields are parsed when structurally complete, but Windows \
                 may omit or truncate beacon IEs. Vendor-specific security outside WPA/WPS remains \
                 unknown, and a Privacy bit without RSN/WPA is conservatively called legacy rather \
                 than definitively WEP.",
    });
}

fn push_hidden(findings: &mut Vec<Finding>, entries: &[BssEntry]) {
    let hidden = entries.iter().filter(|e| e.ssid.is_none()).count();
    if hidden == 0 {
        return;
    }

    findings.push(Finding {
        id: "hidden_ssid_count",
        severity: "info",
        title: format!("{hidden} BSS advertise no SSID"),
        detail: json!({ "hidden": hidden }),
        caveat: "An upper bound, not a count of deliberately hidden networks: Windows also reports an \
                 empty SSID for probe responses that arrived without the element and for mesh backhaul \
                 BSSIDs. Hiding an SSID provides no security either way.",
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wlan::bss::InformationElements;

    fn ie(rsn: bool, count: usize) -> InformationElements {
        InformationElements {
            element_count: count,
            has_rsn: rsn,
            ..Default::default()
        }
    }

    fn bss(
        ssid: Option<&str>,
        bssid: &str,
        band: &'static str,
        channel: u16,
        rssi: i32,
    ) -> BssEntry {
        BssEntry {
            interface_guid: "guid".into(),
            ssid: ssid.map(str::to_string),
            bssid: bssid.into(),
            bss_type: "infrastructure".into(),
            phy_type: "he".into(),
            rssi_dbm: rssi,
            link_quality: 70,
            center_frequency_khz: match band {
                "2.4GHz" => 2_407_000 + u32::from(channel) * 5_000,
                "6GHz" => 5_950_000 + u32::from(channel) * 5_000,
                _ => 5_000_000 + u32::from(channel) * 5_000,
            },
            band,
            channel: Some(channel),
            beacon_period_tu: 100,
            in_reg_domain: true,
            capability_information: 0,
            timestamp: 0,
            host_timestamp: 0,
            rates_mbps: vec![],
            ie_data_complete: true,
            information_elements: ie(true, 12),
        }
    }

    fn connection(ssid: &str, bssid: &str, rssi: i32) -> CurrentConnection {
        CurrentConnection {
            profile_name: Some(ssid.into()),
            ssid: Some(ssid.into()),
            bssid: Some(bssid.into()),
            phy_type: "he".into(),
            signal_quality: 60,
            rssi_dbm_estimate: rssi,
            rx_rate_kbps: 400_000,
            tx_rate_kbps: 300_000,
        }
    }

    #[test]
    fn flags_cochannel_contention_on_the_associated_channel() {
        let mut entries = vec![bss(Some("Mine"), "aa:00", "2.4GHz", 6, -55)];
        for i in 0..5 {
            entries.push(bss(Some("Other"), &format!("bb:{i:02}"), "2.4GHz", 6, -70));
        }

        let analysis = analyze(&entries, Some(&connection("Mine", "aa:00", -55)));
        let finding = analysis
            .findings
            .iter()
            .find(|f| f.id == "cochannel_contention_2g")
            .expect("expected co-channel finding");

        assert_eq!(finding.severity, "warning");
        assert!(!finding.caveat.is_empty());
    }

    #[test]
    fn recommends_the_stronger_band_for_the_same_ssid() {
        let entries = vec![
            bss(Some("Mine"), "aa:00", "2.4GHz", 6, -72),
            bss(Some("Mine"), "aa:01", "5GHz", 36, -55),
        ];

        let analysis = analyze(&entries, Some(&connection("Mine", "aa:00", -72)));
        let finding = analysis
            .findings
            .iter()
            .find(|f| f.id == "band_steering_opportunity")
            .expect("expected band steering finding");

        assert_eq!(finding.detail["candidate"]["delta_db"], 17);
    }

    #[test]
    fn a_marginally_stronger_other_band_is_not_worth_reporting() {
        // +3 dB is inside the noise of a reconstructed RSSI figure.
        let entries = vec![
            bss(Some("Mine"), "aa:00", "2.4GHz", 6, -60),
            bss(Some("Mine"), "aa:01", "5GHz", 36, -57),
        ];

        let analysis = analyze(&entries, Some(&connection("Mine", "aa:00", -60)));
        assert!(!analysis
            .findings
            .iter()
            .any(|f| f.id == "band_steering_opportunity"));
    }

    #[test]
    fn a_truncated_beacon_is_not_reported_as_an_open_network() {
        let mut entry = bss(Some("Ghost"), "cc:00", "5GHz", 36, -80);
        entry.information_elements = ie(false, 0); // no IEs captured at all

        let analysis = analyze(&[entry], None);
        assert!(!analysis
            .findings
            .iter()
            .any(|f| f.id == "insecure_or_legacy_security"));
    }

    #[test]
    fn findings_are_ordered_worst_first() {
        let entries = vec![
            bss(Some("Mine"), "aa:00", "2.4GHz", 6, -84),
            bss(None, "dd:00", "2.4GHz", 6, -80),
        ];

        let analysis = analyze(&entries, Some(&connection("Mine", "aa:00", -84)));
        let severities: Vec<&str> = analysis.findings.iter().map(|f| f.severity).collect();
        let mut sorted = severities.clone();
        sorted.sort_by_key(|s| match *s {
            "critical" => 0,
            "warning" => 1,
            _ => 2,
        });
        assert_eq!(severities, sorted);
    }

    #[test]
    fn an_unassociated_adapter_still_yields_a_census() {
        let entries = vec![
            bss(Some("A"), "aa:00", "5GHz", 36, -60),
            bss(Some("B"), "bb:00", "6GHz", 21, -65),
        ];

        let analysis = analyze(&entries, None);
        assert_eq!(analysis.bss_count, 2);
        assert!(analysis.connected.is_none());
        assert_eq!(analysis.bands.len(), 2);
    }
}
