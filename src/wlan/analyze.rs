//! Turn a BSS list into conclusions.
//!
//! Fifty-eight BSS records are data. "Your AP shares its channel with nine
//! others and the same SSID is 14 dB stronger on 6 GHz" is an answer. This
//! module does that reduction so the caller does not spend tokens deriving it
//! and does not get the arithmetic wrong.
//!
//! Every finding carries a `caveat`: the honest reason it might be wrong. That
//! is deliberately part of the payload rather than a code comment â€” a model
//! reading a bare severity will over-trust it, and most of these signals are
//! genuinely weaker than they look. RSSI in particular is often reconstructed
//! by the driver from a 0..100 quality scale, so a reported -71 dBm may sit
//! anywhere in -69..-73.
//!
//! Pure over its inputs, so the whole thing is testable without a radio.

use alloc::string::String;
use alloc::vec::Vec;
use serde::Serialize;
use serde_json::Value;

use super::bss::BssEntry;
use super::CurrentConnection;

mod channel;
mod link;
mod scan_quality;
mod security;

use channel::{push_cochannel, push_crowded_channel};
use link::{push_band_steering, push_sticky_client, push_weak_signal};
use scan_quality::push_staleness;
use security::{push_hidden, push_security};

/// Below this a BSS is too faint to contribute meaningful contention.
pub(super) const CONTENTION_FLOOR_DBM: i32 = -85;
/// A BSS at or above this is a strong neighbour.
pub(super) const STRONG_DBM: i32 = -75;
/// The 2.4 GHz non-overlapping set under FCC/ETSI practice.
pub(super) const CHANNELS_24: [u16; 3] = [1, 6, 11];

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

#[cfg(test)]
mod tests;
