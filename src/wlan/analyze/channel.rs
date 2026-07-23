use alloc::format;
use alloc::vec::Vec;
use serde_json::json;

use super::{Finding, CHANNELS_24, CONTENTION_FLOOR_DBM, STRONG_DBM};
use crate::wlan::bss::BssEntry;

pub(super) fn push_cochannel(
    findings: &mut Vec<Finding>,
    entries: &[BssEntry],
    connected: Option<&BssEntry>,
) {
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

pub(super) fn push_crowded_channel(
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
        caveat: "Measured from the client's position, not the AP's â€” the AP may hear an entirely \
                 different neighbour set, and in a managed deployment the channel was likely chosen \
                 by a controller with global information this tool does not have.",
    });
}
