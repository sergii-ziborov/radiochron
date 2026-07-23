use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use serde_json::json;

use super::Finding;
use crate::wlan::bss::{BssEntry, SecurityMode};

pub(super) fn push_security(
    findings: &mut Vec<Finding>,
    entries: &[BssEntry],
    connected: Option<&BssEntry>,
) {
    // A truncated or out-of-bounds beacon parses as having no RSN; require a
    // complete IE range before judging. The capability Privacy bit prevents a
    // WEP network from being mislabeled as open.
    let classified: Vec<&BssEntry> = entries
        .iter()
        .filter(|entry| {
            entry
                .reported_security
                .is_some_and(|mode| mode != SecurityMode::Unknown)
                || (entry.ie_data_complete && entry.information_elements.element_count > 0)
        })
        .collect();

    let open = classified
        .iter()
        .filter(|entry| match entry.reported_security {
            Some(SecurityMode::Open) => true,
            Some(mode) if mode != SecurityMode::Unknown => false,
            _ => {
                !entry.information_elements.has_rsn
                    && !entry.information_elements.has_wpa
                    && entry.capability_information & 0x0010 == 0
            }
        })
        .count();
    let legacy = classified
        .iter()
        .filter(|entry| match entry.reported_security {
            Some(SecurityMode::Wep | SecurityMode::WpaPersonal | SecurityMode::WpaWpa2Personal) => {
                true
            }
            Some(mode) if mode != SecurityMode::Unknown => false,
            _ => {
                !entry.information_elements.has_rsn
                    && (entry.information_elements.has_wpa
                        || entry.capability_information & 0x0010 != 0)
            }
        })
        .count();

    let connected_insecure = connected.is_some_and(|entry| match entry.reported_security {
        Some(SecurityMode::Open | SecurityMode::Wep | SecurityMode::WpaPersonal) => true,
        Some(mode) if mode != SecurityMode::Unknown => false,
        _ => {
            entry.ie_data_complete
                && entry.information_elements.element_count > 0
                && !entry.information_elements.has_rsn
        }
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
            "RSN AKM, cipher and PMF fields are parsed when structurally complete. A platform SDK \
                 may instead provide a normalized security mode without raw IEs. Vendor-specific \
                 security outside those reports remains unknown, and a Privacy bit without RSN/WPA \
                 is conservatively called legacy rather than definitively WEP.",
    });
}

pub(super) fn push_hidden(findings: &mut Vec<Finding>, entries: &[BssEntry]) {
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
