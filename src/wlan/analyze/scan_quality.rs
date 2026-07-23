use alloc::format;
use alloc::vec::Vec;
use serde_json::json;

use super::Finding;
use crate::wlan::bss::BssEntry;

pub(super) fn push_staleness(findings: &mut Vec<Finding>, entries: &[BssEntry]) {
    let blind = entries
        .iter()
        .filter(|e| e.information_elements.element_count == 0)
        .count();

    if entries.len() < 5 {
        findings.push(Finding {
            id: "scan_data_sparse",
            severity: "warning",
            title: format!(
                "Only {} BSS visible â€” the scan may be stale",
                entries.len()
            ),
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
