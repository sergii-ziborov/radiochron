use super::*;
use crate::wlan::bss::InformationElements;
use crate::wlan::bss::SecurityMode;

fn ie(rsn: bool, count: usize) -> InformationElements {
    InformationElements {
        element_count: count,
        has_rsn: rsn,
        ..Default::default()
    }
}

fn bss(ssid: Option<&str>, bssid: &str, band: &'static str, channel: u16, rssi: i32) -> BssEntry {
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
        reported_security: None,
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
fn sdk_reported_open_network_is_classified_without_raw_ies() {
    let mut entry = bss(Some("Mine"), "aa:00", "2.4GHz", 6, -55);
    entry.ie_data_complete = false;
    entry.information_elements = InformationElements::default();
    entry.reported_security = Some(SecurityMode::Open);
    let connection = connection("Mine", "aa:00", -55);

    let analysis = analyze(&[entry], Some(&connection));
    assert!(analysis.findings.iter().any(|finding| {
        finding.id == "insecure_or_legacy_security" && finding.severity == "critical"
    }));
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
