use super::*;

#[cfg(all(windows, feature = "scan"))]
use super::windows::{checked_ie_range, decode_rates, MAX_IE_BYTES};
#[cfg(all(windows, feature = "scan"))]
use crate::wlan::sys::WlanBssEntry;

/// Build a TLV: id, length, value.
fn tlv(id: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![id, value.len() as u8];
    out.extend_from_slice(value);
    out
}

#[test]
fn empty_blob_yields_empty_summary() {
    let ie = parse_information_elements(&[]);
    assert_eq!(ie.element_count, 0);
    assert_eq!(ie.byte_length, 0);
    assert!(!ie.has_rsn);
}

#[test]
fn detects_rsn_and_ht() {
    let mut bytes = tlv(0, b"MyNet");
    bytes.extend(tlv(48, &[1, 0])); // RSN
    bytes.extend(tlv(45, &[0; 26])); // HT capabilities

    let ie = parse_information_elements(&bytes);
    assert!(ie.has_rsn);
    assert!(ie.has_ht);
    assert!(!ie.has_vht);
    assert_eq!(ie.element_count, 3);
    assert!(ie.names.contains(&"RSN".to_string()));
}

#[test]
fn detects_legacy_wpa_via_vendor_oui() {
    // 00:50:F2 with subtype 1 == WPA v1.
    let bytes = tlv(221, &[0x00, 0x50, 0xf2, 0x01, 0x01, 0x00]);
    let ie = parse_information_elements(&bytes);
    assert!(ie.has_wpa);
    assert_eq!(ie.vendor_ouis, vec!["00:50:f2".to_string()]);
}

#[test]
fn parses_wpa3_transition_security_and_pmf() {
    let rsn = [
        0x01, 0x00, // version
        0x00, 0x0f, 0xac, 0x04, // group CCMP-128
        0x01, 0x00, // one pairwise cipher
        0x00, 0x0f, 0xac, 0x04, // pairwise CCMP-128
        0x02, 0x00, // two AKMs
        0x00, 0x0f, 0xac, 0x02, // PSK
        0x00, 0x0f, 0xac, 0x08, // SAE
        0xc0, 0x00, // PMF capable and required
    ];
    let ie = parse_information_elements(&tlv(48, &rsn));
    let details = ie.rsn.as_ref().expect("complete RSN");

    assert_eq!(details.group_cipher.as_deref(), Some("ccmp-128"));
    assert_eq!(details.akm_suites, ["psk", "sae"]);
    assert!(details.pmf_capable);
    assert!(details.pmf_required);
    assert_eq!(summary_with(ie).security, "wpa2-personal+wpa3-personal");
}

#[test]
fn parses_bss_load_country_width_and_wps() {
    let mut bytes = tlv(7, b"il ");
    bytes.extend(tlv(11, &[12, 0, 128, 0x34, 0x12]));
    bytes.extend(tlv(61, &[36, 1]));
    bytes.extend(tlv(192, &[1, 42, 0]));
    bytes.extend(tlv(221, &[0x00, 0x50, 0xf2, 0x04]));

    let ie = parse_information_elements(&bytes);
    let load = ie.bss_load.as_ref().unwrap();
    assert_eq!(ie.country_code.as_deref(), Some("IL"));
    assert_eq!(ie.channel_width_mhz, Some(80));
    assert_eq!(load.station_count, 12);
    assert_eq!(load.channel_utilization_percent, 50);
    assert_eq!(load.available_admission_capacity, 0x1234);
    assert!(ie.has_wps);

    let ht_20_only = parse_information_elements(&tlv(61, &[36, 1]));
    let ht_40 = parse_information_elements(&tlv(61, &[36, 5]));
    assert_eq!(ht_20_only.channel_width_mhz, Some(20));
    assert_eq!(ht_40.channel_width_mhz, Some(40));
}

#[test]
fn vendor_oui_without_wpa_subtype_is_not_wpa() {
    let bytes = tlv(221, &[0x00, 0x50, 0xf2, 0x02]); // subtype 2 == WMM
    let ie = parse_information_elements(&bytes);
    assert!(!ie.has_wpa);
}

#[test]
fn detects_he_and_eht_extensions() {
    let mut bytes = tlv(255, &[35]); // HE capabilities
    bytes.extend(tlv(255, &[108])); // EHT operation
    let ie = parse_information_elements(&bytes);
    assert!(ie.has_he);
    assert!(ie.has_eht);
    assert_eq!(ie.extension_ids, vec![35, 108]);
}

#[test]
fn truncated_element_stops_the_walk_without_panicking() {
    // Declares 10 bytes of value but supplies 2.
    let bytes = [48u8, 10, 0x01, 0x00];
    let ie = parse_information_elements(&bytes);
    assert_eq!(ie.element_count, 0);
    assert!(!ie.has_rsn);
}

#[test]
#[cfg(all(windows, feature = "scan"))]
fn rates_decode_and_drop_the_basic_flag() {
    // 0x8016 == basic-rate flag | 22 units => 11 Mbps; 0x0018 => 12 Mbps.
    let rates = decode_rates(&[0x8016, 0x0018, 0, 0], 4);
    assert_eq!(rates, vec![11.0, 12.0]);
}

/// A Wi-Fi 7 AP is not something we can rely on having in radio range, so the
/// EHT path is pinned here instead: a realistic composite beacon carrying
/// every generation of capability element at once.
#[test]
fn composite_beacon_reports_every_capability_generation() {
    let mut bytes = tlv(0, b"Wi-Fi 7 AP"); // SSID
    bytes.extend(tlv(1, &[0x82, 0x84, 0x8b, 0x96])); // supported rates
    bytes.extend(tlv(7, b"IL\0")); // country
    bytes.extend(tlv(11, &[0x01, 0x00, 0x20])); // BSS load
    bytes.extend(tlv(48, &[0x01, 0x00, 0x00, 0x0f, 0xac, 0x04])); // RSN
    bytes.extend(tlv(45, &[0; 26])); // HT capabilities
    bytes.extend(tlv(61, &[0; 22])); // HT operation
    bytes.extend(tlv(191, &[0; 12])); // VHT capabilities
    bytes.extend(tlv(192, &[0; 5])); // VHT operation
    bytes.extend(tlv(255, &[35, 0, 0])); // ext 35 = HE capabilities
    bytes.extend(tlv(255, &[36, 0, 0])); // ext 36 = HE operation
    bytes.extend(tlv(255, &[108, 0, 0])); // ext 108 = EHT capabilities
    bytes.extend(tlv(255, &[106, 0, 0])); // ext 106 = EHT operation
    bytes.extend(tlv(221, &[0x00, 0x50, 0xf2, 0x02, 0x01, 0x01])); // WMM, not WPA

    let ie = parse_information_elements(&bytes);

    assert!(ie.has_rsn);
    assert!(ie.has_ht);
    assert!(ie.has_vht);
    assert!(ie.has_he);
    assert!(
        ie.has_eht,
        "EHT must be detected from extension IDs 106/108"
    );
    assert!(ie.has_country);
    assert!(ie.has_bss_load);
    // Vendor subtype 2 is WMM; only subtype 1 means legacy WPA.
    assert!(!ie.has_wpa);
    assert_eq!(ie.extension_ids, vec![35, 36, 106, 108]);
}

/// WPA/RSN transitional APs advertise both. Both flags must survive, and the
/// summary must prefer the stronger one.
#[test]
fn transitional_ap_reports_both_wpa_and_rsn() {
    let mut bytes = tlv(48, &[0x01, 0x00]); // RSN
    bytes.extend(tlv(221, &[0x00, 0x50, 0xf2, 0x01, 0x01, 0x00])); // WPA v1

    let ie = parse_information_elements(&bytes);
    assert!(ie.has_rsn);
    assert!(ie.has_wpa);
    assert_eq!(summary_with(ie).security, "rsn");
}

#[test]
fn open_network_reports_open() {
    let ie = parse_information_elements(&tlv(0, b"Guest"));
    assert_eq!(summary_with(ie).security, "open");
}

#[test]
fn privacy_bit_without_rsn_is_not_called_open() {
    let mut entry = sample_entry(parse_information_elements(&tlv(0, b"Legacy")));
    entry.capability_information = 0x0010;
    assert_eq!(BssSummary::from(&entry).security, "wep_or_unknown");
}

#[test]
fn band_and_channel_cover_all_three_bands() {
    assert_eq!(band_and_channel(2_412_000), ("2.4GHz", Some(1)));
    assert_eq!(band_and_channel(2_462_000), ("2.4GHz", Some(11)));
    assert_eq!(band_and_channel(2_484_000), ("2.4GHz", Some(14)));
    assert_eq!(band_and_channel(5_180_000), ("5GHz", Some(36)));
    assert_eq!(band_and_channel(5_765_000), ("5GHz", Some(153)));
    // 6 GHz has its own numbering: channel 1 is centred at 5955 MHz.
    assert_eq!(band_and_channel(5_955_000), ("6GHz", Some(1)));
    assert_eq!(band_and_channel(6_295_000), ("6GHz", Some(69)));
    assert_eq!(band_and_channel(1_000_000), ("unknown", None));
}

#[test]
fn summary_drops_the_bulky_fields() {
    let entry = sample_entry(parse_information_elements(&tlv(48, &[0x01, 0x00])));
    let json = serde_json::to_string(&BssSummary::from(&entry)).unwrap();

    for bulky in ["names", "rates_mbps", "timestamp", "element_ids"] {
        assert!(!json.contains(bulky), "summary must not carry {bulky}");
    }
    assert!(json.contains("\"security\":\"rsn\""));
}

#[test]
fn sdk_reported_security_survives_without_raw_ies() {
    let mut entry = sample_entry(InformationElements::default());
    entry.ie_data_complete = false;
    entry.reported_security = Some(SecurityMode::Wpa3Personal);

    assert_eq!(BssSummary::from(&entry).security, "wpa3-personal");
}

fn summary_with(ie: InformationElements) -> BssSummary {
    BssSummary::from(&sample_entry(ie))
}

fn sample_entry(information_elements: InformationElements) -> BssEntry {
    let (band, channel) = band_and_channel(5_180_000);
    BssEntry {
        interface_guid: "00000000-0000-0000-0000-000000000000".into(),
        ssid: Some("Net".into()),
        bssid: "aa:bb:cc:dd:ee:ff".into(),
        bss_type: "infrastructure".into(),
        phy_type: "he".into(),
        rssi_dbm: -60,
        link_quality: 80,
        center_frequency_khz: 5_180_000,
        band,
        channel,
        beacon_period_tu: 100,
        in_reg_domain: true,
        capability_information: 0,
        reported_security: None,
        timestamp: 0,
        host_timestamp: 0,
        rates_mbps: vec![6.0, 12.0],
        ie_data_complete: true,
        information_elements,
    }
}

#[test]
#[cfg(all(windows, feature = "scan"))]
fn ie_range_must_stay_inside_the_native_allocation() {
    let allocation = 1000usize;
    let entry = 1100usize;
    let offset = std::mem::size_of::<WlanBssEntry>();

    assert_eq!(
        checked_ie_range(allocation, 4096, entry, offset, 100),
        Some((entry + offset, 100))
    );
    assert!(checked_ie_range(allocation, 200, entry, offset, 100).is_none());
    assert!(checked_ie_range(allocation, 4096, entry, 1, 100).is_none());
    assert!(checked_ie_range(allocation, 4096, entry, offset, MAX_IE_BYTES + 1).is_none());
}

#[test]
fn scan_refresh_is_complete_only_without_failures_or_timeouts() {
    let mut refresh = ScanRefresh {
        requested: 1,
        completed: 1,
        failed: 0,
        timed_out: 0,
        elapsed_ms: 10,
        observed_at_epoch_seconds: 0,
        interfaces: Vec::new(),
    };
    assert!(refresh.is_complete());
    refresh.failed = 1;
    assert!(!refresh.is_complete());
}
