use super::mapping::{phy_from_ies, rates_from_ies, ssid_from_ies};
use super::status::bitrate;
use super::*;

fn tlv(id: u8, value: &[u8]) -> Vec<u8> {
    let mut output = vec![id, value.len() as u8];
    output.extend_from_slice(value);
    output
}

#[test]
fn reads_ssid_and_legacy_rates_from_ie_bytes() {
    let mut bytes = tlv(0, b"FieldNet");
    bytes.extend(tlv(1, &[0x82, 0x84, 0x8b, 0x96]));
    bytes.extend(tlv(50, &[12, 24]));
    assert_eq!(ssid_from_ies(&bytes).as_deref(), Some("FieldNet"));
    assert_eq!(rates_from_ies(&bytes), [1.0, 2.0, 5.5, 6.0, 11.0, 12.0]);
}

#[test]
fn station_bitrate_uses_kernel_hundred_kilobit_units() {
    let mut nested = Vec::new();
    push_u32(&mut nested, RATE_INFO_BITRATE32, 8667);
    assert_eq!(bitrate(&nested), Some(866_700));
}

#[test]
fn phy_prefers_newest_advertised_generation() {
    let information = InformationElements {
        has_ht: true,
        has_he: true,
        ..InformationElements::default()
    };
    assert_eq!(phy_from_ies(&information, "5GHz"), "he");
}
