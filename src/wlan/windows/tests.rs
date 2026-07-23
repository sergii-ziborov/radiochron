use super::*;

#[test]
fn signal_quality_maps_onto_the_windows_dbm_scale() {
    assert_eq!(quality_to_rssi(0), -100);
    assert_eq!(quality_to_rssi(100), -50);
    assert_eq!(quality_to_rssi(50), -75);
    // Out-of-range input is clamped, never wrapped.
    assert_eq!(quality_to_rssi(255), -50);
}

#[test]
fn wide_string_stops_at_the_nul_terminator() {
    let mut buf = [0u16; 8];
    for (i, c) in "wlan".encode_utf16().enumerate() {
        buf[i] = c;
    }
    assert_eq!(wide_to_string(&buf), "wlan");
}

#[test]
fn ssid_honours_the_declared_length() {
    let mut ssid = Dot11Ssid {
        ssid_length: 5,
        ssid: [0; 32],
    };
    ssid.ssid[..5].copy_from_slice(b"MyNet");
    assert_eq!(ssid_to_string(&ssid).as_deref(), Some("MyNet"));

    let empty = Dot11Ssid {
        ssid_length: 0,
        ssid: [0; 32],
    };
    assert_eq!(ssid_to_string(&empty), None);
}
