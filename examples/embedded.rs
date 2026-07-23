//! Minimal stand-in for an ESP-IDF, Zephyr, Embassy or vendor-HAL adapter.

use core::convert::Infallible;

use radiochron::embedded::{bss_entry, Collector, Snapshot};
use radiochron::wlan::bss::BssEntry;
use radiochron::wlan::{CurrentConnection, WifiStatus, WlanInterface};

struct FirmwareWifi;

impl Collector for FirmwareWifi {
    type Error = Infallible;

    fn collect_status(&mut self, output: &mut Vec<WifiStatus>) -> Result<(), Self::Error> {
        output.push(WifiStatus {
            interface: WlanInterface {
                guid: "wifi0".into(),
                description: "firmware radio".into(),
                state: "connected".into(),
            },
            connection: Some(CurrentConnection {
                profile_name: None,
                ssid: Some("workshop".into()),
                bssid: Some("02:00:00:00:00:01".into()),
                phy_type: "802.11ax".into(),
                signal_quality: 84,
                rssi_dbm_estimate: -58,
                rx_rate_kbps: 144_000,
                tx_rate_kbps: 144_000,
            }),
            connection_error: None,
        });
        Ok(())
    }

    fn collect_bss(&mut self, output: &mut Vec<BssEntry>) -> Result<(), Self::Error> {
        // In real firmware these fields come from the SDK's scan callback.
        output.push(bss_entry(
            "wifi0",
            Some("workshop"),
            [0x02, 0, 0, 0, 0, 1],
            -58,
            5_180_000,
            0x0010,
            &[48, 2, 1, 0],
        ));
        Ok(())
    }
}

fn main() {
    let mut wifi = FirmwareWifi;
    let mut snapshot = Snapshot::new();
    snapshot.refresh(&mut wifi).unwrap();

    let report = snapshot.analyze();
    println!(
        "{} BSS, {} finding(s)",
        report.bss_count,
        report.findings.len()
    );
}
