#![cfg_attr(not(test), no_std)]

//! ESP-IDF collector for RadioChron.
//!
//! The generic [`Driver`] boundary is host-testable. On `target_os = "espidf"`
//! the crate implements it directly for `BlockingWifi<EspWifi>` from
//! `esp-idf-svc`, so firmware only wraps its existing Wi-Fi instance.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use radiochron::embedded::{bss_entry, Collector};
use radiochron::wlan::bss::{BssEntry, SecurityMode};
use radiochron::wlan::{
    quality_from_rssi, CurrentConnection, WifiStatus, WlanInterface,
};

#[cfg(target_os = "espidf")]
mod native;

#[cfg(target_os = "espidf")]
pub use native::disconnect_reason;

/// Normalized subset returned by ESP-IDF's scan and associated-AP APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPoint {
    pub ssid: Option<String>,
    pub bssid: [u8; 6],
    pub channel: u8,
    /// Supply an exact value when the SDK exposes band/frequency separately.
    pub center_frequency_khz: Option<u32>,
    pub signal_dbm: i32,
    pub phy_type: String,
    pub security: SecurityMode,
}

/// Small testable boundary over ESP-IDF Wi-Fi operations.
pub trait Driver {
    type Error;

    fn is_connected(&mut self) -> Result<bool, Self::Error>;

    fn associated_access_point(&mut self) -> Result<Option<AccessPoint>, Self::Error>;

    fn scan(&mut self, output: &mut Vec<AccessPoint>) -> Result<(), Self::Error>;
}

/// RadioChron collector owning an ESP-IDF Wi-Fi handle.
pub struct EspIdfCollector<D> {
    driver: D,
    interface_id: String,
    scan_buffer: Vec<AccessPoint>,
}

impl<D> EspIdfCollector<D> {
    pub fn new(driver: D) -> Self {
        Self::with_interface_id(driver, "wifi0")
    }

    pub fn with_interface_id(driver: D, interface_id: &str) -> Self {
        Self {
            driver,
            interface_id: interface_id.to_string(),
            scan_buffer: Vec::new(),
        }
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    pub fn into_inner(self) -> D {
        self.driver
    }
}

impl<D: Driver> Collector for EspIdfCollector<D> {
    type Error = D::Error;

    fn collect_status(&mut self, output: &mut Vec<WifiStatus>) -> Result<(), Self::Error> {
        let connected = self.driver.is_connected()?;
        let associated = if connected {
            self.driver.associated_access_point()?
        } else {
            None
        };

        let connection = connected.then(|| {
            let signal_dbm = associated.as_ref().map(|ap| ap.signal_dbm).unwrap_or(-100);
            CurrentConnection {
                profile_name: None,
                ssid: associated.as_ref().and_then(|ap| ap.ssid.clone()),
                bssid: associated.as_ref().map(|ap| format_bssid(ap.bssid)),
                phy_type: associated
                    .as_ref()
                    .map(|ap| ap.phy_type.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                signal_quality: quality_from_rssi(signal_dbm),
                rssi_dbm_estimate: signal_dbm,
                rx_rate_kbps: 0,
                tx_rate_kbps: 0,
            }
        });

        output.push(WifiStatus {
            interface: WlanInterface {
                guid: self.interface_id.clone(),
                description: "ESP-IDF station".to_string(),
                state: if connected {
                    "connected".to_string()
                } else {
                    "disconnected".to_string()
                },
            },
            connection,
            connection_error: None,
        });
        Ok(())
    }

    fn collect_bss(&mut self, output: &mut Vec<BssEntry>) -> Result<(), Self::Error> {
        self.scan_buffer.clear();
        self.driver.scan(&mut self.scan_buffer)?;

        for ap in self.scan_buffer.drain(..) {
            let frequency = ap
                .center_frequency_khz
                .unwrap_or_else(|| channel_frequency_khz(ap.channel));
            let protected = ap.security != SecurityMode::Open;
            let mut entry = bss_entry(
                &self.interface_id,
                ap.ssid.as_deref(),
                ap.bssid,
                ap.signal_dbm,
                frequency,
                if protected { 0x0010 } else { 0 },
                &[],
            );
            entry.phy_type = ap.phy_type;
            entry.reported_security = Some(ap.security);
            // esp_wifi_scan_get_ap_records exposes normalized fields, not the
            // raw beacon body. Never claim that the IE set was complete.
            entry.ie_data_complete = false;
            output.push(entry);
        }
        Ok(())
    }
}

pub fn channel_frequency_khz(channel: u8) -> u32 {
    match channel {
        14 => 2_484_000,
        1..=13 => (2_407 + u32::from(channel) * 5) * 1_000,
        _ => (5_000 + u32::from(channel) * 5) * 1_000,
    }
}

fn format_bssid(bssid: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use radiochron::embedded::Snapshot;

    #[derive(Default)]
    struct MockDriver {
        connected: bool,
        associated: Option<AccessPoint>,
        visible: Vec<AccessPoint>,
    }

    impl Driver for MockDriver {
        type Error = core::convert::Infallible;

        fn is_connected(&mut self) -> Result<bool, Self::Error> {
            Ok(self.connected)
        }

        fn associated_access_point(&mut self) -> Result<Option<AccessPoint>, Self::Error> {
            Ok(self.associated.clone())
        }

        fn scan(&mut self, output: &mut Vec<AccessPoint>) -> Result<(), Self::Error> {
            output.extend(self.visible.iter().cloned());
            Ok(())
        }
    }

    fn ap() -> AccessPoint {
        AccessPoint {
            ssid: Some("lab".into()),
            bssid: [0x02, 0, 0, 0, 0, 1],
            channel: 6,
            center_frequency_khz: None,
            signal_dbm: -61,
            phy_type: "802.11n".into(),
            security: SecurityMode::Wpa2Personal,
        }
    }

    #[test]
    fn maps_status_and_scan_without_inventing_raw_ies() {
        let access_point = ap();
        let driver = MockDriver {
            connected: true,
            associated: Some(access_point.clone()),
            visible: alloc::vec![access_point],
        };
        let mut collector = EspIdfCollector::new(driver);
        let mut snapshot = Snapshot::new();
        snapshot.refresh(&mut collector).unwrap();

        let connection = snapshot.statuses[0].connection.as_ref().unwrap();
        assert_eq!(connection.ssid.as_deref(), Some("lab"));
        assert_eq!(connection.bssid.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(snapshot.bss[0].channel, Some(6));
        assert_eq!(
            snapshot.bss[0].reported_security,
            Some(SecurityMode::Wpa2Personal)
        );
        assert!(!snapshot.bss[0].ie_data_complete);
    }

    #[test]
    fn channel_conversion_covers_24_and_5_ghz() {
        assert_eq!(channel_frequency_khz(1), 2_412_000);
        assert_eq!(channel_frequency_khz(14), 2_484_000);
        assert_eq!(channel_frequency_khz(36), 5_180_000);
    }
}
