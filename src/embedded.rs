//! Bare-metal integration for Wi-Fi firmware SDKs.
//!
//! RadioChron does not guess which vendor owns the radio. Firmware translates
//! its SDK's association and scan callbacks into the platform-neutral WLAN
//! types, while this module handles snapshot reuse and analysis. The API uses
//! `alloc`, but never requires `std`, an operating system, threads or files.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::wlan::analyze::{analyze, Analysis};
use crate::wlan::bss::{band_and_channel, parse_information_elements, BssEntry};
use crate::wlan::{quality_from_rssi, WifiStatus};

pub mod chronicle;

/// Firmware-side collector contract.
///
/// Implement this for ESP-IDF, Zephyr, Embassy or a vendor HAL. Implementors
/// append to the supplied vectors so a long-running task can reuse capacity and
/// avoid allocating a fresh scan buffer on every poll.
pub trait Collector {
    type Error;

    fn collect_status(&mut self, output: &mut Vec<WifiStatus>) -> Result<(), Self::Error>;

    fn collect_bss(&mut self, output: &mut Vec<BssEntry>) -> Result<(), Self::Error>;
}

/// Reusable capture buffer for a firmware task.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub statuses: Vec<WifiStatus>,
    pub bss: Vec<BssEntry>,
}

impl Snapshot {
    pub const fn new() -> Self {
        Self {
            statuses: Vec::new(),
            bss: Vec::new(),
        }
    }

    /// Replace this snapshot with the latest firmware observations.
    ///
    /// On an error the buffers can contain a partial capture and must not be
    /// treated as a complete scan.
    pub fn refresh<C: Collector>(&mut self, collector: &mut C) -> Result<(), C::Error> {
        self.statuses.clear();
        self.bss.clear();
        collector.collect_status(&mut self.statuses)?;
        collector.collect_bss(&mut self.bss)
    }

    /// Analyze the scan against the first associated interface, if any.
    pub fn analyze(&self) -> Analysis {
        let connection = self
            .statuses
            .iter()
            .find_map(|status| status.connection.as_ref());
        analyze(&self.bss, connection)
    }
}

/// Convert the minimum observation commonly exposed by firmware Wi-Fi SDKs
/// into RadioChron's full BSS model.
///
/// Callers may fill optional SDK-specific fields (PHY, rates, beacon period,
/// timestamps and regulatory-domain state) on the returned public struct.
pub fn bss_entry(
    interface_id: &str,
    ssid: Option<&str>,
    bssid: [u8; 6],
    rssi_dbm: i32,
    center_frequency_khz: u32,
    capability_information: u16,
    information_elements: &[u8],
) -> BssEntry {
    let (band, channel) = band_and_channel(center_frequency_khz);

    BssEntry {
        interface_guid: interface_id.to_string(),
        ssid: ssid.map(ToString::to_string),
        bssid: format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]
        ),
        bss_type: "infrastructure".to_string(),
        phy_type: "unknown".to_string(),
        rssi_dbm,
        link_quality: quality_from_rssi(rssi_dbm),
        center_frequency_khz,
        band,
        channel,
        beacon_period_tu: 0,
        in_reg_domain: false,
        capability_information,
        reported_security: None,
        timestamp: 0,
        host_timestamp: 0,
        rates_mbps: Vec::new(),
        ie_data_complete: true,
        information_elements: parse_information_elements(information_elements),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wlan::{CurrentConnection, WlanInterface};
    use alloc::vec;

    struct MockCollector;

    impl Collector for MockCollector {
        type Error = core::convert::Infallible;

        fn collect_status(&mut self, output: &mut Vec<WifiStatus>) -> Result<(), Self::Error> {
            output.push(WifiStatus {
                interface: WlanInterface {
                    guid: "wifi0".to_string(),
                    description: "mock radio".to_string(),
                    state: "connected".to_string(),
                },
                connection: Some(CurrentConnection {
                    profile_name: None,
                    ssid: Some("lab".to_string()),
                    bssid: Some("02:00:00:00:00:01".to_string()),
                    phy_type: "802.11n".to_string(),
                    signal_quality: 80,
                    rssi_dbm_estimate: -60,
                    rx_rate_kbps: 72_000,
                    tx_rate_kbps: 72_000,
                }),
                connection_error: None,
            });
            Ok(())
        }

        fn collect_bss(&mut self, output: &mut Vec<BssEntry>) -> Result<(), Self::Error> {
            output.push(bss_entry(
                "wifi0",
                Some("lab"),
                [0x02, 0, 0, 0, 0, 1],
                -60,
                2_437_000,
                0x0010,
                &[48, 2, 1, 0],
            ));
            Ok(())
        }
    }

    #[test]
    fn firmware_adapter_reuses_snapshot_and_runs_analysis() {
        let mut snapshot = Snapshot {
            statuses: Vec::with_capacity(1),
            bss: Vec::with_capacity(8),
        };
        snapshot.refresh(&mut MockCollector).unwrap();

        assert_eq!(snapshot.statuses.len(), 1);
        assert_eq!(snapshot.bss.len(), 1);
        assert_eq!(snapshot.bss[0].channel, Some(6));
        assert_eq!(snapshot.bss[0].information_elements.element_ids, vec![48]);
        assert_eq!(snapshot.analyze().bss_count, 1);
    }
}
