//! Native Wi-Fi collectors with a platform-neutral data model.
//!
//! Windows uses `wlanapi.dll`; Linux talks to the kernel's `nl80211` generic
//! netlink family directly. Neither backend shells out or requires a C build.

use serde::Serialize;

#[cfg(feature = "analyze")]
pub mod analyze;
#[cfg(feature = "scan")]
pub mod bss;
#[cfg(feature = "sample")]
pub mod sample;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
pub mod sys;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::wifi_status;
#[cfg(windows)]
pub use windows::wifi_status;
#[cfg(all(windows, feature = "scan"))]
pub(crate) use windows::{
    guid_to_string, interface_guids, phy_type, ssid_to_string, WlanAllocation, WlanClient,
};

/// One operating-system Wi-Fi interface.
#[derive(Debug, Clone, Serialize)]
pub struct WlanInterface {
    /// Stable platform identifier: Windows GUID or Linux interface index.
    pub guid: String,
    pub description: String,
    pub state: String,
}

/// Current association attributes normalized across collectors.
#[derive(Debug, Clone, Serialize)]
pub struct CurrentConnection {
    pub profile_name: Option<String>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub phy_type: String,
    /// Normalized 0..=100 quality. Linux derives this from dBm; Windows
    /// supplies it and RadioChron derives the approximate dBm value.
    pub signal_quality: u32,
    pub rssi_dbm_estimate: i32,
    pub rx_rate_kbps: u32,
    pub tx_rate_kbps: u32,
}

/// Current state for one Wi-Fi interface.
#[derive(Debug, Clone, Serialize)]
pub struct WifiStatus {
    pub interface: WlanInterface,
    pub connection: Option<CurrentConnection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_error: Option<String>,
}

pub(crate) fn mac_to_string(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(target_os = "linux")]
pub(crate) fn quality_from_rssi(rssi_dbm: i32) -> u32 {
    ((rssi_dbm.clamp(-100, -50) + 100) * 2) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_mac_format_is_stable() {
        assert_eq!(
            mac_to_string(&[0xa4, 0x2b, 0x8c, 0x00, 0x1f, 0xe0]),
            "a4:2b:8c:00:1f:e0"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_dbm_quality_uses_the_windows_scale() {
        assert_eq!(quality_from_rssi(-100), 0);
        assert_eq!(quality_from_rssi(-75), 50);
        assert_eq!(quality_from_rssi(-50), 100);
        assert_eq!(quality_from_rssi(-20), 100);
    }
}
