use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ScanRefresh {
    pub requested: usize,
    pub completed: usize,
    pub failed: usize,
    pub timed_out: usize,
    pub elapsed_ms: u128,
    pub observed_at_epoch_seconds: i64,
    pub interfaces: Vec<ScanInterfaceResult>,
}

impl ScanRefresh {
    pub fn is_complete(&self) -> bool {
        self.requested > 0
            && self.completed == self.requested
            && self.failed == 0
            && self.timed_out == 0
    }
}

#[derive(Debug, Serialize)]
pub struct ScanInterfaceResult {
    pub interface_guid: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct BssCollection {
    pub entries: Vec<BssEntry>,
    pub interface_errors: Vec<BssInterfaceError>,
}

#[derive(Debug, Serialize)]
pub struct BssInterfaceError {
    pub interface_guid: String,
    pub error_code: u32,
}
/// Parsed summary of the 802.11 Information Elements carried in a beacon.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct InformationElements {
    pub byte_length: usize,
    pub element_count: usize,
    pub element_ids: Vec<u8>,
    pub names: Vec<String>,
    pub extension_ids: Vec<u8>,
    pub vendor_ouis: Vec<String>,
    pub has_rsn: bool,
    pub has_wpa: bool,
    pub has_bss_load: bool,
    pub has_country: bool,
    pub has_ht: bool,
    pub has_vht: bool,
    pub has_he: bool,
    pub has_eht: bool,
    pub has_wps: bool,
    pub country_code: Option<String>,
    pub channel_width_mhz: Option<u16>,
    pub bss_load: Option<BssLoad>,
    pub rsn: Option<RsnDetails>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct BssLoad {
    pub station_count: u16,
    /// 0..=100, derived from the IEEE 802.11 0..=255 utilization byte.
    pub channel_utilization_percent: u8,
    pub available_admission_capacity: u16,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct RsnDetails {
    pub group_cipher: Option<String>,
    pub pairwise_ciphers: Vec<String>,
    pub akm_suites: Vec<String>,
    pub pmf_capable: bool,
    pub pmf_required: bool,
}

/// Security classification reported directly by a platform SDK when raw
/// beacon IEs are unavailable. Raw RSN parsing remains the preferred source.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    Open,
    Wep,
    WpaPersonal,
    WpaWpa2Personal,
    Wpa2Personal,
    Wpa2Enterprise,
    Wpa3Personal,
    Wpa3Enterprise,
    Wpa2Wpa3Personal,
    WapiPersonal,
    Unknown,
}

impl SecurityMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Wep => "wep",
            Self::WpaPersonal => "wpa-personal",
            Self::WpaWpa2Personal => "wpa+wpa2-personal",
            Self::Wpa2Personal => "wpa2-personal",
            Self::Wpa2Enterprise => "wpa2-enterprise",
            Self::Wpa3Personal => "wpa3-personal",
            Self::Wpa3Enterprise => "wpa3-enterprise",
            Self::Wpa2Wpa3Personal => "wpa2+wpa3-personal",
            Self::WapiPersonal => "wapi-personal",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BssEntry {
    /// Which WLAN interface saw this BSS â€” machines with more than one radio
    /// report the same SSID from several of them.
    pub interface_guid: String,
    pub ssid: Option<String>,
    pub bssid: String,
    pub bss_type: String,
    pub phy_type: String,
    /// Real signal strength in dBm â€” the value `netsh` never exposes.
    pub rssi_dbm: i32,
    pub link_quality: u32,
    pub center_frequency_khz: u32,
    /// Derived: "2.4GHz", "5GHz", "6GHz" or "unknown".
    pub band: &'static str,
    /// Derived 802.11 channel number, where the frequency maps to one.
    pub channel: Option<u16>,
    pub beacon_period_tu: u16,
    pub in_reg_domain: bool,
    pub capability_information: u16,
    /// Normalized SDK report when the collector cannot retrieve raw beacon IEs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_security: Option<SecurityMode>,
    pub timestamp: u64,
    pub host_timestamp: u64,
    pub rates_mbps: Vec<f64>,
    /// False when the driver's IE offset/size did not fit inside the returned
    /// `WLAN_BSS_LIST` allocation. The entry remains useful for RSSI/channel,
    /// but security and capability conclusions must not trust its empty IE set.
    pub ie_data_complete: bool,
    pub information_elements: InformationElements,
}

/// Compact projection of [`BssEntry`] for the default MCP response.
///
/// A full entry costs roughly 900 bytes, most of it the IE name list (which
/// merely restates `element_ids`), the raw rate table and two 64-bit
/// timestamps. Across ~60 visible BSSIDs that is tens of thousands of tokens
/// per tool call, so the fields an operator actually reasons about are split
/// out and returned by default.
#[derive(Debug, Serialize)]
pub struct BssSummary {
    pub interface_guid: String,
    pub ssid: Option<String>,
    pub bssid: String,
    pub band: &'static str,
    pub channel: Option<u16>,
    pub rssi_dbm: i32,
    pub phy_type: String,
    /// WPA generation/authentication where the RSN suite permits it; otherwise
    /// a conservative "rsn", "wpa", "wep_or_unknown", "unknown" or "open".
    pub security: String,
    pub channel_width_mhz: Option<u16>,
    pub channel_utilization_percent: Option<u8>,
    pub station_count: Option<u16>,
    pub pmf_capable: bool,
    pub pmf_required: bool,
    /// Compact capability list, e.g. "HT,VHT,HE".
    pub caps: String,
}

impl From<&BssEntry> for BssSummary {
    fn from(entry: &BssEntry) -> Self {
        let ie = &entry.information_elements;

        let mut caps = Vec::new();
        for (present, label) in [
            (ie.has_ht, "HT"),
            (ie.has_vht, "VHT"),
            (ie.has_he, "HE"),
            (ie.has_eht, "EHT"),
        ] {
            if present {
                caps.push(label);
            }
        }

        Self {
            interface_guid: entry.interface_guid.clone(),
            ssid: entry.ssid.clone(),
            bssid: entry.bssid.clone(),
            band: entry.band,
            channel: entry.channel,
            rssi_dbm: entry.rssi_dbm,
            phy_type: entry.phy_type.clone(),
            security: security_label(entry),
            channel_width_mhz: ie.channel_width_mhz,
            channel_utilization_percent: ie
                .bss_load
                .as_ref()
                .map(|load| load.channel_utilization_percent),
            station_count: ie.bss_load.as_ref().map(|load| load.station_count),
            pmf_capable: ie.rsn.as_ref().is_some_and(|rsn| rsn.pmf_capable),
            pmf_required: ie.rsn.as_ref().is_some_and(|rsn| rsn.pmf_required),
            caps: caps.join(","),
        }
    }
}

fn security_label(entry: &BssEntry) -> String {
    if let Some(mode) = entry.reported_security {
        return mode.label().to_string();
    }
    let ie = &entry.information_elements;
    if let Some(rsn) = &ie.rsn {
        let has = |name: &str| rsn.akm_suites.iter().any(|suite| suite == name);
        let mut labels = Vec::new();

        if has("sae") || has("ft-sae") {
            labels.push("wpa3-personal");
        }
        if has("owe") {
            labels.push("owe");
        }
        if has("802.1x-suite-b") || has("802.1x-suite-b-192") {
            labels.push("wpa3-enterprise");
        }
        if has("psk") || has("ft-psk") || has("psk-sha256") {
            labels.push("wpa2-personal");
        }
        if has("802.1x") || has("ft-802.1x") || has("802.1x-sha256") {
            labels.push("wpa2-enterprise");
        }

        labels.sort_unstable();
        labels.dedup();
        if !labels.is_empty() {
            return labels.join("+");
        }
    }

    if ie.has_rsn {
        "rsn".to_string()
    } else if ie.has_wpa {
        "wpa".to_string()
    } else if entry.capability_information & 0x0010 != 0 {
        // Privacy bit with no RSN/WPA normally means WEP, but malformed or
        // vendor security IEs are possible, so do not over-claim.
        "wep_or_unknown".to_string()
    } else if !entry.ie_data_complete {
        "unknown".to_string()
    } else {
        "open".to_string()
    }
}

/// Map a channel center frequency onto its band and 802.11 channel number.
///
/// 6 GHz uses its own numbering (channel 1 is centred at 5955 MHz), which is why
/// it cannot share the 5 GHz formula.
#[cfg_attr(not(feature = "scan"), allow(dead_code))]
pub(crate) fn band_and_channel(center_khz: u32) -> (&'static str, Option<u16>) {
    let mhz = center_khz / 1000;

    match mhz {
        2412..=2472 => ("2.4GHz", Some(((mhz - 2407) / 5) as u16)),
        2484 => ("2.4GHz", Some(14)),
        5000..=5895 => ("5GHz", Some(((mhz - 5000) / 5) as u16)),
        5925..=7125 => {
            let channel = (mhz as i32 - 5950) / 5;
            ("6GHz", u16::try_from(channel).ok().filter(|c| *c >= 1))
        }
        _ => ("unknown", None),
    }
}
