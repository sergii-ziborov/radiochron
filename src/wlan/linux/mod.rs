//! Linux collector backed directly by the kernel's `nl80211` family.

mod netlink;

#[cfg(feature = "scan")]
use std::collections::BTreeMap;
#[cfg(feature = "scan")]
use std::sync::atomic::{AtomicI64, Ordering};
#[cfg(feature = "scan")]
use std::time::{Duration, Instant};

use super::bss::{band_and_channel, parse_information_elements, BssEntry, InformationElements};
#[cfg(feature = "scan")]
use super::bss::{refresh_age, BssCollection, BssInterfaceError, ScanInterfaceResult, ScanRefresh};
use super::{mac_to_string, quality_from_rssi, CurrentConnection, WifiStatus, WlanInterface};
use netlink::{attributes, push_attribute, push_u32, read_u16, read_u32, read_u64, GenericSocket};

// Numeric values are the stable userspace ABI from linux/uapi/nl80211.h.
const CMD_GET_INTERFACE: u8 = 5;
const CMD_GET_STATION: u8 = 17;
const CMD_GET_SCAN: u8 = 32;
#[cfg(feature = "scan")]
const CMD_TRIGGER_SCAN: u8 = 33;
#[cfg(feature = "scan")]
const CMD_NEW_SCAN_RESULTS: u8 = 34;
#[cfg(feature = "scan")]
const CMD_SCAN_ABORTED: u8 = 35;

const ATTR_IFINDEX: u16 = 3;
const ATTR_IFNAME: u16 = 4;
const ATTR_IFTYPE: u16 = 5;
const ATTR_MAC: u16 = 6;
const ATTR_STA_INFO: u16 = 21;
#[cfg(feature = "scan")]
const ATTR_SCAN_SSIDS: u16 = 45;
const ATTR_BSS: u16 = 47;
#[cfg(feature = "scan")]
const NLA_F_NESTED: u16 = 0x8000;

const BSS_BSSID: u16 = 1;
const BSS_FREQUENCY: u16 = 2;
const BSS_TSF: u16 = 3;
const BSS_BEACON_INTERVAL: u16 = 4;
const BSS_CAPABILITY: u16 = 5;
const BSS_INFORMATION_ELEMENTS: u16 = 6;
const BSS_SIGNAL_MBM: u16 = 7;
const BSS_SIGNAL_UNSPEC: u16 = 8;
const BSS_STATUS: u16 = 9;
const BSS_BEACON_IES: u16 = 11;
const BSS_CHAN_WIDTH: u16 = 12;
const BSS_LAST_SEEN_BOOTTIME: u16 = 15;
const BSS_STATUS_ASSOCIATED: u32 = 1;

const STA_INFO_SIGNAL: u16 = 7;
const STA_INFO_TX_BITRATE: u16 = 8;
const STA_INFO_RX_BITRATE: u16 = 14;
const RATE_INFO_BITRATE: u16 = 1;
const RATE_INFO_BITRATE32: u16 = 5;

#[cfg(feature = "scan")]
static LAST_REFRESH_EPOCH: AtomicI64 = AtomicI64::new(0);

mod mapping;
#[cfg(feature = "scan")]
mod scan;
mod status;

#[cfg(feature = "scan")]
pub use scan::{
    bss_list, bss_list_detailed, last_refresh_age_seconds, request_scan, scan_and_wait,
};
pub use status::wifi_status;

#[cfg(test)]
mod tests;
