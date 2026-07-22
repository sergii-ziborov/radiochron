//! macOS collector backed by Apple's public CoreWLAN framework.
//!
//! The tiny Objective-C bridge is handwritten so enabling the collector does
//! not add a binding crate or a build script to the IoT core.

#![allow(clashing_extern_declarations)]

use core::ffi::{c_char, c_void};

#[cfg(feature = "scan")]
use std::sync::atomic::{AtomicI64, Ordering};
#[cfg(feature = "scan")]
use std::time::{Duration, Instant};

#[cfg(feature = "scan")]
use super::bss::{
    band_and_channel, parse_information_elements, refresh_age, BssCollection, BssEntry,
    BssInterfaceError, ScanInterfaceResult, ScanRefresh,
};
use super::{quality_from_rssi, CurrentConnection, WifiStatus, WlanInterface};

type Id = *mut c_void;
type Sel = *mut c_void;

#[link(name = "objc")]
extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_autoreleasePoolPush() -> Id;
    fn objc_autoreleasePoolPop(pool: Id);

    #[link_name = "objc_msgSend"]
    fn send_id(receiver: Id, selector: Sel) -> Id;
    #[link_name = "objc_msgSend"]
    fn send_id_index(receiver: Id, selector: Sel, index: usize) -> Id;
    #[link_name = "objc_msgSend"]
    #[cfg(feature = "scan")]
    fn send_scan(receiver: Id, selector: Sel, name: Id, error: *mut Id) -> Id;
    #[link_name = "objc_msgSend"]
    fn send_bool(receiver: Id, selector: Sel) -> bool;
    #[link_name = "objc_msgSend"]
    fn send_bool_id(receiver: Id, selector: Sel, value: Id) -> bool;
    #[link_name = "objc_msgSend"]
    fn send_isize(receiver: Id, selector: Sel) -> isize;
    #[link_name = "objc_msgSend"]
    fn send_usize(receiver: Id, selector: Sel) -> usize;
    #[link_name = "objc_msgSend"]
    fn send_ptr(receiver: Id, selector: Sel) -> *const c_void;
}

// Merely linking the framework loads the Objective-C classes used above.
#[link(name = "CoreWLAN", kind = "framework")]
extern "C" {}
#[link(name = "Foundation", kind = "framework")]
extern "C" {}

#[cfg(feature = "scan")]
static LAST_REFRESH_EPOCH: AtomicI64 = AtomicI64::new(0);

struct AutoreleasePool(Id);

impl AutoreleasePool {
    fn new() -> Self {
        Self(unsafe { objc_autoreleasePoolPush() })
    }
}

impl Drop for AutoreleasePool {
    fn drop(&mut self) {
        unsafe { objc_autoreleasePoolPop(self.0) }
    }
}

pub fn wifi_status() -> anyhow::Result<Vec<WifiStatus>> {
    let _pool = AutoreleasePool::new();
    let interfaces = interface_objects()?;
    let mut output = Vec::with_capacity(interfaces.len());

    for interface in interfaces {
        let name =
            string_property(interface, b"interfaceName\0").unwrap_or_else(|| "unknown".to_string());
        let powered = bool_property(interface, b"powerOn\0");
        let ssid = string_property(interface, b"ssid\0");
        let bssid = string_property(interface, b"bssid\0");
        let associated = ssid.is_some() || bssid.is_some();
        let rssi = integer_property(interface, b"rssiValue\0") as i32;
        let phy_mode = integer_property(interface, b"activePHYMode\0");

        output.push(WifiStatus {
            interface: WlanInterface {
                guid: name.clone(),
                description: format!("CoreWLAN {name}"),
                state: if !powered {
                    "radio_off"
                } else if associated {
                    "connected"
                } else {
                    "disconnected"
                }
                .to_string(),
            },
            connection: associated.then(|| CurrentConnection {
                profile_name: ssid.clone(),
                ssid,
                bssid,
                phy_type: phy_type(phy_mode),
                signal_quality: quality_from_rssi(rssi),
                rssi_dbm_estimate: rssi,
                // CoreWLAN exposes transmitRate as a floating-point value. The
                // portable ABI deliberately avoids architecture-specific
                // objc_msgSend_fpret; scan data still contains PHY capability.
                rx_rate_kbps: 0,
                tx_rate_kbps: 0,
            }),
            connection_error: None,
        });
    }
    Ok(output)
}

#[cfg(feature = "scan")]
pub fn request_scan() -> anyhow::Result<usize> {
    let _pool = AutoreleasePool::new();
    let interfaces = interface_objects()?;
    let mut completed = 0;
    for interface in interfaces {
        if scan_interface(interface).is_ok() {
            completed += 1;
        }
    }
    if completed > 0 {
        LAST_REFRESH_EPOCH.store(crate::time::now_epoch_seconds(), Ordering::Relaxed);
    }
    Ok(completed)
}

#[cfg(feature = "scan")]
pub fn scan_and_wait(timeout: Duration) -> anyhow::Result<ScanRefresh> {
    let started = Instant::now();
    let _pool = AutoreleasePool::new();
    let interfaces = interface_objects()?;
    let requested = interfaces.len();
    let mut results = Vec::with_capacity(requested);

    for interface in interfaces {
        let interface_guid =
            string_property(interface, b"interfaceName\0").unwrap_or_else(|| "unknown".to_string());
        let outcome = scan_interface(interface);
        let exceeded = started.elapsed() > timeout;
        results.push(ScanInterfaceResult {
            interface_guid,
            status: if exceeded {
                "timed_out"
            } else if outcome.is_ok() {
                "complete"
            } else {
                "failed"
            },
            error_code: outcome.err(),
        });
    }

    let observed_at_epoch_seconds = crate::time::now_epoch_seconds();
    let completed = results
        .iter()
        .filter(|item| item.status == "complete")
        .count();
    if completed > 0 {
        LAST_REFRESH_EPOCH.store(observed_at_epoch_seconds, Ordering::Relaxed);
    }
    Ok(ScanRefresh {
        requested,
        completed,
        failed: results
            .iter()
            .filter(|item| item.status == "failed")
            .count(),
        timed_out: results
            .iter()
            .filter(|item| item.status == "timed_out")
            .count(),
        elapsed_ms: started.elapsed().as_millis(),
        observed_at_epoch_seconds,
        interfaces: results,
    })
}

#[cfg(feature = "scan")]
pub fn last_refresh_age_seconds() -> Option<u64> {
    refresh_age(&LAST_REFRESH_EPOCH)
}

#[cfg(feature = "scan")]
pub fn bss_list() -> anyhow::Result<Vec<BssEntry>> {
    Ok(bss_list_detailed()?.entries)
}

#[cfg(feature = "scan")]
pub fn bss_list_detailed() -> anyhow::Result<BssCollection> {
    let _pool = AutoreleasePool::new();
    let interfaces = interface_objects()?;
    let mut entries = Vec::new();
    let mut interface_errors = Vec::new();
    for interface in interfaces {
        let name =
            string_property(interface, b"interfaceName\0").unwrap_or_else(|| "unknown".to_string());
        let networks = unsafe { send_id(interface, selector(b"cachedScanResults\0")) };
        if networks.is_null() {
            interface_errors.push(BssInterfaceError {
                interface_guid: name,
                error_code: u32::MAX,
            });
            continue;
        }
        for network in collection_objects(networks) {
            entries.push(network_entry(network, &name));
        }
    }
    Ok(BssCollection {
        entries,
        interface_errors,
    })
}

fn interface_objects() -> anyhow::Result<Vec<Id>> {
    let class = unsafe { objc_getClass(c"CWWiFiClient".as_ptr()) };
    if class.is_null() {
        anyhow::bail!("CoreWLAN CWWiFiClient class is unavailable");
    }
    let client = unsafe { send_id(class, selector(b"sharedWiFiClient\0")) };
    if client.is_null() {
        anyhow::bail!("CoreWLAN shared client is unavailable");
    }
    let interfaces = unsafe { send_id(client, selector(b"interfaces\0")) };
    if interfaces.is_null() {
        anyhow::bail!("CoreWLAN returned no interface collection");
    }
    Ok(collection_objects(interfaces))
}

#[cfg(feature = "scan")]
fn scan_interface(interface: Id) -> Result<Vec<BssEntry>, u32> {
    let name =
        string_property(interface, b"interfaceName\0").unwrap_or_else(|| "unknown".to_string());
    let mut error = core::ptr::null_mut();
    let networks = unsafe {
        send_scan(
            interface,
            selector(b"scanForNetworksWithName:error:\0"),
            core::ptr::null_mut(),
            &mut error,
        )
    };
    if networks.is_null() {
        let code = (!error.is_null())
            .then(|| integer_property(error, b"code\0"))
            .and_then(|value| u32::try_from(value.unsigned_abs()).ok())
            .unwrap_or(u32::MAX);
        return Err(code);
    }
    Ok(collection_objects(networks)
        .into_iter()
        .map(|network| network_entry(network, &name))
        .collect())
}

#[cfg(feature = "scan")]
fn network_entry(network: Id, interface_name: &str) -> BssEntry {
    let channel_object = unsafe { send_id(network, selector(b"wlanChannel\0")) };
    let channel = (!channel_object.is_null())
        .then(|| integer_property(channel_object, b"channelNumber\0"))
        .and_then(|value| u16::try_from(value).ok());
    let channel_band = if !channel_object.is_null() {
        integer_property(channel_object, b"channelBand\0")
    } else {
        0
    };
    let center_frequency_khz = channel
        .map(|channel| channel_frequency_khz(channel, channel_band))
        .unwrap_or(0);
    let (band, mapped_channel) = band_and_channel(center_frequency_khz);
    let ie_bytes = data_property(network, b"informationElementData\0").unwrap_or_default();
    let information_elements = parse_information_elements(&ie_bytes);
    let phy_type = if information_elements.has_eht {
        "eht"
    } else if information_elements.has_he {
        "he"
    } else if information_elements.has_vht {
        "vht"
    } else if information_elements.has_ht {
        "ht"
    } else {
        "legacy"
    };
    let rssi = integer_property(network, b"rssiValue\0") as i32;

    BssEntry {
        interface_guid: interface_name.to_string(),
        ssid: string_property(network, b"ssid\0"),
        bssid: string_property(network, b"bssid\0").unwrap_or_else(|| "unknown".to_string()),
        bss_type: "infrastructure".to_string(),
        phy_type: phy_type.to_string(),
        rssi_dbm: rssi,
        link_quality: quality_from_rssi(rssi),
        center_frequency_khz,
        band,
        channel: mapped_channel.or(channel),
        beacon_period_tu: u16::try_from(integer_property(network, b"beaconInterval\0"))
            .unwrap_or(0),
        in_reg_domain: true,
        capability_information: 0,
        timestamp: 0,
        host_timestamp: 0,
        rates_mbps: Vec::new(),
        ie_data_complete: !ie_bytes.is_empty(),
        information_elements,
    }
}

#[cfg(feature = "scan")]
fn channel_frequency_khz(channel: u16, band: isize) -> u32 {
    match (band, channel) {
        (1, 14) => 2_484_000,
        (1, value) => (2_407 + u32::from(value) * 5) * 1_000,
        (2, value) => (5_000 + u32::from(value) * 5) * 1_000,
        (3, value) => (5_950 + u32::from(value) * 5) * 1_000,
        (_, value) if value <= 14 => (2_407 + u32::from(value) * 5) * 1_000,
        (_, value) => (5_000 + u32::from(value) * 5) * 1_000,
    }
}

fn collection_objects(collection: Id) -> Vec<Id> {
    // NSSet (scan results) offers allObjects; NSArray simply does not. Asking
    // an object whether it responds avoids assuming which collection Apple
    // returns on a particular SDK revision.
    let responds = unsafe {
        let selector_object = selector(b"allObjects\0");
        send_bool_id(
            collection,
            selector(b"respondsToSelector:\0"),
            // SEL and object pointers have the same machine representation.
            selector_object,
        )
    };
    let array = if responds {
        unsafe { send_id(collection, selector(b"allObjects\0")) }
    } else {
        collection
    };
    if array.is_null() {
        return Vec::new();
    }
    let count = unsafe { send_usize(array, selector(b"count\0")) };
    (0..count)
        .filter_map(|index| {
            let object = unsafe { send_id_index(array, selector(b"objectAtIndex:\0"), index) };
            (!object.is_null()).then_some(object)
        })
        .collect()
}

fn string_property(object: Id, name: &'static [u8]) -> Option<String> {
    if object.is_null() {
        return None;
    }
    let string = unsafe { send_id(object, selector(name)) };
    if string.is_null() {
        return None;
    }
    let bytes = unsafe { send_ptr(string, selector(b"UTF8String\0")) }.cast::<c_char>();
    if bytes.is_null() {
        return None;
    }
    let value = unsafe { std::ffi::CStr::from_ptr(bytes) }
        .to_string_lossy()
        .into_owned();
    (!value.is_empty()).then_some(value)
}

#[cfg(feature = "scan")]
fn data_property(object: Id, name: &'static [u8]) -> Option<Vec<u8>> {
    let data = unsafe { send_id(object, selector(name)) };
    if data.is_null() {
        return None;
    }
    let len = unsafe { send_usize(data, selector(b"length\0")) };
    let bytes = unsafe { send_ptr(data, selector(b"bytes\0")) }.cast::<u8>();
    if len == 0 {
        return Some(Vec::new());
    }
    if bytes.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec())
}

fn bool_property(object: Id, name: &'static [u8]) -> bool {
    unsafe { send_bool(object, selector(name)) }
}

fn integer_property(object: Id, name: &'static [u8]) -> isize {
    unsafe { send_isize(object, selector(name)) }
}

fn selector(name: &'static [u8]) -> Sel {
    debug_assert_eq!(name.last(), Some(&0));
    unsafe { sel_registerName(name.as_ptr().cast()) }
}

fn phy_type(mode: isize) -> String {
    match mode {
        1 => "802.11a",
        2 => "802.11b",
        3 => "802.11g",
        4 => "ht",
        5 => "vht",
        6 => "he",
        7 => "eht",
        _ => return format!("unknown_{mode}"),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn apple_channel_frequency_mapping_covers_all_wifi_bands() {
        assert_eq!(super::channel_frequency_khz(1, 1), 2_412_000);
        assert_eq!(super::channel_frequency_khz(36, 2), 5_180_000);
        assert_eq!(super::channel_frequency_khz(5, 3), 5_975_000);
    }
}
