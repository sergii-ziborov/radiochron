use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{
    band_and_channel, parse_information_elements, BssCollection, BssEntry, BssInterfaceError,
};
use crate::wlan::sys::{self, Guid, WlanBssEntry, WlanBssList};
use crate::wlan::{
    guid_to_string, interface_guids, mac_to_string, phy_type, ssid_to_string, WlanAllocation,
    WlanClient,
};

/// IEEE 802.11 management-frame body ceiling used by Windows for a BSS entry.
pub(super) const MAX_IE_BYTES: usize = 2324;

/// Enumerate the cached BSS list for every WLAN interface.
#[cfg(all(windows, feature = "scan"))]
pub fn bss_list() -> anyhow::Result<Vec<BssEntry>> {
    Ok(bss_list_detailed()?.entries)
}

/// Enumerate cached BSS entries while preserving per-interface failures.
#[cfg(all(windows, feature = "scan"))]
pub fn bss_list_detailed() -> anyhow::Result<BssCollection> {
    let client = WlanClient::open()?;
    let mut out = Vec::new();
    let mut interface_errors = Vec::new();

    for guid in interface_guids(&client)? {
        if let Some(error) = collect_for_interface(client.handle, &guid, &mut out)? {
            interface_errors.push(error);
        }
    }

    Ok(BssCollection {
        entries: out,
        interface_errors,
    })
}

#[cfg(all(windows, feature = "scan"))]
fn collect_for_interface(
    handle: sys::Handle,
    guid: &Guid,
    out: &mut Vec<BssEntry>,
) -> anyhow::Result<Option<BssInterfaceError>> {
    let api = sys::api()?;

    unsafe {
        let mut list_ptr: *mut WlanBssList = std::ptr::null_mut();
        let ret = (api.get_network_bss_list)(
            handle,
            guid as *const Guid,
            std::ptr::null(),
            sys::DOT11_BSS_TYPE_ANY,
            0,
            std::ptr::null_mut(),
            &mut list_ptr,
        );
        let allocation = (!list_ptr.is_null()).then(|| WlanAllocation::new(list_ptr.cast()));
        // A radio that is off or busy returns a non-zero code. That is not fatal
        // for the other interfaces, so skip rather than abort the whole call.
        if ret != 0 || list_ptr.is_null() {
            return Ok(Some(BssInterfaceError {
                interface_guid: guid_to_string(guid),
                error_code: if ret == 0 { u32::MAX } else { ret },
            }));
        }

        let _allocation = allocation.expect("non-null BSS list has an owner");
        let list = &*list_ptr;
        let allocation_len = list.total_size as usize;
        let entries_offset = std::mem::offset_of!(WlanBssList, bss_entries);
        let entry_size = std::mem::size_of::<WlanBssEntry>();
        let entries_bytes = (list.num_items as usize)
            .checked_mul(entry_size)
            .ok_or_else(|| anyhow::anyhow!("WLAN_BSS_LIST entry count overflow"))?;
        let entries_end = entries_offset
            .checked_add(entries_bytes)
            .ok_or_else(|| anyhow::anyhow!("WLAN_BSS_LIST size overflow"))?;

        if allocation_len < entries_offset || entries_end > allocation_len {
            anyhow::bail!(
                "WLAN_BSS_LIST is truncated: total_size={}, entries={}, required={entries_end}",
                list.total_size,
                list.num_items
            );
        }

        let entries =
            std::slice::from_raw_parts(list.bss_entries.as_ptr(), list.num_items as usize);

        let interface_guid = guid_to_string(guid);
        for entry in entries {
            out.push(read_entry(
                entry,
                &interface_guid,
                list_ptr.cast(),
                allocation_len,
            ));
        }
    }

    Ok(None)
}

/// # Safety
/// `entry` must point into a live `WLAN_BSS_LIST` allocation, because the IE
/// bytes live at `entry + ie_offset` inside that same allocation.
#[cfg(all(windows, feature = "scan"))]
unsafe fn read_entry(
    entry: &WlanBssEntry,
    interface_guid: &str,
    allocation_start: *const u8,
    allocation_len: usize,
) -> BssEntry {
    let base = entry as *const WlanBssEntry as *const u8;

    // Validate integer addresses before constructing a slice. Beacon contents
    // are untrusted, and the driver-provided offset is relative to this entry,
    // while the authoritative bound is the enclosing WLAN_BSS_LIST allocation.
    let range = checked_ie_range(
        allocation_start as usize,
        allocation_len,
        base as usize,
        entry.ie_offset as usize,
        entry.ie_size as usize,
    );
    let ie_data_complete = range.is_some();
    let ie_bytes: &[u8] = range
        .map(|(start, len)| std::slice::from_raw_parts(start as *const u8, len))
        .unwrap_or(&[]);

    let (band, channel) = band_and_channel(entry.ch_center_frequency);

    BssEntry {
        interface_guid: interface_guid.to_string(),
        ssid: ssid_to_string(&entry.dot11_ssid),
        bssid: mac_to_string(&entry.dot11_bssid),
        bss_type: bss_type(entry.dot11_bss_type),
        phy_type: phy_type(entry.dot11_bss_phy_type),
        rssi_dbm: entry.rssi,
        link_quality: entry.link_quality,
        center_frequency_khz: entry.ch_center_frequency,
        band,
        channel,
        beacon_period_tu: entry.beacon_period,
        in_reg_domain: entry.in_reg_domain != 0,
        capability_information: entry.capability_information,
        reported_security: None,
        timestamp: entry.timestamp,
        host_timestamp: entry.host_timestamp,
        rates_mbps: decode_rates(&entry.rate_set.rate_set, entry.rate_set.rate_set_length),
        ie_data_complete,
        information_elements: parse_information_elements(ie_bytes),
    }
}

#[cfg(all(windows, feature = "scan"))]
pub(super) fn checked_ie_range(
    allocation_start: usize,
    allocation_len: usize,
    entry_start: usize,
    ie_offset: usize,
    ie_size: usize,
) -> Option<(usize, usize)> {
    if ie_size == 0 {
        return Some((entry_start, 0));
    }
    if ie_size > MAX_IE_BYTES || ie_offset < std::mem::size_of::<WlanBssEntry>() {
        return None;
    }

    let allocation_end = allocation_start.checked_add(allocation_len)?;
    let ie_start = entry_start.checked_add(ie_offset)?;
    let ie_end = ie_start.checked_add(ie_size)?;

    (entry_start >= allocation_start && ie_start >= entry_start && ie_end <= allocation_end)
        .then_some((ie_start, ie_size))
}

#[cfg(all(windows, feature = "scan"))]
fn bss_type(value: i32) -> String {
    match value {
        1 => "infrastructure",
        2 => "independent",
        3 => "any",
        _ => return format!("unknown_{value}"),
    }
    .to_string()
}

/// Rates are stored in 0.5 Mbps units; bit 15 is the "basic rate" flag.
#[cfg(all(windows, feature = "scan"))]
pub(super) fn decode_rates(rate_set: &[u16], len: u32) -> Vec<f64> {
    let len = (len as usize).min(rate_set.len());
    rate_set[..len]
        .iter()
        .map(|raw| f64::from(raw & 0x7fff) * 0.5)
        .filter(|rate| *rate > 0.0)
        .collect()
}
