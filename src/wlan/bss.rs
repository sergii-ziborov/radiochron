//! Nearby BSS enumeration and 802.11 Information Element parsing.
//!
//! This is the module that justifies the whole rewrite. The predecessor could
//! not get dBm RSSI, center frequency, capability bits or raw IE bytes out of
//! `netsh`, so it compiled a C# `WlanGetNetworkBssList` shim at runtime through
//! PowerShell `Add-Type`. Here the same call is plain FFI, and the IE walk —
//! which was already raw-byte logic in that C# — becomes a safe slice walk.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::sys::{self, Guid, WlanBssEntry, WlanBssList};
use super::{mac_to_string, phy_type, ssid_to_string, WlanAllocation, WlanClient};

/// IEEE 802.11 management-frame body ceiling used by Windows for a BSS entry.
const MAX_IE_BYTES: usize = 2324;
const WLAN_NOTIFICATION_SOURCE_NONE: u32 = 0;
const WLAN_NOTIFICATION_SOURCE_ACM: u32 = 0x0000_0008;
const WLAN_NOTIFICATION_ACM_SCAN_COMPLETE: u32 = 7;
const WLAN_NOTIFICATION_ACM_SCAN_FAIL: u32 = 8;

static LAST_REFRESH_EPOCH: AtomicI64 = AtomicI64::new(0);

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

#[derive(Clone, Copy)]
enum ScanState {
    Pending,
    Complete,
    Failed(u32),
    Rejected(u32),
}

struct ScanWaitState {
    interfaces: Mutex<Vec<(Guid, ScanState)>>,
    changed: Condvar,
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

#[derive(Debug, Serialize)]
pub struct BssEntry {
    /// Which WLAN interface saw this BSS — machines with more than one radio
    /// report the same SSID from several of them.
    pub interface_guid: String,
    pub ssid: Option<String>,
    pub bssid: String,
    pub bss_type: String,
    pub phy_type: String,
    /// Real signal strength in dBm — the value `netsh` never exposes.
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
fn band_and_channel(center_khz: u32) -> (&'static str, Option<u16>) {
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

/// Ask the driver to perform a fresh scan on every WLAN interface.
///
/// Results are not immediate: Windows raises a scan-complete notification a few
/// seconds later, after which [`bss_list`] returns refreshed entries.
pub fn request_scan() -> anyhow::Result<usize> {
    let client = WlanClient::open()?;
    let guids = super::interface_guids(&client)?;
    Ok(request_for_interfaces(&client, &guids)
        .into_iter()
        .filter(|(_, code)| *code == 0)
        .count())
}

/// Request a scan and wait for Windows' per-interface completion/failure
/// notifications instead of sleeping for an assumed driver latency.
pub fn scan_and_wait(timeout: Duration) -> anyhow::Result<ScanRefresh> {
    let started = Instant::now();
    let client = WlanClient::open()?;
    let api = sys::api()?;
    let guids = super::interface_guids(&client)?;
    let state = Box::new(ScanWaitState {
        interfaces: Mutex::new(
            guids
                .iter()
                .copied()
                .map(|guid| (guid, ScanState::Pending))
                .collect(),
        ),
        changed: Condvar::new(),
    });

    let register = unsafe {
        (api.register_notification)(
            client.handle,
            WLAN_NOTIFICATION_SOURCE_ACM,
            1,
            Some(scan_notification),
            (&*state as *const ScanWaitState).cast_mut().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if register != 0 {
        anyhow::bail!("WlanRegisterNotification failed (code {register})");
    }
    let _registration = NotificationRegistration { client: &client };

    let requested = request_for_interfaces(&client, &guids);
    {
        let mut interfaces = state.interfaces.lock().unwrap_or_else(|e| e.into_inner());
        for (guid, code) in requested.iter().filter(|(_, code)| *code != 0) {
            if let Some((_, status)) = interfaces.iter_mut().find(|(item, _)| item == guid) {
                *status = ScanState::Rejected(*code);
            }
        }
    }

    let interfaces = state.interfaces.lock().unwrap_or_else(|e| e.into_inner());
    let (interfaces, _) = state
        .changed
        .wait_timeout_while(interfaces, timeout, |items| {
            items
                .iter()
                .any(|(_, status)| matches!(status, ScanState::Pending))
        })
        .unwrap_or_else(|e| e.into_inner());

    let observed_at_epoch_seconds = crate::time::now_epoch_seconds();
    let results: Vec<ScanInterfaceResult> = interfaces
        .iter()
        .map(|(guid, state)| {
            let (status, error_code) = match state {
                ScanState::Pending => ("timed_out", None),
                ScanState::Complete => ("complete", None),
                ScanState::Failed(code) => ("failed", Some(*code)),
                ScanState::Rejected(code) => ("rejected", Some(*code)),
            };
            ScanInterfaceResult {
                interface_guid: super::guid_to_string(guid),
                status,
                error_code,
            }
        })
        .collect();
    drop(interfaces);

    let completed = results
        .iter()
        .filter(|item| item.status == "complete")
        .count();
    if completed > 0 {
        LAST_REFRESH_EPOCH.store(observed_at_epoch_seconds, Ordering::Relaxed);
    }

    Ok(ScanRefresh {
        requested: requested.iter().filter(|(_, code)| *code == 0).count(),
        completed,
        failed: results
            .iter()
            .filter(|item| matches!(item.status, "failed" | "rejected"))
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

/// Age of the last scan completion observed by this process. `None` means the
/// current cache provenance is unknown, not that it is fresh.
pub fn last_refresh_age_seconds() -> Option<u64> {
    let then = LAST_REFRESH_EPOCH.load(Ordering::Relaxed);
    (then > 0).then(|| crate::time::now_epoch_seconds().saturating_sub(then).max(0) as u64)
}

fn request_for_interfaces(client: &WlanClient, guids: &[Guid]) -> Vec<(Guid, u32)> {
    let Ok(api) = sys::api() else {
        return guids.iter().copied().map(|guid| (guid, u32::MAX)).collect();
    };
    guids
        .iter()
        .copied()
        .map(|guid| {
            let code = unsafe {
                (api.scan)(
                    client.handle,
                    &guid as *const Guid,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            };
            (guid, code)
        })
        .collect()
}

unsafe extern "system" fn scan_notification(
    notification: *mut sys::WlanNotificationData,
    context: *mut core::ffi::c_void,
) {
    if notification.is_null() || context.is_null() {
        return;
    }
    let notification = &*notification;
    if notification.notification_source != WLAN_NOTIFICATION_SOURCE_ACM
        || !matches!(
            notification.notification_code,
            WLAN_NOTIFICATION_ACM_SCAN_COMPLETE | WLAN_NOTIFICATION_ACM_SCAN_FAIL
        )
    {
        return;
    }

    let state = &*(context as *const ScanWaitState);
    let mut interfaces = state.interfaces.lock().unwrap_or_else(|e| e.into_inner());
    let Some((_, status)) = interfaces
        .iter_mut()
        .find(|(guid, _)| *guid == notification.interface_guid)
    else {
        return;
    };

    *status = if notification.notification_code == WLAN_NOTIFICATION_ACM_SCAN_COMPLETE {
        ScanState::Complete
    } else {
        let reason = if notification.data_size >= 4 && !notification.data.is_null() {
            *(notification.data as *const u32)
        } else {
            0
        };
        ScanState::Failed(reason)
    };
    drop(interfaces);
    state.changed.notify_all();
}

struct NotificationRegistration<'a> {
    client: &'a WlanClient,
}

impl Drop for NotificationRegistration<'_> {
    fn drop(&mut self) {
        if let Ok(api) = sys::api() {
            unsafe {
                (api.register_notification)(
                    self.client.handle,
                    WLAN_NOTIFICATION_SOURCE_NONE,
                    1,
                    None,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
            }
        }
    }
}

/// Enumerate the cached BSS list for every WLAN interface.
pub fn bss_list() -> anyhow::Result<Vec<BssEntry>> {
    Ok(bss_list_detailed()?.entries)
}

/// Enumerate cached BSS entries while preserving per-interface failures.
pub fn bss_list_detailed() -> anyhow::Result<BssCollection> {
    let client = WlanClient::open()?;
    let mut out = Vec::new();
    let mut interface_errors = Vec::new();

    for guid in super::interface_guids(&client)? {
        if let Some(error) = collect_for_interface(client.handle, &guid, &mut out)? {
            interface_errors.push(error);
        }
    }

    Ok(BssCollection {
        entries: out,
        interface_errors,
    })
}

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
                interface_guid: super::guid_to_string(guid),
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

        let interface_guid = super::guid_to_string(guid);
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
        timestamp: entry.timestamp,
        host_timestamp: entry.host_timestamp,
        rates_mbps: decode_rates(&entry.rate_set.rate_set, entry.rate_set.rate_set_length),
        ie_data_complete,
        information_elements: parse_information_elements(ie_bytes),
    }
}

fn checked_ie_range(
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
fn decode_rates(rate_set: &[u16], len: u32) -> Vec<f64> {
    let len = (len as usize).min(rate_set.len());
    rate_set[..len]
        .iter()
        .map(|raw| f64::from(raw & 0x7fff) * 0.5)
        .filter(|rate| *rate > 0.0)
        .collect()
}

/// Walk the IE blob as 802.11 TLVs: `[id][len][value…]`.
///
/// Pure function over bytes — no FFI, fully unit-testable, and the direct
/// counterpart of `SummarizeInformationElements` in the original C#.
pub fn parse_information_elements(bytes: &[u8]) -> InformationElements {
    let mut ids: Vec<u8> = Vec::new();
    let mut extension_ids: Vec<u8> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut vendor_ouis: Vec<String> = Vec::new();
    let mut has_wpa = false;
    let mut has_wps = false;
    let mut country_code = None;
    let mut channel_width_mhz = None;
    let mut bss_load = None;
    let mut rsn = None;
    let mut count = 0usize;
    let mut offset = 0usize;

    while offset + 2 <= bytes.len() {
        let id = bytes[offset];
        let len = bytes[offset + 1] as usize;
        let value_start = offset + 2;
        let next = value_start + len;

        // Truncated element: stop rather than read past the blob.
        if next > bytes.len() {
            break;
        }

        push_unique(&mut ids, id);
        push_unique_string(&mut names, ie_name(id));
        count += 1;

        let value = &bytes[value_start..next];

        match id {
            7 if value.len() >= 2 => {
                let code = &value[..2];
                if code.iter().all(u8::is_ascii_alphabetic) {
                    country_code = Some(String::from_utf8_lossy(code).to_ascii_uppercase());
                }
            }
            11 if value.len() >= 5 => {
                bss_load = Some(BssLoad {
                    station_count: u16::from_le_bytes([value[0], value[1]]),
                    channel_utilization_percent: ((u16::from(value[2]) * 100 + 127) / 255) as u8,
                    available_admission_capacity: u16::from_le_bytes([value[3], value[4]]),
                });
            }
            48 => rsn = parse_rsn(value),
            // HT Operation: both a secondary-channel offset and the STA
            // channel-width bit are required before claiming 40 MHz.
            61 if value.len() >= 2 => {
                let secondary_channel_offset = value[1] & 0x03;
                let forty_mhz_permitted = value[1] & 0x04 != 0;
                channel_width_mhz = Some(if secondary_channel_offset != 0 && forty_mhz_permitted {
                    40
                } else {
                    20
                });
            }
            // VHT Operation channel-width values: 0 preserves the HT width;
            // 1 is 80 MHz; 2 and 3 occupy 160 MHz of spectrum (contiguous or
            // 80+80 respectively).
            192 if !value.is_empty() => match value[0] {
                1 => channel_width_mhz = Some(80),
                2 | 3 => channel_width_mhz = Some(160),
                _ => {}
            },
            _ => {}
        }

        // Vendor-specific: the first three value bytes are the OUI. A 00:50:F2
        // OUI with subtype 1 is the legacy WPA (pre-RSN) element.
        if id == 221 && len >= 3 {
            let oui = format!(
                "{:02x}:{:02x}:{:02x}",
                bytes[value_start],
                bytes[value_start + 1],
                bytes[value_start + 2]
            );
            if len >= 4 && oui == "00:50:f2" && bytes[value_start + 3] == 1 {
                has_wpa = true;
            }
            if len >= 4 && oui == "00:50:f2" && bytes[value_start + 3] == 4 {
                has_wps = true;
            }
            push_unique_string(&mut vendor_ouis, oui);
        }

        if id == 255 && len >= 1 {
            let ext = bytes[value_start];
            push_unique(&mut extension_ids, ext);
            push_unique_string(&mut names, format!("Extension {ext}"));
        }

        offset = next;
    }

    ids.sort_unstable();
    extension_ids.sort_unstable();
    names.sort();
    vendor_ouis.sort();

    InformationElements {
        byte_length: bytes.len(),
        element_count: count,
        has_rsn: ids.contains(&48),
        has_wpa,
        has_bss_load: ids.contains(&11),
        has_country: ids.contains(&7),
        has_ht: ids.contains(&45) || ids.contains(&61),
        has_vht: ids.contains(&191) || ids.contains(&192),
        has_he: extension_ids.iter().any(|id| (35..=38).contains(id)),
        has_eht: extension_ids.iter().any(|id| (106..=108).contains(id)),
        has_wps,
        country_code,
        channel_width_mhz,
        bss_load,
        rsn,
        element_ids: ids,
        names,
        extension_ids,
        vendor_ouis,
    }
}

fn parse_rsn(value: &[u8]) -> Option<RsnDetails> {
    let mut offset = 0usize;
    if take_u16(value, &mut offset)? != 1 {
        return None;
    }

    let group_cipher = Some(cipher_suite(take_suite(value, &mut offset)?));
    let pairwise_count = take_u16(value, &mut offset)? as usize;
    let mut pairwise_ciphers = Vec::with_capacity(pairwise_count.min(16));
    for _ in 0..pairwise_count {
        push_unique_string(
            &mut pairwise_ciphers,
            cipher_suite(take_suite(value, &mut offset)?),
        );
    }

    let akm_count = take_u16(value, &mut offset)? as usize;
    let mut akm_suites = Vec::with_capacity(akm_count.min(16));
    for _ in 0..akm_count {
        push_unique_string(&mut akm_suites, akm_suite(take_suite(value, &mut offset)?));
    }

    let capabilities = if offset + 2 <= value.len() {
        take_u16(value, &mut offset).unwrap_or(0)
    } else {
        0
    };

    Some(RsnDetails {
        group_cipher,
        pairwise_ciphers,
        akm_suites,
        pmf_required: capabilities & (1 << 6) != 0,
        pmf_capable: capabilities & (1 << 7) != 0,
    })
}

fn take_u16(value: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = value.get(*offset..end)?;
    *offset = end;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn take_suite(value: &[u8], offset: &mut usize) -> Option<[u8; 4]> {
    let end = offset.checked_add(4)?;
    let bytes = value.get(*offset..end)?;
    *offset = end;
    Some([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn cipher_suite(suite: [u8; 4]) -> String {
    if suite[..3] != [0x00, 0x0f, 0xac] {
        return suite_name(suite);
    }
    match suite[3] {
        0 => "use-group",
        1 => "wep-40",
        2 => "tkip",
        4 => "ccmp-128",
        5 => "wep-104",
        6 => "bip-cmac-128",
        8 => "gcmp-128",
        9 => "gcmp-256",
        10 => "ccmp-256",
        11 => "bip-gmac-128",
        12 => "bip-gmac-256",
        13 => "bip-cmac-256",
        _ => return suite_name(suite),
    }
    .to_string()
}

fn akm_suite(suite: [u8; 4]) -> String {
    if suite[..3] != [0x00, 0x0f, 0xac] {
        return suite_name(suite);
    }
    match suite[3] {
        1 => "802.1x",
        2 => "psk",
        3 => "ft-802.1x",
        4 => "ft-psk",
        5 => "802.1x-sha256",
        6 => "psk-sha256",
        8 => "sae",
        9 => "ft-sae",
        11 => "802.1x-suite-b",
        12 => "802.1x-suite-b-192",
        18 => "owe",
        _ => return suite_name(suite),
    }
    .to_string()
}

fn suite_name(suite: [u8; 4]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{}",
        suite[0], suite[1], suite[2], suite[3]
    )
}

fn push_unique<T: PartialEq>(target: &mut Vec<T>, value: T) {
    if !target.contains(&value) {
        target.push(value);
    }
}

fn push_unique_string(target: &mut Vec<String>, value: String) {
    if !target
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&value))
    {
        target.push(value);
    }
}

fn ie_name(id: u8) -> String {
    match id {
        0 => "SSID",
        1 => "Supported rates",
        3 => "DS parameter set",
        5 => "TIM",
        7 => "Country",
        11 => "BSS load",
        32 => "Power constraint",
        45 => "HT capabilities",
        48 => "RSN",
        50 => "Extended supported rates",
        61 => "HT operation",
        70 => "RM enabled capabilities",
        107 => "Interworking",
        127 => "Extended capabilities",
        191 => "VHT capabilities",
        192 => "VHT operation",
        195 => "Transmit power envelope",
        201 => "Reduced neighbor report",
        221 => "Vendor specific",
        255 => "Extension",
        other => return format!("IE {other}"),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TLV: id, length, value.
    fn tlv(id: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![id, value.len() as u8];
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn empty_blob_yields_empty_summary() {
        let ie = parse_information_elements(&[]);
        assert_eq!(ie.element_count, 0);
        assert_eq!(ie.byte_length, 0);
        assert!(!ie.has_rsn);
    }

    #[test]
    fn detects_rsn_and_ht() {
        let mut bytes = tlv(0, b"MyNet");
        bytes.extend(tlv(48, &[1, 0])); // RSN
        bytes.extend(tlv(45, &[0; 26])); // HT capabilities

        let ie = parse_information_elements(&bytes);
        assert!(ie.has_rsn);
        assert!(ie.has_ht);
        assert!(!ie.has_vht);
        assert_eq!(ie.element_count, 3);
        assert!(ie.names.contains(&"RSN".to_string()));
    }

    #[test]
    fn detects_legacy_wpa_via_vendor_oui() {
        // 00:50:F2 with subtype 1 == WPA v1.
        let bytes = tlv(221, &[0x00, 0x50, 0xf2, 0x01, 0x01, 0x00]);
        let ie = parse_information_elements(&bytes);
        assert!(ie.has_wpa);
        assert_eq!(ie.vendor_ouis, vec!["00:50:f2".to_string()]);
    }

    #[test]
    fn parses_wpa3_transition_security_and_pmf() {
        let rsn = [
            0x01, 0x00, // version
            0x00, 0x0f, 0xac, 0x04, // group CCMP-128
            0x01, 0x00, // one pairwise cipher
            0x00, 0x0f, 0xac, 0x04, // pairwise CCMP-128
            0x02, 0x00, // two AKMs
            0x00, 0x0f, 0xac, 0x02, // PSK
            0x00, 0x0f, 0xac, 0x08, // SAE
            0xc0, 0x00, // PMF capable and required
        ];
        let ie = parse_information_elements(&tlv(48, &rsn));
        let details = ie.rsn.as_ref().expect("complete RSN");

        assert_eq!(details.group_cipher.as_deref(), Some("ccmp-128"));
        assert_eq!(details.akm_suites, ["psk", "sae"]);
        assert!(details.pmf_capable);
        assert!(details.pmf_required);
        assert_eq!(summary_with(ie).security, "wpa2-personal+wpa3-personal");
    }

    #[test]
    fn parses_bss_load_country_width_and_wps() {
        let mut bytes = tlv(7, b"il ");
        bytes.extend(tlv(11, &[12, 0, 128, 0x34, 0x12]));
        bytes.extend(tlv(61, &[36, 1]));
        bytes.extend(tlv(192, &[1, 42, 0]));
        bytes.extend(tlv(221, &[0x00, 0x50, 0xf2, 0x04]));

        let ie = parse_information_elements(&bytes);
        let load = ie.bss_load.as_ref().unwrap();
        assert_eq!(ie.country_code.as_deref(), Some("IL"));
        assert_eq!(ie.channel_width_mhz, Some(80));
        assert_eq!(load.station_count, 12);
        assert_eq!(load.channel_utilization_percent, 50);
        assert_eq!(load.available_admission_capacity, 0x1234);
        assert!(ie.has_wps);

        let ht_20_only = parse_information_elements(&tlv(61, &[36, 1]));
        let ht_40 = parse_information_elements(&tlv(61, &[36, 5]));
        assert_eq!(ht_20_only.channel_width_mhz, Some(20));
        assert_eq!(ht_40.channel_width_mhz, Some(40));
    }

    #[test]
    fn vendor_oui_without_wpa_subtype_is_not_wpa() {
        let bytes = tlv(221, &[0x00, 0x50, 0xf2, 0x02]); // subtype 2 == WMM
        let ie = parse_information_elements(&bytes);
        assert!(!ie.has_wpa);
    }

    #[test]
    fn detects_he_and_eht_extensions() {
        let mut bytes = tlv(255, &[35]); // HE capabilities
        bytes.extend(tlv(255, &[108])); // EHT operation
        let ie = parse_information_elements(&bytes);
        assert!(ie.has_he);
        assert!(ie.has_eht);
        assert_eq!(ie.extension_ids, vec![35, 108]);
    }

    #[test]
    fn truncated_element_stops_the_walk_without_panicking() {
        // Declares 10 bytes of value but supplies 2.
        let bytes = [48u8, 10, 0x01, 0x00];
        let ie = parse_information_elements(&bytes);
        assert_eq!(ie.element_count, 0);
        assert!(!ie.has_rsn);
    }

    #[test]
    fn rates_decode_and_drop_the_basic_flag() {
        // 0x8016 == basic-rate flag | 22 units => 11 Mbps; 0x0018 => 12 Mbps.
        let rates = decode_rates(&[0x8016, 0x0018, 0, 0], 4);
        assert_eq!(rates, vec![11.0, 12.0]);
    }

    /// A Wi-Fi 7 AP is not something we can rely on having in radio range, so the
    /// EHT path is pinned here instead: a realistic composite beacon carrying
    /// every generation of capability element at once.
    #[test]
    fn composite_beacon_reports_every_capability_generation() {
        let mut bytes = tlv(0, b"Wi-Fi 7 AP"); // SSID
        bytes.extend(tlv(1, &[0x82, 0x84, 0x8b, 0x96])); // supported rates
        bytes.extend(tlv(7, b"IL\0")); // country
        bytes.extend(tlv(11, &[0x01, 0x00, 0x20])); // BSS load
        bytes.extend(tlv(48, &[0x01, 0x00, 0x00, 0x0f, 0xac, 0x04])); // RSN
        bytes.extend(tlv(45, &[0; 26])); // HT capabilities
        bytes.extend(tlv(61, &[0; 22])); // HT operation
        bytes.extend(tlv(191, &[0; 12])); // VHT capabilities
        bytes.extend(tlv(192, &[0; 5])); // VHT operation
        bytes.extend(tlv(255, &[35, 0, 0])); // ext 35 = HE capabilities
        bytes.extend(tlv(255, &[36, 0, 0])); // ext 36 = HE operation
        bytes.extend(tlv(255, &[108, 0, 0])); // ext 108 = EHT capabilities
        bytes.extend(tlv(255, &[106, 0, 0])); // ext 106 = EHT operation
        bytes.extend(tlv(221, &[0x00, 0x50, 0xf2, 0x02, 0x01, 0x01])); // WMM, not WPA

        let ie = parse_information_elements(&bytes);

        assert!(ie.has_rsn);
        assert!(ie.has_ht);
        assert!(ie.has_vht);
        assert!(ie.has_he);
        assert!(
            ie.has_eht,
            "EHT must be detected from extension IDs 106/108"
        );
        assert!(ie.has_country);
        assert!(ie.has_bss_load);
        // Vendor subtype 2 is WMM; only subtype 1 means legacy WPA.
        assert!(!ie.has_wpa);
        assert_eq!(ie.extension_ids, vec![35, 36, 106, 108]);
    }

    /// WPA/RSN transitional APs advertise both. Both flags must survive, and the
    /// summary must prefer the stronger one.
    #[test]
    fn transitional_ap_reports_both_wpa_and_rsn() {
        let mut bytes = tlv(48, &[0x01, 0x00]); // RSN
        bytes.extend(tlv(221, &[0x00, 0x50, 0xf2, 0x01, 0x01, 0x00])); // WPA v1

        let ie = parse_information_elements(&bytes);
        assert!(ie.has_rsn);
        assert!(ie.has_wpa);
        assert_eq!(summary_with(ie).security, "rsn");
    }

    #[test]
    fn open_network_reports_open() {
        let ie = parse_information_elements(&tlv(0, b"Guest"));
        assert_eq!(summary_with(ie).security, "open");
    }

    #[test]
    fn privacy_bit_without_rsn_is_not_called_open() {
        let mut entry = sample_entry(parse_information_elements(&tlv(0, b"Legacy")));
        entry.capability_information = 0x0010;
        assert_eq!(BssSummary::from(&entry).security, "wep_or_unknown");
    }

    #[test]
    fn band_and_channel_cover_all_three_bands() {
        assert_eq!(band_and_channel(2_412_000), ("2.4GHz", Some(1)));
        assert_eq!(band_and_channel(2_462_000), ("2.4GHz", Some(11)));
        assert_eq!(band_and_channel(2_484_000), ("2.4GHz", Some(14)));
        assert_eq!(band_and_channel(5_180_000), ("5GHz", Some(36)));
        assert_eq!(band_and_channel(5_765_000), ("5GHz", Some(153)));
        // 6 GHz has its own numbering: channel 1 is centred at 5955 MHz.
        assert_eq!(band_and_channel(5_955_000), ("6GHz", Some(1)));
        assert_eq!(band_and_channel(6_295_000), ("6GHz", Some(69)));
        assert_eq!(band_and_channel(1_000_000), ("unknown", None));
    }

    #[test]
    fn summary_drops_the_bulky_fields() {
        let entry = sample_entry(parse_information_elements(&tlv(48, &[0x01, 0x00])));
        let json = serde_json::to_string(&BssSummary::from(&entry)).unwrap();

        for bulky in ["names", "rates_mbps", "timestamp", "element_ids"] {
            assert!(!json.contains(bulky), "summary must not carry {bulky}");
        }
        assert!(json.contains("\"security\":\"rsn\""));
    }

    fn summary_with(ie: InformationElements) -> BssSummary {
        BssSummary::from(&sample_entry(ie))
    }

    fn sample_entry(information_elements: InformationElements) -> BssEntry {
        let (band, channel) = band_and_channel(5_180_000);
        BssEntry {
            interface_guid: "00000000-0000-0000-0000-000000000000".into(),
            ssid: Some("Net".into()),
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            bss_type: "infrastructure".into(),
            phy_type: "he".into(),
            rssi_dbm: -60,
            link_quality: 80,
            center_frequency_khz: 5_180_000,
            band,
            channel,
            beacon_period_tu: 100,
            in_reg_domain: true,
            capability_information: 0,
            timestamp: 0,
            host_timestamp: 0,
            rates_mbps: vec![6.0, 12.0],
            ie_data_complete: true,
            information_elements,
        }
    }

    #[test]
    fn ie_range_must_stay_inside_the_native_allocation() {
        let allocation = 1000usize;
        let entry = 1100usize;
        let offset = std::mem::size_of::<WlanBssEntry>();

        assert_eq!(
            checked_ie_range(allocation, 4096, entry, offset, 100),
            Some((entry + offset, 100))
        );
        assert!(checked_ie_range(allocation, 200, entry, offset, 100).is_none());
        assert!(checked_ie_range(allocation, 4096, entry, 1, 100).is_none());
        assert!(checked_ie_range(allocation, 4096, entry, offset, MAX_IE_BYTES + 1).is_none());
    }

    #[test]
    fn scan_refresh_is_complete_only_without_failures_or_timeouts() {
        let mut refresh = ScanRefresh {
            requested: 1,
            completed: 1,
            failed: 0,
            timed_out: 0,
            elapsed_ms: 10,
            observed_at_epoch_seconds: 0,
            interfaces: Vec::new(),
        };
        assert!(refresh.is_complete());
        refresh.failed = 1;
        assert!(!refresh.is_complete());
    }
}
