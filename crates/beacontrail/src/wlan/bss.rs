//! Nearby BSS enumeration and 802.11 Information Element parsing.
//!
//! This is the module that justifies the whole rewrite. The predecessor could
//! not get dBm RSSI, center frequency, capability bits or raw IE bytes out of
//! `netsh`, so it compiled a C# `WlanGetNetworkBssList` shim at runtime through
//! PowerShell `Add-Type`. Here the same call is plain FFI, and the IE walk —
//! which was already raw-byte logic in that C# — becomes a safe slice walk.

use serde::Serialize;

use super::sys::{self, Guid, WlanBssEntry, WlanBssList};
use super::{mac_to_string, phy_type, ssid_to_string, WlanClient};

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
    pub ssid: Option<String>,
    pub bssid: String,
    pub band: &'static str,
    pub channel: Option<u16>,
    pub rssi_dbm: i32,
    pub phy_type: String,
    /// "rsn", "wpa" (legacy, pre-RSN) or "open".
    pub security: &'static str,
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
            ssid: entry.ssid.clone(),
            bssid: entry.bssid.clone(),
            band: entry.band,
            channel: entry.channel,
            rssi_dbm: entry.rssi_dbm,
            phy_type: entry.phy_type.clone(),
            security: if ie.has_rsn {
                "rsn"
            } else if ie.has_wpa {
                "wpa"
            } else {
                "open"
            },
            caps: caps.join(","),
        }
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
    let api = sys::api()?;
    let mut requested = 0usize;

    for guid in super::interface_guids(&client)? {
        let ret = unsafe {
            (api.scan)(
                client.handle,
                &guid as *const Guid,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            requested += 1;
        }
    }

    Ok(requested)
}

/// Enumerate the cached BSS list for every WLAN interface.
pub fn bss_list() -> anyhow::Result<Vec<BssEntry>> {
    let client = WlanClient::open()?;
    let mut out = Vec::new();

    for guid in super::interface_guids(&client)? {
        collect_for_interface(client.handle, &guid, &mut out)?;
    }

    Ok(out)
}

fn collect_for_interface(
    handle: sys::Handle,
    guid: &Guid,
    out: &mut Vec<BssEntry>,
) -> anyhow::Result<()> {
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
        // A radio that is off or busy returns a non-zero code. That is not fatal
        // for the other interfaces, so skip rather than abort the whole call.
        if ret != 0 || list_ptr.is_null() {
            return Ok(());
        }

        let list = &*list_ptr;
        let entries =
            std::slice::from_raw_parts(list.bss_entries.as_ptr(), list.num_items as usize);

        let interface_guid = super::guid_to_string(guid);
        for entry in entries {
            out.push(read_entry(entry, &interface_guid));
        }

        (api.free_memory)(list_ptr as *mut core::ffi::c_void);
    }

    Ok(())
}

/// # Safety
/// `entry` must point into a live `WLAN_BSS_LIST` allocation, because the IE
/// bytes live at `entry + ie_offset` inside that same allocation.
unsafe fn read_entry(entry: &WlanBssEntry, interface_guid: &str) -> BssEntry {
    let base = entry as *const WlanBssEntry as *const u8;

    // Bound the IE blob defensively: a malformed or hostile beacon must not turn
    // into an out-of-bounds read. 4096 mirrors the original C# guard.
    let ie_bytes: &[u8] = if entry.ie_offset > 0 && entry.ie_size > 0 && entry.ie_size <= 4096 {
        std::slice::from_raw_parts(base.add(entry.ie_offset as usize), entry.ie_size as usize)
    } else {
        &[]
    };

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
        information_elements: parse_information_elements(ie_bytes),
    }
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
        element_ids: ids,
        names,
        extension_ids,
        vendor_ouis,
    }
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
            information_elements,
        }
    }
}
