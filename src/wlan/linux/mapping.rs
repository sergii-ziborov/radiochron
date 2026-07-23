use super::status::{interface_id, Interface};
use super::*;

#[derive(Debug)]
pub(super) struct ParsedBss {
    pub(super) entry: BssEntry,
    pub(super) associated: bool,
    pub(super) bssid: [u8; 6],
}
pub(super) fn scan_cache(
    socket: &mut GenericSocket,
    interface: &Interface,
) -> std::io::Result<Vec<ParsedBss>> {
    let mut request = Vec::new();
    push_u32(&mut request, ATTR_IFINDEX, interface.index);
    let replies = socket.transact(CMD_GET_SCAN, request, true)?;
    let mut output = Vec::new();

    for reply in replies {
        for attribute in attributes(&reply.attributes) {
            if attribute.kind == ATTR_BSS {
                if let Some(entry) = parse_bss(interface, attribute.value) {
                    output.push(entry);
                }
            }
        }
    }
    Ok(output)
}

fn parse_bss(interface: &Interface, bytes: &[u8]) -> Option<ParsedBss> {
    let mut bssid = None;
    let mut frequency_mhz = None;
    let mut tsf = 0;
    let mut beacon_interval = 0;
    let mut capability = 0;
    let mut ies = None;
    let mut beacon_ies = None;
    let mut signal_mbm = None;
    let mut signal_unspecified = None;
    let mut status = None;
    let mut scan_width = None;
    let mut last_seen_boottime = 0;

    for attribute in attributes(bytes) {
        match attribute.kind {
            BSS_BSSID if attribute.value.len() >= 6 => bssid = attribute.value[..6].try_into().ok(),
            BSS_FREQUENCY => frequency_mhz = read_u32(attribute.value),
            BSS_TSF => tsf = read_u64(attribute.value).unwrap_or(0),
            BSS_BEACON_INTERVAL => beacon_interval = read_u16(attribute.value).unwrap_or(0),
            BSS_CAPABILITY => capability = read_u16(attribute.value).unwrap_or(0),
            BSS_INFORMATION_ELEMENTS => ies = Some(attribute.value),
            BSS_SIGNAL_MBM => signal_mbm = read_u32(attribute.value).map(|value| value as i32),
            BSS_SIGNAL_UNSPEC => signal_unspecified = attribute.value.first().copied(),
            BSS_STATUS => status = read_u32(attribute.value),
            BSS_BEACON_IES => beacon_ies = Some(attribute.value),
            BSS_CHAN_WIDTH => scan_width = read_u32(attribute.value),
            BSS_LAST_SEEN_BOOTTIME => last_seen_boottime = read_u64(attribute.value).unwrap_or(0),
            _ => {}
        }
    }

    let bssid = bssid?;
    let center_frequency_khz = frequency_mhz?.saturating_mul(1000);
    let ie_bytes = ies.or(beacon_ies).unwrap_or_default();
    let ie_data_complete = !ie_bytes.is_empty() && ie_bytes.len() <= 2324;
    let information_elements = if ie_data_complete {
        parse_information_elements(ie_bytes)
    } else {
        InformationElements::default()
    };
    let rssi_dbm = signal_mbm
        .map(|value| value / 100)
        .or_else(|| signal_unspecified.map(|quality| -100 + i32::from(quality.min(100)) / 2))
        .unwrap_or(-100);
    let (band, channel) = band_and_channel(center_frequency_khz);
    let mut information_elements = information_elements;
    if information_elements.channel_width_mhz.is_none() {
        information_elements.channel_width_mhz = scan_width.and_then(control_channel_width);
    }

    Some(ParsedBss {
        associated: status == Some(BSS_STATUS_ASSOCIATED),
        bssid,
        entry: BssEntry {
            interface_guid: interface_id(interface),
            ssid: ssid_from_ies(ie_bytes),
            bssid: mac_to_string(&bssid),
            bss_type: "infrastructure".to_string(),
            phy_type: phy_from_ies(&information_elements, band).to_string(),
            rssi_dbm,
            link_quality: quality_from_rssi(rssi_dbm),
            center_frequency_khz,
            band,
            channel,
            beacon_period_tu: beacon_interval,
            in_reg_domain: true,
            capability_information: capability,
            reported_security: None,
            timestamp: tsf,
            host_timestamp: last_seen_boottime,
            rates_mbps: rates_from_ies(ie_bytes),
            ie_data_complete,
            information_elements,
        },
    })
}

pub(super) fn ssid_from_ies(bytes: &[u8]) -> Option<String> {
    for (id, value) in raw_information_elements(bytes) {
        if id == 0 {
            return (!value.is_empty()).then(|| String::from_utf8_lossy(value).into_owned());
        }
    }
    None
}

pub(super) fn rates_from_ies(bytes: &[u8]) -> Vec<f64> {
    let mut rates = Vec::new();
    for (id, value) in raw_information_elements(bytes) {
        if matches!(id, 1 | 50) {
            for rate in value {
                let rate = f64::from(rate & 0x7f) * 0.5;
                if rate > 0.0 && !rates.contains(&rate) {
                    rates.push(rate);
                }
            }
        }
    }
    rates.sort_by(f64::total_cmp);
    rates
}

fn raw_information_elements(mut bytes: &[u8]) -> Vec<(u8, &[u8])> {
    let mut output = Vec::new();
    while bytes.len() >= 2 {
        let length = usize::from(bytes[1]);
        if bytes.len() < length + 2 {
            break;
        }
        output.push((bytes[0], &bytes[2..length + 2]));
        bytes = &bytes[length + 2..];
    }
    output
}

pub(super) fn phy_from_ies(ies: &InformationElements, band: &str) -> &'static str {
    if ies.has_eht {
        "eht"
    } else if ies.has_he {
        "he"
    } else if ies.has_vht {
        "vht"
    } else if ies.has_ht {
        "ht"
    } else if band == "2.4GHz" {
        "erp"
    } else {
        "ofdm"
    }
}

fn control_channel_width(value: u32) -> Option<u16> {
    match value {
        0 => Some(20),
        1 => Some(10),
        2 => Some(5),
        3 => Some(1),
        4 => Some(2),
        _ => None,
    }
}
