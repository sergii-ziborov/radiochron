//! Linux collector backed directly by the kernel's `nl80211` family.

mod netlink;

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use super::bss::{
    band_and_channel, parse_information_elements, refresh_age, BssCollection, BssEntry,
    BssInterfaceError, InformationElements, ScanInterfaceResult, ScanRefresh,
};
use super::{mac_to_string, quality_from_rssi, CurrentConnection, WifiStatus, WlanInterface};
use netlink::{attributes, push_attribute, push_u32, read_u16, read_u32, read_u64, GenericSocket};

// Numeric values are the stable userspace ABI from linux/uapi/nl80211.h.
const CMD_GET_INTERFACE: u8 = 5;
const CMD_GET_STATION: u8 = 17;
const CMD_GET_SCAN: u8 = 32;
const CMD_TRIGGER_SCAN: u8 = 33;
const CMD_NEW_SCAN_RESULTS: u8 = 34;
const CMD_SCAN_ABORTED: u8 = 35;

const ATTR_IFINDEX: u16 = 3;
const ATTR_IFNAME: u16 = 4;
const ATTR_IFTYPE: u16 = 5;
const ATTR_MAC: u16 = 6;
const ATTR_STA_INFO: u16 = 21;
const ATTR_SCAN_SSIDS: u16 = 45;
const ATTR_BSS: u16 = 47;
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

static LAST_REFRESH_EPOCH: AtomicI64 = AtomicI64::new(0);

#[derive(Debug, Clone)]
struct Interface {
    index: u32,
    name: String,
    interface_type: u32,
}

#[derive(Debug, Default)]
struct StationInfo {
    signal_dbm: Option<i32>,
    tx_rate_kbps: Option<u32>,
    rx_rate_kbps: Option<u32>,
}

#[derive(Debug)]
struct ParsedBss {
    entry: BssEntry,
    associated: bool,
    bssid: [u8; 6],
}

pub fn wifi_status() -> anyhow::Result<Vec<WifiStatus>> {
    let mut socket = GenericSocket::open()?;
    let interfaces = interfaces(&mut socket)?;
    let mut output = Vec::with_capacity(interfaces.len());

    for interface in interfaces {
        let guid = interface_id(&interface);
        let scanned = scan_cache(&mut socket, &interface);
        let (connection, connection_error) = match scanned {
            Ok(entries) => {
                let associated = entries.into_iter().find(|entry| entry.associated);
                let connection = associated.map(|associated| {
                    let station = station_info(&mut socket, interface.index, associated.bssid)
                        .unwrap_or_default();
                    connection_from_bss(associated.entry, station)
                });
                (connection, None)
            }
            Err(error) => (None, Some(error.to_string())),
        };

        output.push(WifiStatus {
            interface: WlanInterface {
                guid,
                description: interface.name,
                state: if connection.is_some() {
                    "connected".to_string()
                } else {
                    interface_state(interface.interface_type).to_string()
                },
            },
            connection,
            connection_error,
        });
    }

    Ok(output)
}

pub fn request_scan() -> anyhow::Result<usize> {
    let mut socket = GenericSocket::open()?;
    let interfaces = interfaces(&mut socket)?;
    Ok(interfaces
        .iter()
        .filter(|interface| trigger_scan(&mut socket, interface.index).is_ok())
        .count())
}

pub fn scan_and_wait(timeout: Duration) -> anyhow::Result<ScanRefresh> {
    let started = Instant::now();
    let mut commands = GenericSocket::open()?;
    let interfaces = interfaces(&mut commands)?;
    let events = GenericSocket::open()?;
    events.subscribe_scan()?;

    let mut states: BTreeMap<u32, (&Interface, &'static str, Option<u32>)> = interfaces
        .iter()
        .map(|interface| (interface.index, (interface, "pending", None)))
        .collect();
    for interface in &interfaces {
        if let Err(error) = trigger_scan(&mut commands, interface.index) {
            states.insert(interface.index, (interface, "rejected", error_code(&error)));
        }
    }

    let deadline = Instant::now() + timeout;
    while states.values().any(|(_, state, _)| *state == "pending") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        for event in events.receive_events(remaining)? {
            if !matches!(event.command, CMD_NEW_SCAN_RESULTS | CMD_SCAN_ABORTED) {
                continue;
            }
            let ifindex = attributes(&event.attributes)
                .into_iter()
                .find(|attribute| attribute.kind == ATTR_IFINDEX)
                .and_then(|attribute| read_u32(attribute.value));
            let Some(ifindex) = ifindex else { continue };
            if let Some((interface, state, code)) = states.get_mut(&ifindex) {
                *state = if event.command == CMD_NEW_SCAN_RESULTS {
                    "complete"
                } else {
                    "failed"
                };
                *code = None;
                let _ = interface;
            }
        }
    }

    let observed_at_epoch_seconds = crate::time::now_epoch_seconds();
    let results: Vec<ScanInterfaceResult> = states
        .into_values()
        .map(|(interface, state, error_code)| ScanInterfaceResult {
            interface_guid: interface_id(interface),
            status: if state == "pending" {
                "timed_out"
            } else {
                state
            },
            error_code,
        })
        .collect();
    let completed = results
        .iter()
        .filter(|result| result.status == "complete")
        .count();
    if completed > 0 {
        LAST_REFRESH_EPOCH.store(observed_at_epoch_seconds, Ordering::Relaxed);
    }

    Ok(ScanRefresh {
        requested: results
            .iter()
            .filter(|result| result.status != "rejected")
            .count(),
        completed,
        failed: results
            .iter()
            .filter(|result| matches!(result.status, "failed" | "rejected"))
            .count(),
        timed_out: results
            .iter()
            .filter(|result| result.status == "timed_out")
            .count(),
        elapsed_ms: started.elapsed().as_millis(),
        observed_at_epoch_seconds,
        interfaces: results,
    })
}

pub fn last_refresh_age_seconds() -> Option<u64> {
    refresh_age(&LAST_REFRESH_EPOCH)
}

pub fn bss_list() -> anyhow::Result<Vec<BssEntry>> {
    Ok(bss_list_detailed()?.entries)
}

pub fn bss_list_detailed() -> anyhow::Result<BssCollection> {
    let mut socket = GenericSocket::open()?;
    let interfaces = interfaces(&mut socket)?;
    let mut entries = Vec::new();
    let mut interface_errors = Vec::new();

    for interface in interfaces {
        match scan_cache(&mut socket, &interface) {
            Ok(scanned) => entries.extend(scanned.into_iter().map(|entry| entry.entry)),
            Err(error) => interface_errors.push(BssInterfaceError {
                interface_guid: interface_id(&interface),
                error_code: error_code(&error).unwrap_or(u32::MAX),
            }),
        }
    }

    Ok(BssCollection {
        entries,
        interface_errors,
    })
}

fn interfaces(socket: &mut GenericSocket) -> io::Result<Vec<Interface>> {
    let replies = socket.transact(CMD_GET_INTERFACE, Vec::new(), true)?;
    let mut output = Vec::new();
    for reply in replies {
        let mut index = None;
        let mut name = None;
        let mut interface_type = 0;
        for attribute in attributes(&reply.attributes) {
            match attribute.kind {
                ATTR_IFINDEX => index = read_u32(attribute.value),
                ATTR_IFNAME => {
                    let bytes = attribute
                        .value
                        .strip_suffix(&[0])
                        .unwrap_or(attribute.value);
                    name = Some(String::from_utf8_lossy(bytes).into_owned());
                }
                ATTR_IFTYPE => interface_type = read_u32(attribute.value).unwrap_or(0),
                _ => {}
            }
        }
        if let (Some(index), Some(name)) = (index, name) {
            output.push(Interface {
                index,
                name,
                interface_type,
            });
        }
    }
    Ok(output)
}

fn trigger_scan(socket: &mut GenericSocket, ifindex: u32) -> io::Result<()> {
    let mut request = Vec::new();
    push_u32(&mut request, ATTR_IFINDEX, ifindex);
    let mut wildcard = Vec::new();
    push_attribute(&mut wildcard, 1, &[]);
    push_attribute(&mut request, ATTR_SCAN_SSIDS | NLA_F_NESTED, &wildcard);
    socket
        .transact(CMD_TRIGGER_SCAN, request, false)
        .map(|_| ())
}

fn scan_cache(socket: &mut GenericSocket, interface: &Interface) -> io::Result<Vec<ParsedBss>> {
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
            timestamp: tsf,
            host_timestamp: last_seen_boottime,
            rates_mbps: rates_from_ies(ie_bytes),
            ie_data_complete,
            information_elements,
        },
    })
}

fn station_info(
    socket: &mut GenericSocket,
    ifindex: u32,
    bssid: [u8; 6],
) -> io::Result<StationInfo> {
    let mut request = Vec::new();
    push_u32(&mut request, ATTR_IFINDEX, ifindex);
    push_attribute(&mut request, ATTR_MAC, &bssid);
    let replies = socket.transact(CMD_GET_STATION, request, false)?;
    let mut output = StationInfo::default();

    for reply in replies {
        for attribute in attributes(&reply.attributes) {
            if attribute.kind != ATTR_STA_INFO {
                continue;
            }
            for info in attributes(attribute.value) {
                match info.kind {
                    STA_INFO_SIGNAL => {
                        output.signal_dbm = info.value.first().map(|value| i32::from(*value as i8));
                    }
                    STA_INFO_TX_BITRATE => output.tx_rate_kbps = bitrate(info.value),
                    STA_INFO_RX_BITRATE => output.rx_rate_kbps = bitrate(info.value),
                    _ => {}
                }
            }
        }
    }
    Ok(output)
}

fn bitrate(bytes: &[u8]) -> Option<u32> {
    for attribute in attributes(bytes) {
        match attribute.kind {
            RATE_INFO_BITRATE32 => return read_u32(attribute.value).map(|rate| rate * 100),
            RATE_INFO_BITRATE => {
                return read_u16(attribute.value).map(|rate| u32::from(rate) * 100)
            }
            _ => {}
        }
    }
    None
}

fn connection_from_bss(mut entry: BssEntry, station: StationInfo) -> CurrentConnection {
    if let Some(signal) = station.signal_dbm {
        entry.rssi_dbm = signal;
        entry.link_quality = quality_from_rssi(signal);
    }
    CurrentConnection {
        profile_name: entry.ssid.clone(),
        ssid: entry.ssid,
        bssid: Some(entry.bssid),
        phy_type: entry.phy_type,
        signal_quality: entry.link_quality,
        rssi_dbm_estimate: entry.rssi_dbm,
        rx_rate_kbps: station.rx_rate_kbps.unwrap_or(0),
        tx_rate_kbps: station.tx_rate_kbps.unwrap_or(0),
    }
}

fn ssid_from_ies(bytes: &[u8]) -> Option<String> {
    for (id, value) in raw_information_elements(bytes) {
        if id == 0 {
            return (!value.is_empty()).then(|| String::from_utf8_lossy(value).into_owned());
        }
    }
    None
}

fn rates_from_ies(bytes: &[u8]) -> Vec<f64> {
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

fn phy_from_ies(ies: &InformationElements, band: &str) -> &'static str {
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

fn interface_id(interface: &Interface) -> String {
    format!("ifindex:{}", interface.index)
}

fn interface_state(interface_type: u32) -> &'static str {
    match interface_type {
        2 | 8 => "disconnected", // station / P2P client
        3 => "ap",
        6 => "monitor",
        _ => "not_associated",
    }
}

fn error_code(error: &io::Error) -> Option<u32> {
    error.raw_os_error().map(i32::unsigned_abs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(id: u8, value: &[u8]) -> Vec<u8> {
        let mut output = vec![id, value.len() as u8];
        output.extend_from_slice(value);
        output
    }

    #[test]
    fn reads_ssid_and_legacy_rates_from_ie_bytes() {
        let mut bytes = tlv(0, b"FieldNet");
        bytes.extend(tlv(1, &[0x82, 0x84, 0x8b, 0x96]));
        bytes.extend(tlv(50, &[12, 24]));
        assert_eq!(ssid_from_ies(&bytes).as_deref(), Some("FieldNet"));
        assert_eq!(rates_from_ies(&bytes), [1.0, 2.0, 5.5, 6.0, 11.0, 12.0]);
    }

    #[test]
    fn station_bitrate_uses_kernel_hundred_kilobit_units() {
        let mut nested = Vec::new();
        push_u32(&mut nested, RATE_INFO_BITRATE32, 8667);
        assert_eq!(bitrate(&nested), Some(866_700));
    }

    #[test]
    fn phy_prefers_newest_advertised_generation() {
        let information = InformationElements {
            has_ht: true,
            has_he: true,
            ..InformationElements::default()
        };
        assert_eq!(phy_from_ies(&information, "5GHz"), "he");
    }
}
