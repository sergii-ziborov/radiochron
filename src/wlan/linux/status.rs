use std::io;

use super::mapping::scan_cache;
use super::*;

#[derive(Debug, Clone)]
pub(super) struct Interface {
    pub(super) index: u32,
    pub(super) name: String,
    pub(super) interface_type: u32,
}

#[derive(Debug, Default)]
struct StationInfo {
    signal_dbm: Option<i32>,
    tx_rate_kbps: Option<u32>,
    rx_rate_kbps: Option<u32>,
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

pub(super) fn interfaces(socket: &mut GenericSocket) -> io::Result<Vec<Interface>> {
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

pub(super) fn bitrate(bytes: &[u8]) -> Option<u32> {
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

pub(super) fn interface_id(interface: &Interface) -> String {
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

#[cfg(feature = "scan")]
pub(super) fn error_code(error: &io::Error) -> Option<u32> {
    error.raw_os_error().map(i32::unsigned_abs)
}
