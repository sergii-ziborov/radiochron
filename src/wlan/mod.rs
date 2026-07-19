//! Safe-ish wrappers over the native Windows WLAN API (`wlanapi.dll`) via
//! `windows-rs`.
//!
//! This module is the whole point of BeaconTrail's "no C#, no PowerShell"
//! thesis. The original app reached `wlanapi.dll` by compiling embedded C#
//! at runtime through PowerShell `Add-Type`; here we call the same functions
//! (`WlanOpenHandle` / `WlanEnumInterfaces` / `WlanQueryInterface`) directly
//! as typed FFI — no shell, no .NET, no runtime code generation.
//!
//! NOTE: written before the Rust toolchain was available on this machine, so it
//! has not been compiled yet. `windows-rs` signature details (notably whether
//! the WLAN functions return `WIN32_ERROR` — a newtype over `u32` — or a bare
//! `u32`) are the expected first-build fix-up surface; see the `.0` comments.

use serde::Serialize;
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::{
    WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle, WlanQueryInterface,
    wlan_intf_opcode_current_connection, DOT11_SSID, WLAN_API_VERSION_2_0,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST,
};

/// RAII owner of the WLAN client handle.
struct WlanClient {
    handle: HANDLE,
}

impl WlanClient {
    fn open() -> anyhow::Result<Self> {
        let mut negotiated: u32 = 0;
        let mut handle = HANDLE::default();
        let ret = unsafe {
            WlanOpenHandle(WLAN_API_VERSION_2_0, None, &mut negotiated, &mut handle)
        };
        // `ret` is `WIN32_ERROR` (newtype over u32) in current windows-rs. If your
        // pinned windows version returns a bare `u32`, drop the `.0` here and below.
        if ret.0 != 0 {
            anyhow::bail!("WlanOpenHandle failed (code {})", ret.0);
        }
        Ok(Self { handle })
    }
}

impl Drop for WlanClient {
    fn drop(&mut self) {
        unsafe {
            let _ = WlanCloseHandle(self.handle, None);
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WlanInterface {
    pub guid: String,
    pub description: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct CurrentConnection {
    pub profile_name: Option<String>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub phy_type: String,
    /// Windows-reported signal quality, 0..=100.
    pub signal_quality: u32,
    /// Linear estimate Windows itself uses: quality 0 => -100 dBm, 100 => -50 dBm.
    pub rssi_dbm_estimate: i32,
    pub rx_rate_kbps: u32,
    pub tx_rate_kbps: u32,
}

#[derive(Debug, Serialize)]
pub struct WifiStatus {
    pub interface: WlanInterface,
    pub connection: Option<CurrentConnection>,
}

/// Enumerate every WLAN interface and, for each, its current connection (if any).
pub fn wifi_status() -> anyhow::Result<Vec<WifiStatus>> {
    let client = WlanClient::open()?;
    let mut out = Vec::new();

    unsafe {
        let mut list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let ret = WlanEnumInterfaces(client.handle, None, &mut list_ptr);
        if ret.0 != 0 || list_ptr.is_null() {
            anyhow::bail!("WlanEnumInterfaces failed (code {})", ret.0);
        }

        let list = &*list_ptr;
        let items = std::slice::from_raw_parts(
            list.InterfaceInfo.as_ptr(),
            list.dwNumberOfItems as usize,
        );

        for info in items {
            let interface = WlanInterface {
                guid: guid_to_string(&info.InterfaceGuid),
                description: wide_to_string(&info.strInterfaceDescription),
                state: interface_state(info.isState.0),
            };
            let connection =
                query_current_connection(client.handle, &info.InterfaceGuid).unwrap_or(None);
            out.push(WifiStatus { interface, connection });
        }

        WlanFreeMemory(list_ptr as *const core::ffi::c_void);
    }

    Ok(out)
}

/// Query `wlan_intf_opcode_current_connection` for one interface.
///
/// Returns `Ok(None)` when the interface is not associated (Windows returns a
/// non-zero code such as `ERROR_INVALID_STATE`), which is a normal state, not an
/// error worth propagating.
unsafe fn query_current_connection(
    handle: HANDLE,
    guid: &GUID,
) -> anyhow::Result<Option<CurrentConnection>> {
    let mut data_size: u32 = 0;
    let mut data_ptr: *mut core::ffi::c_void = std::ptr::null_mut();

    let ret = WlanQueryInterface(
        handle,
        guid as *const GUID,
        wlan_intf_opcode_current_connection,
        None,
        &mut data_size,
        &mut data_ptr,
        None,
    );
    if ret.0 != 0 || data_ptr.is_null() {
        return Ok(None);
    }

    let attrs = &*(data_ptr as *const WLAN_CONNECTION_ATTRIBUTES);
    let assoc = &attrs.wlanAssociationAttributes;
    let quality = assoc.wlanSignalQuality;

    let connection = CurrentConnection {
        profile_name: nonempty(wide_to_string(&attrs.strProfileName)),
        ssid: ssid_to_string(&assoc.dot11Ssid),
        bssid: Some(mac_to_string(&assoc.dot11Bssid)),
        phy_type: phy_type(assoc.dot11PhyType.0),
        signal_quality: quality,
        rssi_dbm_estimate: quality_to_rssi(quality),
        rx_rate_kbps: assoc.ulRxRate,
        tx_rate_kbps: assoc.ulTxRate,
    };

    WlanFreeMemory(data_ptr as *const core::ffi::c_void);
    Ok(Some(connection))
}

fn quality_to_rssi(quality: u32) -> i32 {
    // Matches the netsh/Windows convention used by the parent project.
    -100 + (quality.min(100) as i32) / 2
}

fn interface_state(state: i32) -> String {
    match state {
        0 => "not_ready",
        1 => "connected",
        2 => "ad_hoc_network_formed",
        3 => "disconnecting",
        4 => "disconnected",
        5 => "associating",
        6 => "discovering",
        7 => "authenticating",
        _ => return format!("unknown_{state}"),
    }
    .to_string()
}

fn phy_type(t: i32) -> String {
    match t {
        1 => "fhss",
        2 => "dsss",
        3 => "irbaseband",
        4 => "ofdm",
        5 => "hrdsss",
        6 => "erp",
        7 => "ht",
        8 => "vht",
        9 => "dmg",
        10 => "he",
        11 => "eht",
        _ => return format!("unknown_{t}"),
    }
    .to_string()
}

fn wide_to_string(w: &[u16]) -> String {
    let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..len])
}

fn ssid_to_string(ssid: &DOT11_SSID) -> Option<String> {
    let len = (ssid.uSSIDLength as usize).min(ssid.ucSSID.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&ssid.ucSSID[..len]).to_string())
}

fn mac_to_string(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn guid_to_string(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

fn nonempty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
