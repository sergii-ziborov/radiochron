//! Native Windows WLAN collectors.
//!
//! This module is the whole point of RadioChron's "no C#, no PowerShell"
//! thesis. The predecessor reached `wlanapi.dll` by compiling embedded C# at
//! runtime through PowerShell `Add-Type`; here we call the same functions
//! directly through our own FFI declarations (see [`sys`]) — no shell, no .NET,
//! no runtime code generation, and no heavyweight build toolchain.

use serde::Serialize;

#[cfg(feature = "analyze")]
pub mod analyze;
#[cfg(feature = "scan")]
pub mod bss;
#[cfg(feature = "sample")]
pub mod sample;
pub mod sys;

use sys::{Dot11Ssid, Guid, WlanConnectionAttributes, WlanInterfaceInfoList};

/// RAII owner of the WLAN client handle.
pub(crate) struct WlanClient {
    pub(crate) handle: sys::Handle,
}

/// RAII owner for buffers allocated by wlanapi. Keeping this separate from the
/// client handle makes every early return and `?` path release native memory.
pub(crate) struct WlanAllocation(*mut core::ffi::c_void);

impl WlanAllocation {
    /// # Safety
    /// `ptr` must be a non-null buffer returned by a wlanapi function whose
    /// contract requires `WlanFreeMemory`.
    pub(crate) unsafe fn new(ptr: *mut core::ffi::c_void) -> Self {
        debug_assert!(!ptr.is_null());
        Self(ptr)
    }
}

impl Drop for WlanAllocation {
    fn drop(&mut self) {
        if let Ok(api) = sys::api() {
            unsafe { (api.free_memory)(self.0) };
        }
    }
}

impl WlanClient {
    pub(crate) fn open() -> anyhow::Result<Self> {
        let api = sys::api()?;
        let mut negotiated: u32 = 0;
        let mut handle: sys::Handle = std::ptr::null_mut();

        let ret = unsafe {
            (api.open_handle)(
                sys::WLAN_API_VERSION_2_0,
                std::ptr::null_mut(),
                &mut negotiated,
                &mut handle,
            )
        };
        if ret != 0 {
            if !handle.is_null() {
                unsafe { (api.close_handle)(handle, std::ptr::null_mut()) };
            }
            anyhow::bail!("WlanOpenHandle failed (code {ret})");
        }

        Ok(Self { handle })
    }
}

impl Drop for WlanClient {
    fn drop(&mut self) {
        if let Ok(api) = sys::api() {
            unsafe {
                (api.close_handle)(self.handle, std::ptr::null_mut());
            }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_error: Option<String>,
}

/// Collect the GUID of every WLAN interface on the machine.
#[cfg(feature = "scan")]
pub(crate) fn interface_guids(client: &WlanClient) -> anyhow::Result<Vec<Guid>> {
    let api = sys::api()?;

    unsafe {
        let mut list_ptr: *mut WlanInterfaceInfoList = std::ptr::null_mut();
        let ret = (api.enum_interfaces)(client.handle, std::ptr::null_mut(), &mut list_ptr);
        let allocation = (!list_ptr.is_null()).then(|| WlanAllocation::new(list_ptr.cast()));
        if ret != 0 || list_ptr.is_null() {
            anyhow::bail!("WlanEnumInterfaces failed (code {ret})");
        }

        let _allocation = allocation.expect("non-null list has an owner");
        let list = &*list_ptr;
        let guids =
            std::slice::from_raw_parts(list.interface_info.as_ptr(), list.num_items as usize)
                .iter()
                .map(|info| info.interface_guid)
                .collect();

        Ok(guids)
    }
}

/// Enumerate every WLAN interface and, for each, its current connection (if any).
pub fn wifi_status() -> anyhow::Result<Vec<WifiStatus>> {
    let client = WlanClient::open()?;
    let api = sys::api()?;
    let mut out = Vec::new();

    unsafe {
        let mut list_ptr: *mut WlanInterfaceInfoList = std::ptr::null_mut();
        let ret = (api.enum_interfaces)(client.handle, std::ptr::null_mut(), &mut list_ptr);
        let allocation = (!list_ptr.is_null()).then(|| WlanAllocation::new(list_ptr.cast()));
        if ret != 0 || list_ptr.is_null() {
            anyhow::bail!("WlanEnumInterfaces failed (code {ret})");
        }

        let _allocation = allocation.expect("non-null list has an owner");
        let list = &*list_ptr;
        let items =
            std::slice::from_raw_parts(list.interface_info.as_ptr(), list.num_items as usize);

        for info in items {
            let interface = WlanInterface {
                guid: guid_to_string(&info.interface_guid),
                description: wide_to_string(&info.interface_description),
                state: interface_state(info.state),
            };
            let (connection, connection_error) = if info.state == 1 {
                match query_current_connection(client.handle, &info.interface_guid) {
                    Ok(connection) => (connection, None),
                    Err(error) => (None, Some(error.to_string())),
                }
            } else {
                (None, None)
            };
            out.push(WifiStatus {
                interface,
                connection,
                connection_error,
            });
        }
    }

    Ok(out)
}

/// Query the current connection for one interface.
///
/// The caller only invokes this after enumeration reports `connected`. A
/// failure here is therefore collector evidence and is propagated instead of
/// being rewritten as an ordinary disconnect.
unsafe fn query_current_connection(
    handle: sys::Handle,
    guid: &Guid,
) -> anyhow::Result<Option<CurrentConnection>> {
    let api = sys::api()?;
    let mut data_size: u32 = 0;
    let mut data_ptr: *mut core::ffi::c_void = std::ptr::null_mut();

    let ret = (api.query_interface)(
        handle,
        guid as *const Guid,
        sys::WLAN_INTF_OPCODE_CURRENT_CONNECTION,
        std::ptr::null_mut(),
        &mut data_size,
        &mut data_ptr,
        std::ptr::null_mut(),
    );
    let allocation = (!data_ptr.is_null()).then(|| WlanAllocation::new(data_ptr));
    if ret != 0 || data_ptr.is_null() {
        anyhow::bail!("WlanQueryInterface failed (code {ret})");
    }

    let _allocation = allocation.expect("non-null query buffer has an owner");
    if (data_size as usize) < std::mem::size_of::<WlanConnectionAttributes>() {
        anyhow::bail!(
            "WlanQueryInterface returned a truncated connection buffer ({data_size} bytes)"
        );
    }

    let attrs = &*(data_ptr as *const WlanConnectionAttributes);
    let assoc = &attrs.association;
    let quality = assoc.signal_quality;

    let connection = CurrentConnection {
        profile_name: nonempty(wide_to_string(&attrs.profile_name)),
        ssid: ssid_to_string(&assoc.dot11_ssid),
        bssid: Some(mac_to_string(&assoc.dot11_bssid)),
        phy_type: phy_type(assoc.dot11_phy_type),
        signal_quality: quality,
        rssi_dbm_estimate: quality_to_rssi(quality),
        rx_rate_kbps: assoc.rx_rate,
        tx_rate_kbps: assoc.tx_rate,
    };

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

pub(crate) fn phy_type(t: i32) -> String {
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

pub(crate) fn ssid_to_string(ssid: &Dot11Ssid) -> Option<String> {
    let len = (ssid.ssid_length as usize).min(ssid.ssid.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&ssid.ssid[..len]).to_string())
}

pub(crate) fn mac_to_string(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn guid_to_string(g: &Guid) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_quality_maps_onto_the_windows_dbm_scale() {
        assert_eq!(quality_to_rssi(0), -100);
        assert_eq!(quality_to_rssi(100), -50);
        assert_eq!(quality_to_rssi(50), -75);
        // Out-of-range input is clamped, never wrapped.
        assert_eq!(quality_to_rssi(255), -50);
    }

    #[test]
    fn wide_string_stops_at_the_nul_terminator() {
        let mut buf = [0u16; 8];
        for (i, c) in "wlan".encode_utf16().enumerate() {
            buf[i] = c;
        }
        assert_eq!(wide_to_string(&buf), "wlan");
    }

    #[test]
    fn ssid_honours_the_declared_length() {
        let mut ssid = Dot11Ssid {
            ssid_length: 5,
            ssid: [0; 32],
        };
        ssid.ssid[..5].copy_from_slice(b"MyNet");
        assert_eq!(ssid_to_string(&ssid).as_deref(), Some("MyNet"));

        let empty = Dot11Ssid {
            ssid_length: 0,
            ssid: [0; 32],
        };
        assert_eq!(ssid_to_string(&empty), None);
    }

    #[test]
    fn mac_is_lowercase_colon_separated() {
        assert_eq!(
            mac_to_string(&[0xa4, 0x2b, 0x8c, 0x00, 0x1f, 0xe0]),
            "a4:2b:8c:00:1f:e0"
        );
    }
}
