//! Hand-written FFI to `wlanapi.dll`.
//!
//! We deliberately do not depend on the `windows` crate. We need eight
//! functions and a handful of structs; the crate would pull in the
//! `windows-link` / `raw-dylib` machinery, which on the `*-windows-gnu` target
//! requires `dlltool.exe` from a full mingw-w64 install, and on `*-windows-msvc`
//! requires the multi-gigabyte Visual C++ build tools plus the Windows SDK.
//!
//! Instead the DLL is resolved at run time through system32-only `LoadLibraryExW` /
//! `GetProcAddress` (kernel32, whose import library ships with the toolchain).
//! No import library for `wlanapi` is needed, so the crate builds with nothing
//! but a stock `rustup` toolchain — and it degrades honestly on a machine with
//! no WLAN service instead of failing to start.
//!
//! Struct layouts mirror `wlanapi.h` exactly; `#[repr(C)]` gives them the same
//! field order, alignment and padding the C compiler produces.

use std::ffi::c_void;
use std::sync::OnceLock;

use crate::dll::{load_system_library, symbol};

pub type Handle = *mut c_void;

/// `WLAN_API_VERSION_2_0` — the client version for Vista and later.
pub const WLAN_API_VERSION_2_0: u32 = 2;

/// `wlan_intf_opcode_current_connection` — 8th member of `WLAN_INTF_OPCODE`,
/// counting from `wlan_intf_opcode_autoconf_start = 0`.
pub const WLAN_INTF_OPCODE_CURRENT_CONNECTION: i32 = 7;

/// `dot11_BSS_type_any`.
pub const DOT11_BSS_TYPE_ANY: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
pub struct WlanNotificationData {
    pub notification_source: u32,
    pub notification_code: u32,
    pub interface_guid: Guid,
    pub data_size: u32,
    pub data: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dot11Ssid {
    pub ssid_length: u32,
    pub ssid: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WlanInterfaceInfo {
    pub interface_guid: Guid,
    pub interface_description: [u16; 256],
    pub state: i32,
}

#[repr(C)]
pub struct WlanInterfaceInfoList {
    pub num_items: u32,
    pub index: u32,
    /// Variable-length in C; read `num_items` entries from here.
    pub interface_info: [WlanInterfaceInfo; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WlanAssociationAttributes {
    pub dot11_ssid: Dot11Ssid,
    pub dot11_bss_type: i32,
    pub dot11_bssid: [u8; 6],
    pub dot11_phy_type: i32,
    pub dot11_phy_index: u32,
    pub signal_quality: u32,
    pub rx_rate: u32,
    pub tx_rate: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WlanSecurityAttributes {
    pub security_enabled: i32,
    pub one_x_enabled: i32,
    pub dot11_auth_algorithm: i32,
    pub dot11_cipher_algorithm: i32,
}

#[repr(C)]
pub struct WlanConnectionAttributes {
    pub state: i32,
    pub connection_mode: i32,
    pub profile_name: [u16; 256],
    pub association: WlanAssociationAttributes,
    pub security: WlanSecurityAttributes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WlanRateSet {
    pub rate_set_length: u32,
    pub rate_set: [u16; 126],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WlanBssEntry {
    pub dot11_ssid: Dot11Ssid,
    pub phy_id: u32,
    pub dot11_bssid: [u8; 6],
    pub dot11_bss_type: i32,
    pub dot11_bss_phy_type: i32,
    pub rssi: i32,
    pub link_quality: u32,
    pub in_reg_domain: u8,
    pub beacon_period: u16,
    pub timestamp: u64,
    pub host_timestamp: u64,
    pub capability_information: u16,
    pub ch_center_frequency: u32,
    pub rate_set: WlanRateSet,
    pub ie_offset: u32,
    pub ie_size: u32,
}

#[repr(C)]
pub struct WlanBssList {
    pub total_size: u32,
    pub num_items: u32,
    /// Variable-length in C; read `num_items` entries from here.
    pub bss_entries: [WlanBssEntry; 1],
}

type WlanOpenHandleFn = unsafe extern "system" fn(u32, *mut c_void, *mut u32, *mut Handle) -> u32;
type WlanCloseHandleFn = unsafe extern "system" fn(Handle, *mut c_void) -> u32;
type WlanEnumInterfacesFn =
    unsafe extern "system" fn(Handle, *mut c_void, *mut *mut WlanInterfaceInfoList) -> u32;
type WlanQueryInterfaceFn = unsafe extern "system" fn(
    Handle,
    *const Guid,
    i32,
    *mut c_void,
    *mut u32,
    *mut *mut c_void,
    *mut i32,
) -> u32;
type WlanGetNetworkBssListFn = unsafe extern "system" fn(
    Handle,
    *const Guid,
    *const Dot11Ssid,
    i32,
    i32,
    *mut c_void,
    *mut *mut WlanBssList,
) -> u32;
type WlanScanFn = unsafe extern "system" fn(
    Handle,
    *const Guid,
    *const Dot11Ssid,
    *const c_void,
    *mut c_void,
) -> u32;
pub type WlanNotificationCallback =
    Option<unsafe extern "system" fn(*mut WlanNotificationData, *mut c_void)>;
type WlanRegisterNotificationFn = unsafe extern "system" fn(
    Handle,
    u32,
    i32,
    WlanNotificationCallback,
    *mut c_void,
    *mut c_void,
    *mut u32,
) -> u32;
type WlanFreeMemoryFn = unsafe extern "system" fn(*mut c_void);

// Runtime DLL resolution lives in `crate::dll`, shared with the event-log
// module: `wevtapi` has no import library in the toolchain either.

/// The subset of `wlanapi.dll` RadioChron uses, resolved once at first call.
pub struct WlanApi {
    pub open_handle: WlanOpenHandleFn,
    pub close_handle: WlanCloseHandleFn,
    pub enum_interfaces: WlanEnumInterfacesFn,
    pub query_interface: WlanQueryInterfaceFn,
    pub get_network_bss_list: WlanGetNetworkBssListFn,
    pub scan: WlanScanFn,
    pub register_notification: WlanRegisterNotificationFn,
    pub free_memory: WlanFreeMemoryFn,
}

static API: OnceLock<Option<WlanApi>> = OnceLock::new();

/// Resolve `wlanapi.dll`, caching the result for the process lifetime.
///
/// Returns an error rather than panicking when the DLL or a symbol is missing,
/// so a machine without the WLAN service reports a clean diagnostic.
pub fn api() -> anyhow::Result<&'static WlanApi> {
    API.get_or_init(|| unsafe { load() })
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("wlanapi.dll unavailable: no WLAN service on this machine"))
}

unsafe fn load() -> Option<WlanApi> {
    let module = load_system_library("wlanapi.dll")?;

    // The target type is spelled out at every call site: an implicit transmute
    // to a function pointer is exactly the kind of thing that should never be
    // inferred.
    macro_rules! sym {
        ($name:literal, $ty:ty) => {{
            std::mem::transmute::<*mut c_void, $ty>(symbol(module, $name)?)
        }};
    }

    Some(WlanApi {
        open_handle: sym!(c"WlanOpenHandle", WlanOpenHandleFn),
        close_handle: sym!(c"WlanCloseHandle", WlanCloseHandleFn),
        enum_interfaces: sym!(c"WlanEnumInterfaces", WlanEnumInterfacesFn),
        query_interface: sym!(c"WlanQueryInterface", WlanQueryInterfaceFn),
        get_network_bss_list: sym!(c"WlanGetNetworkBssList", WlanGetNetworkBssListFn),
        scan: sym!(c"WlanScan", WlanScanFn),
        register_notification: sym!(c"WlanRegisterNotification", WlanRegisterNotificationFn),
        free_memory: sym!(c"WlanFreeMemory", WlanFreeMemoryFn),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards against silent ABI drift: these sizes must match `wlanapi.h`
    /// under the MSVC/mingw x64 layout rules.
    #[test]
    fn struct_layouts_match_the_c_abi() {
        assert_eq!(std::mem::size_of::<Guid>(), 16);
        assert_eq!(std::mem::size_of::<Dot11Ssid>(), 36);
        assert_eq!(std::mem::size_of::<WlanRateSet>(), 256);
        assert_eq!(
            std::mem::size_of::<WlanNotificationData>(),
            if std::mem::size_of::<usize>() == 8 {
                40
            } else {
                32
            }
        );
        // 4-byte aligned GUID + 512-byte description + 4-byte state.
        assert_eq!(std::mem::size_of::<WlanInterfaceInfo>(), 532);
        // Contains u64 fields, so the struct is 8-byte aligned.
        assert_eq!(std::mem::align_of::<WlanBssEntry>(), 8);
    }
}
