//! Hand-written FFI to `wlanapi.dll`.
//!
//! We deliberately do not depend on the `windows` crate. We need seven
//! functions and a handful of structs; the crate would pull in the
//! `windows-link` / `raw-dylib` machinery, which on the `*-windows-gnu` target
//! requires `dlltool.exe` from a full mingw-w64 install, and on `*-windows-msvc`
//! requires the multi-gigabyte Visual C++ build tools plus the Windows SDK.
//!
//! Instead the DLL is resolved at run time through `LoadLibraryW` /
//! `GetProcAddress` (kernel32, whose import library ships with the toolchain).
//! No import library for `wlanapi` is needed, so the crate builds with nothing
//! but a stock `rustup` toolchain — and it degrades honestly on a machine with
//! no WLAN service instead of failing to start.
//!
//! Struct layouts mirror `wlanapi.h` exactly; `#[repr(C)]` gives them the same
//! field order, alignment and padding the C compiler produces.

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;

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
type WlanFreeMemoryFn = unsafe extern "system" fn(*mut c_void);

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(file_name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const c_char) -> *mut c_void;
}

/// Load a system DLL by name, or `None` if it is unavailable.
///
/// Shared with the event-log module: `wevtapi` has no import library in the
/// toolchain either, so it is resolved the same way.
pub(crate) fn load_system_library(name: &str) -> Option<*mut c_void> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };

    if module.is_null() {
        None
    } else {
        Some(module)
    }
}

/// Resolve an exported symbol. `name` must be NUL-terminated ANSI.
pub(crate) fn symbol(module: *mut c_void, name: &std::ffi::CStr) -> Option<*mut c_void> {
    let ptr = unsafe { GetProcAddress(module, name.as_ptr()) };

    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

/// The subset of `wlanapi.dll` BeaconTrail uses, resolved once at first call.
pub struct WlanApi {
    pub open_handle: WlanOpenHandleFn,
    pub close_handle: WlanCloseHandleFn,
    pub enum_interfaces: WlanEnumInterfacesFn,
    pub query_interface: WlanQueryInterfaceFn,
    pub get_network_bss_list: WlanGetNetworkBssListFn,
    pub scan: WlanScanFn,
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
    // UTF-16, NUL-terminated, as LoadLibraryW requires.
    let name: Vec<u16> = "wlanapi.dll\0".encode_utf16().collect();
    let module = LoadLibraryW(name.as_ptr());
    if module.is_null() {
        return None;
    }

    // The target type is spelled out at every call site: an implicit transmute
    // to a function pointer is exactly the kind of thing that should never be
    // inferred.
    macro_rules! sym {
        ($name:literal, $ty:ty) => {{
            let ptr = GetProcAddress(module, $name.as_ptr());
            if ptr.is_null() {
                return None;
            }
            std::mem::transmute::<*mut c_void, $ty>(ptr)
        }};
    }

    Some(WlanApi {
        open_handle: sym!(c"WlanOpenHandle", WlanOpenHandleFn),
        close_handle: sym!(c"WlanCloseHandle", WlanCloseHandleFn),
        enum_interfaces: sym!(c"WlanEnumInterfaces", WlanEnumInterfacesFn),
        query_interface: sym!(c"WlanQueryInterface", WlanQueryInterfaceFn),
        get_network_bss_list: sym!(c"WlanGetNetworkBssList", WlanGetNetworkBssListFn),
        scan: sym!(c"WlanScan", WlanScanFn),
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
        // 4-byte aligned GUID + 512-byte description + 4-byte state.
        assert_eq!(std::mem::size_of::<WlanInterfaceInfo>(), 532);
        // Contains u64 fields, so the struct is 8-byte aligned.
        assert_eq!(std::mem::align_of::<WlanBssEntry>(), 8);
    }
}
