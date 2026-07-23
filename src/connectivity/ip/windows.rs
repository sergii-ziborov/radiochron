use std::net::IpAddr;

use super::fallback_configuration;
use crate::connectivity::{IpAssignment, IpConfiguration};
#[cfg(windows)]
pub(super) fn platform_inspect(
    interface_id: &str,
    _description: &str,
    selected: Option<IpAddr>,
) -> IpConfiguration {
    use core::ffi::{c_char, c_void};

    #[repr(C)]
    struct IpAddrString {
        next: *mut IpAddrString,
        ip_address: [c_char; 16],
        ip_mask: [c_char; 16],
        context: u32,
    }

    #[repr(C)]
    struct IpAdapterInfo {
        next: *mut IpAdapterInfo,
        combo_index: u32,
        adapter_name: [c_char; 260],
        description: [c_char; 132],
        address_length: u32,
        address: [u8; 8],
        index: u32,
        adapter_type: u32,
        dhcp_enabled: u32,
        current_ip_address: *mut IpAddrString,
        ip_address_list: IpAddrString,
        gateway_list: IpAddrString,
        dhcp_server: IpAddrString,
    }

    type GetAdaptersInfo =
        unsafe extern "system" fn(adapter_info: *mut IpAdapterInfo, size: *mut u32) -> u32;

    let fallback = || {
        fallback_configuration(
            selected,
            "GetAdaptersInfo did not return the associated WLAN adapter",
        )
    };

    let Some(module) = crate::dll::load_system_library("iphlpapi.dll") else {
        return fallback();
    };
    let Some(symbol) = crate::dll::symbol(module, c"GetAdaptersInfo") else {
        return fallback();
    };
    let function: GetAdaptersInfo =
        unsafe { std::mem::transmute::<*mut c_void, GetAdaptersInfo>(symbol) };
    let mut size = 0u32;
    unsafe { function(core::ptr::null_mut(), &mut size) };
    if size == 0 {
        return fallback();
    }
    let words = (size as usize).div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0usize; words];
    let first = storage.as_mut_ptr().cast::<IpAdapterInfo>();
    if unsafe { function(first, &mut size) } != 0 {
        return fallback();
    }

    let wanted = interface_id.trim_matches(['{', '}']).to_ascii_lowercase();
    let mut current = first;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let name = c_string(&adapter.adapter_name)
            .trim_matches(['{', '}'])
            .to_ascii_lowercase();
        if name == wanted {
            let mut addresses = list(&adapter.ip_address_list);
            if let Some(address) = selected.map(|ip| ip.to_string()) {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
            let gateway = list(&adapter.gateway_list)
                .into_iter()
                .find(|value| value != "0.0.0.0");
            return IpConfiguration {
                assignment: if adapter.dhcp_enabled != 0 {
                    IpAssignment::Dhcp
                } else {
                    IpAssignment::Static
                },
                addresses,
                gateway,
                evidence: format!(
                    "Windows IP Helper reports DhcpEnabled={}",
                    adapter.dhcp_enabled
                ),
            };
        }
        current = adapter.next;
    }
    return fallback();

    fn c_string(bytes: &[c_char]) -> String {
        let len = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), len)
        })
        .into_owned()
    }

    fn list(first: &IpAddrString) -> Vec<String> {
        let mut output = Vec::new();
        let mut current = first as *const IpAddrString;
        while !current.is_null() {
            let item = unsafe { &*current };
            let address = c_string(&item.ip_address);
            if !address.is_empty() && address != "0.0.0.0" {
                output.push(address);
            }
            current = item.next;
        }
        output
    }
}
