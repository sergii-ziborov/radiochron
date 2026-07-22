use std::net::{IpAddr, ToSocketAddrs, UdpSocket};

use super::{IpAssignment, IpConfiguration};

pub(super) fn inspect(
    interface_id: &str,
    description: &str,
    route_target: Option<&str>,
) -> IpConfiguration {
    let selected_address = route_target.and_then(selected_address);
    platform_inspect(interface_id, description, selected_address)
}

fn selected_address(target: &str) -> Option<IpAddr> {
    let remote = target.to_socket_addrs().ok()?.next()?;
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[cfg(target_os = "linux")]
fn platform_inspect(
    interface_id: &str,
    interface_name: &str,
    selected: Option<IpAddr>,
) -> IpConfiguration {
    use std::fs;
    use std::path::{Path, PathBuf};

    let index = interface_id
        .strip_prefix("ifindex:")
        .unwrap_or(interface_id);
    let mut addresses = selected
        .into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();
    let lease_path = PathBuf::from(format!("/run/systemd/netif/leases/{index}"));
    if let Ok(lease) = fs::read_to_string(&lease_path) {
        let lease_address = value(&lease, "ADDRESS");
        if let Some(address) = lease_address.as_deref() {
            let address = address.split('/').next().unwrap_or(address).to_string();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        return IpConfiguration {
            assignment: IpAssignment::Dhcp,
            addresses,
            gateway: value(&lease, "ROUTER").or_else(|| linux_gateway(interface_name)),
            evidence: format!("active systemd-networkd lease {}", lease_path.display()),
        };
    }

    if network_manager_lease_matches(interface_name, selected) {
        return IpConfiguration {
            assignment: IpAssignment::Dhcp,
            addresses,
            gateway: linux_gateway(interface_name),
            evidence: "active address matches a NetworkManager/dhclient lease".to_string(),
        };
    }

    let link_path = PathBuf::from(format!("/run/systemd/netif/links/{index}"));
    if let Ok(link) = fs::read_to_string(&link_path) {
        if let Some(network_file) = value(&link, "NETWORK_FILE") {
            if let Ok(configuration) = fs::read_to_string(&network_file) {
                let dhcp = ini_value(&configuration, "DHCP").unwrap_or_default();
                let has_static = configuration
                    .lines()
                    .map(str::trim)
                    .any(|line| line.starts_with("Address="));
                if matches!(dhcp.to_ascii_lowercase().as_str(), "no" | "false" | "0") && has_static
                {
                    return IpConfiguration {
                        assignment: IpAssignment::Static,
                        addresses,
                        gateway: linux_gateway(interface_name),
                        evidence: format!(
                            "active systemd-networkd profile {network_file} explicitly disables DHCP and defines Address"
                        ),
                    };
                }
            }
        }
    }

    let assignment = if selected.is_some_and(is_link_local) {
        IpAssignment::LinkLocal
    } else {
        IpAssignment::Unknown
    };
    let evidence = match assignment {
        IpAssignment::LinkLocal => "route selected a link-local address".to_string(),
        _ => "no matching DHCP lease or explicit active static profile was found".to_string(),
    };
    return IpConfiguration {
        assignment,
        addresses,
        gateway: linux_gateway(interface_name),
        evidence,
    };

    fn value(contents: &str, name: &str) -> Option<String> {
        contents.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == name).then(|| value.trim().trim_matches('"').to_string())
        })
    }

    fn ini_value(contents: &str, name: &str) -> Option<String> {
        value(contents, name)
    }

    fn network_manager_lease_matches(interface: &str, selected: Option<IpAddr>) -> bool {
        let Some(selected) = selected else {
            return false;
        };
        let needle = selected.to_string();
        [
            Path::new("/var/lib/NetworkManager"),
            Path::new("/var/lib/dhcp"),
            Path::new("/run/NetworkManager"),
        ]
        .into_iter()
        .filter_map(|directory| fs::read_dir(directory).ok())
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .any(|lease| {
            lease.contains(&needle)
                && (lease.contains(&format!("interface \"{interface}\""))
                    || lease.contains("fixed-address")
                    || lease.contains("ADDRESS="))
        })
    }

    fn linux_gateway(interface: &str) -> Option<String> {
        let routes = fs::read_to_string("/proc/net/route").ok()?;
        routes.lines().skip(1).find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 || fields[0] != interface || fields[1] != "00000000" {
                return None;
            }
            let raw = u32::from_str_radix(fields[2], 16).ok()?;
            Some(std::net::Ipv4Addr::from(raw.to_le_bytes()).to_string())
        })
    }
}

#[cfg(windows)]
fn platform_inspect(
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

    let fallback = || IpConfiguration {
        assignment: selected
            .filter(|address| is_link_local(*address))
            .map(|_| IpAssignment::LinkLocal)
            .unwrap_or(IpAssignment::Unknown),
        addresses: selected.into_iter().map(|ip| ip.to_string()).collect(),
        gateway: None,
        evidence: "GetAdaptersInfo did not return the associated WLAN adapter".to_string(),
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

#[cfg(target_os = "macos")]
fn platform_inspect(
    _interface_id: &str,
    interface_name: &str,
    selected: Option<IpAddr>,
) -> IpConfiguration {
    use core::ffi::{c_char, c_void};

    type CfRef = *const c_void;
    type CfIndex = isize;
    type CfTypeId = usize;
    const UTF8: u32 = 0x0800_0100;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(value: CfRef);
        fn CFStringCreateWithCString(
            allocator: CfRef,
            value: *const c_char,
            encoding: u32,
        ) -> CfRef;
        fn CFStringGetCString(
            value: CfRef,
            buffer: *mut c_char,
            size: CfIndex,
            encoding: u32,
        ) -> bool;
        fn CFStringGetTypeID() -> CfTypeId;
        fn CFGetTypeID(value: CfRef) -> CfTypeId;
        fn CFArrayGetCount(array: CfRef) -> CfIndex;
        fn CFArrayGetValueAtIndex(array: CfRef, index: CfIndex) -> CfRef;
        fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
    }
    #[link(name = "SystemConfiguration", kind = "framework")]
    extern "C" {
        fn SCDynamicStoreCopyKeyList(store: CfRef, pattern: CfRef) -> CfRef;
        fn SCDynamicStoreCopyValue(store: CfRef, key: CfRef) -> CfRef;
        fn SCDynamicStoreCopyDHCPInfo(store: CfRef, service_id: CfRef) -> CfRef;
    }

    struct OwnedCf(CfRef);
    impl Drop for OwnedCf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    fn cf_string(value: &str) -> Option<OwnedCf> {
        let value = std::ffi::CString::new(value).ok()?;
        let reference =
            unsafe { CFStringCreateWithCString(core::ptr::null(), value.as_ptr(), UTF8) };
        (!reference.is_null()).then_some(OwnedCf(reference))
    }
    unsafe fn rust_string(value: CfRef) -> Option<String> {
        if value.is_null() || CFGetTypeID(value) != CFStringGetTypeID() {
            return None;
        }
        let mut buffer = vec![0i8; 4096];
        CFStringGetCString(value, buffer.as_mut_ptr(), buffer.len() as isize, UTF8).then(|| {
            std::ffi::CStr::from_ptr(buffer.as_ptr())
                .to_string_lossy()
                .into_owned()
        })
    }
    unsafe fn dictionary_string(dictionary: CfRef, key: &str) -> Option<String> {
        let key = cf_string(key)?;
        rust_string(CFDictionaryGetValue(dictionary, key.0))
    }
    unsafe fn dictionary_strings(dictionary: CfRef, key: &str) -> Vec<String> {
        let Some(key) = cf_string(key) else {
            return Vec::new();
        };
        let array = CFDictionaryGetValue(dictionary, key.0);
        if array.is_null() {
            return Vec::new();
        }
        (0..CFArrayGetCount(array))
            .filter_map(|index| rust_string(CFArrayGetValueAtIndex(array, index)))
            .collect()
    }

    let Some(pattern) = cf_string("State:/Network/Service/.*/IPv4") else {
        return fallback(selected, "could not create SystemConfiguration query");
    };
    let keys = OwnedCf(unsafe { SCDynamicStoreCopyKeyList(core::ptr::null(), pattern.0) });
    if keys.0.is_null() {
        return fallback(
            selected,
            "SystemConfiguration returned no IPv4 service keys",
        );
    }

    let count = unsafe { CFArrayGetCount(keys.0) };
    for index in 0..count {
        let key = unsafe { CFArrayGetValueAtIndex(keys.0, index) };
        let Some(key_text) = (unsafe { rust_string(key) }) else {
            continue;
        };
        let state = OwnedCf(unsafe { SCDynamicStoreCopyValue(core::ptr::null(), key) });
        if state.0.is_null()
            || unsafe { dictionary_string(state.0, "InterfaceName") }.as_deref()
                != Some(interface_name)
        {
            continue;
        }
        let service_id = key_text
            .strip_prefix("State:/Network/Service/")
            .and_then(|value| value.strip_suffix("/IPv4"))
            .unwrap_or_default();
        let Some(service) = cf_string(service_id) else {
            continue;
        };
        let dhcp = OwnedCf(unsafe { SCDynamicStoreCopyDHCPInfo(core::ptr::null(), service.0) });
        let setup_key = cf_string(&format!("Setup:/Network/Service/{service_id}/IPv4"));
        let setup = setup_key
            .as_ref()
            .map(|key| OwnedCf(unsafe { SCDynamicStoreCopyValue(core::ptr::null(), key.0) }));
        let method = setup
            .as_ref()
            .and_then(|setup| unsafe { dictionary_string(setup.0, "ConfigMethod") });
        let assignment = if !dhcp.0.is_null()
            || matches!(method.as_deref(), Some("DHCP" | "BOOTP" | "INFORM"))
        {
            IpAssignment::Dhcp
        } else if method.as_deref() == Some("Manual") {
            IpAssignment::Static
        } else {
            IpAssignment::Unknown
        };
        let mut addresses = unsafe { dictionary_strings(state.0, "Addresses") };
        if let Some(address) = selected.map(|ip| ip.to_string()) {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        return IpConfiguration {
            assignment,
            addresses,
            gateway: unsafe { dictionary_string(state.0, "Router") },
            evidence: format!(
                "SystemConfiguration service {service_id}, ConfigMethod={}",
                method.as_deref().unwrap_or("unknown")
            ),
        };
    }
    return fallback(
        selected,
        "no SystemConfiguration IPv4 service matched the Wi-Fi interface",
    );

    fn fallback(selected: Option<IpAddr>, evidence: &str) -> IpConfiguration {
        IpConfiguration {
            assignment: selected
                .filter(|address| is_link_local(*address))
                .map(|_| IpAssignment::LinkLocal)
                .unwrap_or(IpAssignment::Unknown),
            addresses: selected.into_iter().map(|ip| ip.to_string()).collect(),
            gateway: None,
            evidence: evidence.to_string(),
        }
    }
}

fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.segments()[0] & 0xffc0 == 0xfe80,
    }
}
