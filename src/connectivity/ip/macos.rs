use std::net::IpAddr;

use super::fallback_configuration;
use crate::connectivity::{IpAssignment, IpConfiguration};
#[cfg(target_os = "macos")]
pub(super) fn platform_inspect(
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
        return fallback_configuration(selected, "could not create SystemConfiguration query");
    };
    let keys = OwnedCf(unsafe { SCDynamicStoreCopyKeyList(core::ptr::null(), pattern.0) });
    if keys.0.is_null() {
        return fallback_configuration(
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
    fallback_configuration(
        selected,
        "no SystemConfiguration IPv4 service matched the Wi-Fi interface",
    )
}
