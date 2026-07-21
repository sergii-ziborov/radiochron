//! Runtime resolution of system DLLs.
//!
//! Shared infrastructure rather than part of any one collector: `wlanapi` and
//! `wevtapi` are both resolved this way, and a target that compiles only the
//! event-log reader still needs it.
//!
//! Loading at run time instead of linking is a deliberate choice. Neither
//! `libwlanapi.a` nor `libwevtapi.a` ships with the Rust toolchain, so a
//! link-time dependency would require mingw's `dlltool` or the Visual C++ build
//! tools plus the Windows SDK. It also degrades honestly: a machine without the
//! WLAN service returns a clean error instead of failing to start. That second
//! property is not hypothetical — `windows-rs` issue #1425 exists because
//! statically binding `wlanapi.dll` hard-crashes at load on SKUs where the DLL
//! is absent, and the suggested workaround is exactly this.

use std::ffi::{c_char, c_void, CStr};

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(file_name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const c_char) -> *mut c_void;
}

/// Search only `%SystemRoot%\System32`. A bare `LoadLibraryW("name.dll")`
/// follows the process DLL search order and can resolve an attacker-controlled
/// file before the Windows component we intended to load.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

/// Load a system DLL by name, or `None` if it is unavailable.
pub(crate) fn load_system_library(name: &str) -> Option<*mut c_void> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };

    if module.is_null() {
        None
    } else {
        Some(module)
    }
}

/// Resolve an exported symbol. `name` must be NUL-terminated ANSI — note that
/// `GetProcAddress` takes ANSI even though `LoadLibraryW` takes wide.
pub(crate) fn symbol(module: *mut c_void, name: &CStr) -> Option<*mut c_void> {
    let ptr = unsafe { GetProcAddress(module, name.as_ptr()) };

    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_dll_that_is_always_present() {
        let module = load_system_library("kernel32.dll").expect("kernel32 must load");
        assert!(symbol(module, c"GetProcAddress").is_some());
    }

    #[test]
    fn a_missing_library_is_none_rather_than_a_panic() {
        assert!(load_system_library("radiochron-no-such-library.dll").is_none());
    }

    #[test]
    fn a_missing_symbol_is_none() {
        let module = load_system_library("kernel32.dll").unwrap();
        assert!(symbol(module, c"RadioChronNoSuchExport").is_none());
    }
}
