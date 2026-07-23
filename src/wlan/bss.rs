//! Nearby BSS enumeration and 802.11 Information Element parsing.
//!
//! The public module is a facade over four focused pieces: stable data models,
//! the pure IE parser, scan lifecycle handling, and the Windows BSS collector.

mod model;
mod parser;
#[cfg(all(windows, feature = "scan"))]
mod scan;
#[cfg(all(windows, feature = "scan"))]
mod windows;

pub use model::{
    BssCollection, BssEntry, BssInterfaceError, BssLoad, BssSummary, InformationElements,
    RsnDetails, ScanInterfaceResult, ScanRefresh, SecurityMode,
};
pub use parser::parse_information_elements;

pub(crate) use model::band_and_channel;

#[cfg(all(windows, feature = "scan"))]
pub use scan::{last_refresh_age_seconds, request_scan, scan_and_wait};
#[cfg(all(windows, feature = "scan"))]
pub use windows::{bss_list, bss_list_detailed};

#[cfg(all(target_os = "linux", feature = "scan"))]
pub use super::linux::{
    bss_list, bss_list_detailed, last_refresh_age_seconds, request_scan, scan_and_wait,
};
#[cfg(all(target_os = "macos", feature = "scan"))]
pub use super::macos::{
    bss_list, bss_list_detailed, last_refresh_age_seconds, request_scan, scan_and_wait,
};

/// Age of a collector's last completed scan. `None` means the cache
/// provenance is unknown, not that it is fresh.
#[cfg(feature = "scan")]
pub(crate) fn refresh_age(last_refresh_epoch: &std::sync::atomic::AtomicI64) -> Option<u64> {
    use std::sync::atomic::Ordering;

    let then = last_refresh_epoch.load(Ordering::Relaxed);
    (then > 0).then(|| crate::time::now_epoch_seconds().saturating_sub(then).max(0) as u64)
}

#[cfg(test)]
mod tests;
