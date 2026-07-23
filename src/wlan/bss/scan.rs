use alloc::vec::Vec;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use super::{ScanInterfaceResult, ScanRefresh};
use crate::wlan::sys::{self, Guid};
use crate::wlan::{guid_to_string, interface_guids, WlanClient};

const WLAN_NOTIFICATION_SOURCE_NONE: u32 = 0;
const WLAN_NOTIFICATION_SOURCE_ACM: u32 = 0x0000_0008;
const WLAN_NOTIFICATION_ACM_SCAN_COMPLETE: u32 = 7;
const WLAN_NOTIFICATION_ACM_SCAN_FAIL: u32 = 8;
static LAST_REFRESH_EPOCH: AtomicI64 = AtomicI64::new(0);

#[derive(Clone, Copy)]
#[cfg(all(windows, feature = "scan"))]
enum ScanState {
    Pending,
    Complete,
    Failed(u32),
    Rejected(u32),
}

#[cfg(all(windows, feature = "scan"))]
struct ScanWaitState {
    interfaces: Mutex<Vec<(Guid, ScanState)>>,
    changed: Condvar,
}
/// Ask the driver to perform a fresh scan on every WLAN interface.
///
/// Results are not immediate: Windows raises a scan-complete notification a few
/// seconds later, after which the platform BSS collector returns refreshed entries.
#[cfg(all(windows, feature = "scan"))]
pub fn request_scan() -> anyhow::Result<usize> {
    let client = WlanClient::open()?;
    let guids = interface_guids(&client)?;
    Ok(request_for_interfaces(&client, &guids)
        .into_iter()
        .filter(|(_, code)| *code == 0)
        .count())
}

/// Request a scan and wait for Windows' per-interface completion/failure
/// notifications instead of sleeping for an assumed driver latency.
#[cfg(all(windows, feature = "scan"))]
pub fn scan_and_wait(timeout: Duration) -> anyhow::Result<ScanRefresh> {
    let started = Instant::now();
    let client = WlanClient::open()?;
    let api = sys::api()?;
    let guids = interface_guids(&client)?;
    let state = Box::new(ScanWaitState {
        interfaces: Mutex::new(
            guids
                .iter()
                .copied()
                .map(|guid| (guid, ScanState::Pending))
                .collect(),
        ),
        changed: Condvar::new(),
    });

    let register = unsafe {
        (api.register_notification)(
            client.handle,
            WLAN_NOTIFICATION_SOURCE_ACM,
            1,
            Some(scan_notification),
            (&*state as *const ScanWaitState).cast_mut().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if register != 0 {
        anyhow::bail!("WlanRegisterNotification failed (code {register})");
    }
    let _registration = NotificationRegistration { client: &client };

    let requested = request_for_interfaces(&client, &guids);
    {
        let mut interfaces = state.interfaces.lock().unwrap_or_else(|e| e.into_inner());
        for (guid, code) in requested.iter().filter(|(_, code)| *code != 0) {
            if let Some((_, status)) = interfaces.iter_mut().find(|(item, _)| item == guid) {
                *status = ScanState::Rejected(*code);
            }
        }
    }

    let interfaces = state.interfaces.lock().unwrap_or_else(|e| e.into_inner());
    let (interfaces, _) = state
        .changed
        .wait_timeout_while(interfaces, timeout, |items| {
            items
                .iter()
                .any(|(_, status)| matches!(status, ScanState::Pending))
        })
        .unwrap_or_else(|e| e.into_inner());

    let observed_at_epoch_seconds = crate::time::now_epoch_seconds();
    let results: Vec<ScanInterfaceResult> = interfaces
        .iter()
        .map(|(guid, state)| {
            let (status, error_code) = match state {
                ScanState::Pending => ("timed_out", None),
                ScanState::Complete => ("complete", None),
                ScanState::Failed(code) => ("failed", Some(*code)),
                ScanState::Rejected(code) => ("rejected", Some(*code)),
            };
            ScanInterfaceResult {
                interface_guid: guid_to_string(guid),
                status,
                error_code,
            }
        })
        .collect();
    drop(interfaces);

    let completed = results
        .iter()
        .filter(|item| item.status == "complete")
        .count();
    if completed > 0 {
        LAST_REFRESH_EPOCH.store(observed_at_epoch_seconds, Ordering::Relaxed);
    }

    Ok(ScanRefresh {
        requested: requested.iter().filter(|(_, code)| *code == 0).count(),
        completed,
        failed: results
            .iter()
            .filter(|item| matches!(item.status, "failed" | "rejected"))
            .count(),
        timed_out: results
            .iter()
            .filter(|item| item.status == "timed_out")
            .count(),
        elapsed_ms: started.elapsed().as_millis(),
        observed_at_epoch_seconds,
        interfaces: results,
    })
}

/// Age of the last scan completion observed by this process. `None` means the
/// current cache provenance is unknown, not that it is fresh.
#[cfg(all(windows, feature = "scan"))]
pub fn last_refresh_age_seconds() -> Option<u64> {
    super::refresh_age(&LAST_REFRESH_EPOCH)
}

#[cfg(all(windows, feature = "scan"))]
fn request_for_interfaces(client: &WlanClient, guids: &[Guid]) -> Vec<(Guid, u32)> {
    let Ok(api) = sys::api() else {
        return guids.iter().copied().map(|guid| (guid, u32::MAX)).collect();
    };
    guids
        .iter()
        .copied()
        .map(|guid| {
            let code = unsafe {
                (api.scan)(
                    client.handle,
                    &guid as *const Guid,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            };
            (guid, code)
        })
        .collect()
}

#[cfg(all(windows, feature = "scan"))]
unsafe extern "system" fn scan_notification(
    notification: *mut sys::WlanNotificationData,
    context: *mut core::ffi::c_void,
) {
    if notification.is_null() || context.is_null() {
        return;
    }
    let notification = &*notification;
    if notification.notification_source != WLAN_NOTIFICATION_SOURCE_ACM
        || !matches!(
            notification.notification_code,
            WLAN_NOTIFICATION_ACM_SCAN_COMPLETE | WLAN_NOTIFICATION_ACM_SCAN_FAIL
        )
    {
        return;
    }

    let state = &*(context as *const ScanWaitState);
    let mut interfaces = state.interfaces.lock().unwrap_or_else(|e| e.into_inner());
    let Some((_, status)) = interfaces
        .iter_mut()
        .find(|(guid, _)| *guid == notification.interface_guid)
    else {
        return;
    };

    *status = if notification.notification_code == WLAN_NOTIFICATION_ACM_SCAN_COMPLETE {
        ScanState::Complete
    } else {
        let reason = if notification.data_size >= 4 && !notification.data.is_null() {
            *(notification.data as *const u32)
        } else {
            0
        };
        ScanState::Failed(reason)
    };
    drop(interfaces);
    state.changed.notify_all();
}

#[cfg(all(windows, feature = "scan"))]
struct NotificationRegistration<'a> {
    client: &'a WlanClient,
}

#[cfg(all(windows, feature = "scan"))]
impl Drop for NotificationRegistration<'_> {
    fn drop(&mut self) {
        if let Ok(api) = sys::api() {
            unsafe {
                (api.register_notification)(
                    self.client.handle,
                    WLAN_NOTIFICATION_SOURCE_NONE,
                    1,
                    None,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
            }
        }
    }
}
