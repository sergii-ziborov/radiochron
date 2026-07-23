use std::io;

use super::mapping::scan_cache;
use super::status::{error_code, interface_id, interfaces, Interface};
use super::*;

pub fn request_scan() -> anyhow::Result<usize> {
    let mut socket = GenericSocket::open()?;
    let interfaces = interfaces(&mut socket)?;
    Ok(interfaces
        .iter()
        .filter(|interface| trigger_scan(&mut socket, interface.index).is_ok())
        .count())
}

#[cfg(feature = "scan")]
pub fn scan_and_wait(timeout: Duration) -> anyhow::Result<ScanRefresh> {
    let started = Instant::now();
    let mut commands = GenericSocket::open()?;
    let interfaces = interfaces(&mut commands)?;
    let events = GenericSocket::open()?;
    events.subscribe_scan()?;

    let mut states: BTreeMap<u32, (&Interface, &'static str, Option<u32>)> = interfaces
        .iter()
        .map(|interface| (interface.index, (interface, "pending", None)))
        .collect();
    for interface in &interfaces {
        if let Err(error) = trigger_scan(&mut commands, interface.index) {
            states.insert(interface.index, (interface, "rejected", error_code(&error)));
        }
    }

    let deadline = Instant::now() + timeout;
    while states.values().any(|(_, state, _)| *state == "pending") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        for event in events.receive_events(remaining)? {
            if !matches!(event.command, CMD_NEW_SCAN_RESULTS | CMD_SCAN_ABORTED) {
                continue;
            }
            let ifindex = attributes(&event.attributes)
                .into_iter()
                .find(|attribute| attribute.kind == ATTR_IFINDEX)
                .and_then(|attribute| read_u32(attribute.value));
            let Some(ifindex) = ifindex else { continue };
            if let Some((interface, state, code)) = states.get_mut(&ifindex) {
                *state = if event.command == CMD_NEW_SCAN_RESULTS {
                    "complete"
                } else {
                    "failed"
                };
                *code = None;
                let _ = interface;
            }
        }
    }

    let observed_at_epoch_seconds = crate::time::now_epoch_seconds();
    let results: Vec<ScanInterfaceResult> = states
        .into_values()
        .map(|(interface, state, error_code)| ScanInterfaceResult {
            interface_guid: interface_id(interface),
            status: if state == "pending" {
                "timed_out"
            } else {
                state
            },
            error_code,
        })
        .collect();
    let completed = results
        .iter()
        .filter(|result| result.status == "complete")
        .count();
    if completed > 0 {
        LAST_REFRESH_EPOCH.store(observed_at_epoch_seconds, Ordering::Relaxed);
    }

    Ok(ScanRefresh {
        requested: results
            .iter()
            .filter(|result| result.status != "rejected")
            .count(),
        completed,
        failed: results
            .iter()
            .filter(|result| matches!(result.status, "failed" | "rejected"))
            .count(),
        timed_out: results
            .iter()
            .filter(|result| result.status == "timed_out")
            .count(),
        elapsed_ms: started.elapsed().as_millis(),
        observed_at_epoch_seconds,
        interfaces: results,
    })
}

#[cfg(feature = "scan")]
pub fn last_refresh_age_seconds() -> Option<u64> {
    refresh_age(&LAST_REFRESH_EPOCH)
}

#[cfg(feature = "scan")]
pub fn bss_list() -> anyhow::Result<Vec<BssEntry>> {
    Ok(bss_list_detailed()?.entries)
}

#[cfg(feature = "scan")]
pub fn bss_list_detailed() -> anyhow::Result<BssCollection> {
    let mut socket = GenericSocket::open()?;
    let interfaces = interfaces(&mut socket)?;
    let mut entries = Vec::new();
    let mut interface_errors = Vec::new();

    for interface in interfaces {
        match scan_cache(&mut socket, &interface) {
            Ok(scanned) => entries.extend(scanned.into_iter().map(|entry| entry.entry)),
            Err(error) => interface_errors.push(BssInterfaceError {
                interface_guid: interface_id(&interface),
                error_code: error_code(&error).unwrap_or(u32::MAX),
            }),
        }
    }

    Ok(BssCollection {
        entries,
        interface_errors,
    })
}

fn trigger_scan(socket: &mut GenericSocket, ifindex: u32) -> io::Result<()> {
    let mut request = Vec::new();
    push_u32(&mut request, ATTR_IFINDEX, ifindex);
    let mut wildcard = Vec::new();
    push_attribute(&mut wildcard, 1, &[]);
    push_attribute(&mut request, ATTR_SCAN_SSIDS | NLA_F_NESTED, &wildcard);
    socket
        .transact(CMD_TRIGGER_SCAN, request, false)
        .map(|_| ())
}
