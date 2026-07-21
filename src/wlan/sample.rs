//! Connection dynamics: what a single snapshot cannot tell you.
//!
//! A one-shot `wifi_status` says "-58 dBm, fine". It cannot say that the link
//! swung 30 dB over the last minute, roamed between three BSSIDs, or dropped
//! twice. Those are the shapes that explain a complaint, so this samples the
//! association over a bounded window and reports both the series and the
//! aggregates worth reasoning about.

use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::wifi_status;

/// Hard ceiling on a sampling run. A tool call blocks the JSON-RPC channel, so
/// an unbounded window would hang the client rather than answer it.
pub const MAX_DURATION_S: u64 = 120;
pub const MIN_INTERVAL_MS: u64 = 250;

#[derive(Debug, Serialize)]
pub struct Sample {
    pub elapsed_ms: u128,
    pub interface_guid: Option<String>,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_error: Option<String>,
    pub bssid: Option<String>,
    pub signal_quality: Option<u32>,
    pub rssi_dbm_estimate: Option<i32>,
    pub rx_rate_kbps: Option<u32>,
    pub tx_rate_kbps: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SampleRun {
    pub duration_s: u64,
    pub interval_ms: u64,
    pub sample_count: usize,
    pub interface_guid: Option<String>,
    pub ssid: Option<String>,
    /// Samples where the interface was not associated.
    pub disconnected_samples: usize,
    /// Polls where state could not be observed. Kept separate from genuine
    /// disconnected samples so collector faults do not impersonate radio drops.
    pub failed_samples: usize,
    /// Distinct BSSIDs observed, in the order first seen.
    pub bssids_seen: Vec<String>,
    /// Transitions between BSSIDs — roaming, or an unstable choice of AP.
    pub roam_count: usize,
    pub rssi_min_dbm: Option<i32>,
    pub rssi_max_dbm: Option<i32>,
    pub rssi_mean_dbm: Option<i32>,
    /// Peak-to-trough swing. Large values mean an unstable link even when the
    /// mean looks healthy.
    pub rssi_swing_db: Option<i32>,
    pub rx_rate_min_kbps: Option<u32>,
    pub rx_rate_max_kbps: Option<u32>,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SampleProgress {
    pub elapsed_ms: u128,
    pub total_ms: u128,
    pub sample_count: usize,
}

/// Sample the current association for `duration_s`, one reading per `interval_ms`.
pub fn sample_connection(duration_s: u64, interval_ms: u64) -> anyhow::Result<SampleRun> {
    sample_connection_on(None, duration_s, interval_ms)
}

/// Sample one interface. When no GUID is supplied, the first connected
/// interface (or otherwise the first interface) is selected once and retained
/// for the entire run.
pub fn sample_connection_on(
    interface_guid: Option<&str>,
    duration_s: u64,
    interval_ms: u64,
) -> anyhow::Result<SampleRun> {
    sample_connection_on_controlled(interface_guid, duration_s, interval_ms, |_| Ok(()))
}

/// Sampling variant for transports that support cancellation/progress. The
/// callback runs after every observation and may stop the run by returning an
/// error.
pub fn sample_connection_on_controlled<F>(
    interface_guid: Option<&str>,
    duration_s: u64,
    interval_ms: u64,
    mut on_progress: F,
) -> anyhow::Result<SampleRun>
where
    F: FnMut(SampleProgress) -> anyhow::Result<()>,
{
    let duration_s = duration_s.clamp(1, MAX_DURATION_S);
    let interval_ms = interval_ms.max(MIN_INTERVAL_MS);

    let started = Instant::now();
    let deadline = Duration::from_secs(duration_s);
    let interval = Duration::from_millis(interval_ms);

    let mut samples: Vec<Sample> = Vec::new();
    let mut ssid: Option<String> = None;
    let mut selected_guid = interface_guid.map(str::to_string);

    loop {
        let elapsed = started.elapsed();
        samples.push(read_sample(elapsed, &mut ssid, &mut selected_guid));
        on_progress(SampleProgress {
            elapsed_ms: started.elapsed().as_millis(),
            total_ms: deadline.as_millis(),
            sample_count: samples.len(),
        })?;

        if started.elapsed() + interval > deadline {
            break;
        }

        // Keep long sampling intervals cancelable. The progress callback is
        // also the control hook used by MCP cancellation, so do not disappear
        // into a single sleep that can last up to 60 seconds.
        let wake_at = started.elapsed() + interval;
        while started.elapsed() < wake_at {
            let remaining = wake_at.saturating_sub(started.elapsed());
            sleep(remaining.min(Duration::from_millis(250)));
            on_progress(SampleProgress {
                elapsed_ms: started.elapsed().as_millis(),
                total_ms: deadline.as_millis(),
                sample_count: samples.len(),
            })?;
        }
    }

    Ok(summarize(
        duration_s,
        interval_ms,
        selected_guid,
        ssid,
        samples,
    ))
}

fn read_sample(
    elapsed: Duration,
    ssid: &mut Option<String>,
    selected_guid: &mut Option<String>,
) -> Sample {
    let interfaces = match wifi_status() {
        Ok(interfaces) => interfaces,
        Err(error) => return failed_sample(elapsed, selected_guid.clone(), error.to_string()),
    };

    if selected_guid.is_none() {
        *selected_guid = interfaces
            .iter()
            .find(|entry| entry.connection.is_some())
            .or_else(|| interfaces.first())
            .map(|entry| entry.interface.guid.clone());
    }

    let Some(interface_guid) = selected_guid.as_deref() else {
        return failed_sample(elapsed, None, "no WLAN interfaces found".to_string());
    };
    let Some(interface) = interfaces
        .into_iter()
        .find(|entry| entry.interface.guid.eq_ignore_ascii_case(interface_guid))
    else {
        return failed_sample(
            elapsed,
            selected_guid.clone(),
            format!("WLAN interface not found: {interface_guid}"),
        );
    };

    if let Some(error) = interface.connection_error {
        return failed_sample(elapsed, selected_guid.clone(), error);
    }

    match interface.connection {
        Some(connection) => {
            if ssid.is_none() {
                ssid.clone_from(&connection.ssid);
            }

            Sample {
                elapsed_ms: elapsed.as_millis(),
                interface_guid: selected_guid.clone(),
                connected: true,
                collector_error: None,
                bssid: connection.bssid,
                signal_quality: Some(connection.signal_quality),
                rssi_dbm_estimate: Some(connection.rssi_dbm_estimate),
                rx_rate_kbps: Some(connection.rx_rate_kbps),
                tx_rate_kbps: Some(connection.tx_rate_kbps),
            }
        }
        None => Sample {
            elapsed_ms: elapsed.as_millis(),
            interface_guid: selected_guid.clone(),
            connected: false,
            collector_error: None,
            bssid: None,
            signal_quality: None,
            rssi_dbm_estimate: None,
            rx_rate_kbps: None,
            tx_rate_kbps: None,
        },
    }
}

fn failed_sample(elapsed: Duration, interface_guid: Option<String>, message: String) -> Sample {
    Sample {
        elapsed_ms: elapsed.as_millis(),
        interface_guid,
        connected: false,
        collector_error: Some(message),
        bssid: None,
        signal_quality: None,
        rssi_dbm_estimate: None,
        rx_rate_kbps: None,
        tx_rate_kbps: None,
    }
}

fn summarize(
    duration_s: u64,
    interval_ms: u64,
    interface_guid: Option<String>,
    ssid: Option<String>,
    samples: Vec<Sample>,
) -> SampleRun {
    let rssi: Vec<i32> = samples.iter().filter_map(|s| s.rssi_dbm_estimate).collect();
    let rates: Vec<u32> = samples.iter().filter_map(|s| s.rx_rate_kbps).collect();

    let mut bssids_seen: Vec<String> = Vec::new();
    let mut roam_count = 0usize;
    let mut previous: Option<&str> = None;

    for bssid in samples.iter().filter_map(|s| s.bssid.as_deref()) {
        if !bssids_seen.iter().any(|seen| seen == bssid) {
            bssids_seen.push(bssid.to_string());
        }
        // Count a transition only between two observed associations, so a drop
        // and reconnect to the same AP is not miscounted as roaming.
        if previous.is_some_and(|prev| prev != bssid) {
            roam_count += 1;
        }
        previous = Some(bssid);
    }

    let rssi_min = rssi.iter().copied().min();
    let rssi_max = rssi.iter().copied().max();

    SampleRun {
        duration_s,
        interval_ms,
        sample_count: samples.len(),
        interface_guid,
        ssid,
        disconnected_samples: samples
            .iter()
            .filter(|s| !s.connected && s.collector_error.is_none())
            .count(),
        failed_samples: samples
            .iter()
            .filter(|s| s.collector_error.is_some())
            .count(),
        bssids_seen,
        roam_count,
        rssi_min_dbm: rssi_min,
        rssi_max_dbm: rssi_max,
        rssi_mean_dbm: mean(&rssi),
        rssi_swing_db: rssi_max.zip(rssi_min).map(|(max, min)| max - min),
        rx_rate_min_kbps: rates.iter().copied().min(),
        rx_rate_max_kbps: rates.iter().copied().max(),
        samples,
    }
}

fn mean(values: &[i32]) -> Option<i32> {
    if values.is_empty() {
        return None;
    }

    let sum: i64 = values.iter().map(|v| i64::from(*v)).sum();
    Some((sum / values.len() as i64) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(elapsed_ms: u128, bssid: Option<&str>, rssi: Option<i32>) -> Sample {
        Sample {
            elapsed_ms,
            interface_guid: Some("guid".to_string()),
            connected: bssid.is_some(),
            collector_error: None,
            bssid: bssid.map(str::to_string),
            signal_quality: rssi.map(|_| 70),
            rssi_dbm_estimate: rssi,
            rx_rate_kbps: rssi.map(|_| 400_000),
            tx_rate_kbps: rssi.map(|_| 300_000),
        }
    }

    #[test]
    fn counts_roams_between_distinct_bssids() {
        let run = summarize(
            4,
            1000,
            Some("guid".into()),
            Some("Net".into()),
            vec![
                sample(0, Some("aa:aa:aa:aa:aa:aa"), Some(-50)),
                sample(1000, Some("aa:aa:aa:aa:aa:aa"), Some(-55)),
                sample(2000, Some("bb:bb:bb:bb:bb:bb"), Some(-60)),
                sample(3000, Some("aa:aa:aa:aa:aa:aa"), Some(-52)),
            ],
        );

        assert_eq!(run.roam_count, 2);
        assert_eq!(run.bssids_seen.len(), 2);
    }

    #[test]
    fn a_drop_and_return_to_the_same_ap_is_not_a_roam() {
        let run = summarize(
            3,
            1000,
            Some("guid".into()),
            Some("Net".into()),
            vec![
                sample(0, Some("aa:aa:aa:aa:aa:aa"), Some(-50)),
                sample(1000, None, None),
                sample(2000, Some("aa:aa:aa:aa:aa:aa"), Some(-51)),
            ],
        );

        assert_eq!(run.roam_count, 0);
        assert_eq!(run.disconnected_samples, 1);
    }

    #[test]
    fn reports_the_swing_not_just_the_mean() {
        let run = summarize(
            3,
            1000,
            Some("guid".into()),
            None,
            vec![
                sample(0, Some("aa:aa:aa:aa:aa:aa"), Some(-45)),
                sample(1000, Some("aa:aa:aa:aa:aa:aa"), Some(-85)),
                sample(2000, Some("aa:aa:aa:aa:aa:aa"), Some(-65)),
            ],
        );

        assert_eq!(run.rssi_min_dbm, Some(-85));
        assert_eq!(run.rssi_max_dbm, Some(-45));
        assert_eq!(run.rssi_mean_dbm, Some(-65));
        // A 40 dB swing is the finding here; the mean alone looks unremarkable.
        assert_eq!(run.rssi_swing_db, Some(40));
    }

    #[test]
    fn an_entirely_disconnected_run_yields_no_signal_statistics() {
        let run = summarize(
            2,
            1000,
            Some("guid".into()),
            None,
            vec![sample(0, None, None), sample(1000, None, None)],
        );

        assert_eq!(run.disconnected_samples, 2);
        assert_eq!(run.rssi_mean_dbm, None);
        assert_eq!(run.rssi_swing_db, None);
        assert!(run.bssids_seen.is_empty());
    }
}
