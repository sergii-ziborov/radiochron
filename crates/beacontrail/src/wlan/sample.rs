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
    pub connected: bool,
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
    pub ssid: Option<String>,
    /// Samples where the interface was not associated.
    pub disconnected_samples: usize,
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

/// Sample the current association for `duration_s`, one reading per `interval_ms`.
pub fn sample_connection(duration_s: u64, interval_ms: u64) -> anyhow::Result<SampleRun> {
    let duration_s = duration_s.clamp(1, MAX_DURATION_S);
    let interval_ms = interval_ms.max(MIN_INTERVAL_MS);

    let started = Instant::now();
    let deadline = Duration::from_secs(duration_s);
    let interval = Duration::from_millis(interval_ms);

    let mut samples: Vec<Sample> = Vec::new();
    let mut ssid: Option<String> = None;

    loop {
        let elapsed = started.elapsed();
        samples.push(read_sample(elapsed, &mut ssid));

        if started.elapsed() + interval > deadline {
            break;
        }
        sleep(interval);
    }

    Ok(summarize(duration_s, interval_ms, ssid, samples))
}

fn read_sample(elapsed: Duration, ssid: &mut Option<String>) -> Sample {
    // A transient query failure is a data point, not a reason to abort the run.
    let connection = wifi_status()
        .ok()
        .and_then(|interfaces| interfaces.into_iter().find_map(|entry| entry.connection));

    match connection {
        Some(connection) => {
            if ssid.is_none() {
                ssid.clone_from(&connection.ssid);
            }

            Sample {
                elapsed_ms: elapsed.as_millis(),
                connected: true,
                bssid: connection.bssid,
                signal_quality: Some(connection.signal_quality),
                rssi_dbm_estimate: Some(connection.rssi_dbm_estimate),
                rx_rate_kbps: Some(connection.rx_rate_kbps),
                tx_rate_kbps: Some(connection.tx_rate_kbps),
            }
        }
        None => Sample {
            elapsed_ms: elapsed.as_millis(),
            connected: false,
            bssid: None,
            signal_quality: None,
            rssi_dbm_estimate: None,
            rx_rate_kbps: None,
            tx_rate_kbps: None,
        },
    }
}

fn summarize(
    duration_s: u64,
    interval_ms: u64,
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
        ssid,
        disconnected_samples: samples.iter().filter(|s| !s.connected).count(),
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
            connected: bssid.is_some(),
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
            None,
            vec![sample(0, None, None), sample(1000, None, None)],
        );

        assert_eq!(run.disconnected_samples, 2);
        assert_eq!(run.rssi_mean_dbm, None);
        assert_eq!(run.rssi_swing_db, None);
        assert!(run.bssids_seen.is_empty());
    }
}
