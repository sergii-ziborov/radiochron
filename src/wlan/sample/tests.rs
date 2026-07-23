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
