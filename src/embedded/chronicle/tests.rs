use super::*;
use crate::wlan::{CurrentConnection, WifiStatus, WlanInterface};

#[derive(Debug)]
struct ManualClock {
    now_ms: u64,
}

impl Clock for ManualClock {
    fn now(&mut self) -> ClockReading {
        ClockReading {
            monotonic_ms: self.now_ms,
            unix_epoch_ms: None,
            quality: ClockQuality::Unknown,
        }
    }
}

fn status(connected: bool, bssid: &str, rssi: i32) -> WifiStatus {
    WifiStatus {
        interface: WlanInterface {
            guid: "wifi0".into(),
            description: "test".into(),
            state: if connected {
                "connected".into()
            } else {
                "disconnected".into()
            },
        },
        connection: connected.then(|| CurrentConnection {
            profile_name: None,
            ssid: Some("lab".into()),
            bssid: Some(bssid.into()),
            phy_type: "802.11n".into(),
            signal_quality: 80,
            rssi_dbm_estimate: rssi,
            rx_rate_kbps: 72_000,
            tx_rate_kbps: 72_000,
        }),
        connection_error: None,
    }
}

fn recorder() -> Chronicle<VecSink, ManualClock> {
    Chronicle::new(
        VecSink::default(),
        ManualClock { now_ms: 0 },
        Identity {
            device_id: Some("device".into()),
            boot_id: "boot".into(),
        },
        7,
        8,
    )
}

#[test]
fn records_changes_with_versioned_deduplicable_envelope() {
    let mut chronicle = recorder();
    assert_eq!(chronicle.observe_status(&status(true, "aa", -60)), Ok(1));
    chronicle.clock_mut().now_ms = 1000;
    assert_eq!(chronicle.observe_status(&status(true, "aa", -62)), Ok(0));
    chronicle.clock_mut().now_ms = 2000;
    assert_eq!(
        chronicle.observe_status_with_reason(&status(false, "", 0), Some(15)),
        Ok(1)
    );

    let entries = &chronicle.sink().0;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].schema_version, SCHEMA_VERSION);
    assert_eq!(entries[0].sequence, 7);
    assert_eq!(entries[0].event_id, "radiochron:1:6:device:4:boot:7");
    assert!(matches!(
        entries[1].event,
        EventKind::Disconnected {
            reason_code: Some(15),
            ..
        }
    ));
}

#[test]
fn metrics_measure_elapsed_time_and_connection_stages() {
    let mut chronicle = recorder();
    chronicle
        .note_association_attempt("wifi0", Some("lab"))
        .unwrap();
    chronicle.clock_mut().now_ms = 1000;
    chronicle.observe_status(&status(true, "aa", -60)).unwrap();
    chronicle.clock_mut().now_ms = 1500;
    chronicle
        .note_ip_acquired("wifi0", Some("192.0.2.2"))
        .unwrap();
    chronicle.clock_mut().now_ms = 2000;
    chronicle
        .note_backend_result("wifi0", "broker", true, Some(20))
        .unwrap();
    chronicle.clock_mut().now_ms = 5000;

    let metrics = chronicle.emit_metrics().unwrap();
    assert_eq!(metrics.expected_connectivity_ms, 5000);
    assert_eq!(metrics.wifi_connected_ms, 4000);
    assert_eq!(metrics.expected_wifi_connected_ms, 4000);
    assert_eq!(metrics.connectivity_uptime_permille, Some(800));
    assert_eq!(metrics.association_attempts, 1);
    assert_eq!(metrics.backend_successes, 1);
    assert_eq!(metrics.last_time_to_associate_ms, Some(1000));
    assert_eq!(metrics.last_time_to_ip_ms, Some(1500));
    assert_eq!(metrics.last_time_to_backend_ms, Some(2000));
    assert_eq!(metrics.rssi_mean_dbm, Some(-60));
}

#[test]
fn disabling_expectation_removes_sleep_from_the_denominator() {
    let mut tracker = MetricsTracker::new(0);
    tracker.observe_connection(0, true, None, None);
    tracker.set_expected(1000, false);
    tracker.set_expected(9000, true);
    let metrics = tracker.snapshot(10_000);

    assert_eq!(metrics.expected_connectivity_ms, 2000);
    assert_eq!(metrics.wifi_connected_ms, 10_000);
    assert_eq!(metrics.expected_wifi_connected_ms, 2000);
    assert_eq!(metrics.connectivity_uptime_permille, Some(1000));
}
