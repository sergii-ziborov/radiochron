use radiochron::embedded::chronicle::{
    Chronicle, Clock, ClockQuality, ClockReading, Identity, VecSink,
};
use radiochron::wlan::{CurrentConnection, WifiStatus, WlanInterface};

struct FirmwareClock(u64);

impl Clock for FirmwareClock {
    fn now(&mut self) -> ClockReading {
        ClockReading {
            monotonic_ms: self.0,
            unix_epoch_ms: None,
            quality: ClockQuality::Unknown,
        }
    }
}

fn main() {
    let mut chronicle = Chronicle::new(
        VecSink::default(),
        FirmwareClock(0),
        Identity {
            device_id: Some("sensor-7".into()),
            boot_id: "boot-42".into(),
        },
        1,
        8,
    );

    chronicle
        .note_association_attempt("wifi0", Some("workshop"))
        .unwrap();
    chronicle.clock_mut().0 = 850;
    chronicle
        .observe_status(&WifiStatus {
            interface: WlanInterface {
                guid: "wifi0".into(),
                description: "firmware radio".into(),
                state: "connected".into(),
            },
            connection: Some(CurrentConnection {
                profile_name: None,
                ssid: Some("workshop".into()),
                bssid: Some("02:00:00:00:00:01".into()),
                phy_type: "802.11n".into(),
                signal_quality: 80,
                rssi_dbm_estimate: -60,
                rx_rate_kbps: 72_000,
                tx_rate_kbps: 72_000,
            }),
            connection_error: None,
        })
        .unwrap();
    chronicle.clock_mut().0 = 1200;
    chronicle
        .note_ip_acquired("wifi0", Some("192.0.2.7"))
        .unwrap();
    chronicle.clock_mut().0 = 1500;
    chronicle
        .note_backend_result("wifi0", "mqtt-broker", true, Some(24))
        .unwrap();
    chronicle.clock_mut().0 = 60_000;

    let metrics = chronicle.emit_metrics().unwrap();
    println!(
        "uptime={:?}‰, time-to-backend={:?}ms",
        metrics.connectivity_uptime_permille, metrics.last_time_to_backend_ms
    );
}
