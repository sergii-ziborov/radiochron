use super::*;
use crate::chronicle::VecSink;

struct FakeCollector {
    polls: Vec<Vec<CollectorSample>>,
}

impl Collector for FakeCollector {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn collect(&mut self) -> anyhow::Result<Vec<CollectorSample>> {
        Ok(self.polls.remove(0))
    }
}

#[test]
fn injected_collector_records_versioned_ordered_entries() {
    let collector = FakeCollector {
        polls: vec![vec![CollectorSample::observed(
            "wlan0",
            Observation {
                connected: true,
                ssid: Some("lab".into()),
                bssid: Some("aa:bb:cc:dd:ee:ff".into()),
                rssi_dbm: Some(-55),
            },
        )]],
    };
    let options = RecorderOptions {
        identity: ChronicleIdentity {
            device_id: Some("device".into()),
            boot_id: "boot".into(),
            clock_quality: super::super::ClockQuality::Synchronized,
        },
        initial_sequence: 7,
        ..RecorderOptions::default()
    };
    let mut recorder = Recorder::with_collector(VecSink::default(), collector, options);

    assert_eq!(recorder.step().unwrap(), 1);
    assert_eq!(recorder.next_sequence(), 8);
    let entry = &recorder.into_sink().0[0];
    assert_eq!(entry.event_id, "radiochron:1:6:device:4:boot:7");
    assert_eq!(entry.schema_version, super::super::CHRONICLE_SCHEMA_VERSION);
}
