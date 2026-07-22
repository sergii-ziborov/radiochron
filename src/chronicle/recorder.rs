//! Portable collector contract and chronicle recording loop.

use std::collections::BTreeMap;
use std::time::Duration;

use super::{ChangeDetector, ChronicleIdentity, Entry, EntryKind, Observation, Sink};

#[cfg(all(any(windows, target_os = "linux"), feature = "status"))]
mod native;
#[cfg(all(any(windows, target_os = "linux"), feature = "status"))]
pub use native::NativeCollector;

#[derive(Debug, Clone)]
pub struct RecorderOptions {
    /// Delay between polls in [`Recorder::run_for`].
    pub interval: Duration,
    /// Hysteresis for [`EntryKind::SignalShift`], in dB.
    pub signal_threshold_db: i32,
    /// Fleet and boot identity included in every entry.
    pub identity: ChronicleIdentity,
    /// First sequence number. A durable agent should restore this from spool.
    pub initial_sequence: u64,
}

impl Default for RecorderOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            signal_threshold_db: 8,
            identity: ChronicleIdentity::default(),
            initial_sequence: 1,
        }
    }
}

/// A per-interface collector failure. It is evidence about observation health,
/// not evidence that the interface disconnected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorFailure {
    pub source: String,
    pub message: String,
}

/// One interface result from a [`Collector`] poll.
#[derive(Debug, Clone)]
pub struct CollectorSample {
    pub interface_id: String,
    pub observation: Option<Observation>,
    pub failure: Option<CollectorFailure>,
}

impl CollectorSample {
    pub fn observed(interface_id: impl Into<String>, observation: Observation) -> Self {
        Self {
            interface_id: interface_id.into(),
            observation: Some(observation),
            failure: None,
        }
    }

    pub fn failed(
        interface_id: impl Into<String>,
        source: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            interface_id: interface_id.into(),
            observation: None,
            failure: Some(CollectorFailure {
                source: source.into(),
                message: message.into(),
            }),
        }
    }
}

/// A native or device-specific event already expressed as a chronicle kind.
#[derive(Debug, Clone)]
pub struct CollectorEvent {
    pub interface_id: Option<String>,
    pub kind: EntryKind,
}

/// Portable source contract. Implementations may use nl80211, WLAN API, a
/// modem SDK, firmware IPC, or test fixtures; the recorder does not care.
pub trait Collector {
    fn name(&self) -> &'static str;
    fn collect(&mut self) -> anyhow::Result<Vec<CollectorSample>>;

    fn collect_events(&mut self, _interval: Duration) -> anyhow::Result<Vec<CollectorEvent>> {
        Ok(Vec::new())
    }
}

pub struct Recorder<S: Sink, C: Collector> {
    sink: S,
    collector: C,
    detectors: BTreeMap<String, ChangeDetector>,
    options: RecorderOptions,
    next_sequence: u64,
    last_collector_error: Option<String>,
    interface_errors: BTreeMap<String, CollectorFailure>,
    last_event_error: Option<String>,
}

impl<S: Sink, C: Collector> Recorder<S, C> {
    pub fn with_collector(sink: S, collector: C, options: RecorderOptions) -> Self {
        let next_sequence = options.initial_sequence;
        Self {
            sink,
            collector,
            detectors: BTreeMap::new(),
            options,
            next_sequence,
            last_collector_error: None,
            interface_errors: BTreeMap::new(),
            last_event_error: None,
        }
    }

    /// One poll: observe, detect and write. Returns entries written.
    pub fn step(&mut self) -> anyhow::Result<usize> {
        let source = self.collector.name();
        let mut events = Vec::new();

        match self.collector.collect() {
            Ok(samples) => {
                if self.last_collector_error.take().is_some() {
                    events.push(CollectorEvent {
                        interface_id: None,
                        kind: EntryKind::CollectorRecovered {
                            source: source.to_string(),
                        },
                    });
                }
                self.process_samples(samples, &mut events);
            }
            Err(error) => {
                let message = error.to_string();
                if self.last_collector_error.as_deref() != Some(&message) {
                    events.push(CollectorEvent {
                        interface_id: None,
                        kind: EntryKind::CollectorError {
                            source: source.to_string(),
                            message: message.clone(),
                        },
                    });
                }
                self.last_collector_error = Some(message);
            }
        }

        let event_source = format!("{source}_events");
        match self.collector.collect_events(self.options.interval) {
            Ok(collected) => {
                if self.last_event_error.take().is_some() {
                    events.push(CollectorEvent {
                        interface_id: None,
                        kind: EntryKind::CollectorRecovered {
                            source: event_source,
                        },
                    });
                }
                events.extend(collected);
            }
            Err(error) => {
                let message = error.to_string();
                if self.last_event_error.as_deref() != Some(&message) {
                    events.push(CollectorEvent {
                        interface_id: None,
                        kind: EntryKind::CollectorError {
                            source: event_source,
                            message: message.clone(),
                        },
                    });
                }
                self.last_event_error = Some(message);
            }
        }

        let written = events.len();
        for event in events {
            let entry = Entry::stamped(
                &self.options.identity,
                self.next_sequence,
                event.interface_id,
                event.kind,
            );
            self.next_sequence = self.next_sequence.saturating_add(1);
            self.sink.write(&entry)?;
        }
        if written > 0 {
            self.sink.flush()?;
        }
        Ok(written)
    }

    fn process_samples(&mut self, samples: Vec<CollectorSample>, events: &mut Vec<CollectorEvent>) {
        for sample in samples {
            let interface_id = sample.interface_id;
            if let Some(failure) = sample.failure {
                if self.interface_errors.get(&interface_id) != Some(&failure) {
                    events.push(CollectorEvent {
                        interface_id: Some(interface_id.clone()),
                        kind: EntryKind::CollectorError {
                            source: failure.source.clone(),
                            message: failure.message.clone(),
                        },
                    });
                }
                self.interface_errors.insert(interface_id, failure);
                continue;
            }

            if let Some(previous) = self.interface_errors.remove(&interface_id) {
                events.push(CollectorEvent {
                    interface_id: Some(interface_id.clone()),
                    kind: EntryKind::CollectorRecovered {
                        source: previous.source,
                    },
                });
            }
            let Some(observation) = sample.observation else {
                continue;
            };
            let detector = self
                .detectors
                .entry(interface_id.clone())
                .or_insert_with(|| ChangeDetector::new(self.options.signal_threshold_db));
            events.extend(
                detector
                    .observe(observation)
                    .into_iter()
                    .map(|kind| CollectorEvent {
                        interface_id: Some(interface_id.clone()),
                        kind,
                    }),
            );
        }
    }

    pub fn run_for(&mut self, duration: Duration) -> anyhow::Result<usize> {
        let started = std::time::Instant::now();
        let mut total = 0;
        loop {
            total += self.step()?;
            if started.elapsed() + self.options.interval > duration {
                return Ok(total);
            }
            std::thread::sleep(self.options.interval);
        }
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn into_sink(self) -> S {
        self.sink
    }
}

#[cfg(all(any(windows, target_os = "linux"), feature = "status"))]
impl<S: Sink> Recorder<S, NativeCollector> {
    pub fn new(sink: S, options: RecorderOptions) -> Self {
        Self::with_collector(sink, NativeCollector::default(), options)
    }
}

#[cfg(test)]
mod tests {
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
}
