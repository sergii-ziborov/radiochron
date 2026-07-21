//! The loop that writes the chronicle on Windows.
//!
//! Combines two sources into one stream of entries: polled association state
//! (through the pure [`ChangeDetector`]) and, when the `history` feature is
//! compiled in, new WLAN AutoConfig events — which is where reason codes live.
//!
//! The caller owns the loop. [`Recorder::step`] does one poll and returns how
//! many entries were written, so an IoT agent embeds it in its own scheduler,
//! and [`Recorder::run_for`] is the convenience wrapper for everyone else.

use std::collections::BTreeMap;
use std::time::Duration;

use super::{ChangeDetector, Entry, Observation, Sink};
use crate::wlan;

#[derive(Debug, Clone, Copy)]
pub struct RecorderOptions {
    /// Delay between polls in [`Recorder::run_for`].
    pub interval: Duration,
    /// Hysteresis for [`EntryKind::SignalShift`], in dB.
    pub signal_threshold_db: i32,
}

impl Default for RecorderOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            signal_threshold_db: 8,
        }
    }
}

pub struct Recorder<S: Sink> {
    sink: S,
    detectors: BTreeMap<String, ChangeDetector>,
    options: RecorderOptions,
    last_status_error: Option<String>,
    interface_errors: BTreeMap<String, String>,
    /// Only events newer than this reach the chronicle. Starts at construction
    /// time: the chronicle records what happens *while recording* — the past is
    /// already served by [`crate::events::recent`], and dumping it here would
    /// duplicate every event on every restart.
    #[cfg(feature = "history")]
    last_log_epoch: i64,
    #[cfg(feature = "history")]
    last_log_record_id: Option<u64>,
    #[cfg(feature = "history")]
    last_history_error: Option<String>,
}

impl<S: Sink> Recorder<S> {
    pub fn new(sink: S, options: RecorderOptions) -> Self {
        Self {
            sink,
            detectors: BTreeMap::new(),
            options,
            last_status_error: None,
            interface_errors: BTreeMap::new(),
            #[cfg(feature = "history")]
            last_log_epoch: crate::time::now_epoch_seconds(),
            #[cfg(feature = "history")]
            last_log_record_id: None,
            #[cfg(feature = "history")]
            last_history_error: None,
        }
    }

    /// One poll: observe, detect, tail the log, write. Returns entries written.
    ///
    /// A failed status read becomes collector-health evidence rather than a
    /// false disconnect. Every WLAN interface has its own change detector.
    pub fn step(&mut self) -> anyhow::Result<usize> {
        let mut kinds: Vec<(Option<String>, super::EntryKind)> = Vec::new();

        match wlan::wifi_status() {
            Ok(statuses) => {
                if self.last_status_error.take().is_some() {
                    kinds.push((
                        None,
                        super::EntryKind::CollectorRecovered {
                            source: "wifi_status".to_string(),
                        },
                    ));
                }

                for status in statuses {
                    let guid = status.interface.guid;
                    if let Some(message) = status.connection_error {
                        if self.interface_errors.get(&guid) != Some(&message) {
                            kinds.push((
                                Some(guid.clone()),
                                super::EntryKind::CollectorError {
                                    source: "current_connection".to_string(),
                                    message: message.clone(),
                                },
                            ));
                        }
                        self.interface_errors.insert(guid, message);
                        continue;
                    }
                    if self.interface_errors.remove(&guid).is_some() {
                        kinds.push((
                            Some(guid.clone()),
                            super::EntryKind::CollectorRecovered {
                                source: "current_connection".to_string(),
                            },
                        ));
                    }
                    let observation = status
                        .connection
                        .map(|connection| Observation {
                            connected: true,
                            ssid: connection.ssid,
                            bssid: connection.bssid,
                            rssi_dbm: Some(connection.rssi_dbm_estimate),
                        })
                        .unwrap_or_default();
                    let detector = self
                        .detectors
                        .entry(guid.clone())
                        .or_insert_with(|| ChangeDetector::new(self.options.signal_threshold_db));
                    kinds.extend(
                        detector
                            .observe(observation)
                            .into_iter()
                            .map(|kind| (Some(guid.clone()), kind)),
                    );
                }
            }
            Err(error) => {
                let message = error.to_string();
                if self.last_status_error.as_deref() != Some(&message) {
                    kinds.push((
                        None,
                        super::EntryKind::CollectorError {
                            source: "wifi_status".to_string(),
                            message: message.clone(),
                        },
                    ));
                }
                self.last_status_error = Some(message);
            }
        }

        #[cfg(feature = "history")]
        kinds.extend(self.tail_event_log());

        let written = kinds.len();
        for (interface_guid, kind) in kinds {
            self.sink
                .write(&Entry::now_for_interface(interface_guid, kind))?;
        }
        if written > 0 {
            self.sink.flush()?;
        }

        Ok(written)
    }

    /// Poll on the configured interval until `duration` elapses.
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

    /// Recover the sink (for tests and for callers that reuse it).
    pub fn into_sink(self) -> S {
        self.sink
    }

    /// New WLAN AutoConfig events since the last step, oldest first.
    ///
    /// A read failure is recorded once and recovery is recorded once; it does
    /// not stop the primary polled recorder.
    #[cfg(feature = "history")]
    fn tail_event_log(&mut self) -> Vec<(Option<String>, super::EntryKind)> {
        // EventRecordID, not timestamp seconds, is the durable cursor. The
        // bounded read remains honest under bursts because a detected gap is
        // recorded explicitly rather than silently discarded.
        // The event query must cover at least one complete polling interval;
        // otherwise a deliberately slow recorder can miss events before the
        // EventRecordID cursor has seen them.
        let event_lookback = self
            .options
            .interval
            .as_secs()
            .saturating_mul(2)
            .clamp(120, 3_600);
        let events = match crate::events::recent(512, Some(event_lookback)) {
            Ok(events) => events,
            Err(error) => {
                let message = error.to_string();
                let mut out = Vec::new();
                if self.last_history_error.as_deref() != Some(&message) {
                    out.push((
                        None,
                        super::EntryKind::CollectorError {
                            source: "wlan_event_log".to_string(),
                            message: message.clone(),
                        },
                    ));
                }
                self.last_history_error = Some(message);
                return out;
            }
        };

        let mut out = Vec::new();
        if self.last_history_error.take().is_some() {
            out.push((
                None,
                super::EntryKind::CollectorRecovered {
                    source: "wlan_event_log".to_string(),
                },
            ));
        }

        let previous_record_id = self.last_log_record_id;
        let mut fresh: Vec<&crate::events::WlanEvent> = events
            .iter()
            .filter(|event| match (previous_record_id, event.record_id) {
                (Some(previous), Some(record)) => record > previous,
                _ => event.epoch_seconds > self.last_log_epoch,
            })
            .collect();
        // `recent` is newest-first; a chronicle reads oldest-first.
        fresh.reverse();

        if let (Some(previous), Some(first)) = (
            previous_record_id,
            fresh.iter().filter_map(|event| event.record_id).min(),
        ) {
            if first > previous.saturating_add(1) {
                out.push((
                    None,
                    super::EntryKind::HistoryGap {
                        after_record_id: previous,
                        before_record_id: first,
                    },
                ));
            }
        }

        out.extend(fresh.into_iter().map(|event| {
            (
                event.interface_guid().map(str::to_string),
                super::EntryKind::LogEvent {
                    event_id: event.event_id,
                    record_id: event.record_id,
                    meaning: event.meaning.to_string(),
                    fields: event.data.clone(),
                },
            )
        }));

        if let Some(newest) = events.iter().map(|e| e.epoch_seconds).max() {
            self.last_log_epoch = self.last_log_epoch.max(newest);
        }
        if let Some(newest) = events.iter().filter_map(|e| e.record_id).max() {
            self.last_log_record_id = Some(self.last_log_record_id.unwrap_or(0).max(newest));
        }

        out
    }
}
