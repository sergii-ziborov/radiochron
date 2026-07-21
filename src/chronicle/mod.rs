//! The chronicle: recording what the radio does, as it happens.
//!
//! Reading history and writing it are different problems. [`crate::events`]
//! reads what Windows already recorded; this module records our own — which is
//! the only way history exists on platforms whose OS keeps no log, and the only
//! way it survives in a fleet where the OS log rotates away before anyone looks.
//!
//! # Structure
//!
//! - [`Entry`] / [`EntryKind`] — one recorded observation, serialisable.
//! - [`Sink`] — where entries go. The shipped implementation is [`JsonlSink`]:
//!   append-only JSON Lines with size-based rotation, zero new dependencies,
//!   greppable, and safer across power loss than a database mid-transaction.
//! - [`ChangeDetector`] — pure state machine turning a stream of connection
//!   observations into entries. No OS calls, so it is testable without a radio
//!   and portable to collectors that do not exist yet.
//! - `Recorder` (Windows, `status` feature) — the loop that feeds the detector
//!   from live polls and, when the `history` feature is present, tails the WLAN
//!   event log for reason codes.
//!
//! # Why a module and not a `radiochron-history` crate
//!
//! The recording layer moves in lockstep with the collectors it observes, and
//! the dependency argument for splitting dissolves under the [`Sink`] trait:
//! heavy backends live in the *consumer's* crate. A bundled SQLite sink would
//! also break this library's defining property — building on a stock rustup
//! toolchain — because `rusqlite`'s vendored C requires a C compiler. Measured,
//! not assumed.

mod detect;
mod jsonl;

#[cfg(all(windows, feature = "status"))]
mod recorder;

use std::collections::BTreeMap;
use std::io;

use serde::Serialize;

pub use detect::{ChangeDetector, Observation};
pub use jsonl::{read_recent_jsonl, JsonlRead, JsonlSink, RotationPolicy};

#[cfg(all(windows, feature = "status"))]
pub use recorder::{Recorder, RecorderOptions};

/// One recorded observation.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// Seconds since the Unix epoch, stamped at write time.
    pub epoch_seconds: i64,
    /// The same instant as RFC 3339 UTC, for humans grepping the file.
    pub time: String,
    /// Interface responsible for the entry. `None` is reserved for process-wide
    /// collector health and legacy callers that construct entries manually.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_guid: Option<String>,
    #[serde(flatten)]
    pub kind: EntryKind,
}

impl Entry {
    /// Stamp an entry with the current time.
    pub fn now(kind: EntryKind) -> Self {
        Self::now_for_interface(None, kind)
    }

    pub fn now_for_interface(interface_guid: Option<String>, kind: EntryKind) -> Self {
        let epoch_seconds = crate::time::now_epoch_seconds();
        Self {
            epoch_seconds,
            time: crate::time::format_epoch(epoch_seconds),
            interface_guid,
            kind,
        }
    }
}

/// What happened. Serialised with a `kind` tag so a JSONL consumer can filter
/// with a substring match before parsing.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryKind {
    /// The interface associated (or the recorder started while associated).
    Associated {
        ssid: Option<String>,
        bssid: Option<String>,
        rssi_dbm: i32,
    },
    /// The association was lost.
    Disconnected { last_bssid: Option<String> },
    /// The association moved to a different BSSID without an observed gap.
    Roamed {
        from_bssid: String,
        to_bssid: String,
        rssi_dbm: i32,
    },
    /// Signal moved beyond the hysteresis threshold since last reported.
    SignalShift {
        bssid: Option<String>,
        from_dbm: i32,
        to_dbm: i32,
    },
    /// A WLAN AutoConfig event observed while recording (Windows only).
    LogEvent {
        event_id: u32,
        record_id: Option<u64>,
        meaning: String,
        fields: BTreeMap<String, String>,
    },
    /// A native collector failed. This is deliberately not represented as a
    /// disconnect: inability to observe the interface is not evidence that the
    /// radio disconnected.
    CollectorError { source: String, message: String },
    /// Emitted once when a previously failing collector succeeds again.
    CollectorRecovered { source: String },
    /// Windows rotated or outpaced the bounded event-log query between polls.
    HistoryGap {
        after_record_id: u64,
        before_record_id: u64,
    },
}

/// Where chronicle entries go.
///
/// Implementations must be durable-ish, not transactional: a recorder is a
/// long-running loop and a crash should cost at most the unflushed tail.
pub trait Sink {
    fn write(&mut self, entry: &Entry) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

/// A sink that keeps everything in memory. For tests and for callers that want
/// to batch entries somewhere themselves.
#[derive(Debug, Default)]
pub struct VecSink(pub Vec<Entry>);

impl Sink for VecSink {
    fn write(&mut self, entry: &Entry) -> io::Result<()> {
        self.0.push(entry.clone());
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_serialise_with_a_kind_tag() {
        let entry = Entry {
            epoch_seconds: 1_784_528_615,
            time: "2026-07-20T06:23:35Z".into(),
            interface_guid: Some("guid".into()),
            kind: EntryKind::Roamed {
                from_bssid: "aa:aa:aa:aa:aa:aa".into(),
                to_bssid: "bb:bb:bb:bb:bb:bb".into(),
                rssi_dbm: -61,
            },
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"kind\":\"roamed\""), "{json}");
        assert!(json.contains("\"from_bssid\":\"aa:aa:aa:aa:aa:aa\""));
        assert!(json.contains("\"epoch_seconds\":1784528615"));
    }
}
