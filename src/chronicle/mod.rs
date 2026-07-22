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
//! - [`Collector`] / [`Recorder`] — portable collection contract and loop. The
//!   bundled adapter uses WLAN API on Windows and nl80211 on Linux; Windows can
//!   additionally tail the WLAN event log for reason codes.
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

mod recorder;

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};

pub use detect::{ChangeDetector, Observation};
pub use jsonl::{read_recent_jsonl, JsonlRead, JsonlSink, RotationPolicy};

#[cfg(all(any(windows, target_os = "linux"), feature = "status"))]
pub use recorder::NativeCollector;
pub use recorder::{
    Collector, CollectorEvent, CollectorFailure, CollectorSample, Recorder, RecorderOptions,
};

/// Current wire/storage schema for [`Entry`].
pub const CHRONICLE_SCHEMA_VERSION: u16 = 1;

/// How trustworthy the wall clock was when an event was stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockQuality {
    Unknown,
    Synchronized,
    Unsynchronized,
}

/// Clock provenance carried by every entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockMetadata {
    pub quality: ClockQuality,
    pub source: String,
    /// Process-monotonic time. Useful for ordering when wall time jumps.
    pub monotonic_ms: u64,
}

/// Stable identity for one recorder process or device boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChronicleIdentity {
    pub device_id: Option<String>,
    pub boot_id: String,
    pub clock_quality: ClockQuality,
}

impl Default for ChronicleIdentity {
    fn default() -> Self {
        process_identity().clone()
    }
}

/// One recorded observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub schema_version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub boot_id: String,
    /// Monotonic within one `(device_id, boot_id)` stream.
    pub sequence: u64,
    /// Deduplication key derived from the stream identity.
    pub event_id: String,
    pub clock: ClockMetadata,
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
        let sequence = PROCESS_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self::stamped(process_identity(), sequence, interface_guid, kind)
    }

    /// Stamp using a caller-owned identity and sequence. Recorders use this so
    /// an offline spool can resume sequence numbers after a restart.
    pub fn stamped(
        identity: &ChronicleIdentity,
        sequence: u64,
        interface_guid: Option<String>,
        kind: EntryKind,
    ) -> Self {
        let epoch_seconds = crate::time::now_epoch_seconds();
        let device_component = identity.device_id.as_deref().unwrap_or("anonymous");
        Self {
            schema_version: CHRONICLE_SCHEMA_VERSION,
            device_id: identity.device_id.clone(),
            boot_id: identity.boot_id.clone(),
            sequence,
            event_id: event_id(device_component, &identity.boot_id, sequence),
            clock: ClockMetadata {
                quality: identity.clock_quality,
                source: "system_utc".to_string(),
                monotonic_ms: process_started().elapsed().as_millis() as u64,
            },
            epoch_seconds,
            time: crate::time::format_epoch(epoch_seconds),
            interface_guid,
            kind,
        }
    }
}

/// What happened. Serialised with a `kind` tag so a JSONL consumer can filter
/// with a substring match before parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// End-to-end state beyond association, collected on explicit targets.
    #[cfg(feature = "connectivity")]
    Connectivity {
        report: Box<crate::connectivity::ConnectivityReport>,
    },
}

static PROCESS_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn process_started() -> &'static Instant {
    static STARTED: OnceLock<Instant> = OnceLock::new();
    STARTED.get_or_init(Instant::now)
}

fn process_identity() -> &'static ChronicleIdentity {
    static IDENTITY: OnceLock<ChronicleIdentity> = OnceLock::new();
    IDENTITY.get_or_init(|| ChronicleIdentity {
        device_id: std::env::var("RADIOCHRON_DEVICE_ID")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        boot_id: native_boot_id().unwrap_or_else(|| {
            format!(
                "process-{}-{}",
                std::process::id(),
                crate::time::now_epoch_seconds()
            )
        }),
        clock_quality: ClockQuality::Unknown,
    })
}

#[cfg(target_os = "linux")]
fn native_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn event_id(device_id: &str, boot_id: &str, sequence: u64) -> String {
    format!(
        "radiochron:1:{}:{device_id}:{}:{boot_id}:{sequence}",
        device_id.len(),
        boot_id.len()
    )
}

#[cfg(not(target_os = "linux"))]
fn native_boot_id() -> Option<String> {
    None
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
            schema_version: CHRONICLE_SCHEMA_VERSION,
            device_id: Some("device-7".into()),
            boot_id: "boot-a".into(),
            sequence: 42,
            event_id: "radiochron:1:8:device-7:6:boot-a:42".into(),
            clock: ClockMetadata {
                quality: ClockQuality::Synchronized,
                source: "system_utc".into(),
                monotonic_ms: 100,
            },
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
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"event_id\":\"radiochron:1:8:device-7:6:boot-a:42\""));
    }

    #[test]
    fn event_ids_are_unambiguous_when_identity_contains_colons() {
        assert_ne!(event_id("a:b", "c", 1), event_id("a", "b:c", 1));
    }
}
