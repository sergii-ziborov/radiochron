use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;

use serde::{Deserialize, Serialize};

pub use crate::schema::CHRONICLE_SCHEMA_VERSION as SCHEMA_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockQuality {
    Unknown,
    Synchronized,
    Unsynchronized,
}

/// One firmware clock reading. Monotonic time is mandatory; wall time is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockReading {
    pub monotonic_ms: u64,
    pub unix_epoch_ms: Option<i64>,
    pub quality: ClockQuality,
}

/// Clock implemented by an RTOS tick counter, hardware timer or firmware SDK.
pub trait Clock {
    fn now(&mut self) -> ClockReading;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub device_id: Option<String>,
    pub boot_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityStage {
    Radio,
    Authentication,
    Ip,
    Dns,
    Tcp,
    Tls,
    Backend,
}

/// Aggregated heartbeat suitable for a fleet metric or an offline spool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub window_started_ms: u64,
    pub window_ended_ms: u64,
    pub expected_connectivity_ms: u64,
    /// Total radio-associated time, including periods where connectivity was optional.
    pub wifi_connected_ms: u64,
    /// Radio-associated time while connectivity was expected.
    pub expected_wifi_connected_ms: u64,
    /// Connected/expected ratio in tenths of one percent (0..=1000).
    pub connectivity_uptime_permille: Option<u16>,
    pub association_attempts: u32,
    pub disconnect_count: u32,
    pub roam_count: u32,
    pub backend_successes: u32,
    pub backend_failures: u32,
    pub rssi_sample_count: u32,
    pub rssi_min_dbm: Option<i32>,
    pub rssi_max_dbm: Option<i32>,
    pub rssi_mean_dbm: Option<i32>,
    pub last_disconnect_reason: Option<u16>,
    pub last_time_to_associate_ms: Option<u64>,
    pub last_time_to_ip_ms: Option<u64>,
    pub last_time_to_backend_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    AssociationAttempt {
        ssid: Option<String>,
    },
    Associated {
        ssid: Option<String>,
        bssid: Option<String>,
        rssi_dbm: Option<i32>,
    },
    Disconnected {
        last_bssid: Option<String>,
        reason_code: Option<u16>,
    },
    Roamed {
        from_bssid: String,
        to_bssid: String,
        rssi_dbm: Option<i32>,
    },
    SignalShift {
        bssid: Option<String>,
        from_dbm: i32,
        to_dbm: i32,
    },
    IpAcquired {
        address: Option<String>,
    },
    BackendCheck {
        endpoint: String,
        reachable: bool,
        latency_ms: Option<u32>,
    },
    ConnectivityFailure {
        stage: ConnectivityStage,
        code: Option<i32>,
    },
    Metrics {
        snapshot: MetricsSnapshot,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub schema_version: u16,
    pub device_id: Option<String>,
    pub boot_id: String,
    pub sequence: u64,
    pub event_id: String,
    pub clock: ClockReading,
    pub interface_id: Option<String>,
    #[serde(flatten)]
    pub event: EventKind,
}

/// Caller-owned durable destination: flash ring, NVS, MQTT spool or RAM.
pub trait Sink {
    type Error;

    fn write(&mut self, entry: &Entry) -> Result<(), Self::Error>;

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct VecSink(pub Vec<Entry>);

impl Sink for VecSink {
    type Error = Infallible;

    fn write(&mut self, entry: &Entry) -> Result<(), Self::Error> {
        self.0.push(entry.clone());
        Ok(())
    }
}
