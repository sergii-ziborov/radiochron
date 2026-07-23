use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

use crate::wlan::WifiStatus;

use super::detect::{ChangeDetector, Observation};
use super::{
    Clock, ClockReading, ConnectivityStage, Entry, EventKind, Identity, MetricsSnapshot,
    MetricsTracker, Sink, SCHEMA_VERSION,
};

/// Change-only recorder with fleet-safe identity and heartbeat metrics.
///
/// Metrics describe one logical connectivity path. Firmware with independent
/// Wi-Fi and cellular links should keep one recorder per path rather than
/// interleaving their connected states.
pub struct Chronicle<S: Sink, C: Clock> {
    sink: S,
    clock: C,
    identity: Identity,
    next_sequence: u64,
    signal_threshold_db: i32,
    detectors: BTreeMap<String, ChangeDetector>,
    metrics: MetricsTracker,
}

impl<S: Sink, C: Clock> Chronicle<S, C> {
    pub fn new(
        sink: S,
        mut clock: C,
        identity: Identity,
        initial_sequence: u64,
        signal_threshold_db: i32,
    ) -> Self {
        let started_ms = clock.now().monotonic_ms;
        Self {
            sink,
            clock,
            identity,
            next_sequence: initial_sequence,
            signal_threshold_db: signal_threshold_db.max(1),
            detectors: BTreeMap::new(),
            metrics: MetricsTracker::new(started_ms),
        }
    }

    pub fn observe_status(&mut self, status: &WifiStatus) -> Result<usize, S::Error> {
        self.observe_status_with_reason(status, None)
    }

    pub fn observe_status_with_reason(
        &mut self,
        status: &WifiStatus,
        disconnect_reason: Option<u16>,
    ) -> Result<usize, S::Error> {
        let reading = self.clock.now();
        let interface_id = status.interface.guid.clone();
        let observation = Observation {
            connected: status.connection.is_some(),
            ssid: status
                .connection
                .as_ref()
                .and_then(|connection| connection.ssid.clone()),
            bssid: status
                .connection
                .as_ref()
                .and_then(|connection| connection.bssid.clone()),
            rssi_dbm: status
                .connection
                .as_ref()
                .map(|connection| connection.rssi_dbm_estimate),
        };

        self.metrics.observe_connection(
            reading.monotonic_ms,
            observation.connected,
            observation.rssi_dbm,
            disconnect_reason,
        );
        let events = self
            .detectors
            .entry(interface_id.clone())
            .or_insert_with(|| ChangeDetector::new(self.signal_threshold_db))
            .observe(observation, disconnect_reason);

        let count = events.len();
        for event in events {
            if matches!(&event, EventKind::Roamed { .. }) {
                self.metrics.roam(reading.monotonic_ms);
            }
            self.write_at(reading, Some(interface_id.clone()), event)?;
        }
        if count > 0 {
            self.sink.flush()?;
        }
        Ok(count)
    }

    pub fn note_association_attempt(
        &mut self,
        interface_id: &str,
        ssid: Option<&str>,
    ) -> Result<(), S::Error> {
        self.note_timed_interface_event(
            interface_id,
            EventKind::AssociationAttempt {
                ssid: ssid.map(ToString::to_string),
            },
            MetricsTracker::association_attempt,
        )
    }

    pub fn note_ip_acquired(
        &mut self,
        interface_id: &str,
        address: Option<&str>,
    ) -> Result<(), S::Error> {
        self.note_timed_interface_event(
            interface_id,
            EventKind::IpAcquired {
                address: address.map(ToString::to_string),
            },
            MetricsTracker::ip_acquired,
        )
    }

    pub fn note_backend_result(
        &mut self,
        interface_id: &str,
        endpoint: &str,
        reachable: bool,
        latency_ms: Option<u32>,
    ) -> Result<(), S::Error> {
        let reading = self.clock.now();
        self.metrics.backend_result(reading.monotonic_ms, reachable);
        self.write_interface_event(
            reading,
            interface_id,
            EventKind::BackendCheck {
                endpoint: endpoint.to_string(),
                reachable,
                latency_ms,
            },
        )
    }

    pub fn note_connectivity_failure(
        &mut self,
        interface_id: Option<&str>,
        stage: ConnectivityStage,
        code: Option<i32>,
    ) -> Result<(), S::Error> {
        let reading = self.clock.now();
        self.write_and_flush(
            reading,
            interface_id.map(ToString::to_string),
            EventKind::ConnectivityFailure { stage, code },
        )
    }

    pub fn set_connectivity_expected(&mut self, expected: bool) {
        let reading = self.clock.now();
        self.metrics.set_expected(reading.monotonic_ms, expected);
    }

    pub fn emit_metrics(&mut self) -> Result<MetricsSnapshot, S::Error> {
        let reading = self.clock.now();
        let snapshot = self.metrics.snapshot(reading.monotonic_ms);
        self.write_and_flush(
            reading,
            None,
            EventKind::Metrics {
                snapshot: snapshot.clone(),
            },
        )?;
        self.metrics.reset_window(reading.monotonic_ms);
        Ok(snapshot)
    }

    pub fn record(
        &mut self,
        interface_id: Option<String>,
        event: EventKind,
    ) -> Result<(), S::Error> {
        let reading = self.clock.now();
        self.write_and_flush(reading, interface_id, event)
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn into_sink(self) -> S {
        self.sink
    }

    fn write_and_flush(
        &mut self,
        reading: ClockReading,
        interface_id: Option<String>,
        event: EventKind,
    ) -> Result<(), S::Error> {
        self.write_at(reading, interface_id, event)?;
        self.sink.flush()
    }

    fn write_interface_event(
        &mut self,
        reading: ClockReading,
        interface_id: &str,
        event: EventKind,
    ) -> Result<(), S::Error> {
        self.write_and_flush(reading, Some(interface_id.to_string()), event)
    }

    fn note_timed_interface_event(
        &mut self,
        interface_id: &str,
        event: EventKind,
        update_metrics: fn(&mut MetricsTracker, u64),
    ) -> Result<(), S::Error> {
        let reading = self.clock.now();
        update_metrics(&mut self.metrics, reading.monotonic_ms);
        self.write_interface_event(reading, interface_id, event)
    }

    fn write_at(
        &mut self,
        reading: ClockReading,
        interface_id: Option<String>,
        event: EventKind,
    ) -> Result<(), S::Error> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let device_component = self.identity.device_id.as_deref().unwrap_or("anonymous");
        let entry = Entry {
            schema_version: SCHEMA_VERSION,
            device_id: self.identity.device_id.clone(),
            boot_id: self.identity.boot_id.clone(),
            sequence,
            event_id: format!(
                "radiochron:1:{}:{device_component}:{}:{}:{sequence}",
                device_component.len(),
                self.identity.boot_id.len(),
                self.identity.boot_id
            ),
            clock: reading,
            interface_id,
            event,
        };
        self.sink.write(&entry)
    }
}
