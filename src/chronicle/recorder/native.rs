//! OS collector adapter for the portable recorder.

#[cfg(all(windows, feature = "history"))]
use super::CollectorEvent;
use super::{Collector, CollectorSample};
#[cfg(all(windows, feature = "history"))]
use crate::chronicle::EntryKind;
use crate::chronicle::Observation;

#[derive(Debug)]
#[cfg_attr(not(all(windows, feature = "history")), derive(Default))]
pub struct NativeCollector {
    #[cfg(all(windows, feature = "history"))]
    last_log_epoch: i64,
    #[cfg(all(windows, feature = "history"))]
    last_log_record_id: Option<u64>,
}

#[cfg(all(windows, feature = "history"))]
impl Default for NativeCollector {
    fn default() -> Self {
        Self {
            #[cfg(all(windows, feature = "history"))]
            last_log_epoch: crate::time::now_epoch_seconds(),
            #[cfg(all(windows, feature = "history"))]
            last_log_record_id: None,
        }
    }
}

impl Collector for NativeCollector {
    fn name(&self) -> &'static str {
        "wifi_status"
    }

    fn collect(&mut self) -> anyhow::Result<Vec<CollectorSample>> {
        Ok(crate::wlan::wifi_status()?
            .into_iter()
            .map(|status| {
                let interface_id = status.interface.guid;
                if let Some(message) = status.connection_error {
                    return CollectorSample::failed(interface_id, "current_connection", message);
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
                CollectorSample::observed(interface_id, observation)
            })
            .collect())
    }

    #[cfg(all(windows, feature = "history"))]
    fn collect_events(
        &mut self,
        interval: std::time::Duration,
    ) -> anyhow::Result<Vec<CollectorEvent>> {
        let lookback = interval.as_secs().saturating_mul(2).clamp(120, 3_600);
        let events = crate::events::recent(512, Some(lookback))?;
        let previous_record_id = self.last_log_record_id;
        let mut fresh: Vec<&crate::events::WlanEvent> = events
            .iter()
            .filter(|event| match (previous_record_id, event.record_id) {
                (Some(previous), Some(record)) => record > previous,
                _ => event.epoch_seconds > self.last_log_epoch,
            })
            .collect();
        fresh.reverse();

        let mut out = Vec::new();
        if let (Some(previous), Some(first)) = (
            previous_record_id,
            fresh.iter().filter_map(|event| event.record_id).min(),
        ) {
            if first > previous.saturating_add(1) {
                out.push(CollectorEvent {
                    interface_id: None,
                    kind: EntryKind::HistoryGap {
                        after_record_id: previous,
                        before_record_id: first,
                    },
                });
            }
        }

        out.extend(fresh.into_iter().map(|event| CollectorEvent {
            interface_id: event.interface_guid().map(str::to_string),
            kind: EntryKind::LogEvent {
                event_id: event.event_id,
                record_id: event.record_id,
                meaning: event.meaning.to_string(),
                fields: event.data.clone(),
            },
        }));

        if let Some(newest) = events.iter().map(|event| event.epoch_seconds).max() {
            self.last_log_epoch = self.last_log_epoch.max(newest);
        }
        if let Some(newest) = events.iter().filter_map(|event| event.record_id).max() {
            self.last_log_record_id = Some(self.last_log_record_id.unwrap_or(0).max(newest));
        }
        Ok(out)
    }
}
