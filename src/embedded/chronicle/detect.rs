use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::EventKind;

#[derive(Debug, Clone, Default)]
pub(super) struct Observation {
    pub(super) connected: bool,
    pub(super) ssid: Option<String>,
    pub(super) bssid: Option<String>,
    pub(super) rssi_dbm: Option<i32>,
}

#[derive(Debug)]
pub(super) struct ChangeDetector {
    previous: Option<Observation>,
    reported_rssi: Option<i32>,
    threshold_db: i32,
}

impl ChangeDetector {
    pub(super) fn new(threshold_db: i32) -> Self {
        Self {
            previous: None,
            reported_rssi: None,
            threshold_db: threshold_db.max(1),
        }
    }

    pub(super) fn observe(&mut self, current: Observation, reason: Option<u16>) -> Vec<EventKind> {
        let mut events = Vec::new();
        let previous = self.previous.replace(current.clone());
        let was_connected = previous.as_ref().is_some_and(|value| value.connected);

        match (was_connected, current.connected) {
            (false, true) => {
                self.reported_rssi = current.rssi_dbm;
                events.push(EventKind::Associated {
                    ssid: current.ssid,
                    bssid: current.bssid,
                    rssi_dbm: current.rssi_dbm,
                });
            }
            (true, false) => {
                self.reported_rssi = None;
                events.push(EventKind::Disconnected {
                    last_bssid: previous.and_then(|value| value.bssid),
                    reason_code: reason,
                });
            }
            (true, true) => {
                let previous = previous.expect("connected state has a previous observation");
                match (previous.bssid.as_deref(), current.bssid.as_deref()) {
                    (Some(from), Some(to)) if from != to => {
                        self.reported_rssi = current.rssi_dbm;
                        events.push(EventKind::Roamed {
                            from_bssid: from.to_string(),
                            to_bssid: to.to_string(),
                            rssi_dbm: current.rssi_dbm,
                        });
                    }
                    _ => {
                        if let (Some(reported), Some(now)) = (self.reported_rssi, current.rssi_dbm)
                        {
                            if (now - reported).abs() >= self.threshold_db {
                                self.reported_rssi = Some(now);
                                events.push(EventKind::SignalShift {
                                    bssid: current.bssid,
                                    from_dbm: reported,
                                    to_dbm: now,
                                });
                            }
                        } else if self.reported_rssi.is_none() {
                            self.reported_rssi = current.rssi_dbm;
                        }
                    }
                }
            }
            (false, false) => {}
        }
        events
    }
}
