//! Turn a stream of connection observations into chronicle entries.
//!
//! Pure state machine: no OS calls, no clock. That is what makes it testable
//! without a radio, and reusable verbatim once a Linux or cellular collector
//! produces the same [`Observation`] shape.

use super::EntryKind;

/// A single poll of the current association, decoupled from any collector's
/// native types so non-Windows collectors can feed the same detector.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observation {
    pub connected: bool,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub rssi_dbm: Option<i32>,
}

/// Emits entries only on *change*, with hysteresis on signal level.
///
/// The alternative — logging every poll — buries the story in noise: a stable
/// link polled every two seconds is 43 200 identical lines a day. The chronicle
/// records transitions, and the signal only when it has genuinely moved.
#[derive(Debug)]
pub struct ChangeDetector {
    previous: Option<Observation>,
    /// Signal level last written to the chronicle; the hysteresis baseline.
    reported_rssi: Option<i32>,
    threshold_db: i32,
}

impl ChangeDetector {
    /// `threshold_db` — how far the signal must move from the last *reported*
    /// level before a shift is recorded. Values under ~5 dB chase driver noise:
    /// most Windows drivers reconstruct dBm from a 0..100 quality scale with
    /// about 2 dB of quantisation.
    pub fn new(threshold_db: i32) -> Self {
        Self {
            previous: None,
            reported_rssi: None,
            threshold_db: threshold_db.max(1),
        }
    }

    /// Feed one observation; returns the entries it implies, in order.
    pub fn observe(&mut self, current: Observation) -> Vec<EntryKind> {
        let mut out = Vec::new();
        let previous = self.previous.replace(current.clone());

        match (
            previous.as_ref().is_some_and(|p| p.connected),
            current.connected,
        ) {
            // First sight of an association, or a reconnect after a gap. A
            // return to the same BSSID after a gap is deliberately Associated,
            // not Roamed — the gap is the story, and it was already recorded.
            (false, true) => {
                self.reported_rssi = current.rssi_dbm;
                out.push(EntryKind::Associated {
                    ssid: current.ssid.clone(),
                    bssid: current.bssid.clone(),
                    rssi_dbm: current.rssi_dbm.unwrap_or(0),
                });
            }
            (true, false) => {
                self.reported_rssi = None;
                out.push(EntryKind::Disconnected {
                    last_bssid: previous.and_then(|p| p.bssid),
                });
            }
            (true, true) => {
                let prev = previous.expect("connected implies a previous observation");

                match (prev.bssid.as_deref(), current.bssid.as_deref()) {
                    (Some(from), Some(to)) if from != to => {
                        // A roam resets the hysteresis baseline: the new AP's
                        // level is a new context, not a shift of the old one.
                        self.reported_rssi = current.rssi_dbm;
                        out.push(EntryKind::Roamed {
                            from_bssid: from.to_string(),
                            to_bssid: to.to_string(),
                            rssi_dbm: current.rssi_dbm.unwrap_or(0),
                        });
                    }
                    _ => {
                        if let (Some(reported), Some(now)) = (self.reported_rssi, current.rssi_dbm)
                        {
                            if (now - reported).abs() >= self.threshold_db {
                                self.reported_rssi = Some(now);
                                out.push(EntryKind::SignalShift {
                                    bssid: current.bssid.clone(),
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
            // Still disconnected: nothing to say.
            (false, false) => {}
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(bssid: Option<&str>, rssi: Option<i32>) -> Observation {
        Observation {
            connected: bssid.is_some(),
            ssid: bssid.map(|_| "Net".to_string()),
            bssid: bssid.map(str::to_string),
            rssi_dbm: rssi,
        }
    }

    fn kinds(entries: &[EntryKind]) -> Vec<&'static str> {
        entries
            .iter()
            .map(|e| match e {
                EntryKind::Associated { .. } => "associated",
                EntryKind::Disconnected { .. } => "disconnected",
                EntryKind::Roamed { .. } => "roamed",
                EntryKind::SignalShift { .. } => "signal_shift",
                EntryKind::LogEvent { .. } => "log_event",
                EntryKind::CollectorError { .. } => "collector_error",
                EntryKind::CollectorRecovered { .. } => "collector_recovered",
                EntryKind::HistoryGap { .. } => "history_gap",
            })
            .collect()
    }

    #[test]
    fn a_stable_link_produces_one_entry_then_silence() {
        let mut d = ChangeDetector::new(8);
        assert_eq!(
            kinds(&d.observe(obs(Some("aa"), Some(-60)))),
            ["associated"]
        );

        // 43 more identical polls: the chronicle stays quiet.
        for _ in 0..43 {
            assert!(d.observe(obs(Some("aa"), Some(-61))).is_empty());
        }
    }

    #[test]
    fn drift_below_the_threshold_is_noise_beyond_it_is_a_shift() {
        let mut d = ChangeDetector::new(8);
        d.observe(obs(Some("aa"), Some(-60)));

        assert!(
            d.observe(obs(Some("aa"), Some(-66))).is_empty(),
            "6 dB is inside hysteresis"
        );

        let shift = d.observe(obs(Some("aa"), Some(-69)));
        assert_eq!(
            kinds(&shift),
            ["signal_shift"],
            "9 dB from the reported -60 must fire"
        );
        match &shift[0] {
            EntryKind::SignalShift {
                from_dbm, to_dbm, ..
            } => {
                assert_eq!((*from_dbm, *to_dbm), (-60, -69));
            }
            other => panic!("unexpected {other:?}"),
        }

        // The baseline moved to -69: another 6 dB stays quiet again.
        assert!(d.observe(obs(Some("aa"), Some(-64))).is_empty());
    }

    #[test]
    fn a_bssid_change_is_a_roam_and_resets_the_baseline() {
        let mut d = ChangeDetector::new(8);
        d.observe(obs(Some("aa"), Some(-75)));

        let roam = d.observe(obs(Some("bb"), Some(-55)));
        assert_eq!(kinds(&roam), ["roamed"]);

        // -55 is the new baseline, so a poll at -60 (5 dB) is quiet, and the
        // 20 dB jump at the roam itself was not double-reported as a shift.
        assert!(d.observe(obs(Some("bb"), Some(-60))).is_empty());
    }

    #[test]
    fn a_gap_and_return_to_the_same_ap_is_disconnect_then_associate_not_a_roam() {
        let mut d = ChangeDetector::new(8);
        d.observe(obs(Some("aa"), Some(-60)));

        assert_eq!(kinds(&d.observe(obs(None, None))), ["disconnected"]);
        assert_eq!(
            kinds(&d.observe(obs(Some("aa"), Some(-62)))),
            ["associated"]
        );
    }

    #[test]
    fn disconnected_polls_say_nothing_repeatedly() {
        let mut d = ChangeDetector::new(8);
        assert!(d.observe(obs(None, None)).is_empty());
        assert!(d.observe(obs(None, None)).is_empty());
    }

    #[test]
    fn missing_rssi_never_panics_and_recovers_the_baseline() {
        let mut d = ChangeDetector::new(8);
        d.observe(obs(Some("aa"), None));
        // Baseline arrives late: first real reading becomes it silently.
        assert!(d.observe(obs(Some("aa"), Some(-70))).is_empty());
        // And from there hysteresis works normally.
        assert_eq!(
            kinds(&d.observe(obs(Some("aa"), Some(-80)))),
            ["signal_shift"]
        );
    }
}
