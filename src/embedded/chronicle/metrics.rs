use super::MetricsSnapshot;

/// for the elapsed interval, so irregular polling does not distort uptime.
#[derive(Debug, Clone)]
pub struct MetricsTracker {
    window_started_ms: u64,
    last_accounted_ms: u64,
    expected: bool,
    connected: bool,
    expected_connectivity_ms: u64,
    wifi_connected_ms: u64,
    expected_wifi_connected_ms: u64,
    association_attempts: u32,
    disconnect_count: u32,
    roam_count: u32,
    backend_successes: u32,
    backend_failures: u32,
    rssi_sample_count: u32,
    rssi_sum_dbm: i64,
    rssi_min_dbm: Option<i32>,
    rssi_max_dbm: Option<i32>,
    last_disconnect_reason: Option<u16>,
    attempt_started_ms: Option<u64>,
    last_time_to_associate_ms: Option<u64>,
    last_time_to_ip_ms: Option<u64>,
    last_time_to_backend_ms: Option<u64>,
}

impl MetricsTracker {
    pub fn new(started_ms: u64) -> Self {
        Self {
            window_started_ms: started_ms,
            last_accounted_ms: started_ms,
            expected: true,
            connected: false,
            expected_connectivity_ms: 0,
            wifi_connected_ms: 0,
            expected_wifi_connected_ms: 0,
            association_attempts: 0,
            disconnect_count: 0,
            roam_count: 0,
            backend_successes: 0,
            backend_failures: 0,
            rssi_sample_count: 0,
            rssi_sum_dbm: 0,
            rssi_min_dbm: None,
            rssi_max_dbm: None,
            last_disconnect_reason: None,
            attempt_started_ms: None,
            last_time_to_associate_ms: None,
            last_time_to_ip_ms: None,
            last_time_to_backend_ms: None,
        }
    }

    pub fn set_expected(&mut self, now_ms: u64, expected: bool) {
        self.account(now_ms);
        self.expected = expected;
    }

    pub fn association_attempt(&mut self, now_ms: u64) {
        self.account(now_ms);
        self.association_attempts = self.association_attempts.saturating_add(1);
        self.attempt_started_ms = Some(now_ms);
    }

    pub fn observe_connection(
        &mut self,
        now_ms: u64,
        connected: bool,
        rssi_dbm: Option<i32>,
        disconnect_reason: Option<u16>,
    ) {
        self.account(now_ms);

        if !self.connected && connected {
            self.last_time_to_associate_ms = self
                .attempt_started_ms
                .map(|started| now_ms.saturating_sub(started));
        } else if self.connected && !connected {
            self.disconnect_count = self.disconnect_count.saturating_add(1);
            self.last_disconnect_reason = disconnect_reason;
        }
        self.connected = connected;

        if let Some(rssi) = rssi_dbm {
            self.rssi_sample_count = self.rssi_sample_count.saturating_add(1);
            self.rssi_sum_dbm = self.rssi_sum_dbm.saturating_add(i64::from(rssi));
            self.rssi_min_dbm = Some(self.rssi_min_dbm.map_or(rssi, |value| value.min(rssi)));
            self.rssi_max_dbm = Some(self.rssi_max_dbm.map_or(rssi, |value| value.max(rssi)));
        }
    }

    pub fn roam(&mut self, now_ms: u64) {
        self.account(now_ms);
        self.roam_count = self.roam_count.saturating_add(1);
    }

    pub fn ip_acquired(&mut self, now_ms: u64) {
        self.account(now_ms);
        self.last_time_to_ip_ms = self
            .attempt_started_ms
            .map(|started| now_ms.saturating_sub(started));
    }

    pub fn backend_result(&mut self, now_ms: u64, reachable: bool) {
        self.account(now_ms);
        if reachable {
            self.backend_successes = self.backend_successes.saturating_add(1);
            self.last_time_to_backend_ms = self
                .attempt_started_ms
                .map(|started| now_ms.saturating_sub(started));
            self.attempt_started_ms = None;
        } else {
            self.backend_failures = self.backend_failures.saturating_add(1);
        }
    }

    pub fn snapshot(&mut self, now_ms: u64) -> MetricsSnapshot {
        self.account(now_ms);
        let uptime = (self.expected_connectivity_ms > 0).then(|| {
            let scaled = self
                .expected_wifi_connected_ms
                .saturating_mul(1000)
                .checked_div(self.expected_connectivity_ms)
                .unwrap_or(0)
                .min(1000);
            scaled as u16
        });
        let mean = (self.rssi_sample_count > 0)
            .then(|| (self.rssi_sum_dbm / i64::from(self.rssi_sample_count)) as i32);

        MetricsSnapshot {
            window_started_ms: self.window_started_ms,
            window_ended_ms: now_ms,
            expected_connectivity_ms: self.expected_connectivity_ms,
            wifi_connected_ms: self.wifi_connected_ms,
            expected_wifi_connected_ms: self.expected_wifi_connected_ms,
            connectivity_uptime_permille: uptime,
            association_attempts: self.association_attempts,
            disconnect_count: self.disconnect_count,
            roam_count: self.roam_count,
            backend_successes: self.backend_successes,
            backend_failures: self.backend_failures,
            rssi_sample_count: self.rssi_sample_count,
            rssi_min_dbm: self.rssi_min_dbm,
            rssi_max_dbm: self.rssi_max_dbm,
            rssi_mean_dbm: mean,
            last_disconnect_reason: self.last_disconnect_reason,
            last_time_to_associate_ms: self.last_time_to_associate_ms,
            last_time_to_ip_ms: self.last_time_to_ip_ms,
            last_time_to_backend_ms: self.last_time_to_backend_ms,
        }
    }

    pub fn reset_window(&mut self, now_ms: u64) {
        self.account(now_ms);
        self.window_started_ms = now_ms;
        self.last_accounted_ms = now_ms;
        self.expected_connectivity_ms = 0;
        self.wifi_connected_ms = 0;
        self.expected_wifi_connected_ms = 0;
        self.association_attempts = 0;
        self.disconnect_count = 0;
        self.roam_count = 0;
        self.backend_successes = 0;
        self.backend_failures = 0;
        self.rssi_sample_count = 0;
        self.rssi_sum_dbm = 0;
        self.rssi_min_dbm = None;
        self.rssi_max_dbm = None;
        self.last_disconnect_reason = None;
        self.last_time_to_associate_ms = None;
        self.last_time_to_ip_ms = None;
        self.last_time_to_backend_ms = None;
    }

    fn account(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_accounted_ms);
        if self.expected {
            self.expected_connectivity_ms = self.expected_connectivity_ms.saturating_add(elapsed);
        }
        if self.connected {
            self.wifi_connected_ms = self.wifi_connected_ms.saturating_add(elapsed);
        }
        if self.expected && self.connected {
            self.expected_wifi_connected_ms =
                self.expected_wifi_connected_ms.saturating_add(elapsed);
        }
        self.last_accounted_ms = now_ms;
    }
}
