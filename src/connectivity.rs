//! End-to-end connectivity diagnosis after radio association.
//!
//! The module performs no periodic work and has no built-in Internet target.
//! Callers explicitly choose every DNS/TCP/Internet endpoint, keeping the core
//! local-first and suitable for isolated IoT networks.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ConnectivityConfig {
    /// Name whose resolver path should be checked, for example `broker.lan`.
    pub dns_name: Option<String>,
    /// Service endpoint proving LAN/application reachability.
    pub tcp_target: Option<String>,
    /// Explicit external endpoint proving Internet reachability.
    pub internet_target: Option<String>,
    pub timeout: Duration,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            dns_name: None,
            tcp_target: None,
            internet_target: None,
            timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Pass,
    Fail,
    Unknown,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticStage {
    pub status: StageStatus,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityReport {
    pub observed_at_epoch_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_id: Option<String>,
    pub radio: DiagnosticStage,
    pub authentication: DiagnosticStage,
    /// This tests usable IP configuration after association. Portable APIs do
    /// not prove whether the address came from DHCP or static configuration.
    pub dhcp: DiagnosticStage,
    pub dns: DiagnosticStage,
    pub tcp: DiagnosticStage,
    pub internet: DiagnosticStage,
}

pub fn diagnose(config: &ConnectivityConfig) -> ConnectivityReport {
    let observed_at_epoch_seconds = crate::time::now_epoch_seconds();
    let statuses = match crate::wlan::wifi_status() {
        Ok(statuses) => statuses,
        Err(error) => {
            return unavailable_report(observed_at_epoch_seconds, error.to_string());
        }
    };
    let connected = statuses.iter().find(|status| status.connection.is_some());
    let interface_id = connected
        .map(|status| status.interface.guid.clone())
        .or_else(|| statuses.first().map(|status| status.interface.guid.clone()));
    let radio = if statuses.is_empty() {
        stage(StageStatus::Fail, "no Wi-Fi interface reported")
    } else {
        stage(
            StageStatus::Pass,
            format!("{} Wi-Fi interface(s) reported", statuses.len()),
        )
    };
    let authentication = match connected.and_then(|status| status.connection.as_ref()) {
        Some(connection) => stage(
            StageStatus::Pass,
            format!(
                "associated with {}",
                connection.ssid.as_deref().unwrap_or("hidden SSID")
            ),
        ),
        None if statuses.is_empty() => stage(StageStatus::Skipped, "radio unavailable"),
        None => stage(StageStatus::Fail, "not associated/authenticated with an AP"),
    };

    let route_target = config
        .tcp_target
        .as_deref()
        .or(config.internet_target.as_deref());
    let dhcp = if authentication.status != StageStatus::Pass {
        stage(StageStatus::Skipped, "association has not completed")
    } else if let Some(target) = route_target {
        ip_configuration(target)
    } else {
        stage(
            StageStatus::Unknown,
            "no target supplied; DHCP/static address cannot be tested",
        )
    };
    let dns = match config.dns_name.as_deref() {
        Some(name) if authentication.status == StageStatus::Pass => resolve_name(name),
        Some(_) => stage(StageStatus::Skipped, "association has not completed"),
        None => stage(StageStatus::Skipped, "no DNS name supplied"),
    };
    let tcp = match config.tcp_target.as_deref() {
        Some(target) if authentication.status == StageStatus::Pass => {
            connect_target(target, config.timeout)
        }
        Some(_) => stage(StageStatus::Skipped, "association has not completed"),
        None => stage(StageStatus::Skipped, "no TCP target supplied"),
    };
    let internet = match config.internet_target.as_deref() {
        Some(target) if authentication.status == StageStatus::Pass => {
            connect_target(target, config.timeout)
        }
        Some(_) => stage(StageStatus::Skipped, "association has not completed"),
        None => stage(StageStatus::Skipped, "no Internet target supplied"),
    };

    ConnectivityReport {
        observed_at_epoch_seconds,
        interface_id,
        radio,
        authentication,
        dhcp,
        dns,
        tcp,
        internet,
    }
}

fn unavailable_report(epoch: i64, message: String) -> ConnectivityReport {
    ConnectivityReport {
        observed_at_epoch_seconds: epoch,
        interface_id: None,
        radio: stage(
            StageStatus::Fail,
            format!("radio collector failed: {message}"),
        ),
        authentication: stage(StageStatus::Skipped, "radio unavailable"),
        dhcp: stage(StageStatus::Skipped, "radio unavailable"),
        dns: stage(StageStatus::Skipped, "radio unavailable"),
        tcp: stage(StageStatus::Skipped, "radio unavailable"),
        internet: stage(StageStatus::Skipped, "radio unavailable"),
    }
}

fn ip_configuration(target: &str) -> DiagnosticStage {
    let Some(remote) = resolve_target(target)
        .ok()
        .and_then(|mut addrs| addrs.pop())
    else {
        return stage(
            StageStatus::Unknown,
            "target could not be resolved for route/IP test",
        );
    };
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    match UdpSocket::bind(bind).and_then(|socket| {
        socket.connect(remote)?;
        socket.local_addr()
    }) {
        Ok(local) if !local.ip().is_unspecified() && !local.ip().is_loopback() => stage(
            StageStatus::Pass,
            format!(
                "usable local address {}; DHCP vs static is not observable portably",
                local.ip()
            ),
        ),
        Ok(local) => stage(
            StageStatus::Fail,
            format!("route selected unusable local address {}", local.ip()),
        ),
        Err(error) => stage(StageStatus::Fail, format!("no usable IP route: {error}")),
    }
}

fn resolve_name(name: &str) -> DiagnosticStage {
    let started = Instant::now();
    match (name, 0).to_socket_addrs() {
        Ok(mut addrs) => {
            if addrs.next().is_some() {
                timed_stage(StageStatus::Pass, format!("resolved {name}"), started)
            } else {
                timed_stage(
                    StageStatus::Fail,
                    format!("resolver returned no address for {name}"),
                    started,
                )
            }
        }
        Err(error) => timed_stage(
            StageStatus::Fail,
            format!("DNS lookup failed for {name}: {error}"),
            started,
        ),
    }
}

fn connect_target(target: &str, timeout: Duration) -> DiagnosticStage {
    let started = Instant::now();
    let addrs = match resolve_target(target) {
        Ok(addrs) => addrs,
        Err(error) => {
            return timed_stage(StageStatus::Fail, error, started);
        }
    };
    let mut last_error = None;
    for address in addrs {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(_) => {
                return timed_stage(
                    StageStatus::Pass,
                    format!("connected to {target} via {address}"),
                    started,
                );
            }
            Err(error) => last_error = Some(error),
        }
    }
    timed_stage(
        StageStatus::Fail,
        format!(
            "could not connect to {target}: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no address".to_string())
        ),
        started,
    )
}

fn resolve_target(target: &str) -> Result<Vec<SocketAddr>, String> {
    target
        .to_socket_addrs()
        .map(|addresses| addresses.collect())
        .map_err(|error| format!("could not resolve {target}: {error}"))
}

fn stage(status: StageStatus, evidence: impl Into<String>) -> DiagnosticStage {
    DiagnosticStage {
        status,
        evidence: evidence.into(),
        latency_ms: None,
    }
}

fn timed_stage(
    status: StageStatus,
    evidence: impl Into<String>,
    started: Instant,
) -> DiagnosticStage {
    DiagnosticStage {
        status,
        evidence: evidence.into(),
        latency_ms: Some(started.elapsed().as_millis() as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_probe_distinguishes_reachable_from_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let open = connect_target(&address.to_string(), Duration::from_millis(100));
        assert_eq!(open.status, StageStatus::Pass);
        drop(listener);
        let closed = connect_target(&address.to_string(), Duration::from_millis(100));
        assert_eq!(closed.status, StageStatus::Fail);
    }

    #[test]
    fn malformed_target_is_a_failure_not_a_panic() {
        let result = connect_target("not-an-endpoint", Duration::from_millis(10));
        assert_eq!(result.status, StageStatus::Fail);
    }
}
