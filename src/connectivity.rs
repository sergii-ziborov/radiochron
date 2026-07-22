//! End-to-end connectivity diagnosis after radio association.
//!
//! The module performs no periodic work and has no built-in Internet target.
//! Callers explicitly choose every DNS/TCP/Internet endpoint, keeping the core
//! local-first and suitable for isolated IoT networks.

mod ip;

use std::io::{Read, Write};
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
    /// HTTP endpoint with a known status, commonly a local 204 endpoint. Core
    /// handles `http://`; the agent upgrades `https://` through rustls.
    pub captive_portal_url: Option<String>,
    pub captive_portal_expected_status: u16,
    /// TLS service in `host:port` form. The core delegates certificate
    /// validation to a caller-supplied probe so it remains dependency-light.
    pub tls_target: Option<String>,
    /// Endpoint sampled repeatedly for connection-loss and jitter estimates.
    pub quality_target: Option<String>,
    pub quality_attempts: u8,
    pub timeout: Duration,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            dns_name: None,
            tcp_target: None,
            internet_target: None,
            captive_portal_url: None,
            captive_portal_expected_status: 204,
            tls_target: None,
            quality_target: None,
            quality_attempts: 4,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpAssignment {
    Dhcp,
    Static,
    LinkLocal,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpConfiguration {
    pub assignment: IpAssignment,
    pub addresses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketQuality {
    pub attempts: u8,
    pub successes: u8,
    pub loss_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityReport {
    pub observed_at_epoch_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_id: Option<String>,
    pub radio: DiagnosticStage,
    pub authentication: DiagnosticStage,
    /// Kept as `dhcp` for schema compatibility; evidence now distinguishes a
    /// proven DHCP lease from explicit static configuration and unknown origin.
    pub dhcp: DiagnosticStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_configuration: Option<IpConfiguration>,
    pub gateway: DiagnosticStage,
    pub dns: DiagnosticStage,
    pub tcp: DiagnosticStage,
    pub captive_portal: DiagnosticStage,
    pub tls: DiagnosticStage,
    pub packet_quality: DiagnosticStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_quality_measurement: Option<PacketQuality>,
    pub internet: DiagnosticStage,
}

pub fn diagnose(config: &ConnectivityConfig) -> ConnectivityReport {
    diagnose_with_tls(config, |_target, _timeout| {
        stage(
            StageStatus::Unknown,
            "TLS target supplied but no TLS probe was installed by the caller",
        )
    })
}

/// Diagnose with a transport-owned TLS verifier. The agent supplies rustls;
/// embedded users can supply their platform TLS stack without changing core.
pub fn diagnose_with_tls<F>(config: &ConnectivityConfig, tls_probe: F) -> ConnectivityReport
where
    F: Fn(&str, Duration) -> DiagnosticStage,
{
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
        .or(config.internet_target.as_deref())
        .or(config.quality_target.as_deref());
    let ip_configuration = if authentication.status == StageStatus::Pass {
        connected.map(|status| {
            ip::inspect(
                &status.interface.guid,
                &status.interface.description,
                route_target,
            )
        })
    } else {
        None
    };
    let dhcp = if authentication.status != StageStatus::Pass {
        stage(StageStatus::Skipped, "association has not completed")
    } else if let Some(configuration) = &ip_configuration {
        let status = if configuration.addresses.is_empty() {
            StageStatus::Fail
        } else {
            StageStatus::Pass
        };
        stage(
            status,
            format!(
                "IP assignment is {:?}: {}",
                configuration.assignment, configuration.evidence
            )
            .to_lowercase(),
        )
    } else if let Some(target) = route_target {
        ip_route(target)
    } else {
        stage(
            StageStatus::Unknown,
            "no associated interface was available",
        )
    };
    let gateway = if authentication.status != StageStatus::Pass {
        stage(StageStatus::Skipped, "association has not completed")
    } else {
        match ip_configuration
            .as_ref()
            .and_then(|configuration| configuration.gateway.as_deref())
        {
            Some(address) => stage(StageStatus::Pass, format!("default gateway is {address}")),
            None => stage(
                StageStatus::Unknown,
                "platform adapter found no default gateway for this interface",
            ),
        }
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
    let captive_portal = match config.captive_portal_url.as_deref() {
        Some(target) if authentication.status == StageStatus::Pass => portal_probe(
            target,
            config.captive_portal_expected_status,
            config.timeout,
        ),
        Some(_) => stage(StageStatus::Skipped, "association has not completed"),
        None => stage(StageStatus::Skipped, "no captive portal target supplied"),
    };
    let tls = match config.tls_target.as_deref() {
        Some(target) if authentication.status == StageStatus::Pass => {
            tls_probe(target, config.timeout)
        }
        Some(_) => stage(StageStatus::Skipped, "association has not completed"),
        None => stage(StageStatus::Skipped, "no TLS target supplied"),
    };
    let (packet_quality, packet_quality_measurement) = match config.quality_target.as_deref() {
        Some(target) if authentication.status == StageStatus::Pass => {
            let measurement = sample_connection_quality(
                target,
                config.timeout,
                config.quality_attempts.clamp(1, 20),
            );
            let status = if measurement.successes == measurement.attempts {
                StageStatus::Pass
            } else {
                StageStatus::Fail
            };
            (
                stage(
                    status,
                    format!(
                        "{} of {} TCP probes succeeded ({:.1}% loss)",
                        measurement.successes, measurement.attempts, measurement.loss_percent
                    ),
                ),
                Some(measurement),
            )
        }
        Some(_) => (
            stage(StageStatus::Skipped, "association has not completed"),
            None,
        ),
        None => (
            stage(StageStatus::Skipped, "no packet-quality target supplied"),
            None,
        ),
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
        ip_configuration,
        gateway,
        dns,
        tcp,
        captive_portal,
        tls,
        packet_quality,
        packet_quality_measurement,
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
        ip_configuration: None,
        gateway: stage(StageStatus::Skipped, "radio unavailable"),
        dns: stage(StageStatus::Skipped, "radio unavailable"),
        tcp: stage(StageStatus::Skipped, "radio unavailable"),
        captive_portal: stage(StageStatus::Skipped, "radio unavailable"),
        tls: stage(StageStatus::Skipped, "radio unavailable"),
        packet_quality: stage(StageStatus::Skipped, "radio unavailable"),
        packet_quality_measurement: None,
        internet: stage(StageStatus::Skipped, "radio unavailable"),
    }
}

fn ip_route(target: &str) -> DiagnosticStage {
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
                "usable local address {} (assignment source unavailable)",
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

fn portal_probe(url: &str, expected_status: u16, timeout: Duration) -> DiagnosticStage {
    let Some(rest) = url.strip_prefix("http://") else {
        return stage(
            StageStatus::Unknown,
            "HTTPS captive-portal probes require the agent TLS transport",
        );
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        return stage(StageStatus::Fail, "captive portal URL has no host");
    }
    let target = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let started = Instant::now();
    let mut addresses = match resolve_target(&target) {
        Ok(addresses) => addresses,
        Err(error) => return timed_stage(StageStatus::Fail, error, started),
    };
    let Some(address) = addresses.pop() else {
        return timed_stage(StageStatus::Fail, "portal host has no address", started);
    };
    let mut stream = match TcpStream::connect_timeout(&address, timeout) {
        Ok(stream) => stream,
        Err(error) => {
            return timed_stage(
                StageStatus::Fail,
                format!("portal endpoint is unreachable: {error}"),
                started,
            )
        }
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let request = format!(
        "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: radiochron/0.2\r\n\r\n"
    );
    if let Err(error) = stream.write_all(request.as_bytes()) {
        return timed_stage(
            StageStatus::Fail,
            format!("portal request failed: {error}"),
            started,
        );
    }
    let mut response = [0u8; 8192];
    let read = match stream.read(&mut response) {
        Ok(read) => read,
        Err(error) => {
            return timed_stage(
                StageStatus::Fail,
                format!("portal response failed: {error}"),
                started,
            )
        }
    };
    let first_line = String::from_utf8_lossy(&response[..read])
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let status = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok());
    let (status, evidence) = portal_outcome(status, expected_status);
    timed_stage(status, evidence, started)
}

fn portal_outcome(status: Option<u16>, expected_status: u16) -> (StageStatus, String) {
    match status {
        Some(actual) if actual == expected_status => (
            StageStatus::Pass,
            format!("portal sentinel returned expected HTTP {actual}"),
        ),
        Some(actual) if matches!(actual, 300..=399) => (
            StageStatus::Fail,
            format!("captive portal suspected: sentinel redirected with HTTP {actual}"),
        ),
        Some(actual) => (
            StageStatus::Fail,
            format!(
                "captive portal or interception suspected: expected HTTP {expected_status}, got {actual}"
            ),
        ),
        None => (
            StageStatus::Fail,
            "portal sentinel returned a malformed HTTP response".to_string(),
        ),
    }
}

fn sample_connection_quality(target: &str, timeout: Duration, attempts: u8) -> PacketQuality {
    let mut latencies = Vec::new();
    for _ in 0..attempts {
        let started = Instant::now();
        if connect_target(target, timeout).status == StageStatus::Pass {
            latencies.push(started.elapsed().as_secs_f64() * 1_000.0);
        }
    }
    let successes = latencies.len() as u8;
    let mean =
        (!latencies.is_empty()).then(|| latencies.iter().sum::<f64>() / latencies.len() as f64);
    let jitter = (latencies.len() > 1).then(|| {
        latencies
            .windows(2)
            .map(|pair| (pair[1] - pair[0]).abs())
            .sum::<f64>()
            / (latencies.len() - 1) as f64
    });
    PacketQuality {
        attempts,
        successes,
        loss_percent: (f64::from(attempts - successes) / f64::from(attempts)) * 100.0,
        mean_latency_ms: mean,
        jitter_ms: jitter,
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

    #[test]
    fn portal_status_distinguishes_expected_sentinel_from_redirect() {
        assert_eq!(portal_outcome(Some(204), 204).0, StageStatus::Pass);
        assert_eq!(portal_outcome(Some(302), 204).0, StageStatus::Fail);
        assert_eq!(portal_outcome(None, 204).0, StageStatus::Fail);
    }

    #[test]
    fn packet_quality_reports_connection_attempt_loss() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..3 {
                listener.accept().unwrap();
            }
        });
        let quality = sample_connection_quality(&address.to_string(), Duration::from_secs(1), 3);
        server.join().unwrap();
        assert_eq!(quality.successes, 3);
        assert_eq!(quality.loss_percent, 0.0);
        assert!(quality.mean_latency_ms.is_some());
    }
}
