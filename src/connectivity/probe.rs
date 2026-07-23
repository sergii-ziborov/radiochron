use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use super::{ConnectivityReport, DiagnosticStage, PacketQuality, StageStatus};

pub(super) fn unavailable_report(epoch: i64, message: String) -> ConnectivityReport {
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

pub(super) fn ip_route(target: &str) -> DiagnosticStage {
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

pub(super) fn portal_probe(url: &str, expected_status: u16, timeout: Duration) -> DiagnosticStage {
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
        concat!(
            "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            "User-Agent: radiochron/",
            env!("CARGO_PKG_VERSION"),
            "\r\n\r\n"
        ),
        path, authority
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

pub(super) fn portal_outcome(status: Option<u16>, expected_status: u16) -> (StageStatus, String) {
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

pub(super) fn sample_connection_quality(
    target: &str,
    timeout: Duration,
    attempts: u8,
) -> PacketQuality {
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

pub(super) fn resolve_name(name: &str) -> DiagnosticStage {
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

pub(super) fn connect_target(target: &str, timeout: Duration) -> DiagnosticStage {
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

pub(super) fn stage(status: StageStatus, evidence: impl Into<String>) -> DiagnosticStage {
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
