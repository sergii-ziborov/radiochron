use std::time::Duration;

use super::ip;
use super::probe::{
    connect_target, ip_route, portal_probe, resolve_name, sample_connection_quality, stage,
    unavailable_report,
};
use super::{ConnectivityConfig, ConnectivityReport, DiagnosticStage, StageStatus};

pub fn diagnose(config: &ConnectivityConfig) -> ConnectivityReport {
    diagnose_with_tls(config, |_target, _timeout| {
        stage(
            StageStatus::Unknown,
            "TLS target supplied but no TLS probe was installed by the caller",
        )
    })
}

/// Diagnose with a transport-owned TLS verifier. The agent supplies system TLS;
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
