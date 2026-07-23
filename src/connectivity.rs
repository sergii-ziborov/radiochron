//! End-to-end connectivity diagnosis after radio association.
//!
//! The module performs no periodic work and has no built-in Internet target.
//! Callers explicitly choose every DNS/TCP/Internet endpoint, keeping the core
//! local-first and suitable for isolated IoT networks.

mod ip;

use std::time::Duration;

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
    /// handles `http://`; a transport crate can add HTTPS without coupling TLS
    /// dependencies to core.
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

mod diagnose;
mod probe;

pub use diagnose::{diagnose, diagnose_with_tls};

#[cfg(test)]
mod tests;
