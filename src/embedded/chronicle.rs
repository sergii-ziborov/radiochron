//! `no_std` change chronicle and connectivity metrics for firmware.
//!
//! Time and durability are application-owned. The public facade keeps the
//! schema, metrics, change detector and recorder as separate internal modules.

mod detect;
mod metrics;
mod recorder;
mod types;

pub use metrics::MetricsTracker;
pub use recorder::Chronicle;
pub use types::{
    Clock, ClockQuality, ClockReading, ConnectivityStage, Entry, EventKind, Identity,
    MetricsSnapshot, Sink, VecSink, SCHEMA_VERSION,
};

#[cfg(test)]
mod tests;
