//! BeaconTrail entry point.
//!
//! STEP 1 (current): a temporary CLI that prints a `wifi_status` snapshot,
//! proving the pure-Rust wlanapi path end-to-end on a real adapter.
//!
//! STEP 2 (next): replace this `main` with an `rmcp` stdio MCP server exposing
//! the read-only diagnostic tools (`wifi_status`, `wifi_networks`,
//! `wifi_events`, `wifi_timeline`, run history/analysis/compare/report). The
//! sensitive collectors (plaintext profile key, adapter-identity changes,
//! external AI review, active LAN sweep) stay off the default surface / behind
//! an explicit opt-in, per the feasibility review.

fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let status = beacontrail::wlan::wifi_status()?;
        println!("{}", serde_json::to_string_pretty(&status)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        anyhow::bail!("BeaconTrail requires Windows (it talks to wlanapi.dll).");
    }
}
