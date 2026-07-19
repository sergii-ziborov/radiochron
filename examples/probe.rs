//! Minimal proof of the "no C#, no PowerShell" thesis.
//!
//! Enumerates WLAN interfaces and the current connection using ONLY pure-Rust
//! FFI into `wlanapi.dll`. No child process is spawned, no .NET is loaded, no
//! code is generated at runtime.
//!
//! Run:  cargo run --example probe
//!
//! This example links only the library (not the binary), so it stays buildable
//! independently of the MCP server wiring.

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
