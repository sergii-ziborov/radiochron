//! Proof of the "no C#, no PowerShell" thesis.
//!
//! Reads the current connection and the nearby BSS list using only hand-written
//! FFI into `wlanapi.dll`. No child process is spawned, no .NET is loaded, no
//! code is generated at run time.
//!
//! Run:  cargo run --example probe

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use radiochron::wlan;

    println!("== interfaces & current connection ==");
    println!("{}", serde_json::to_string_pretty(&wlan::wifi_status()?)?);

    // Ask the driver to refresh; results land asynchronously, so the list below
    // may still be the previous scan on the first run.
    match wlan::bss::request_scan() {
        Ok(n) => println!("\n== scan requested on {n} interface(s) =="),
        Err(e) => println!("\n== scan request failed: {e} =="),
    }
    std::thread::sleep(std::time::Duration::from_secs(4));

    let entries = wlan::bss::bss_list()?;
    println!("\n== nearby BSS: {} entries ==", entries.len());

    for entry in entries.iter().take(12) {
        let ie = &entry.information_elements;
        let mut caps = Vec::new();
        if ie.has_rsn {
            caps.push("RSN");
        }
        if ie.has_wpa {
            caps.push("WPA");
        }
        if ie.has_ht {
            caps.push("HT");
        }
        if ie.has_vht {
            caps.push("VHT");
        }
        if ie.has_he {
            caps.push("HE");
        }
        if ie.has_eht {
            caps.push("EHT");
        }

        println!(
            "{:<28} {} {:>5} dBm {:>9} kHz  phy={:<4} ie={:>4}B/{:<3} [{}]",
            entry.ssid.as_deref().unwrap_or("<hidden>"),
            entry.bssid,
            entry.rssi_dbm,
            entry.center_frequency_khz,
            entry.phy_type,
            ie.byte_length,
            ie.element_count,
            caps.join(",")
        );
    }

    Ok(())
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("RadioChron requires Windows (it talks to wlanapi.dll).")
}
