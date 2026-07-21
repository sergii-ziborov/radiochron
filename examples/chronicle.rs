//! Record the chronicle for a few seconds and show what it wrote.
//!
//! Run:  cargo run --example chronicle
//!
//! On a stable link expect very little — one `associated` entry and silence.
//! That is the point: the chronicle records change, not polls. Toggle Wi-Fi
//! mid-run to watch disconnect/reconnect entries appear.

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use radiochron::chronicle::{JsonlSink, Recorder, RecorderOptions, RotationPolicy};
    use std::time::Duration;

    let path = std::env::temp_dir().join("radiochron-example-chronicle.jsonl");
    let _ = std::fs::remove_file(&path);

    let sink = JsonlSink::open(&path, RotationPolicy::default())?;
    let mut recorder = Recorder::new(
        sink,
        RecorderOptions {
            interval: Duration::from_secs(2),
            signal_threshold_db: 6,
        },
    );

    println!("recording to {} for 10 seconds…", path.display());
    let written = recorder.run_for(Duration::from_secs(10))?;
    println!("entries written: {written}\n");

    for line in std::fs::read_to_string(&path)?.lines() {
        println!("{line}");
    }

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The recorder loop currently has collectors only on Windows.");
}
