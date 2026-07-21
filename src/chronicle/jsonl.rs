//! Append-only JSON Lines sink with size-based rotation.
//!
//! The default sink is a file, not a database, on purpose. A JSONL stream can
//! be tailed, grepped and shipped without tooling; it has no schema to migrate;
//! and interrupted power costs at most the unflushed tail rather than a
//! database recovering mid-transaction. On the flash budgets of embedded
//! devices, rotation is not optional — hence it is built in rather than left to
//! logrotate, which the target may not have.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Entry, Sink};

/// When and how to rotate.
#[derive(Debug, Clone, Copy)]
pub struct RotationPolicy {
    /// Rotate once the active file exceeds this many bytes.
    pub max_bytes: u64,
    /// Keep this many rotated files besides the active one; the oldest is
    /// deleted. Total disk ceiling ≈ `max_bytes * (max_files + 1)`.
    pub max_files: u32,
}

impl Default for RotationPolicy {
    /// 1 MiB active + 3 rotated ≈ a 4 MiB ceiling — sized for an embedded
    /// flash budget, not a workstation.
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_files: 3,
        }
    }
}

/// One JSON object per line, `chronicle.jsonl` → `chronicle.jsonl.1` → … .
pub struct JsonlSink {
    path: PathBuf,
    /// `None` only transiently during rotation — Windows cannot rename a file
    /// that still has an open handle, so the handle must drop first.
    file: Option<File>,
    written: u64,
    policy: RotationPolicy,
}

#[derive(Debug, serde::Serialize)]
pub struct JsonlRead {
    pub entries: Vec<Value>,
    pub invalid_lines: usize,
}

/// Read the newest entries across the active file and its rotation chain,
/// returning them in chronological order. A torn line is counted rather than
/// hiding the rest of the durable journal.
pub fn read_recent_jsonl(path: &Path, max_files: u32, max_entries: usize) -> io::Result<JsonlRead> {
    let mut newest_first = Vec::new();
    let mut invalid_lines = 0usize;

    for index in 0..=max_files {
        let candidate = if index == 0 {
            path.to_path_buf()
        } else {
            rotated_name(path, index)
        };
        if !candidate.exists() {
            continue;
        }

        let text = std::fs::read_to_string(candidate)?;
        for line in text.lines().rev() {
            if newest_first.len() >= max_entries {
                break;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(entry) => newest_first.push(entry),
                Err(_) => invalid_lines += 1,
            }
        }
        if newest_first.len() >= max_entries {
            break;
        }
    }

    newest_first.reverse();
    Ok(JsonlRead {
        entries: newest_first,
        invalid_lines,
    })
}

impl JsonlSink {
    /// Open (or create) the chronicle at `path`, appending to what exists —
    /// a recorder restart must continue the story, not truncate it.
    pub fn open(path: impl Into<PathBuf>, policy: RotationPolicy) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }

        let file = open_append(&path)?;
        let written = file.metadata()?.len();

        Ok(Self {
            path,
            file: Some(file),
            written,
            policy,
        })
    }

    /// Close the active file, shift `.1 → .2 → …` dropping the oldest, move the
    /// active file to `.1`, and start a fresh active file.
    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        } // handle drops here, releasing the rename lock

        let _ = std::fs::remove_file(rotated_name(&self.path, self.policy.max_files));
        for n in (1..self.policy.max_files).rev() {
            let from = rotated_name(&self.path, n);
            if from.exists() {
                std::fs::rename(&from, rotated_name(&self.path, n + 1))?;
            }
        }

        if self.policy.max_files > 0 {
            std::fs::rename(&self.path, rotated_name(&self.path, 1))?;
        } else {
            std::fs::remove_file(&self.path)?;
        }

        self.file = Some(open_append(&self.path)?);
        self.written = 0;
        Ok(())
    }

    fn file(&mut self) -> io::Result<&mut File> {
        // Self-heal if a previous rotation failed midway.
        if self.file.is_none() {
            self.file = Some(open_append(&self.path)?);
        }
        Ok(self.file.as_mut().expect("just ensured"))
    }
}

impl Sink for JsonlSink {
    fn write(&mut self, entry: &Entry) -> io::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(io::Error::other)?;
        line.push(b'\n');

        // `written > 0` guards the pathological case of a single entry larger
        // than the limit: it must still be written, not rotate forever.
        if self.written > 0 && self.written + line.len() as u64 > self.policy.max_bytes {
            self.rotate()?;
        }

        self.file()?.write_all(&line)?;
        self.written += line.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file()?.flush()
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn rotated_name(path: &Path, n: u32) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chronicle::EntryKind;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("radiochron-jsonl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(n: usize) -> Entry {
        Entry {
            epoch_seconds: n as i64,
            time: format!("t{n}"),
            interface_guid: None,
            kind: EntryKind::Disconnected {
                last_bssid: Some(format!("aa:bb:cc:dd:ee:{n:02x}")),
            },
        }
    }

    #[test]
    fn writes_one_json_object_per_line_and_appends_across_reopen() {
        let dir = temp_dir("append");
        let path = dir.join("chronicle.jsonl");

        {
            let mut sink = JsonlSink::open(&path, RotationPolicy::default()).unwrap();
            sink.write(&entry(1)).unwrap();
            sink.flush().unwrap();
        }
        {
            // A restarted recorder continues the file rather than truncating it.
            let mut sink = JsonlSink::open(&path, RotationPolicy::default()).unwrap();
            sink.write(&entry(2)).unwrap();
            sink.flush().unwrap();
        }

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["kind"], "disconnected");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotates_at_the_size_limit_and_caps_the_file_count() {
        let dir = temp_dir("rotate");
        let path = dir.join("chronicle.jsonl");
        // Each entry is ~120 bytes; a 200-byte limit rotates every other write.
        let policy = RotationPolicy {
            max_bytes: 200,
            max_files: 2,
        };

        let mut sink = JsonlSink::open(&path, policy).unwrap();
        for n in 0..12 {
            sink.write(&entry(n)).unwrap();
        }
        sink.flush().unwrap();

        assert!(path.exists(), "active file must exist");
        assert!(rotated_name(&path, 1).exists());
        assert!(rotated_name(&path, 2).exists());
        assert!(
            !rotated_name(&path, 3).exists(),
            "max_files=2 must cap the chain; .3 would grow without bound"
        );

        // Every surviving line is still valid JSON — rotation never tears one.
        for p in [path.clone(), rotated_name(&path, 1), rotated_name(&path, 2)] {
            for line in std::fs::read_to_string(&p).unwrap().lines() {
                serde_json::from_str::<serde_json::Value>(line)
                    .unwrap_or_else(|e| panic!("torn line in {p:?}: {e}"));
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_oversized_single_entry_still_writes_rather_than_looping() {
        let dir = temp_dir("oversize");
        let path = dir.join("chronicle.jsonl");
        let policy = RotationPolicy {
            max_bytes: 10, // smaller than any entry
            max_files: 1,
        };

        let mut sink = JsonlSink::open(&path, policy).unwrap();
        sink.write(&entry(1)).unwrap();
        sink.write(&entry(2)).unwrap();
        sink.flush().unwrap();

        // Both entries exist somewhere in the chain, intact.
        let mut total = 0;
        for p in [path.clone(), rotated_name(&path, 1)] {
            if p.exists() {
                total += std::fs::read_to_string(&p).unwrap().lines().count();
            }
        }
        assert_eq!(total, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
