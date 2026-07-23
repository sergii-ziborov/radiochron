use std::fs;
use std::path::{Path, PathBuf};

const MAX_RUST_FILE_LINES: usize = 300;

#[test]
fn rust_sources_stay_below_the_architecture_limit() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut oversized = Vec::new();
    inspect_directory(&root, &root, &mut oversized);

    assert!(
        oversized.is_empty(),
        "Rust files must stay at or below {MAX_RUST_FILE_LINES} lines:\n{}",
        oversized.join("\n")
    );
}

fn inspect_directory(root: &Path, directory: &Path, oversized: &mut Vec<String>) {
    for entry in fs::read_dir(directory).expect("source directory must be readable") {
        let entry = entry.expect("source entry must be readable");
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|value| value.to_str());
            if !matches!(name, Some(".git" | "target")) {
                inspect_directory(root, &path, oversized);
            }
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }

        let source = fs::read_to_string(&path).expect("Rust source must be UTF-8");
        let lines = source.lines().count();
        if lines > MAX_RUST_FILE_LINES {
            let relative = path.strip_prefix(root).unwrap_or(&path).display();
            oversized.push(format!("{relative}: {lines}"));
        }
    }
}
