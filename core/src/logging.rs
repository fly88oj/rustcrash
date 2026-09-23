//! Logging utilities: rotated event log, tracing init, crash reports.
//!
//! Mirrors ShellCrash's logger behaviour: the action log is capped at
//! `MAX_LOG_LINES`; when exceeded the oldest `TRIM_LINES` lines are dropped.

use crate::error::Result;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Soft cap before rotation kicks in (ShellCrash trims past 199 lines).
pub const MAX_LOG_LINES: usize = 199;
/// Lines removed from the top when rotating.
pub const TRIM_LINES: usize = 20;

/// Append one line to a log file, rotating when it exceeds the cap.
pub fn append_rotated(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let current = fs::read_to_string(path).unwrap_or_default();
    let line_count = current.lines().count();
    if line_count >= MAX_LOG_LINES {
        // Rewrite the file with the oldest lines dropped, new line included.
        let kept: Vec<&str> = current.lines().skip(TRIM_LINES).collect();
        let mut out = kept.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
        out.push('\n');
        fs::write(path, out)?;
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Read the last `lines` lines of a file (empty when missing).
/// Reads backward in blocks so large logs are not fully loaded.
pub fn tail_file(path: &Path, lines: usize) -> Vec<String> {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(size) = file.metadata().map(|m| m.len()) else {
        return Vec::new();
    };
    // Assume ~256 bytes/line with margin; grow the window until we have
    // enough newlines or hit the start of the file.
    let mut window: usize = (lines + 1).saturating_mul(256);
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        window = window.min(size as usize);
        let start = size - window as u64;
        if file.seek(SeekFrom::Start(start)).is_err() {
            return Vec::new();
        }
        buffer.clear();
        if std::io::Read::read_to_end(&mut file, &mut buffer).is_err() {
            return Vec::new();
        }
        let newline_count = buffer.iter().filter(|b| **b == b'\n').count();
        if newline_count > lines || window >= size as usize {
            break;
        }
        window = window.saturating_mul(2);
    }
    let text = String::from_utf8_lossy(&buffer);
    text.lines()
        .rev()
        .take(lines)
        .map(|l| l.to_string())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

/// Initialize tracing with the configured level.
///
/// Priority: `RUST_LOG` env var, then `config.log_level`, then "info".
/// "debug"/"trace" levels enable the debug mode output (FR-10.3).
pub fn init_logging(configured_level: &str) {
    let level = std::env::var("RUST_LOG")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| configured_level.to_string());
    let filter = tracing_subscriber::EnvFilter::try_new(&level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

/// Install a panic hook that writes a crash report into the log dir
/// (FR-10.4). Reports are local-only on purpose: during a panic the
/// network stack may be part of what is broken.
pub fn install_crash_reporting(platform: &crate::platform::Platform) {
    let log_dir = platform.log_dir();
    std::panic::set_hook(Box::new(move |info| {
        let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let report_path =
            std::path::Path::new(&log_dir).join(format!("crash-report-{timestamp}.md"));
        let payload = format!(
            "# RustCrash crash report\n\n\
             - time: {timestamp}\n\
             - version: {}\n\
             - location: {location}\n\
             - payload: {payload}\n\n\
             ## backtrace\n\n```\n{backtrace}\n```\n",
            env!("CARGO_PKG_VERSION"),
            location = info.location().map(|l| l.to_string()).unwrap_or_default(),
            payload = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string()),
            backtrace = std::backtrace::Backtrace::force_capture(),
        );
        let _ = fs::create_dir_all(std::path::Path::new(&log_dir));
        let _ = fs::write(&report_path, payload);
    }));
}

/// Most recently modified file in `dir` whose name passes `predicate`.
/// Returns None when the directory is missing or nothing matches.
pub fn newest_file<P>(dir: &Path, predicate: P) -> Option<std::path::PathBuf>
where
    P: Fn(&str) -> bool,
{
    let entries = fs::read_dir(dir).ok()?;
    let mut newest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let matches = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(&predicate)
            .unwrap_or(false);
        if !matches {
            continue;
        }
        if let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) {
            if newest.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
                newest = Some((mtime, path));
            }
        }
    }
    newest.map(|(_, path)| path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_rotated_appends_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events.log");
        append_rotated(&path, "one").unwrap();
        append_rotated(&path, "two").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "one\ntwo\n");
    }

    #[test]
    fn append_rotated_trims_when_cap_reached() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events.log");
        for i in 0..MAX_LOG_LINES {
            append_rotated(&path, &format!("line{i}")).unwrap();
        }
        assert_eq!(
            fs::read_to_string(&path).unwrap().lines().count(),
            MAX_LOG_LINES
        );

        // Next append triggers the trim of the oldest TRIM_LINES lines.
        append_rotated(&path, "overflow").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), MAX_LOG_LINES - TRIM_LINES + 1);
        assert_eq!(lines[0], format!("line{}", TRIM_LINES));
        assert_eq!(lines[lines.len() - 1], "overflow");
    }

    #[test]
    fn tail_file_returns_last_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.log");
        fs::write(&path, "a\nb\nc\nd\n").unwrap();
        assert_eq!(tail_file(&path, 2), vec!["c", "d"]);
        assert_eq!(tail_file(&path, 100), vec!["a", "b", "c", "d"]);
        assert!(tail_file(&tmp.path().join("missing.log"), 5).is_empty());
    }

    #[test]
    fn newest_file_finds_recent_match() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a.log");
        let b = tmp.path().join("b.log");
        fs::write(&a, "x").unwrap();
        fs::write(&b, "y").unwrap();
        let found = newest_file(tmp.path(), |n| n.ends_with(".log"));
        assert!(found.is_some());
        let name = found.unwrap();
        assert!(name == a || name == b);

        fs::write(tmp.path().join("c.txt"), "z").unwrap();
        assert!(newest_file(tmp.path(), |n| n.ends_with(".txt")).is_some());
        assert!(newest_file(tmp.path(), |n| n.ends_with(".zzz")).is_none());
        assert!(newest_file(&tmp.path().join("nope"), |_| true).is_none());
    }

    #[test]
    fn crash_report_written_on_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let platform = crate::platform::Platform::for_crash_dir(tmp.path().to_str().unwrap());
        install_crash_reporting(&platform);

        let result = std::panic::catch_unwind(|| {
            panic!("boom-test");
        });
        assert!(result.is_err());

        // A crash report file exists in the log dir.
        let log_dir = tmp.path().join("logs");
        let reports: Vec<_> = std::fs::read_dir(&log_dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("crash-report-"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !reports.is_empty(),
            "expected a crash report in {log_dir:?}"
        );
        let content = fs::read_to_string(&reports[0]).unwrap();
        assert!(content.contains("boom-test"));
        assert!(content.contains("crash report"));
    }
}
