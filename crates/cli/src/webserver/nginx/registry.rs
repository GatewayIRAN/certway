// SPDX-License-Identifier: MIT

//! The append-only log of nginx edits certway has made: what
//! `cmd::rollback`'s no-argument form reads to list available backups.
//! Without it there is no way to discover which
//! files certway has touched on a given host — a backup is only
//! discoverable by name if you already know which file it protects.
//!
//! One JSON object per line (`certway_core::json`, no new crate),
//! mode 0600. Written by `transaction::run` itself, strictly **after** a
//! successful reload — never before, and never on a path that ends in a
//! restore, so a validation/reload failure that triggers the automatic
//! restore can never leave a phantom entry pointing at an edit that didn't
//! actually take effect.
//!
//! Read-modify-write-whole-file via `store::atomic_write` rather than a
//! raw append — the one write primitive this program uses everywhere
//! else, at the cost of a narrow, low-consequence race between two
//! `certway` processes editing different files at the same moment (a lost
//! registry line, never a corrupted file — the underlying write is still
//! atomic). Acceptable for what this file is: a discovery aid, not the
//! source of truth for whether a backup exists — `rollback <file>` never
//! reads it at all, only `rollback` with no argument does.

use certway_core::json::{self as json, JsonVal};
use certway_core::{self as core};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditRecord {
    pub file: PathBuf,
    pub backup_path: PathBuf,
    pub domain: String,
    pub timestamp: String,
}

/// Appends one record to `registry_path`, creating its parent directory
/// (mode 0700) if needed.
pub fn append(registry_path: &Path, record: &EditRecord) -> Result<(), core::Error> {
    let mut existing = read_raw(registry_path)?;
    existing.push_str(&json::write_object(&[
        ("file", JsonVal::Str(&record.file.to_string_lossy())),
        (
            "backup_path",
            JsonVal::Str(&record.backup_path.to_string_lossy()),
        ),
        ("domain", JsonVal::Str(&record.domain)),
        ("timestamp", JsonVal::Str(&record.timestamp)),
    ]));
    existing.push('\n');

    if let Some(parent) = registry_path.parent() {
        if !parent.as_os_str().is_empty() {
            crate::store::create_dir_secure(parent, 0o700)?;
        }
    }
    crate::store::atomic_write(registry_path, existing.as_bytes(), 0o600)
}

fn read_raw(registry_path: &Path) -> Result<String, core::Error> {
    match std::fs::read_to_string(registry_path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(core::Error::io(registry_path, e)),
    }
}

/// Every record in the registry, oldest first. `None` — never `Err` —
/// when the file doesn't exist or can't be read at all, since
/// `cmd::rollback` treats "no registry" as "print the manual alternative,"
/// not as a hard failure over bookkeeping. A single malformed line is
/// skipped rather than discarding every valid line after it — this file
/// is only ever written by `append` above, so corruption here would mean
/// something outside certway touched it, and the other, valid lines are
/// still real backups worth listing.
pub fn read_all(registry_path: &Path) -> Option<Vec<EditRecord>> {
    let text = std::fs::read_to_string(registry_path).ok()?;
    Some(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(parse_line)
            .collect(),
    )
}

fn parse_line(line: &str) -> Option<EditRecord> {
    let parsed = json::Json::parse(line.as_bytes()).ok()?;
    Some(EditRecord {
        file: PathBuf::from(parsed.str("file").ok()?),
        backup_path: PathBuf::from(parsed.str("backup_path").ok()?),
        domain: parsed.str("domain").ok()?.to_string(),
        timestamp: parsed.str("timestamp").ok()?.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-nginx-registry-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{tag}.jsonl"))
    }

    fn record(file: &str, domain: &str, ts: &str) -> EditRecord {
        EditRecord {
            file: PathBuf::from(file),
            backup_path: PathBuf::from(format!("{file}.certway-backup-{ts}")),
            domain: domain.to_string(),
            timestamp: ts.to_string(),
        }
    }

    #[test]
    fn append_then_read_all_round_trips() {
        let path = tmp_path("round-trip");
        let _ = std::fs::remove_file(&path);

        append(
            &path,
            &record(
                "/etc/nginx/sites-enabled/a.com",
                "a.com",
                "2026-08-01T14-02-11Z",
            ),
        )
        .unwrap();
        append(
            &path,
            &record(
                "/etc/nginx/sites-enabled/b.com",
                "b.com",
                "2026-08-02T09-00-00Z",
            ),
        )
        .unwrap();

        let records = read_all(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].domain, "a.com");
        assert_eq!(records[1].domain, "b.com");
    }

    #[test]
    fn read_all_on_a_missing_file_is_none_not_a_panic() {
        let path = tmp_path("missing");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_all(&path), None);
    }

    #[test]
    fn a_malformed_line_is_skipped_not_fatal_to_the_rest() {
        let path = tmp_path("malformed-line");
        std::fs::write(&path, "not json at all\n{\"file\":\"/etc/nginx/x\",\"backup_path\":\"/etc/nginx/x.certway-backup-2026-08-01T00-00-00Z\",\"domain\":\"x.com\",\"timestamp\":\"2026-08-01T00-00-00Z\"}\n").unwrap();

        let records = read_all(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "x.com");
    }

    #[test]
    fn registry_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("mode");
        let _ = std::fs::remove_file(&path);
        append(
            &path,
            &record(
                "/etc/nginx/nginx.conf",
                "example.com",
                "2026-08-01T00-00-00Z",
            ),
        )
        .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
