// SPDX-License-Identifier: MIT

//! The ARI window cache — `<data>/<name>/ari.json`, mode `0644`, no
//! secrets.
//!
//! Advisory only: `certway-core::ari` never touches disk (its one I/O rule
//! — see `ari.rs`'s module doc), so caching the fetched window and its
//! `Retry-After` deadline across wakes is entirely this module's job. A
//! corrupt or unreadable cache is deleted and re-fetched, never an error —
//! watch mode and twice-daily timers would otherwise re-fetch on every
//! wake, exactly what `Retry-After` exists to prevent, but a wedged cache
//! file must never be a reason `renew` stops working.

use super::atomic::atomic_write;
use certway_core::json::{write_object, Json, JsonVal};
use certway_core::{self as core, RenewalWindow};
use std::path::{Path, PathBuf};

pub fn ari_cache_path(cert_root: &Path) -> PathBuf {
    cert_root.join("ari.json")
}

fn parse_cache(text: &str) -> Option<RenewalWindow> {
    let json = Json::parse(text.as_bytes()).ok()?;
    let start = json.str("start").ok()?.parse().ok()?;
    let end = json.str("end").ok()?.parse().ok()?;
    let retry_after_deadline = json.str("retry_after_deadline").ok()?.parse().ok()?;
    let explanation_url = json.opt_str("explanation_url").map(str::to_string);
    Some(RenewalWindow {
        start,
        end,
        explanation_url,
        retry_after_deadline,
    })
}

/// Reads the cached window at `path`. `None` for "absent", "unreadable",
/// or "doesn't parse" alike — the caller re-fetches in every one of those
/// cases, and this function also deletes the file in the latter two, since
/// a corrupt cache must not linger to be misread again next wake.
pub fn read_ari_cache(path: &Path) -> Option<RenewalWindow> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return None,
    };
    match parse_cache(&text) {
        Some(window) => Some(window),
        None => {
            let _ = std::fs::remove_file(path);
            None
        }
    }
}

/// Deletes the cached window, if any. Called once a renewal succeeds: the
/// cached window describes the *replaced* certificate, and RFC 9773 §4.2
/// is explicit that a client "MUST NOT fetch RenewalInfo" for a
/// certificate that has already been replaced — a window computed for a
/// certID that no longer exists must not survive to be misread as still
/// applying to the new certificate (it would `now >= moment` forever,
/// since a past window never becomes true again as time passes it by,
/// forcing every future `renew` to renew again on every run).
pub fn invalidate_ari_cache(path: &Path) {
    let _ = std::fs::remove_file(path);
}

pub fn write_ari_cache(path: &Path, window: &RenewalWindow) -> Result<(), core::Error> {
    let start = window.start.to_string();
    let end = window.end.to_string();
    let deadline = window.retry_after_deadline.to_string();
    let mut fields: Vec<(&str, JsonVal)> = vec![
        ("start", JsonVal::Str(&start)),
        ("end", JsonVal::Str(&end)),
        ("retry_after_deadline", JsonVal::Str(&deadline)),
    ];
    if let Some(u) = &window.explanation_url {
        fields.push(("explanation_url", JsonVal::Str(u)));
    }
    let body = write_object(&fields);
    atomic_write(path, body.as_bytes(), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-ari-cache-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn window(start: i64, end: i64) -> RenewalWindow {
        RenewalWindow {
            start,
            end,
            explanation_url: Some("https://example.com/ari".to_string()),
            retry_after_deadline: 999,
        }
    }

    #[test]
    fn round_trips_through_write_then_read() {
        let dir = tmp_root("roundtrip");
        let path = ari_cache_path(&dir);
        let w = window(1000, 2000);
        write_ari_cache(&path, &w).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let read_back = read_ari_cache(&path).unwrap();
        assert_eq!(read_back.start, 1000);
        assert_eq!(read_back.end, 2000);
        assert_eq!(read_back.retry_after_deadline, 999);
        assert_eq!(
            read_back.explanation_url.as_deref(),
            Some("https://example.com/ari")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_reads_as_none() {
        let dir = tmp_root("missing");
        assert!(read_ari_cache(&dir.join("ari.json")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_is_deleted_and_reads_as_none() {
        let dir = tmp_root("corrupt");
        let path = ari_cache_path(&dir);
        std::fs::write(&path, b"not json at all").unwrap();
        assert!(read_ari_cache(&path).is_none());
        assert!(
            !path.exists(),
            "a corrupt cache must be deleted, not left behind to be misread again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalidate_removes_an_existing_cache_and_tolerates_a_missing_one() {
        let dir = tmp_root("invalidate");
        let path = ari_cache_path(&dir);
        write_ari_cache(&path, &window(1000, 2000)).unwrap();
        assert!(path.exists());
        invalidate_ari_cache(&path);
        assert!(!path.exists());
        invalidate_ari_cache(&path); // missing file: must not panic
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn window_without_explanation_url_omits_the_field() {
        let dir = tmp_root("no-explanation");
        let path = ari_cache_path(&dir);
        let w = RenewalWindow {
            start: 1,
            end: 2,
            explanation_url: None,
            retry_after_deadline: 3,
        };
        write_ari_cache(&path, &w).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("explanation_url"));
        let read_back = read_ari_cache(&path).unwrap();
        assert!(read_back.explanation_url.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
