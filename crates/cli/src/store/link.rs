// SPDX-License-Identifier: MIT

//! `--link-to`/`--link`/`--link-force`/`--copy`.
//!
//! Target inspection, in order:
//!
//! ```text
//! absent                               -> create
//! a symlink pointing into our data dir -> replace (certway owns it)
//! anything else                        -> refuse, unless --link-force
//! ```
//!
//! The refusal is the important case: a user who mistypes `--link-to
//! /etc/ssl` must not have their existing files replaced. Ownership is
//! decided by the symlink's own target, not by a record on disk — that
//! keeps the check correct even the very first time a link is created,
//! before any `config.json` entry exists for it.
//!
//! Both the symlink and the copy path create at a temp sibling name and
//! `rename(2)` over the target (`super::atomic`'s same primitive), so
//! there is never a moment where the target path is missing.

use super::atomic::{create_dir_secure, random_suffix};
use certway_core::{self as core};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Absent,
    OwnedSymlink,
    NotOwned,
}

/// Inspects `target` without following it.
pub fn inspect(target: &Path, data_root: &Path) -> Result<TargetState, core::Error> {
    let meta = match std::fs::symlink_metadata(target) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(TargetState::Absent),
        Err(e) => return Err(core::Error::io(target, e)),
    };
    if !meta.file_type().is_symlink() {
        return Ok(TargetState::NotOwned);
    }
    let dest = std::fs::read_link(target).map_err(|e| core::Error::io(target, e))?;
    let resolved = if dest.is_absolute() {
        dest
    } else {
        target.parent().unwrap_or_else(|| Path::new("")).join(&dest)
    };
    if resolved.starts_with(data_root) {
        Ok(TargetState::OwnedSymlink)
    } else {
        Ok(TargetState::NotOwned)
    }
}

/// Applies one link: `source` (a file certway just wrote, inside
/// `data_root`) to `target`. Refuses per `inspect`'s rule unless `force`.
/// `copy` writes a real copy instead of a symlink — the `--copy` flag's
/// behavior, and also what every Windows build does unconditionally
/// (symlinks need elevation there — see the `cfg(windows)` arm below).
///
/// Returns `true` when a copy was actually written (whether by `--copy` or
/// the Windows fallback) — the caller uses this to decide whether the
/// "certway falls back to copying on Windows" one-time note applies.
pub fn apply(
    source: &Path,
    target: &Path,
    data_root: &Path,
    force: bool,
    copy: bool,
    mode: u32,
) -> Result<bool, core::Error> {
    let parent = target.parent().ok_or_else(|| {
        core::Error::io(
            target,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link target has no parent directory",
            ),
        )
    })?;
    create_dir_secure(parent, 0o755)?;

    match inspect(target, data_root)? {
        TargetState::NotOwned if !force => {
            return Err(core::Error::LinkTargetNotOwned {
                path: target.to_path_buf(),
            })
        }
        _ => {}
    }

    link_or_copy(source, target, copy, mode)
}

#[cfg(unix)]
fn link_or_copy(source: &Path, target: &Path, copy: bool, mode: u32) -> Result<bool, core::Error> {
    if copy {
        atomic_copy(source, target, mode)?;
        return Ok(true);
    }
    atomic_symlink(source, target)?;
    Ok(false)
}

#[cfg(windows)]
fn link_or_copy(source: &Path, target: &Path, _copy: bool, mode: u32) -> Result<bool, core::Error> {
    // Symlinks require elevation on Windows — copy unconditionally, and
    // tell the caller so the one-time note prints.
    let _ = mode;
    atomic_copy(source, target, mode)?;
    Ok(true)
}

#[cfg(unix)]
fn atomic_symlink(source: &Path, target: &Path) -> Result<(), core::Error> {
    let dir = target.parent().ok_or_else(|| {
        core::Error::io(
            target,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link target has no parent directory",
            ),
        )
    })?;
    let file_name = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        core::Error::io(
            target,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link target has no file name",
            ),
        )
    })?;
    let tmp: PathBuf = dir.join(format!(".{file_name}.tmp.{}", random_suffix()?));

    if let Err(e) = std::os::unix::fs::symlink(source, &tmp) {
        return Err(core::Error::io(&tmp, e));
    }
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(core::Error::io(target, e));
    }
    Ok(())
}

fn atomic_copy(source: &Path, target: &Path, mode: u32) -> Result<(), core::Error> {
    let data = std::fs::read(source).map_err(|e| core::Error::io(source, e))?;
    super::atomic::atomic_write(target, &data, mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certway-link-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_secure(&dir, 0o755).unwrap();
        dir
    }

    #[test]
    fn inspect_absent_target() {
        let dir = tmp_dir("absent");
        let target = dir.join("does-not-exist.pem");
        assert_eq!(inspect(&target, &dir).unwrap(), TargetState::Absent);
    }

    #[test]
    fn apply_to_an_absent_target_creates_a_symlink() {
        let dir = tmp_dir("create");
        let data_root = dir.join("data");
        create_dir_secure(&data_root, 0o755).unwrap();
        let source = data_root.join("fullchain.pem");
        std::fs::write(&source, b"cert bytes").unwrap();

        let target = dir.join("out").join("fullchain.pem");
        let used_copy = apply(&source, &target, &data_root, false, false, 0o644).unwrap();
        assert!(!used_copy);
        assert_eq!(
            inspect(&target, &data_root).unwrap(),
            TargetState::OwnedSymlink
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"cert bytes");
    }

    #[test]
    fn apply_over_our_own_link_replaces_it() {
        let dir = tmp_dir("replace-own");
        let data_root = dir.join("data");
        create_dir_secure(&data_root, 0o755).unwrap();
        let old_source = data_root.join("old.pem");
        let new_source = data_root.join("new.pem");
        std::fs::write(&old_source, b"old").unwrap();
        std::fs::write(&new_source, b"new").unwrap();

        let target = dir.join("out.pem");
        apply(&old_source, &target, &data_root, false, false, 0o644).unwrap();
        apply(&new_source, &target, &data_root, false, false, 0o644).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::read_link(&target).unwrap(), new_source);
    }

    /// Linking over a real file (not owned by certway) must be refused,
    /// and the file must be byte-for-byte untouched afterward — not just
    /// "an error was returned." This is the case that matters most: a
    /// user pointing `--link-to` at the wrong path must never lose data,
    /// even partially via a truncate-then-fail.
    #[test]
    fn apply_over_a_real_file_is_refused_and_the_file_is_untouched() {
        let dir = tmp_dir("refuse");
        let data_root = dir.join("data");
        create_dir_secure(&data_root, 0o755).unwrap();
        let source = data_root.join("fullchain.pem");
        std::fs::write(&source, b"new cert").unwrap();

        let target = dir.join("etc-ssl-example.pem");
        std::fs::write(&target, b"the user's own unrelated file").unwrap();
        let before = std::fs::read(&target).unwrap();
        let before_mtime = std::fs::metadata(&target).unwrap().modified().unwrap();

        let err = apply(&source, &target, &data_root, false, false, 0o644).unwrap_err();
        assert!(matches!(err, core::Error::LinkTargetNotOwned { .. }));

        let after = std::fs::read(&target).unwrap();
        assert_eq!(
            before, after,
            "the refused target's contents must be byte-identical afterward"
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().modified().unwrap(),
            before_mtime,
            "the file must not even have been touched (mtime unchanged)"
        );
    }

    #[test]
    fn link_force_replaces_a_real_file_not_owned_by_certway() {
        let dir = tmp_dir("force");
        let data_root = dir.join("data");
        create_dir_secure(&data_root, 0o755).unwrap();
        let source = data_root.join("fullchain.pem");
        std::fs::write(&source, b"new cert").unwrap();

        let target = dir.join("etc-ssl-example.pem");
        std::fs::write(&target, b"old unrelated file").unwrap();

        apply(&source, &target, &data_root, true, false, 0o644).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new cert");
    }

    #[test]
    fn copy_writes_real_bytes_not_a_symlink_and_does_not_track_the_source() {
        let dir = tmp_dir("copy");
        let data_root = dir.join("data");
        create_dir_secure(&data_root, 0o755).unwrap();
        let source = data_root.join("fullchain.pem");
        std::fs::write(&source, b"v1").unwrap();

        let target = dir.join("copied.pem");
        let used_copy = apply(&source, &target, &data_root, false, true, 0o644).unwrap();
        assert!(used_copy);
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"v1");

        // A copy does not track its source: changing the source after the
        // fact must not change the already-copied file.
        std::fs::write(&source, b"v2").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"v1");
    }

    #[test]
    fn inspect_a_symlink_pointing_outside_the_data_root_is_not_owned() {
        let dir = tmp_dir("foreign-symlink");
        let data_root = dir.join("data");
        create_dir_secure(&data_root, 0o755).unwrap();
        let elsewhere = dir.join("elsewhere.pem");
        std::fs::write(&elsewhere, b"not ours").unwrap();

        let target = dir.join("target.pem");
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();

        assert_eq!(inspect(&target, &data_root).unwrap(), TargetState::NotOwned);
    }
}
