// SPDX-License-Identifier: MIT

//! The edit transaction, the sequence that makes defence #3 (automatic
//! restore) real:
//!
//! ```text
//! 0. validate the config as found — never touch a file we can't already
//!    confirm is valid (baseline validation added after early testing
//!    showed a pre-existing broken config could otherwise get blamed on
//!    this edit's own restore path)
//! 1. read the file, record its mode and ownership
//! 2. copy to <file>.certway-backup-<rfc3339>, preserving mode+ownership
//! 3. compute the new content in memory (the caller's job — this module
//!    never decides *what* to write, only how to write it safely)
//! 4. --dry-run? return the diff, stop here
//! 5. atomic write, preserving mode+ownership
//! 6. validate again — `status.success()` is not enough (see below)
//! 7.   passed  -> reload
//! 8.   failed  -> RESTORE, verify the restore, report
//! 9.   reload failed -> RESTORE, verify, report
//! ```
//!
//! **Step 6's validation is not just an exit code check.** A duplicate
//! exact `server_name` on the same `address:port` produces `[warn]
//! conflicting server name "X" on 0.0.0.0:80, ignored` on stderr with
//! **exit code 0** — the one case that does NOT fail `nginx -t` — and the
//! second block is silently and
//! permanently ignored at runtime. If certway's own append created that
//! shadow (a bug, or a case `matching.rs` didn't catch), a plain exit-code
//! check would report success while the new certificate never actually
//! serves anything — printing "Nothing else to do." over a site that
//! still isn't working. `validate_after_edit` below therefore checks
//! `status.success() AND stderr does not contain "conflicting server
//! name"`. This stricter check applies **only** to the post-edit
//! validation (step 6) — the baseline (step 0) and the restore-verify
//! (inside steps 8/9) both just need `status.success()`, since a
//! pre-existing or restored-to state was never something *this edit*
//! could have shadowed.

use super::registry;
use super::version::NginxVersion;
use certway_core::{self as core};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub enum EditOutcome {
    Edited {
        backup_path: PathBuf,
    },
    DryRun {
        diff: String,
    },
    PreexistingConfigInvalid {
        stderr: String,
    },
    ValidationFailedRestored {
        backup_path: PathBuf,
        stderr: String,
    },
    ReloadFailedRestored {
        backup_path: PathBuf,
        reload_error: String,
    },
    /// The restore's own re-validation failed — the user must intervene
    /// by hand, so this is reported as maximum severity.
    RestoreFailed {
        backup_path: PathBuf,
        restore_stderr: String,
    },
}

#[derive(Debug, Clone)]
pub struct ValidateOutcome {
    pub success: bool,
    pub stderr: String,
}

/// Runs the server's own config test. Implementations: `NginxValidator`
/// (real `nginx -t`) in production, a scripted stand-in in tests — the
/// seam that makes this whole module provable without nginx or Docker.
pub trait Validator {
    fn validate(&self) -> ValidateOutcome;
}

/// Reloads (or, under `--hook-url`, deliberately does nothing — the HTTP
/// hook is the reload mechanism because the server is in another
/// container, unreachable by a local `systemctl`/`nginx -s`).
pub trait Reloader {
    fn reload(&self) -> Result<(), String>;
}

pub struct NginxValidator {
    /// `None` runs `nginx -t` with no `-c`, letting nginx use its own
    /// compiled-in default config path — the right choice when the caller
    /// (`cmd::rollback`, given only a config *file*, not a full detected
    /// installation) has no entry-config path to hand it. `find_and_edit`'s
    /// caller, which already knows the top-level entry file, should still
    /// pass `Some(..)` so the whole include tree is checked explicitly.
    pub entry_config_path: Option<PathBuf>,
    pub nginx_bin: String,
}

impl Validator for NginxValidator {
    fn validate(&self) -> ValidateOutcome {
        let mut cmd = Command::new(&self.nginx_bin);
        cmd.arg("-t");
        if let Some(path) = &self.entry_config_path {
            cmd.arg("-c").arg(path);
        }
        match cmd.output() {
            Ok(output) => ValidateOutcome {
                success: output.status.success(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            },
            Err(e) => ValidateOutcome {
                success: false,
                stderr: format!("failed to run {}: {e}", self.nginx_bin),
            },
        }
    }
}

/// `systemctl reload nginx`, falling back to `nginx -s reload`. Never
/// `restart` — it drops connections for no benefit.
pub struct SystemReloader {
    pub nginx_bin: String,
}

impl Reloader for SystemReloader {
    fn reload(&self) -> Result<(), String> {
        if let Ok(status) = Command::new("systemctl")
            .arg("reload")
            .arg("nginx")
            .status()
        {
            if status.success() {
                return Ok(());
            }
        }
        match Command::new(&self.nginx_bin)
            .arg("-s")
            .arg("reload")
            .output()
        {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(String::from_utf8_lossy(&output.stderr).into_owned()),
            Err(e) => Err(format!("failed to run {} -s reload: {e}", self.nginx_bin)),
        }
    }
}

/// `--hook-url`'s reload path: no local reload is attempted at all, ever
/// successfully, by construction.
pub struct NoopReloader;

impl Reloader for NoopReloader {
    fn reload(&self) -> Result<(), String> {
        Ok(())
    }
}

fn validate_after_edit(v: &dyn Validator) -> ValidateOutcome {
    let raw = v.validate();
    let strict_success = raw.success && !raw.stderr.contains("conflicting server name");
    ValidateOutcome {
        success: strict_success,
        stderr: raw.stderr,
    }
}

struct FileState {
    data: Vec<u8>,
    mode: u32,
    owner: (u32, u32),
}

fn read_file_state(path: &Path) -> Result<FileState, core::Error> {
    let data = std::fs::read(path).map_err(|e| core::Error::io(path, e))?;
    let meta = std::fs::metadata(path).map_err(|e| core::Error::io(path, e))?;
    Ok(FileState {
        data,
        mode: meta.mode() & 0o777,
        owner: (meta.uid(), meta.gid()),
    })
}

fn write_preserving(path: &Path, data: &[u8], state: &FileState) -> Result<(), core::Error> {
    crate::store::atomic::atomic_write_owned(path, data, state.mode, Some(state.owner))
}

/// Where to log a successful edit (`registry.rs`) — `None` when the caller
/// has no registry to log to (every test in this module, and any caller
/// that doesn't need `rollback`'s no-argument listing to find this edit).
pub struct EditRegistration<'a> {
    pub registry_path: &'a Path,
    pub domain: &'a str,
}

/// Runs the whole transaction against `target_file` (the file `matching.rs`
/// identified as containing the block to edit), validating via
/// `entry_config_path` (the top of the `include` tree — usually a
/// *different* file than `target_file`, so `nginx -t` sees the whole
/// config, not just the one file changing). `new_content` is the complete
/// replacement bytes for `target_file` — computed by the caller (`edit.rs`,
/// item 6); this module has no opinion on *what* changes, only on doing
/// the change safely.
pub fn run(
    target_file: &Path,
    new_content: &[u8],
    validator: &dyn Validator,
    reloader: &dyn Reloader,
    dry_run: bool,
    registration: Option<EditRegistration>,
) -> Result<EditOutcome, core::Error> {
    // Step 0 — baseline. Never touch a config we can't already confirm is
    // valid; a pre-existing failure unrelated to this edit must not turn
    // into a false "the restore failed" report later.
    let baseline = validator.validate();
    if !baseline.success {
        return Ok(EditOutcome::PreexistingConfigInvalid {
            stderr: baseline.stderr,
        });
    }

    // Step 1 — read the file, record mode and ownership.
    let original = read_file_state(target_file)?;

    if dry_run {
        let diff = render_diff(target_file, &original.data, new_content);
        return Ok(EditOutcome::DryRun { diff });
    }

    // Step 2 — backup, preserving mode and ownership. Never deleted by
    // this module or any other — a few kilobytes against the one artefact
    // that makes recovery possible.
    let backup_path = backup_path_for(target_file);
    write_preserving(&backup_path, &original.data, &original)?;

    // Step 5 — atomic write, preserving mode and ownership.
    write_preserving(target_file, new_content, &original)?;

    // Step 6 — validate again, strictly (see module doc).
    let after = validate_after_edit(validator);
    if !after.success {
        return Ok(restore_after_failure(
            target_file,
            &backup_path,
            validator,
            RestoreCause::Validation(after.stderr),
        ));
    }

    // Step 7 — reload.
    match reloader.reload() {
        Ok(()) => {
            // Registered strictly here, after a successful reload — never
            // before, and never on any path that ends in a restore. An
            // edit that got rolled back never took effect, so it must
            // never appear in the list `rollback` (no argument) reads.
            // Best-effort: a registry-write failure doesn't undo an edit
            // that already succeeded and is already live — it only means
            // this one edit stays invisible to the no-argument listing;
            // `rollback <file>` still finds its backup directly, since
            // that lookup never depends on the registry at all.
            if let Some(reg) = &registration {
                let record = registry::EditRecord {
                    file: target_file.to_path_buf(),
                    backup_path: backup_path.clone(),
                    domain: reg.domain.to_string(),
                    timestamp: rfc3339_now(),
                };
                let _ = registry::append(reg.registry_path, &record);
            }
            Ok(EditOutcome::Edited { backup_path })
        }
        Err(reload_error) => Ok(restore_after_failure(
            target_file,
            &backup_path,
            validator,
            RestoreCause::Reload(reload_error),
        )),
    }
}

enum RestoreCause {
    Validation(String),
    Reload(String),
}

/// Steps 8/9 — restore, then verify the restore with a plain (non-strict)
/// re-validation: a byte-identical restore returns the config to a state
/// step 0 already proved valid, so `status.success()` alone is the right
/// bar here, not the stricter post-edit check.
fn restore_after_failure(
    target_file: &Path,
    backup_path: &Path,
    validator: &dyn Validator,
    cause: RestoreCause,
) -> EditOutcome {
    match restore_and_verify(target_file, backup_path, validator) {
        Ok(RestoreOutcome::Restored) => match cause {
            RestoreCause::Validation(stderr) => EditOutcome::ValidationFailedRestored {
                backup_path: backup_path.to_path_buf(),
                stderr,
            },
            RestoreCause::Reload(reload_error) => EditOutcome::ReloadFailedRestored {
                backup_path: backup_path.to_path_buf(),
                reload_error,
            },
        },
        Ok(RestoreOutcome::RestoreFailed { stderr }) => EditOutcome::RestoreFailed {
            backup_path: backup_path.to_path_buf(),
            restore_stderr: stderr,
        },
        // The restore write itself failed at the filesystem layer (e.g.
        // disk full, backup file vanished) — still maximum severity, still
        // names the backup path so the user can recover by hand.
        Err(_io_err) => EditOutcome::RestoreFailed {
            backup_path: backup_path.to_path_buf(),
            restore_stderr: "restore write failed".to_string(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    Restored,
    RestoreFailed { stderr: String },
}

/// Restores `target_file` from `backup_path` (preserving the backup's own
/// mode and ownership — a backup is always byte- and mode-identical to
/// what it was taken from, so reading it back is equivalent to restoring
/// the in-memory original) and re-validates with a plain, non-strict
/// check: a byte-identical restore returns to a state already known
/// valid, so the stricter post-edit stderr check (`validate_after_edit`)
/// does not apply here. Shared by the automatic restore-on-failure path
/// above, `cmd::rollback`'s manual restore, and the real-container restore
/// proof — all three restores are the same operation, just triggered
/// differently.
pub fn restore_and_verify(
    target_file: &Path,
    backup_path: &Path,
    validator: &dyn Validator,
) -> Result<RestoreOutcome, core::Error> {
    let backup = read_file_state(backup_path)?;
    write_preserving(target_file, &backup.data, &backup)?;

    let check = validator.validate();
    if check.success {
        Ok(RestoreOutcome::Restored)
    } else {
        Ok(RestoreOutcome::RestoreFailed {
            stderr: check.stderr,
        })
    }
}

/// **Resolves a symlink first — this is not cosmetic.** Found live on
/// a real Debian/Ubuntu box: Debian's own `sites-enabled -> sites-
/// available` symlink convention means `target_file` is very often a
/// symlink, and `include sites-enabled/*;` (the Debian/Ubuntu default,
/// with **no extension filter** — unlike `conf.d/*.conf`) picks up
/// *every* file dropped in that directory, backup or not. A backup
/// written beside the symlink itself became a second, stale copy of the
/// exact block nginx also parsed on the next reload — a self-inflicted
/// `server_name` collision, the precise failure mode this module's own
/// strict post-edit check (this file's own module doc comment) exists to
/// catch, except this time certway caused it. Writing the backup beside
/// the real, resolved file instead (`sites-available/`, never glob-
/// included) is both safe and the more literal reading of "beside the
/// file" — the file's real content lives there; `sites-enabled/` only
/// holds a pointer to it. `cmd::rollback`'s `most_recent_backup` performs
/// the same resolution before searching, so a backup written here is
/// still found regardless of which path form (`sites-enabled/...` or
/// `sites-available/...`) the user gives `certway rollback`. Falls back
/// to the given path when it isn't a symlink (the common case, and the
/// pinned container's own layout) or `canonicalize` fails for any reason
/// — never a hard error over where a backup lands.
fn backup_path_for(target_file: &Path) -> PathBuf {
    let real_file =
        std::fs::canonicalize(target_file).unwrap_or_else(|_| target_file.to_path_buf());
    let file_name = real_file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    real_file.with_file_name(format!("{file_name}.certway-backup-{}", rfc3339_now()))
}

fn rfc3339_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    crate::cmd::renew::format_rfc3339(now)
}

/// A minimal unified-style diff for `--dry-run` — line-based, no external
/// diff algorithm (no new crate): every removed line prefixed `-`, every
/// added line prefixed `+`, common lines dropped. Good enough to *show*
/// the change; not a general-purpose diff tool.
fn render_diff(path: &Path, before: &[u8], after: &[u8]) -> String {
    diff_lines(
        path,
        &String::from_utf8_lossy(before),
        &String::from_utf8_lossy(after),
    )
}

fn diff_lines(path: &Path, before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let mut out = format!("--- {}\n+++ {}\n", path.display(), path.display());
    let common_prefix = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    let common_suffix = a[common_prefix..]
        .iter()
        .rev()
        .zip(b[common_prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    for line in &a[common_prefix..a.len() - common_suffix] {
        out.push_str(&format!("-{line}\n"));
    }
    for line in &b[common_prefix..b.len() - common_suffix] {
        out.push_str(&format!("+{line}\n"));
    }
    out
}

/// Detects `--nginx`'s http2 form once, from a parsed `nginx -V`, reused
/// by `edit.rs` — kept here rather than in `version.rs` since it's a
/// transaction-time input (the running server's version), not a parsing
/// concern.
pub fn detect_http2_directive_support(nginx_bin: &str) -> Option<NginxVersion> {
    let output = Command::new(nginx_bin).arg("-v").output().ok()?;
    super::version::parse_version(&String::from_utf8_lossy(&output.stderr))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::{Reloader, ValidateOutcome, Validator};
    use std::cell::RefCell;

    /// A scripted validator: returns each outcome in `script` in order,
    /// repeating the last one once exhausted (so a test doesn't need to
    /// predict exactly how many times `validate` gets called).
    pub struct ScriptedValidator {
        pub script: RefCell<Vec<ValidateOutcome>>,
    }

    impl ScriptedValidator {
        pub fn new(script: Vec<ValidateOutcome>) -> Self {
            ScriptedValidator {
                script: RefCell::new(script),
            }
        }

        pub fn always(outcome: ValidateOutcome) -> Self {
            Self::new(vec![outcome])
        }
    }

    impl Validator for ScriptedValidator {
        fn validate(&self) -> ValidateOutcome {
            let mut script = self.script.borrow_mut();
            if script.len() > 1 {
                script.remove(0)
            } else {
                script[0].clone()
            }
        }
    }

    pub struct ScriptedReloader {
        pub result: Result<(), String>,
    }

    impl Reloader for ScriptedReloader {
        fn reload(&self) -> Result<(), String> {
            self.result.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{ScriptedReloader, ScriptedValidator};
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-transaction-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ok_outcome() -> ValidateOutcome {
        ValidateOutcome {
            success: true,
            stderr: String::new(),
        }
    }

    fn failed_outcome(stderr: &str) -> ValidateOutcome {
        ValidateOutcome {
            success: false,
            stderr: stderr.to_string(),
        }
    }

    // -- backup_path_for: the Debian/Ubuntu symlink bug -----------------
    //
    // Found live: `sites-enabled -> sites-available` is Debian/Ubuntu's
    // own stock convention, and `include sites-enabled/*;` has no
    // extension filter — it picks up literally anything dropped there,
    // backup file or not. A backup written beside the symlink itself, not
    // the real file, became a second copy of the same `server_name`
    // nginx also parsed on reload: a self-inflicted collision.

    #[cfg(unix)]
    #[test]
    fn backup_path_for_resolves_a_symlink_to_the_real_files_own_directory() {
        let real_dir = tmp_dir("backup-real-dir");
        let link_dir = tmp_dir("backup-link-dir");
        let real_file = real_dir.join("example.com");
        std::fs::write(&real_file, b"content").unwrap();
        let link_file = link_dir.join("example.com");
        std::os::unix::fs::symlink(&real_file, &link_file).unwrap();

        let backup = backup_path_for(&link_file);
        assert_eq!(
            backup.parent().unwrap(),
            real_dir.canonicalize().unwrap(),
            "the backup must land beside the real file, not beside the symlink: {backup:?}"
        );
        assert!(
            backup
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("example.com.certway-backup-"),
            "backup file name: {backup:?}"
        );
    }

    #[test]
    fn backup_path_for_a_plain_non_symlink_file_is_unchanged_from_before() {
        let dir = tmp_dir("backup-plain");
        let file = dir.join("example.com.conf");
        std::fs::write(&file, b"content").unwrap();

        let backup = backup_path_for(&file);
        assert_eq!(backup.parent().unwrap(), dir.canonicalize().unwrap());
    }

    /// The real-world proof, through the actual transaction: editing a
    /// config reached via a symlink must never leave a backup sitting in
    /// the symlink's own directory — a directory that, on a real
    /// Debian/Ubuntu `sites-enabled/`, nginx's own glob-include would
    /// then parse as a live (stale) config on the very next reload.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_target_never_leaves_a_backup_in_the_symlinks_own_directory() {
        let real_dir = tmp_dir("e2e-real-dir");
        let link_dir = tmp_dir("e2e-link-dir");
        let real_file = real_dir.join("example.com");
        std::fs::write(&real_file, b"old content").unwrap();
        let link_file = link_dir.join("example.com");
        std::os::unix::fs::symlink(&real_file, &link_file).unwrap();

        let validator = ScriptedValidator::always(ok_outcome());
        let reloader = ScriptedReloader { result: Ok(()) };
        let result = run(
            &link_file,
            b"new content",
            &validator,
            &reloader,
            false,
            None,
        )
        .unwrap();
        assert!(
            matches!(result, EditOutcome::Edited { .. }),
            "expected Edited, got {result:?}"
        );

        let link_dir_entries: Vec<_> = std::fs::read_dir(&link_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            link_dir_entries,
            vec![std::ffi::OsString::from("example.com")],
            "the symlink's own directory must contain nothing but the symlink itself, \
             never a backup file a glob-include would pick up: {link_dir_entries:?}"
        );

        let real_dir_entries: Vec<_> = std::fs::read_dir(&real_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            real_dir_entries.len(),
            2,
            "the real file's own directory must hold the file and exactly one backup: {real_dir_entries:?}"
        );
    }

    #[test]
    fn happy_path_writes_backs_up_and_reloads() {
        let dir = tmp_dir("happy");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();

        let validator = ScriptedValidator::always(ok_outcome());
        let reloader = ScriptedReloader { result: Ok(()) };

        let result = run(&target, b"new content", &validator, &reloader, false, None).unwrap();
        match result {
            EditOutcome::Edited { backup_path } => {
                assert_eq!(std::fs::read(&target).unwrap(), b"new content");
                assert_eq!(std::fs::read(&backup_path).unwrap(), b"old content");
                assert!(backup_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains("certway-backup-"));
            }
            other => panic!("expected Edited, got {other:?}"),
        }
    }

    #[test]
    fn a_successful_edit_with_registration_appends_a_registry_record() {
        let dir = tmp_dir("registration-success");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();
        let registry_path = dir.join("edits.jsonl");

        let validator = ScriptedValidator::always(ok_outcome());
        let reloader = ScriptedReloader { result: Ok(()) };
        let registration = EditRegistration {
            registry_path: &registry_path,
            domain: "example.com",
        };

        let result = run(
            &target,
            b"new content",
            &validator,
            &reloader,
            false,
            Some(registration),
        )
        .unwrap();
        let EditOutcome::Edited { backup_path } = result else {
            panic!("expected Edited")
        };

        let records = registry::read_all(&registry_path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "example.com");
        assert_eq!(records[0].file, target);
        assert_eq!(records[0].backup_path, backup_path);
    }

    #[test]
    fn a_restored_edit_never_appends_a_registry_record() {
        let dir = tmp_dir("registration-restored");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();
        let registry_path = dir.join("edits.jsonl");

        // baseline passes, post-edit fails -> restored, never reaches the
        // reload-success point registration lives at.
        let validator = ScriptedValidator::new(vec![
            ok_outcome(),
            failed_outcome("[emerg] bad edit"),
            ok_outcome(),
        ]);
        let reloader = ScriptedReloader { result: Ok(()) };
        let registration = EditRegistration {
            registry_path: &registry_path,
            domain: "example.com",
        };

        let result = run(
            &target,
            b"new content",
            &validator,
            &reloader,
            false,
            Some(registration),
        )
        .unwrap();
        assert!(matches!(
            result,
            EditOutcome::ValidationFailedRestored { .. }
        ));
        assert_eq!(
            registry::read_all(&registry_path),
            None,
            "a rolled-back edit must never leave a phantom registry entry"
        );
    }

    #[test]
    fn dry_run_writes_nothing_and_no_backup_is_created() {
        let dir = tmp_dir("dry-run");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();

        let validator = ScriptedValidator::always(ok_outcome());
        let reloader = ScriptedReloader { result: Ok(()) };

        let result = run(&target, b"new content", &validator, &reloader, true, None).unwrap();
        match result {
            EditOutcome::DryRun { diff } => {
                assert!(diff.contains("-old content"));
                assert!(diff.contains("+new content"));
            }
            other => panic!("expected DryRun, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"old content",
            "dry-run must never write the target"
        );
        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("backup"))
            .collect();
        assert!(backups.is_empty(), "dry-run must never create a backup");
    }

    #[test]
    fn preexisting_invalid_config_is_never_touched() {
        let dir = tmp_dir("preexisting-invalid");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();
        let before = std::fs::read(&target).unwrap();

        let validator = ScriptedValidator::always(failed_outcome("[emerg] pre-existing problem"));
        let reloader = ScriptedReloader { result: Ok(()) };

        let result = run(&target, b"new content", &validator, &reloader, false, None).unwrap();
        assert!(matches!(
            result,
            EditOutcome::PreexistingConfigInvalid { .. }
        ));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            before,
            "must never write when the baseline is already invalid"
        );
        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("backup"))
            .collect();
        assert!(
            backups.is_empty(),
            "must never even take a backup when the baseline is already invalid"
        );
    }

    #[test]
    fn validation_failure_restores_and_verifies() {
        let dir = tmp_dir("validation-failure");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();

        // baseline passes, post-edit fails, restore-verify passes.
        let validator = ScriptedValidator::new(vec![
            ok_outcome(),
            failed_outcome("[emerg] bad edit"),
            ok_outcome(),
        ]);
        let reloader = ScriptedReloader { result: Ok(()) };

        let result = run(&target, b"new content", &validator, &reloader, false, None).unwrap();
        match result {
            EditOutcome::ValidationFailedRestored {
                backup_path,
                stderr,
            } => {
                assert_eq!(
                    std::fs::read(&target).unwrap(),
                    b"old content",
                    "must be restored byte-identical"
                );
                assert_eq!(std::fs::read(&backup_path).unwrap(), b"old content");
                assert_eq!(stderr, "[emerg] bad edit");
            }
            other => panic!("expected ValidationFailedRestored, got {other:?}"),
        }
    }

    #[test]
    fn restore_that_itself_fails_is_maximum_severity() {
        let dir = tmp_dir("restore-fails");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();

        // baseline passes, post-edit fails, restore-verify ALSO fails.
        let validator = ScriptedValidator::new(vec![
            ok_outcome(),
            failed_outcome("[emerg] bad edit"),
            failed_outcome("[emerg] still broken"),
        ]);
        let reloader = ScriptedReloader { result: Ok(()) };

        let result = run(&target, b"new content", &validator, &reloader, false, None).unwrap();
        match result {
            EditOutcome::RestoreFailed {
                backup_path,
                restore_stderr,
            } => {
                assert_eq!(
                    std::fs::read(&target).unwrap(),
                    b"old content",
                    "the write itself must still have restored the bytes"
                );
                assert!(
                    std::fs::metadata(&backup_path).is_ok(),
                    "backup must survive so the user can recover by hand"
                );
                assert_eq!(restore_stderr, "[emerg] still broken");
            }
            other => panic!("expected RestoreFailed, got {other:?}"),
        }
    }

    #[test]
    fn reload_failure_restores_the_edit_even_though_validation_passed() {
        let dir = tmp_dir("reload-failure");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();

        let validator = ScriptedValidator::always(ok_outcome());
        let reloader = ScriptedReloader {
            result: Err("reload timed out".to_string()),
        };

        let result = run(&target, b"new content", &validator, &reloader, false, None).unwrap();
        match result {
            EditOutcome::ReloadFailedRestored {
                backup_path: _,
                reload_error,
            } => {
                assert_eq!(std::fs::read(&target).unwrap(), b"old content");
                assert_eq!(reload_error, "reload timed out");
            }
            other => panic!("expected ReloadFailedRestored, got {other:?}"),
        }
    }

    /// End-to-end proof of this module's core guarantee: a config where
    /// certway's own edit creates a shadowing duplicate `server_name`.
    /// `nginx -t` exits 0 for this — a real, well-known nginx gotcha, not
    /// something this test invents — so this test asserts the *strict*
    /// stderr check catches it anyway: treated as a failure, restored,
    /// never reported as `Edited`.
    #[test]
    fn shadowing_duplicate_server_name_is_treated_as_failure_despite_exit_code_0() {
        let dir = tmp_dir("shadow-duplicate");
        let target = dir.join("example.com.conf");
        std::fs::write(
            &target,
            b"server { listen 443 ssl; server_name example.com; }",
        )
        .unwrap();

        // baseline: clean pass, no conflict yet (only one block names
        // example.com before our edit). post-edit: exit 0, but stderr
        // carries the real nginx warning shape for a duplicate exact
        // server_name — nginx's own well-known trap: it warns but still
        // exits 0.
        let post_edit_stderr = "nginx: [warn] conflicting server name \"example.com\" on 0.0.0.0:443, ignored\nnginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful";
        let validator = ScriptedValidator::new(vec![
            ok_outcome(),
            ValidateOutcome {
                success: true,
                stderr: post_edit_stderr.to_string(),
            }, // exit 0, warning present
            ok_outcome(), // restore-verify
        ]);
        let reloader = ScriptedReloader { result: Ok(()) };

        let new_content = b"server { listen 443 ssl; server_name example.com; } server { listen 443 ssl; server_name example.com; ssl_certificate /new/cert.pem; }";
        let result = run(&target, new_content, &validator, &reloader, false, None).unwrap();

        match result {
            EditOutcome::ValidationFailedRestored { .. } => {
                assert_eq!(std::fs::read(&target).unwrap(), b"server { listen 443 ssl; server_name example.com; }", "must be restored, not left with the shadowing duplicate");
            }
            other => panic!("expected ValidationFailedRestored despite exit code 0, got {other:?} — the false-confidence failure this design exists to prevent"),
        }
        // Never reaches Edited — the trailer must never print "Nothing else to do." for this case.
        assert!(!matches!(result, EditOutcome::Edited { .. }));
    }

    #[test]
    fn mode_and_ownership_are_preserved_across_the_write() {
        let dir = tmp_dir("mode-ownership");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

        let validator = ScriptedValidator::always(ok_outcome());
        let reloader = ScriptedReloader { result: Ok(()) };

        run(&target, b"new content", &validator, &reloader, false, None).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o640,
            "the original file's mode must survive the edit, not fall back to a default"
        );
    }

    /// `restore_and_verify` used standalone, the shape `cmd::rollback` and
    /// the real-container proof both need: no in-memory `FileState` in
    /// hand, only a backup path found on disk.
    #[test]
    fn restore_and_verify_restores_from_a_backup_path_alone() {
        let dir = tmp_dir("standalone-restore");
        let target = dir.join("example.com.conf");
        let backup = dir.join("example.com.conf.certway-backup-2026-01-01T00-00-00Z");
        std::fs::write(&target, b"corrupted garbage").unwrap();
        std::fs::write(&backup, b"known good content").unwrap();

        let validator = ScriptedValidator::always(ok_outcome());
        let result = restore_and_verify(&target, &backup, &validator).unwrap();

        assert_eq!(result, RestoreOutcome::Restored);
        assert_eq!(std::fs::read(&target).unwrap(), b"known good content");
    }

    #[test]
    fn restore_and_verify_reports_failure_when_the_restored_config_still_fails() {
        let dir = tmp_dir("standalone-restore-fails");
        let target = dir.join("example.com.conf");
        let backup = dir.join("example.com.conf.certway-backup-2026-01-01T00-00-00Z");
        std::fs::write(&target, b"corrupted garbage").unwrap();
        std::fs::write(&backup, b"known good content").unwrap();

        let validator = ScriptedValidator::always(failed_outcome("[emerg] still broken"));
        let result = restore_and_verify(&target, &backup, &validator).unwrap();

        assert_eq!(
            result,
            RestoreOutcome::RestoreFailed {
                stderr: "[emerg] still broken".to_string()
            }
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"known good content",
            "the write itself must still have happened"
        );
    }

    #[test]
    fn backup_is_never_deleted_even_on_success() {
        let dir = tmp_dir("backup-survives");
        let target = dir.join("example.com.conf");
        std::fs::write(&target, b"old content").unwrap();

        let validator = ScriptedValidator::always(ok_outcome());
        let reloader = ScriptedReloader { result: Ok(()) };

        let result = run(&target, b"new content", &validator, &reloader, false, None).unwrap();
        let EditOutcome::Edited { backup_path } = result else {
            panic!("expected Edited")
        };
        assert!(
            backup_path.exists(),
            "a successful edit's backup must still exist afterward"
        );
    }
}
