// SPDX-License-Identifier: MIT

//! The `rollback` command: `certway rollback [<file>]` — the manual
//! counterpart to the automatic restore-on-failure inside the edit
//! transaction (`webserver::nginx::transaction::run`'s steps 8/9), for the
//! case where nginx's config test passed but the resulting behavior was
//! wrong anyway, so the person running certway wants to undo the edit by
//! hand after the fact.
//!
//! With a `<file>` argument: finds that file's most recent
//! `<file-name>.certway-backup-<rfc3339>` sibling (the exact naming
//! `transaction::backup_path_for` uses — always written in the same
//! directory as the file it backs up, so no separate registry is needed to
//! find it), restores it via `transaction::restore_and_verify` — the
//! identical routine the automatic path uses, proven against a real
//! `nginx:1.29.3` container in `tests/nginx_container_proofs.rs` — and
//! reloads on success.
//!
//! **Known gap, reported rather than silently filled.** With no argument,
//! this command is meant to list every available backup on the host. This
//! build has no persistent registry of which files certway has edited.
//! The `<file>` case above needs no registry — a backup always sits next
//! to the file it came from — but *discovering every backup on the host*
//! with nothing to scan from is a real, unresolved question. Inventing a
//! mechanism for it now (e.g. walking nginx's resolved config tree to
//! find directories that might contain backups) would be scope nobody
//! asked for and a discovery path nobody has verified is complete. This
//! arm reports the gap outright instead.

use crate::args::RollbackArgs;
use crate::render::{pad_field, Out, MUTED, RESET};
use crate::report;
use crate::store;
use crate::webserver::nginx::registry;
use crate::webserver::nginx::transaction::{
    self, NginxValidator, Reloader, RestoreOutcome, SystemReloader,
};
use certway_core::{self as core};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The registry `transaction::run` writes to on every successful edit
/// (`registry.rs`) — the same data root every other command resolves via
/// `store::resolve`, so a registration made during `issue`/`renew` and a
/// lookup made here always agree on where to look.
fn registry_path() -> Option<PathBuf> {
    store::resolve(store::Role::Data, None, "--out")
        .ok()
        .map(|root| root.join("edits.jsonl"))
}

/// `certway rollback --help` — see `cmd::issue::ISSUE_HELP`'s doc comment
/// for the shape every command's help follows.
const ROLLBACK_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp
{
    usage: "certway rollback [<file>] [flags]",
    examples: &[
        "certway rollback",
        "certway rollback /etc/nginx/sites-enabled/example.com",
    ],
    groups: &[crate::cmd::command_help::FlagGroup {
        heading: "",
        flags: &[
            crate::cmd::command_help::FlagHelp {
                flag: "--json",
                about: "Machine-readable output",
            },
            crate::cmd::command_help::FlagHelp {
                flag: "--no-color",
                about: "Disable colour",
            },
        ],
    }],
};

pub fn run(args: RollbackArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &ROLLBACK_HELP);
        return 0;
    }

    // `rollback` edits a local config file and never contacts a CA, so the
    // header prints bare `certway {version}` with no CA-status suffix.
    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    let Some(file) = args.file.as_deref() else {
        return no_argument(out);
    };
    let target = Path::new(file);

    let backup = match most_recent_backup(target) {
        Ok(Some(b)) => b,
        Ok(None) => return no_backup_found(out, file),
        Err(e) => return io_failed(out, file, &e),
    };

    let _ = out.step_done(
        "backup",
        &backup_timestamp_label(&backup, target),
        Duration::ZERO,
    );

    // `entry_config_path: None` — rollback is given a config *file*, not a
    // detected installation with a known top-level entry, so `nginx -t`
    // runs with no `-c` and validates against the compiled-in default
    // path (`NginxValidator`'s own doc comment).
    let validator = NginxValidator {
        entry_config_path: None,
        nginx_bin: "nginx".to_string(),
    };

    let restore = match transaction::restore_and_verify(target, &backup, &validator) {
        Ok(r) => r,
        Err(e) => return io_failed(out, file, &e),
    };

    match restore {
        RestoreOutcome::RestoreFailed { stderr } => {
            return restore_failed(out, file, &backup, &stderr)
        }
        RestoreOutcome::Restored => {
            let _ = out.step_done("restore", "written", Duration::ZERO);
            let _ = out.step_done("validate", "nginx -t passed", Duration::ZERO);
        }
    }

    let reloader = SystemReloader {
        nginx_bin: "nginx".to_string(),
    };
    match reloader.reload() {
        Ok(()) => {
            let _ = out.step_done("reload", "nginx reloaded", Duration::ZERO);
            0
        }
        Err(reload_error) => {
            // The dangerous part is already done and verified — the file
            // is restored and valid. A reload failure only means the
            // running server hasn't picked it up yet, the same
            // satellite-failure-is-a-warning treatment `hook.rs` already
            // gives a failing post-issuance hook.
            let _ = out.step_warned("reload", &reload_error);
            0
        }
    }
}

/// The no-argument form: a table of every edit `edits.jsonl` has
/// recorded, most recent first. Missing or unreadable
/// (no registry yet, or it can't be resolved at all) prints the manual
/// alternative instead of an error — backups are always discoverable by
/// hand next to the file they protect, registry or not.
fn no_argument(out: &mut Out<impl Write>) -> i32 {
    let records = registry_path().and_then(|p| registry::read_all(&p));

    match records {
        Some(records) if !records.is_empty() => {
            let mut sorted = records;
            sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            print_backup_table(out, &sorted);
            0
        }
        _ => {
            print_no_record_message(out);
            0
        }
    }
}

fn print_backup_table(out: &mut Out<impl Write>, records: &[registry::EditRecord]) {
    let color = out.caps.color;
    let unicode = out.caps.unicode;
    let _ = out.raw_line("");
    let header = format!("{}FILE", pad_field("BACKUP", 27, unicode));
    let _ = out.raw_line(&format!(
        "  {}",
        if color {
            format!("{MUTED}{header}{RESET}")
        } else {
            header
        }
    ));
    for record in records {
        let _ = out.raw_line(&format!(
            "  {}{}",
            pad_field(&record.timestamp, 27, unicode),
            record.file.display()
        ));
    }
    let _ = out.raw_line("");
    let _ = out.raw_line("    certway rollback <file>  restores the most recent.");
    let _ = out.raw_line("");
}

fn print_no_record_message(out: &mut Out<impl Write>) {
    let _ = out.raw_line("certway has no record of any edits.");
    let _ = out.raw_line("");
    let _ = out.raw_line("Backups are written beside the file they protect:");
    let _ = out.raw_line("");
    let _ = out.raw_line("  ls /etc/nginx/**/*.certway-backup-*");
    let _ = out.raw_line("");
    let _ = out.raw_line("Restore one with:");
    let _ = out.raw_line("");
    let _ = out.raw_line("  certway rollback <file>");
}

fn no_backup_found(out: &mut Out<impl Write>, file: &str) -> i32 {
    let block = report::rollback_no_backup_found(file);
    let _ = out.step_failed("rollback", &block.summary);
    let _ = out.error_block(&block);
    1
}

fn restore_failed(out: &mut Out<impl Write>, file: &str, backup: &Path, stderr: &str) -> i32 {
    let block = report::rollback_restore_failed(file, &backup.display().to_string(), stderr);
    let _ = out.step_failed("rollback", &block.summary);
    let _ = out.error_block(&block);
    1
}

fn io_failed(out: &mut Out<impl Write>, file: &str, err: &core::Error) -> i32 {
    let block = report::rollback_io_failed(file, err);
    let _ = out.step_failed("rollback", &block.summary);
    let _ = out.error_block(&block);
    1
}

/// `target`'s most recent `<file-name>.certway-backup-<rfc3339>` sibling.
/// RFC3339 timestamps sort lexicographically in chronological order (the
/// same property `transaction::backup_path_for`'s callers already rely
/// on), so the lexicographically-last matching name is the most recent.
fn most_recent_backup(target: &Path) -> Result<Option<PathBuf>, core::Error> {
    // Resolves a symlink first, matching where `transaction::backup_path_
    // for` actually writes backups (`transaction.rs`'s own doc comment on
    // why — Debian/Ubuntu's `sites-enabled -> sites-available`, and
    // `include sites-enabled/*;`'s no-extension-filter glob). Without
    // this, `certway rollback /etc/nginx/sites-enabled/example.com` (the
    // exact path form a user copies from `certway rollback`'s own no-
    // argument listing) would search the symlink's own directory and
    // never find a backup that's actually sitting in `sites-available/`.
    // Falls back to the given path when it isn't a symlink or resolving
    // it fails for any reason (e.g. the file was since deleted) —
    // `Ok(None)` ("no backup found") is still the right answer to surface
    // through the normal path below, not a hard error here.
    let target = std::fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    let Some(file_name) = target.file_name().and_then(|n| n.to_str()) else {
        return Ok(None);
    };
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let prefix = format!("{file_name}.certway-backup-");

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(core::Error::io(dir, e)),
    };

    let mut candidates: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with(&prefix) {
                candidates.push(name.to_string());
            }
        }
    }
    candidates.sort();
    Ok(candidates
        .into_iter()
        .next_back()
        .map(|name| dir.join(name)))
}

fn backup_timestamp_label(backup: &Path, target: &Path) -> String {
    let backup_name = backup
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let target_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let prefix = format!("{target_name}.certway-backup-");
    backup_name
        .strip_prefix(&prefix)
        .unwrap_or(backup_name)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;
    use crate::render::Mode;
    use crate::webserver::nginx::transaction::{ValidateOutcome, Validator};

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-rollback-cmd-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run_captured(args: RollbackArgs) -> (i32, String) {
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 80,
        };
        let mut buf = Vec::new();
        let code = {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            run(args, &mut out)
        };
        (code, String::from_utf8(buf).unwrap())
    }

    #[test]
    fn most_recent_backup_picks_the_lexicographically_last_timestamp() {
        let dir = tmp_dir("most-recent");
        let target = dir.join("nginx.conf");
        std::fs::write(&target, b"current").unwrap();
        std::fs::write(
            dir.join("nginx.conf.certway-backup-2026-07-14T09-31-44Z"),
            b"older",
        )
        .unwrap();
        std::fs::write(
            dir.join("nginx.conf.certway-backup-2026-08-01T14-02-11Z"),
            b"newer",
        )
        .unwrap();
        // A file that merely contains the prefix as a substring elsewhere
        // must not be picked up as a match.
        std::fs::write(
            dir.join("unrelated.conf.certway-backup-2026-09-01T00-00-00Z"),
            b"unrelated",
        )
        .unwrap();

        let picked = most_recent_backup(&target).unwrap().unwrap();
        assert_eq!(
            picked.file_name().unwrap().to_str().unwrap(),
            "nginx.conf.certway-backup-2026-08-01T14-02-11Z"
        );
    }

    /// Bug found live: `transaction::backup_path_for` writes a symlinked
    /// target's backup beside the *real* file, not the symlink — so
    /// looking it up must resolve the same way, or `certway rollback
    /// /etc/nginx/sites-enabled/example.com` (exactly the path form shown
    /// by `certway rollback`'s own no-argument listing) would search the
    /// wrong directory and report "no backup found" for one that exists.
    #[cfg(unix)]
    #[test]
    fn most_recent_backup_resolves_a_symlinked_target_to_where_the_backup_actually_lives() {
        let real_dir = tmp_dir("symlink-real-dir");
        let link_dir = tmp_dir("symlink-link-dir");
        let real_file = real_dir.join("example.com");
        std::fs::write(&real_file, b"current").unwrap();
        std::fs::write(
            real_dir.join("example.com.certway-backup-2026-08-01T14-02-11Z"),
            b"backed up",
        )
        .unwrap();
        let link_file = link_dir.join("example.com");
        std::os::unix::fs::symlink(&real_file, &link_file).unwrap();

        let picked = most_recent_backup(&link_file).unwrap().unwrap();
        assert_eq!(
            picked,
            real_dir
                .canonicalize()
                .unwrap()
                .join("example.com.certway-backup-2026-08-01T14-02-11Z")
        );
    }

    #[test]
    fn no_backup_found_reports_a_clean_failure_and_touches_nothing() {
        let dir = tmp_dir("no-backup");
        let target = dir.join("nginx.conf");
        std::fs::write(&target, b"current").unwrap();

        let (code, text) = run_captured(RollbackArgs {
            file: Some(target.to_str().unwrap().to_string()),
            ..Default::default()
        });
        assert_eq!(code, 1);
        assert!(text.contains("No backup was found"), "{text}");
        assert_eq!(std::fs::read(&target).unwrap(), b"current");
    }

    // `no_argument`'s own registry-path resolution goes through
    // `store::resolve`, which reads real ambient environment/filesystem
    // state (`CERTWAY_DATA_DIR`, `$HOME`, ...) — not something a unit test
    // should mutate globally (`store::paths`'s own tests already need a
    // dedicated mutex for exactly that reason, scoped to that module).
    // These two tests instead prove the print functions themselves are
    // correct against explicit data, independent of where it came from.

    fn captured(f: impl FnOnce(&mut Out<&mut Vec<u8>>)) -> String {
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 80,
        };
        let mut buf = Vec::new();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            f(&mut out);
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn backup_table_lists_every_record_with_its_file_and_timestamp() {
        let records = vec![
            registry::EditRecord {
                file: PathBuf::from("/etc/nginx/sites-enabled/example.com"),
                backup_path: PathBuf::from(
                    "/etc/nginx/sites-enabled/example.com.certway-backup-2026-08-01T14:02:11Z",
                ),
                domain: "example.com".to_string(),
                timestamp: "2026-08-01T14:02:11Z".to_string(),
            },
            registry::EditRecord {
                file: PathBuf::from("/etc/nginx/sites-enabled/other.com"),
                backup_path: PathBuf::from(
                    "/etc/nginx/sites-enabled/other.com.certway-backup-2026-07-14T09:31:44Z",
                ),
                domain: "other.com".to_string(),
                timestamp: "2026-07-14T09:31:44Z".to_string(),
            },
        ];
        let text = captured(|out| print_backup_table(out, &records));

        assert!(text.contains("BACKUP"), "{text}");
        assert!(text.contains("FILE"), "{text}");
        assert!(
            text.contains("2026-08-01T14:02:11Z")
                && text.contains("/etc/nginx/sites-enabled/example.com"),
            "{text}"
        );
        assert!(
            text.contains("2026-07-14T09:31:44Z")
                && text.contains("/etc/nginx/sites-enabled/other.com"),
            "{text}"
        );
        assert!(text.contains("certway rollback <file>"), "{text}");
    }

    #[test]
    fn no_record_message_never_fabricates_a_listing_and_names_the_manual_path() {
        // Not redundant: the bare fn item fails to unify with `captured`'s
        // higher-ranked `FnOnce` bound (rustc: "implementation of FnOnce
        // is not general enough") — the closure is the fix, not decoration.
        #[allow(clippy::redundant_closure)]
        let text = captured(|out| print_no_record_message(out));
        assert!(text.contains("no record of any edits"), "{text}");
        assert!(text.contains("certway-backup-"), "{text}");
        assert!(
            !text.contains("BACKUP"),
            "must never fabricate a listing table it cannot actually populate: {text}"
        );
    }

    #[test]
    fn no_argument_never_panics_and_always_exits_zero() {
        // Exercises the real `run()` path end to end — whatever the
        // ambient environment resolves to (a real registry, none, or an
        // unresolvable data root), this is informational, never a
        // failure: exit 0 either way.
        let (code, _text) = run_captured(RollbackArgs::default());
        assert_eq!(code, 0);
    }

    #[test]
    fn restore_and_verify_wiring_restores_the_backup_bytes_directly() {
        // A full `run()` call needs a real `nginx` binary on PATH to
        // validate — covered end to end against a real container in
        // `tests/nginx_container_proofs.rs`. This proves the piece that
        // doesn't need nginx: `most_recent_backup` + `restore_and_verify`
        // together restore the right bytes, using the same `Validator`
        // seam `transaction.rs`'s own tests use.
        let dir = tmp_dir("restore-wiring");
        let target = dir.join("nginx.conf");
        std::fs::write(&target, b"corrupted").unwrap();
        std::fs::write(
            dir.join("nginx.conf.certway-backup-2026-08-01T14-02-11Z"),
            b"known good",
        )
        .unwrap();

        struct AlwaysOk;
        impl Validator for AlwaysOk {
            fn validate(&self) -> ValidateOutcome {
                ValidateOutcome {
                    success: true,
                    stderr: String::new(),
                }
            }
        }

        let backup = most_recent_backup(&target).unwrap().unwrap();
        let result = transaction::restore_and_verify(&target, &backup, &AlwaysOk).unwrap();
        assert_eq!(result, RestoreOutcome::Restored);
        assert_eq!(std::fs::read(&target).unwrap(), b"known good");
    }
}
