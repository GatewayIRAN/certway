// SPDX-License-Identifier: MIT

//! cron fallback scheduling (`ref/debian-cron-3.0pl1-162.md`).

use super::*;

pub const MARKER: &str =
    "# certway renewal \u{2014} managed by `certway install`, do not edit this line";

/// The minute is derived from a hash of the hostname, not hardcoded —
/// same spreading reason as the systemd timer's `RandomizedDelaySec`:
/// every host firing at the identical fixed minute would hit the CA
/// (and cron itself) all at once instead of spread across the window.
pub fn minute(hostname: &str) -> u8 {
    (hash64(hostname, "cron-minute") % 60) as u8
}

pub fn job_line(hostname: &str) -> String {
    format!(
        "{} 3,15 * * * certway renew --all --quiet",
        minute(hostname)
    )
}

/// Idempotent merge: strips any previous certway-managed block — the
/// marker line plus the job line immediately after it, wherever it
/// appears — and appends a fresh one at the end. Every other line
/// (someone else's cron jobs, blank lines, `SHELL=`/`MAILTO=` settings)
/// survives untouched, since `crontab file` is a full replace with no
/// merge primitive of its own (`ref/debian-cron-3.0pl1-162.md`'s
/// `crontab -u user file` trap) — this function *is* the merge.
/// Pure: no `crontab` call, so re-running `install` twice is directly
/// testable without a real crontab.
pub fn merge(existing: &str, hostname: &str) -> String {
    let lines: Vec<&str> = existing.lines().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        if lines[i] == MARKER {
            i += 2; // drop the marker and the job line right after it
            continue;
        }
        kept.push(lines[i]);
        i += 1;
    }
    while kept.last() == Some(&"") {
        kept.pop();
    }

    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(MARKER);
    out.push('\n');
    out.push_str(&job_line(hostname));
    out.push('\n'); // crontab(1) DIAGNOSTICS: a missing trailing newline is rejected
    out
}

/// Reads the current crontab. A missing crontab (`crontab -l` exits
/// non-zero) is Vixie/Debian cron's ordinary "nothing installed yet"
/// state, not a failure (`ref/debian-cron-3.0pl1-162.md`) — treated as
/// empty here, not surfaced as an error.
fn read_crontab() -> Option<String> {
    let output = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

fn run_crontab_with_stdin(args: &[&str], content: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = std::process::Command::new("crontab")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run crontab: {e}"))?;
    // `child.stdin` is `Some` by construction (`.stdin(Stdio::piped())`
    // above, and `spawn()` already succeeded) — but this crate avoids
    // `unwrap`/`expect` outside tests, so this stays a real `Result`
    // path even though the `None` arm is unreachable in practice.
    let mut stdin = match child.stdin.take() {
        Some(s) => s,
        None => return Err("internal error: crontab's stdin was not piped".to_string()),
    };
    stdin
        .write_all(content.as_bytes())
        .map_err(|e| format!("could not write to crontab: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("crontab did not exit cleanly: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() {
            "crontab rejected the new crontab".to_string()
        } else {
            stderr
        })
    }
}

/// Merges in the certway block, dry-validates with `crontab -n -`
/// (`ref/debian-cron-3.0pl1-162.md`'s `-n`, a Debian patch), then
/// installs for real with `crontab -`. Both forms accept `-` for
/// stdin, so neither step touches a temp file.
pub fn install(hostname: &str) -> Result<(), String> {
    let existing = read_crontab().unwrap_or_default();
    let merged = merge(&existing, hostname);
    run_crontab_with_stdin(&["-n", "-"], &merged)?;
    run_crontab_with_stdin(&["-"], &merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minute_is_deterministic_and_in_range() {
        for host in ["a", "example.com", "my-host-123"] {
            let m = minute(host);
            assert!(m < 60);
            assert_eq!(m, minute(host));
        }
    }

    #[test]
    fn job_line_runs_renew_all_quiet_at_3_and_15() {
        let line = job_line("myhost");
        assert!(line.ends_with(" 3,15 * * * certway renew --all --quiet"));
    }

    #[test]
    fn merge_on_empty_crontab_appends_marker_and_job() {
        let merged = merge("", "myhost");
        assert_eq!(merged, format!("{MARKER}\n{}\n", job_line("myhost")));
        assert!(
            merged.ends_with('\n'),
            "crontab(1) rejects a file with no trailing newline"
        );
    }

    #[test]
    fn merge_preserves_unrelated_existing_lines() {
        let existing = "SHELL=/bin/sh\n0 4 * * * /usr/local/bin/backup.sh\n";
        let merged = merge(existing, "myhost");
        assert!(merged.starts_with("SHELL=/bin/sh\n0 4 * * * /usr/local/bin/backup.sh\n"));
        assert!(merged.contains(MARKER));
        assert!(merged.contains(&job_line("myhost")));
    }

    #[test]
    fn merge_is_idempotent_running_twice_leaves_one_entry() {
        let once = merge("", "myhost");
        let twice = merge(&once, "myhost");
        assert_eq!(once, twice);
        assert_eq!(twice.matches(MARKER).count(), 1);
    }

    #[test]
    fn merge_replaces_a_stale_block_in_place_of_removing_everything_after_it() {
        // A previous certway block sitting in the *middle* of the
        // crontab (not just the end) must still be replaced, not
        // duplicated, and lines after it must survive.
        let existing = format!("SHELL=/bin/sh\n{MARKER}\n7 3,15 * * * certway renew --all --quiet\n0 4 * * * /usr/local/bin/backup.sh\n");
        let merged = merge(&existing, "myhost");
        assert_eq!(merged.matches(MARKER).count(), 1);
        assert!(merged.contains("0 4 * * * /usr/local/bin/backup.sh"));
        assert!(
            !merged.contains("7 3,15 * * * certway renew"),
            "the stale job line must be gone, not just the marker"
        );
    }

    #[test]
    fn merge_never_puts_a_comment_on_the_same_line_as_the_job() {
        // ref/debian-cron-3.0pl1-162.md: a same-line comment becomes
        // part of the command, silently. Structural proof the marker
        // and the job are always two separate lines.
        let merged = merge("", "myhost");
        for line in merged.lines() {
            if line == MARKER {
                continue;
            }
            assert!(
                !line.contains('#'),
                "job line must not carry a trailing comment: {line:?}"
            );
        }
    }
}
