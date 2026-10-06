//! The external DNS hook: removes the single-provider limitation by
//! shelling out to a user-supplied command instead of talking to one
//! specific API.

use super::{DnsTxtProvider, TxtRecord};
use crate::error::Error;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HOOK_TIMEOUT_SECS: u64 = 120;
const POLL_INTERVAL_MS: u64 = 25;

pub struct HookProvider {
    create_argv: Vec<String>,
    cleanup_argv: Vec<String>,
}

impl HookProvider {
    /// `create_cmd`/`cleanup_cmd` are the raw `--dns-hook`/`--dns-cleanup`
    /// strings. Split on whitespace when `use_shell` is false (`execvp`,
    /// no shell — none exists in a scratch container); passed whole to
    /// `sh -c` when `use_shell` is true (`--hook-shell`, explicit opt-in).
    /// `use_shell` only shapes argv at construction — nothing downstream
    /// needs to know which mode built it.
    pub fn new(create_cmd: &str, cleanup_cmd: &str, use_shell: bool) -> HookProvider {
        HookProvider {
            create_argv: to_argv(create_cmd, use_shell),
            cleanup_argv: to_argv(cleanup_cmd, use_shell),
        }
    }
}

fn to_argv(cmd: &str, use_shell: bool) -> Vec<String> {
    if use_shell {
        vec!["sh".to_string(), "-c".to_string(), cmd.to_string()]
    } else {
        cmd.split_whitespace().map(str::to_string).collect()
    }
}

impl DnsTxtProvider for HookProvider {
    /// Stops at the first failing invocation: a partially-created set of
    /// records is itself a `prepare` failure. Cleanup (`remove`) is what
    /// handles the partial state afterward — not a reason for `create`
    /// itself to press on past an error.
    fn create(&mut self, records: &[TxtRecord]) -> Result<(), Error> {
        for env in per_record_env(records) {
            run_hook(&self.create_argv, &env)?;
        }
        Ok(())
    }

    /// Never stops at the first failure: every record gets its own
    /// removal attempt regardless of whether an earlier one failed, and
    /// the first failure (if any) is what's returned once all of them
    /// have been tried.
    fn remove(&mut self, records: &[TxtRecord]) -> Result<(), Error> {
        let mut first_err = None;
        for env in per_record_env(records) {
            if let Err(e) = run_hook(&self.cleanup_argv, &env) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// One environment-variable set per record — hooks are otherwise called
/// once per record — each carrying `CERTWAY_ALL_VALUES` so a hook whose
/// own provider supports it can set every value for that name in a single
/// call regardless of which invocation it is.
fn per_record_env(records: &[TxtRecord]) -> Vec<[(String, String); 4]> {
    records
        .iter()
        .map(|record| {
            let all_values: Vec<&str> = records
                .iter()
                .filter(|r| r.name == record.name)
                .map(|r| r.value.as_str())
                .collect();
            [
                ("CERTWAY_DOMAIN".to_string(), record.domain.clone()),
                ("CERTWAY_RECORD_NAME".to_string(), record.name.clone()),
                ("CERTWAY_RECORD_VALUE".to_string(), record.value.clone()),
                ("CERTWAY_ALL_VALUES".to_string(), all_values.join("\n")),
            ]
        })
        .collect()
}

fn run_hook(argv: &[String], env: &[(String, String)]) -> Result<(), Error> {
    let Some((program, args)) = argv.split_first() else {
        return Err(Error::DnsHookFailed {
            stderr: "empty hook command".to_string(),
        });
    };

    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    // Never receives the account key or any certificate — inherited
    // environment already carries neither, and this module never adds
    // them. stdin closed: a hook is never meant to read anything from
    // certway.
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    // `program`/`args` (the argv `--dns-hook`/`--dns-cleanup` were parsed
    // into) are used only to spawn the process — never captured into the
    // returned `Error` (`Error::DnsHookFailed`'s own doc comment: a
    // `--dns-hook` command line routinely carries a credential as an
    // argument, and this error is what the CLI's `report::classify`
    // eventually renders to the user).
    let child = cmd.spawn().map_err(|e| Error::DnsHookFailed {
        stderr: e.to_string(),
    })?;

    wait_with_timeout(child, Duration::from_secs(HOOK_TIMEOUT_SECS))
}

fn wait_with_timeout(mut child: Child, timeout: Duration) -> Result<(), Error> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let mut stderr = String::new();
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_string(&mut stderr);
                }
                return Err(Error::DnsHookFailed { stderr });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::DnsHookTimeout {
                        secs: timeout.as_secs(),
                    });
                }
                std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
            Err(e) => {
                return Err(Error::DnsHookFailed {
                    stderr: e.to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(domain: &str, value: &str) -> TxtRecord {
        TxtRecord {
            domain: domain.to_string(),
            name: format!("_acme-challenge.{domain}"),
            value: value.to_string(),
        }
    }

    #[test]
    fn to_argv_splits_on_whitespace_without_a_shell() {
        assert_eq!(
            to_argv("/usr/bin/my-hook create --fast", false),
            vec!["/usr/bin/my-hook", "create", "--fast"]
        );
    }

    #[test]
    fn to_argv_with_shell_wraps_the_whole_string() {
        assert_eq!(
            to_argv("echo hi && echo bye", true),
            vec!["sh", "-c", "echo hi && echo bye"]
        );
    }

    #[test]
    fn successful_hook_receives_expected_env_vars_via_a_probe_script() {
        // The probe script writes the env vars it sees to a file; this test
        // reads it back rather than capturing stdout (which the hook
        // runner deliberately discards).
        let out_path =
            std::env::temp_dir().join(format!("certway-hook-probe-{}.txt", std::process::id()));
        let script = format!(
            "printf '%s|%s|%s|%s' \"$CERTWAY_DOMAIN\" \"$CERTWAY_RECORD_NAME\" \"$CERTWAY_RECORD_VALUE\" \"$CERTWAY_ALL_VALUES\" > {}",
            out_path.display()
        );
        let mut provider = HookProvider::new(&script, "true", true);
        let records = vec![
            record("example.com", "valueA"),
            record("example.com", "valueB"),
        ];
        provider.create(&records).unwrap();

        let contents = std::fs::read_to_string(&out_path).unwrap();
        let _ = std::fs::remove_file(&out_path);
        // The *last* invocation (record for valueB) is what's on disk,
        // since both invocations write the same file.
        assert_eq!(
            contents,
            "example.com|_acme-challenge.example.com|valueB|valueA\nvalueB"
        );
    }

    #[test]
    fn nonzero_exit_reports_captured_stderr() {
        // --hook-shell (sh -c) so the compound "write to stderr, then
        // fail" script is parsed as one shell command, not execvp'd
        // literally as an argv split on whitespace.
        let mut provider = HookProvider::new("sh -c 'echo boom >&2; exit 3'", "true", true);
        let records = vec![record("example.com", "v")];
        let err = provider.create(&records).unwrap_err();
        match err {
            Error::DnsHookFailed { stderr, .. } => assert!(
                stderr.contains("boom"),
                "expected stderr to contain boom, got {stderr:?}"
            ),
            other => panic!("expected DnsHookFailed, got {other:?}"),
        }
    }

    /// A `--dns-hook` command line routinely carries a credential as an
    /// argument, and the natural way to report a failing hook — print the
    /// command that failed — is exactly what must not happen. Grep the
    /// entire rendered output (`Display` *and* `Debug`, since a stray
    /// `{err:?}` is just as real a leak as `{err}`) for the planted secret.
    #[test]
    fn a_failing_hook_never_echoes_its_own_argv_including_a_secret() {
        let mut provider = HookProvider::new("/bin/false --token SECRET123", "true", false);
        let records = vec![record("example.com", "v")];
        let err = provider.create(&records).unwrap_err();

        let displayed = err.to_string();
        let debugged = format!("{err:?}");
        assert!(
            !displayed.contains("SECRET123"),
            "rendered error must never contain the hook's argv: {displayed:?}"
        );
        assert!(
            !displayed.contains("/bin/false"),
            "rendered error must never contain the hook's argv: {displayed:?}"
        );
        assert!(
            !debugged.contains("SECRET123"),
            "debug output must never contain the hook's argv either: {debugged:?}"
        );
    }

    #[test]
    fn nonexistent_command_without_shell_fails_clearly() {
        let mut provider = HookProvider::new("/no/such/certway-hook-binary", "true", false);
        let records = vec![record("example.com", "v")];
        assert!(provider.create(&records).is_err());
    }

    #[test]
    fn empty_command_is_a_clean_error_not_a_panic() {
        let mut provider = HookProvider::new("", "true", false);
        let records = vec![record("example.com", "v")];
        assert!(provider.create(&records).is_err());
    }

    /// The bug this module's `remove` exists to not have: a cleanup
    /// command that fails for the *first* record must still be invoked
    /// for the second, third record instead of stopping — every one
    /// of these three markers must exist afterward, not just the first.
    #[test]
    fn remove_attempts_every_record_even_after_an_earlier_one_fails() {
        let dir =
            std::env::temp_dir().join(format!("certway-hook-remove-all-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Fails on odd invocations (touching a marker only on the even
        // ones would hide a stop-after-first-failure bug just as well,
        // but failing unconditionally on record "a" and succeeding while
        // marking on "b" and "c" is the more direct proof this test wants:
        // record "a" always errors, "b" and "c" must still run regardless.
        let cleanup_script = format!(
            "if [ \"$CERTWAY_RECORD_VALUE\" = \"a\" ]; then exit 1; fi; touch {}/\"$CERTWAY_RECORD_VALUE\"",
            dir.display()
        );
        let mut provider = HookProvider::new("true", &cleanup_script, true);
        let records = vec![
            record("example.com", "a"),
            record("example.com", "b"),
            record("example.com", "c"),
        ];

        let result = provider.remove(&records);
        assert!(
            result.is_err(),
            "the first record's failure must still surface"
        );
        assert!(
            dir.join("b").exists(),
            "record b's cleanup must still have run"
        );
        assert!(
            dir.join("c").exists(),
            "record c's cleanup must still have run"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_runs_the_separate_cleanup_command() {
        let out_path = std::env::temp_dir().join(format!(
            "certway-hook-cleanup-probe-{}.txt",
            std::process::id()
        ));
        let cleanup_script = format!("echo cleaned > {}", out_path.display());
        let mut provider = HookProvider::new("true", &cleanup_script, true);
        let records = vec![record("example.com", "v")];
        provider.remove(&records).unwrap();
        let contents = std::fs::read_to_string(&out_path).unwrap();
        let _ = std::fs::remove_file(&out_path);
        assert_eq!(contents.trim(), "cleaned");
    }
}
