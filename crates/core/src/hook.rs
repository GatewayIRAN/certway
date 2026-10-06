//! Post-issuance hooks: `--hook`, `--hook-failure`, `--reload`. Same
//! execvp/shell shape as `dns_provider::hook`, deliberately not shared
//! with it — that module's `run_hook` is private to the `DnsTxtProvider`
//! trait and its errors (`Error::DnsHookFailed`) are propagated as hard
//! failures, while a post-issuance hook's non-zero exit is only ever a
//! warning: the certificate is never rolled back for it. Reusing the DNS
//! module's error variants here would make that warning indistinguishable
//! from a DNS hook's hard failure at the call site.

use crate::error::Error;
use crate::http::{Client, Method};
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HOOK_TIMEOUT_SECS: u64 = 120;
const POLL_INTERVAL_MS: u64 = 25;

/// Splits `cmd` into argv. `execvp`, no shell, when `use_shell` is false —
/// none exists in a scratch container. `use_shell` (`--hook-shell`) wraps
/// the whole string through `sh -c` instead.
pub fn to_argv(cmd: &str, use_shell: bool) -> Vec<String> {
    if use_shell {
        vec!["sh".to_string(), "-c".to_string(), cmd.to_string()]
    } else {
        cmd.split_whitespace().map(str::to_string).collect()
    }
}

/// Runs one hook command to completion, `env` set in addition to whatever
/// the process already inherits. Returns `Err(Error::HookFailed{..})` on a
/// non-zero exit or `Error::HookTimeout{..}` past `HOOK_TIMEOUT_SECS` — the
/// caller decides what that means (a post-issuance hook renders it as a
/// warning; nothing here treats it as fatal on its own).
pub fn run_local(cmd: &str, use_shell: bool, env: &[(&str, &str)]) -> Result<(), Error> {
    let argv = to_argv(cmd, use_shell);
    let Some((program, args)) = argv.split_first() else {
        return Err(Error::HookFailed {
            stderr: "empty hook command".to_string(),
        });
    };

    let mut proc = Command::new(program);
    proc.args(args);
    for (k, v) in env {
        proc.env(k, v);
    }
    // Never receives the account key or the private key — the caller
    // builds `env` from public metadata only (domains, paths, notAfter).
    proc.stdin(Stdio::null());
    proc.stdout(Stdio::null());
    proc.stderr(Stdio::piped());

    // `program`/`args` are used only to spawn — never captured into the
    // returned `Error` (`Error::HookFailed`'s own doc comment: `--hook`/
    // `--hook-failure`/`--reload` can carry a credential as an argument
    // just as easily as `--dns-hook` can).
    let child = proc.spawn().map_err(|e| Error::HookFailed {
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
                return Err(Error::HookFailed { stderr });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::HookTimeout {
                        secs: timeout.as_secs(),
                    });
                }
                std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
            Err(e) => {
                return Err(Error::HookFailed {
                    stderr: e.to_string(),
                })
            }
        }
    }
}

/// `--hook-url`: `POST`s `body` (already-serialized JSON, built by the
/// caller via `json::write_object` — never `format!`, since a value
/// containing a quote would produce a malformed request body) to `url`.
/// The body must never carry the certificate or the private key —
/// enforced by the caller building `body`, not by this function, which
/// only transports whatever it's given. `url` must be `https://`:
/// `Client::request` itself refuses anything else (`http.rs`'s
/// `HttpMalformed { detail: "url must use https" }`), e.g.
/// `https://nginx-sidecar/reload`.
pub fn post_hook_url(client: &Client, url: &str, body: &str) -> Result<(), Error> {
    let response = client.request(
        Method::Post,
        url,
        Some("application/json"),
        Some(body.as_bytes()),
    )?;
    if !(200..300).contains(&response.status) {
        return Err(Error::http_status(response.status, &response.body));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_argv_splits_on_whitespace_without_a_shell() {
        assert_eq!(
            to_argv("/usr/bin/reload --fast", false),
            vec!["/usr/bin/reload", "--fast"]
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
    fn successful_hook_receives_every_env_var_via_a_probe_script() {
        let out_path =
            std::env::temp_dir().join(format!("certway-posthook-probe-{}.txt", std::process::id()));
        let script = format!(
            "printf '%s|%s|%s|%s' \"$CERTWAY_DOMAINS\" \"$CERTWAY_CERT_PATH\" \"$CERTWAY_KEY_PATH\" \"$CERTWAY_NOT_AFTER\" > {}",
            out_path.display()
        );
        run_local(
            &script,
            true,
            &[
                ("CERTWAY_DOMAINS", "example.com"),
                ("CERTWAY_CERT_PATH", "/data/example.com/fullchain.pem"),
                ("CERTWAY_KEY_PATH", "/data/example.com/privkey.pem"),
                ("CERTWAY_NOT_AFTER", "2026-11-01T00:00:00Z"),
            ],
        )
        .unwrap();

        let contents = std::fs::read_to_string(&out_path).unwrap();
        let _ = std::fs::remove_file(&out_path);
        assert_eq!(
            contents,
            "example.com|/data/example.com/fullchain.pem|/data/example.com/privkey.pem|2026-11-01T00:00:00Z"
        );
    }

    #[test]
    fn nonzero_exit_reports_captured_stderr_as_a_warning_not_a_hard_error_type() {
        let err = run_local("sh -c 'echo boom >&2; exit 3'", true, &[]).unwrap_err();
        match err {
            Error::HookFailed { stderr, .. } => assert!(stderr.contains("boom")),
            other => panic!("expected HookFailed, got {other:?}"),
        }
    }

    #[test]
    fn nonexistent_command_without_shell_fails_clearly() {
        assert!(run_local("/no/such/certway-hook-binary", false, &[]).is_err());
    }

    #[test]
    fn empty_command_is_a_clean_error_not_a_panic() {
        assert!(run_local("", false, &[]).is_err());
    }

    #[test]
    fn post_hook_url_rejects_plain_http() {
        let client = Client::new().unwrap();
        let err = post_hook_url(&client, "http://example.com/reload", "{}").unwrap_err();
        assert!(matches!(err, Error::HttpMalformed { .. }));
    }
}
