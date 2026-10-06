// SPDX-License-Identifier: MIT

//! Post-issuance hook orchestration: wires `store::HookConfig` to
//! `certway_core::hook` and reports each
//! attempt through `Out`'s step machinery. `--hook`/`--reload` are local
//! commands (`execvp`, `--hook-shell` opts into `sh -c`); `--hook-url`
//! `POST`s a JSON body over the same `https://`-only `core::Client` the
//! rest of the program uses.

use crate::render::Out;
use crate::store::HookConfig;
use certway_core::json::{write_object, JsonVal};
use certway_core::{self as core, Client};
use std::io::Write;

/// The four public, non-secret facts a success hook/`--hook-url` body may
/// carry — never the certificate or the key. A hook script or URL is
/// often supplied by a config file or an argument that could leak into
/// logs, so the payload is scoped to what's safe to hand to it.
pub struct HookEnv<'a> {
    pub domains: &'a str,
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub not_after: &'a str,
}

fn env_pairs<'a>(env: &HookEnv<'a>) -> [(&'static str, &'a str); 4] {
    [
        ("CERTWAY_DOMAINS", env.domains),
        ("CERTWAY_CERT_PATH", env.cert_path),
        ("CERTWAY_KEY_PATH", env.key_path),
        ("CERTWAY_NOT_AFTER", env.not_after),
    ]
}

/// Runs the success path — `--hook`, then `--hook-url`, then `--reload` —
/// after a certificate has already been written to disk. Never fails the
/// caller: every failure becomes `step_warned`. The certificate is already
/// valid and on disk by this point, so a failing hook or reload command
/// must not roll it back or report the run as failed — the cert is real
/// regardless of what the hook does with it.
pub fn run_success(out: &mut Out<impl Write>, http: &Client, hooks: &HookConfig, env: &HookEnv) {
    if let Some(cmd) = &hooks.hook {
        report_local(out, "hook", cmd, hooks.hook_shell, env);
    }
    if let Some(url) = &hooks.hook_url {
        report_url_success(out, http, url, env);
    }
    if let Some(cmd) = &hooks.reload {
        report_local(out, "reload", cmd, hooks.hook_shell, env);
    }
}

fn report_local(
    out: &mut Out<impl Write>,
    label: &'static str,
    cmd: &str,
    use_shell: bool,
    env: &HookEnv,
) {
    match core::run_hook(cmd, use_shell, &env_pairs(env)) {
        Ok(()) => {
            let _ = out.step_done(label, cmd, std::time::Duration::ZERO);
        }
        Err(e) => {
            let _ = out.step_warned(label, &e.to_string());
        }
    }
}

fn success_body(env: &HookEnv) -> String {
    write_object(&[
        ("domains", JsonVal::Str(env.domains)),
        ("cert_path", JsonVal::Str(env.cert_path)),
        ("key_path", JsonVal::Str(env.key_path)),
        ("not_after", JsonVal::Str(env.not_after)),
    ])
}

fn report_url_success(out: &mut Out<impl Write>, http: &Client, url: &str, env: &HookEnv) {
    let body = success_body(env);
    match core::post_hook_url(http, url, &body) {
        Ok(()) => {
            let _ = out.step_done("hook", url, std::time::Duration::ZERO);
        }
        Err(e) => {
            let _ = out.step_warned("hook", &e.to_string());
        }
    }
}

/// `--hook-failure`/`--hook-url`'s failure path, called from
/// `cmd::issue::fail`/`cmd::renew`'s equivalent at every
/// stage. Best-effort and silent on its own failure — a notification hook
/// that itself fails must never mask or replace the real failure the
/// caller is already reporting (`cmd::issue::run_dns_cleanup` already
/// applies this same principle to DNS cleanup failures).
///
/// `http` is the run's own client — carrying whatever `--ca-bundle` was
/// given — used for `--hook-url` whenever one already exists at the call
/// site, so a hook sidecar reachable only via a custom CA is actually
/// reachable from the failure path too, not just the success path
/// (`run_success`'s `report_url_success` always had this; this one didn't).
/// `None` only at the handful of call sites that fail before any `Client`
/// exists yet — resolving `--out`, acquiring the data-directory lock, or
/// the client's own construction failing — where a fresh throwaway client
/// (embedded roots only) is the only one that could possibly exist.
pub fn run_failure(
    hooks: &HookConfig,
    http: Option<&Client>,
    domains: &str,
    stage: &str,
    error: &str,
) {
    if let Some(cmd) = &hooks.hook_failure {
        let env = [
            ("CERTWAY_DOMAINS", domains),
            ("CERTWAY_STAGE", stage),
            ("CERTWAY_ERROR", error),
        ];
        let _ = core::run_hook(cmd, hooks.hook_shell, &env);
    }
    if let Some(url) = &hooks.hook_url {
        let body = write_object(&[
            ("domains", JsonVal::Str(domains)),
            ("stage", JsonVal::Str(stage)),
            ("error", JsonVal::Str(error)),
        ]);
        match http {
            Some(client) => {
                let _ = core::post_hook_url(client, url, &body);
            }
            None => {
                if let Ok(client) = Client::new() {
                    let _ = core::post_hook_url(&client, url, &body);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `--hook-url` body must never contain the certificate or the
    /// private key — assert it on the exact bytes sent, not on the code
    /// path's intent.
    #[test]
    fn hook_url_success_body_never_carries_cert_or_key_material() {
        let env = HookEnv {
            domains: "example.com",
            cert_path: "/data/example.com/fullchain.pem",
            key_path: "/data/example.com/privkey.pem",
            not_after: "2026-11-01T00:00:00Z",
        };
        let body = success_body(&env);
        assert!(!body.contains("BEGIN CERTIFICATE"));
        assert!(!body.contains("BEGIN PRIVATE KEY"));
        assert!(!body.contains("BEGIN EC PRIVATE KEY"));
        // The *paths* to the files are fine to send — naming the domains
        // and the new file locations is the whole point of the hook — only
        // the file *contents* are forbidden.
        assert!(body.contains("fullchain.pem"));
        assert!(body.contains("privkey.pem"));
    }

    /// The same security property as `dns_provider::hook`'s own test, for
    /// the other hook path: a failing `--hook`/
    /// `--reload` command's rendered `step_warned` line must never contain
    /// the command it ran, since that command can carry a credential as an
    /// argument exactly like `--dns-hook` can.
    #[test]
    fn a_failing_post_issuance_hook_never_echoes_its_own_argv_including_a_secret() {
        let env = HookEnv {
            domains: "example.com",
            cert_path: "/a",
            key_path: "/b",
            not_after: "2026-11-01T00:00:00Z",
        };
        let hooks = HookConfig {
            hook: Some("/bin/false --token SECRET123".to_string()),
            ..HookConfig::default()
        };

        let mut buf = Vec::new();
        let caps = crate::caps::Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 100,
        };
        {
            let mut out = crate::render::Out::new(&mut buf, caps, crate::render::Mode::Human);
            let http = Client::new().expect("client construction with embedded root");
            run_success(&mut out, &http, &hooks, &env);
        }

        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            !rendered.contains("SECRET123"),
            "rendered output must never contain the hook's argv: {rendered:?}"
        );
        assert!(
            !rendered.contains("/bin/false"),
            "rendered output must never contain the hook's argv: {rendered:?}"
        );
    }

    #[test]
    fn hook_url_success_body_is_well_formed_json_with_the_four_fields() {
        let env = HookEnv {
            domains: "example.com",
            cert_path: "/a",
            key_path: "/b",
            not_after: "2026-11-01T00:00:00Z",
        };
        let body = success_body(&env);
        let parsed = core::Json::parse(body.as_bytes()).unwrap();
        assert_eq!(parsed.str("domains").unwrap(), "example.com");
        assert_eq!(parsed.str("cert_path").unwrap(), "/a");
        assert_eq!(parsed.str("key_path").unwrap(), "/b");
        assert_eq!(parsed.str("not_after").unwrap(), "2026-11-01T00:00:00Z");
    }
}
