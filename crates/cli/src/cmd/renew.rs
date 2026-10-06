// SPDX-License-Identifier: MIT

//! The `renew` command.
//!
//! `preflight`/`rehearsal`/`--watch`/web-server reload (tier-1 config
//! *editing*) are not implemented by this build — this build's renewal
//! sequence, once a certificate is decided due, is identical to `issue`
//! from the `order` step onward: `cmd::issue`'s `run_challenges` (dns-01 or
//! http-01, shared with `issue` so the two can never provision a wildcard
//! differently) and `fail` are reused directly rather than duplicated.
//! Links and hooks are implemented: recorded links/hooks from
//! `config.json` re-apply unconditionally; `--link`/`--hook`/etc. given on
//! this invocation replace the recorded set for this and every future
//! renewal. `--dns`/`--dns-hook`/`--dns-cleanup` follow the same rule
//! (`effective_challenge_config`'s doc comment).

use crate::args::RenewArgs;
use crate::cmd::issue::{
    challenge_record, dns01_fail, fail, links_from_args, run_challenges, ChallengeFailure,
};
use crate::hooks::{self, HookEnv};
use crate::render::{Mode, Out};
use crate::report::{self, Stage};
use crate::steps::run_with_spinner;
use crate::store::{self, CertConfig, HookConfig, LinkSpec};
use certway_core::ari::skew_seconds;
use certway_core::{
    self as core, build_csr, download_certificate, ensure_account, finalize, new_order, CertId,
    CertKey, Client, CloudflareProvider, Directory, DnsTxtProvider, HookProvider, Identifier,
    Order, ParsedCert, RenewalWindow, Resolver, Session,
};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Matches `cmd::issue`'s own staging-by-default safety rail for this
/// build (see that module's doc comment) — used only as a last-resort
/// fallback when a certificate's `config.json` carries no `ca_directory`
/// at all (e.g. hand-copied from somewhere, or written before that field
/// existed).
const STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const THIRTY_DAYS_SECS: i64 = 30 * 86_400;
/// A clock skew over 5 minutes is a warning.
const CLOCK_SKEW_WARNING_SECS: i64 = 5 * 60;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `certway renew --help`, matching every flag `args::RENEW_FLAGS`
/// actually accepts — see `cmd::issue::ISSUE_HELP`'s doc comment for the
/// shape and sourcing rule this and every other command's help follows.
const RENEW_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway renew <name> | --all [flags]",
    examples: &["certway renew example.com", "certway renew --all --watch"],
    groups: &[
        crate::cmd::command_help::FlagGroup {
            heading: "Renewal",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--all",
                    about: "Every certificate",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--force",
                    about: "Ignore \"already valid\" and \"not due\"",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--reuse-key",
                    about: "Keep the existing key across renewals",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--watch",
                    about: "Stay running and renew on a schedule",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Challenge selection",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--dns <provider>",
                    about: "DNS-01. cloudflare is the only built-in provider",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--dns-hook <cmd>",
                    about: "DNS-01 via an external command. Any provider",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--dns-cleanup <cmd>",
                    about: "Paired removal command for --dns-hook",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--http-01-port <n>",
                    about: "Bind a port other than 80, for reverse-proxy setups",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Output placement",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--out <dir>",
                    about: "Override the data directory",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--link-to <dir>",
                    about: "Link all files into another directory",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--link <name>=<path>",
                    about: "Link one file to an exact path",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--link-force",
                    about: "Replace a link target certway does not own",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--copy",
                    about: "Copy instead of linking",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "After renewal",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--reload <cmd>",
                    about: "Shorthand for the most common deploy hook",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--hook <cmd>",
                    about: "Run after a successful renewal",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--hook-failure <cmd>",
                    about: "Run on failure",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--hook-url <url>",
                    about: "POST on success and on failure",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--hook-shell",
                    about: "Run hooks through sh -c",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "CA",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--server <url>",
                    about: "An ACME directory other than Let's Encrypt",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--ca-bundle <path>",
                    about: "Trust these roots instead of the embedded ones",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--relax-permissions",
                    about: "Downgrade unsafe account key permissions to a warning",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Output",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--explain",
                    about: "Report which renewal path each certificate took",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--json",
                    about: "Machine-readable output",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--quiet",
                    about: "Silence on success",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--verbose",
                    about: "Show raw protocol errors",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--no-color",
                    about: "Disable colour",
                },
            ],
        },
    ],
};

pub fn run(args: RenewArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &RENEW_HELP);
        return 0;
    }

    if args.watch {
        return run_watch(&args, out);
    }

    run_once(&args, out)
}

/// `renew --all --watch`: one pass now, then one pass per wake, forever,
/// until a shutdown request is observed — never carrying state across
/// wakes (`run_once` re-resolves and re-reads everything from disk every
/// time, identical to a plain invocation).
///
/// What this does *not* implement: printing one muted line per wake and
/// reserving full step output for when work actually happens — every wake
/// prints the same full output a normal `renew --all` would, whether or
/// not anything was due.
fn run_watch(args: &RenewArgs, out: &mut Out<impl Write>) -> i32 {
    let hostname = crate::scheduler::hostname();
    let interval = crate::scheduler::watch::wake_interval(&hostname);
    run_watch_with(args, out, interval, &crate::signal::SHUTDOWN)
}

/// `run_watch`, with the interval and shutdown flag injected — the seam
/// that makes the wiring testable without a real 12h wait or touching the
/// process-global `crate::signal::SHUTDOWN`.
fn run_watch_with(
    args: &RenewArgs,
    out: &mut Out<impl Write>,
    interval: std::time::Duration,
    shutdown: &std::sync::atomic::AtomicBool,
) -> i32 {
    let mut last_exit = 0i32;
    crate::scheduler::watch::run(interval, shutdown, || {
        last_exit = run_once(args, out);
    });
    last_exit
}

fn run_once(args: &RenewArgs, out: &mut Out<impl Write>) -> i32 {
    // Built once per invocation, same as `cmd::issue::run` — every
    // certificate in a `--all` run shares the flags given on this one
    // command line. Empty `hooks`/`links` (the common case: nothing given
    // on this renewal) signal "keep whatever was recorded" to `renew_one`
    // below, not "clear it."
    let hooks = HookConfig {
        hook: args.hook.clone(),
        hook_failure: args.hook_failure.clone(),
        hook_url: args.hook_url.clone(),
        reload: args.reload.clone(),
        hook_shell: args.hook_shell,
    };
    let links = links_from_args(&args.link_to, &args.links, args.copy);

    // Resolved before the header, not after — the header needs it too.
    let data_root_result = store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out");

    // Found live to matter, not a hypothetical: renewing a production
    // certificate with no `--server` showed "(staging)" in the header
    // even though the certificate itself, and this renewal, were both
    // production — `config.json`'s whole point is "recorded so it need
    // not be repeated" (`store::cert::CertConfig`'s own doc comment), so
    // this was the *default* case for anyone who ever renews without
    // re-typing `--server`, not a rare one. An explicit `--server` still
    // wins outright (this run's real override). Otherwise, for a single
    // named certificate, its own recorded `ca_directory` is now read and
    // used. `--all`'s multi-certificate case still can't be labelled
    // perfectly this way — different certificates may genuinely record
    // different CAs — and keeps the `STAGING_URL` fallback, honest in the
    // sense that it never asserts "Let's Encrypt" for a URL that isn't.
    let header_url = args.server.clone().unwrap_or_else(|| {
        data_root_result
            .as_ref()
            .ok()
            .and_then(|root| recorded_ca_directory_for_single_target(root, args))
            .unwrap_or_else(|| STAGING_URL.to_string())
    });
    let _ = out.header(env!("CARGO_PKG_VERSION"), Some(&header_url));

    let data_root = match data_root_result {
        Ok(p) => p,
        // No `Client` exists yet at this level — one is built per
        // certificate inside `renew_one`, not once here.
        Err(e) => return fail(out, Stage::Account, &e, &[], &hooks, None),
    };
    // A data directory that doesn't exist yet is "nothing to renew," not a
    // failure — zero due certificates is a normal no-op day (cron must not
    // alarm on it), and a freshly `install`ed machine's very first timer
    // firing, before anything has ever been issued, is exactly this case.
    // Same bug, same fix, as `cmd::list` (`store::is_missing_data_dir`'s
    // own doc comment). Neither creates the directory here:
    // `resolve_targets` below already
    // tolerates a missing one for `--all` (empty result), and for a named
    // certificate it correctly reports "not found" either way.
    let _lock = match store::acquire_exclusive(&data_root) {
        Ok(l) => Some(l),
        Err(e) if store::is_missing_data_dir(&e) => None,
        Err(e) => return fail(out, Stage::Account, &e, &[], &hooks, None),
    };

    let targets = match resolve_targets(&data_root, args) {
        Ok(t) => t,
        Err(e) => return fail(out, Stage::Account, &e, &[], &hooks, None),
    };

    let mut directories: HashMap<String, (Client, Directory)> = HashMap::new();
    let mut skew_checked = false;
    let now = now_unix();

    let mut renewed = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut worst_exit = 0i32;

    for (i, cert_root) in targets.iter().enumerate() {
        // The shutdown check point between certificates in `--all`. No real
        // signal can set this yet (`crate::signal`'s doc comment), so this
        // is unreachable in practice today — it stops the *next*
        // certificate from starting, tested directly in `crate::signal`'s
        // own tests.
        if crate::signal::requested() {
            break;
        }
        if i > 0 {
            let _ = out.raw_line("");
            // Renewals spaced 1s apart — politeness to the CA, invisible to
            // the user.
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        let name = cert_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();

        match renew_one(
            out,
            args,
            &data_root,
            cert_root,
            &name,
            now,
            &mut directories,
            &mut skew_checked,
            &links,
            &hooks,
        ) {
            CertOutcome::Renewed => renewed += 1,
            CertOutcome::NotDue => skipped += 1,
            CertOutcome::Failed(code) => {
                failed += 1;
                worst_exit = worst_exit.max(code);
            }
        }
    }

    if targets.len() > 1 || args.all {
        let _ = out.raw_line("");
        let _ = out.raw_line(&format!(
            "  {renewed} renewed, {skipped} skipped (not due), {failed} failed"
        ));
    }

    // Exit 0 when nothing was due — cron must not email on a normal no-op
    // day. Only an actual failure raises the exit code above 0.
    if failed > 0 {
        worst_exit
    } else {
        0
    }
}

enum CertOutcome {
    Renewed,
    NotDue,
    Failed(i32),
}

/// The header-only peek behind `run_once`'s CA-label fix: a single named
/// target's own recorded `ca_directory`, read before the exclusive lock
/// and before `resolve_targets`'s own (authoritative) resolution runs.
/// Read-only and silently `None` on absolutely anything — `--all`, no
/// name, the certificate not found yet, a missing or unparseable
/// `config.json` — because this is only ever used to choose a header
/// label; the real resolution and its real errors happen exactly as
/// before, right after.
fn recorded_ca_directory_for_single_target(data_root: &Path, args: &RenewArgs) -> Option<String> {
    if args.all {
        return None;
    }
    let name = args.name.as_deref()?;
    let direct = data_root.join(name);
    let cert_root = if direct.join("fullchain.pem").exists() {
        direct
    } else {
        let sanitized = data_root.join(store::cert_dir_name(name));
        if sanitized.join("fullchain.pem").exists() {
            sanitized
        } else {
            return None;
        }
    };
    let config = store::read_config(&store::cert_paths(&cert_root).config)?;
    Some(config.ca_directory)
}

/// `--all` -> every directory under `<data>` that looks like a certificate
/// (has a `fullchain.pem`), skipping `account` and any dotfile. A single
/// name -> that one directory, tried both as given and sanitized the same
/// way `cert_dir_name` sanitizes a wildcard on write, so `renew
/// "*.example.com"` and `renew _.example.com` both resolve.
fn resolve_targets(data_root: &Path, args: &RenewArgs) -> Result<Vec<PathBuf>, core::Error> {
    if args.all {
        let mut dirs = Vec::new();
        let entries = match std::fs::read_dir(data_root) {
            Ok(e) => e,
            Err(_) => return Ok(dirs), // no data directory yet -> nothing to renew
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "account" || name.starts_with('.') {
                continue;
            }
            if path.join("fullchain.pem").exists() {
                dirs.push(path);
            }
        }
        dirs.sort();
        return Ok(dirs);
    }

    let name = args.name.as_deref().unwrap_or_default();
    let direct = data_root.join(name);
    if direct.join("fullchain.pem").exists() {
        return Ok(vec![direct]);
    }
    let sanitized = data_root.join(store::cert_dir_name(name));
    if sanitized.join("fullchain.pem").exists() {
        return Ok(vec![sanitized]);
    }
    Err(core::Error::io(
        &direct,
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no certificate named {name:?} found under {}",
                data_root.display()
            ),
        ),
    ))
}

/// Which path the renewal decision took — for `--explain` and for
/// `list`'s RENEW column.
pub(crate) enum RenewPath {
    Forced,
    Expired,
    Ari(RenewalWindow),
    Fallback,
    NotDue { window: Option<RenewalWindow> },
}

#[allow(clippy::too_many_arguments)]
fn renew_one(
    out: &mut Out<impl Write>,
    args: &RenewArgs,
    data_root: &Path,
    cert_root: &Path,
    name: &str,
    now: i64,
    directories: &mut HashMap<String, (Client, Directory)>,
    skew_checked: &mut bool,
    links: &[LinkSpec],
    hooks: &HookConfig,
) -> CertOutcome {
    // `config.json` is read — and the hook set merged — before anything
    // that can itself fail: a certificate whose `fullchain.pem` is
    // corrupt/unreadable still has a `--hook-failure` recorded from
    // issuance, and that hook must fire even though this run never
    // received `--hook-failure` on its own command line. Reading it
    // this early is safe — `read_config` is pure/local and already
    // tolerant of a missing or corrupt file (its own doc comment), so it
    // cannot itself introduce a new failure mode here.
    // Checked *before* `read_config` (which tightens unconditionally as
    // part of every read — its own doc comment) purely so this can report
    // whether anything actually needed tightening; the tighten itself is
    // never gated on `--verbose` or on this check running at all.
    let config_path = cert_root.join("config.json");
    let config_needed_tightening = store::tighten_permissions(&config_path);
    let config = store::read_config(&config_path);
    if config_needed_tightening && args.verbose && out.mode == Mode::Human {
        let _ = out.raw_line(&format!(
            "  · config.json permissions were loosened, tightened to 0600: {}",
            config_path.display()
        ));
    }

    // `store::cert::CertConfig`'s doc comment: links/hooks given on *this*
    // renewal replace the recorded set (for this and every future renewal,
    // since they're re-recorded below); given none, the previously
    // recorded set re-applies unchanged. This is what makes
    // `--link-to`/`--reload` given once at `issue` time keep working
    // across every renewal without repeating the flag.
    let hooks: HookConfig = if hooks.is_empty() {
        config.as_ref().map(|c| c.hooks.clone()).unwrap_or_default()
    } else {
        hooks.clone()
    };

    let fullchain_path = cert_root.join("fullchain.pem");
    let pem = match std::fs::read_to_string(&fullchain_path) {
        Ok(p) => p,
        // No `Client` exists yet — it's built further down, once the
        // certificate's own CA directory is known.
        Err(e) => {
            let code = fail(
                out,
                Stage::Account,
                &core::Error::io(&fullchain_path, e),
                &[name.to_string()],
                &hooks,
                None,
            );
            return CertOutcome::Failed(code);
        }
    };

    // A certificate that does not parse is reported and skipped, not a
    // reason to stop `renew --all`.
    let parsed = match ParsedCert::from_leaf_pem(&pem) {
        Ok(p) => p,
        Err(e) => {
            let code = fail(out, Stage::Account, &e, &[name.to_string()], &hooks, None);
            return CertOutcome::Failed(code);
        }
    };

    // Which challenge actually drives this renewal — a `--dns`/`--dns-hook`
    // flag on this invocation, else whatever was recorded at issuance.
    // Resolved before any `Client`/CA contact so both guards below stay
    // genuinely local, never needing a request to the CA to fail fast.
    let challenge_config = effective_challenge_config(args, config.as_ref());

    if let Some(identifier) = wildcard_identifier(&parsed.sans) {
        if !challenge_config.use_dns() {
            let example_command = format!("certway renew {name} --dns cloudflare");
            let code = preflight_fail(out, identifier, example_command, name, &hooks);
            return CertOutcome::Failed(code);
        }
    }
    // A `"hook"` provider needs the actual `--dns-hook`/`--dns-cleanup`
    // command to run, and `config.json` only carries one when DNS-hook
    // commands were persisted at issuance (`store::cert::CertConfig::dns_hook`'s
    // doc comment) — a certificate issued before that was added, or a
    // `config.json` edited by hand, can record the marker with nothing to
    // run it. Caught here rather than failing confusingly (or worse,
    // silently attempting http-01) once `run_challenges` is reached.
    if challenge_config.use_dns()
        && challenge_config.dns_provider.as_deref() == Some("hook")
        && challenge_config.dns_hook.is_none()
    {
        let detail = format!("{name} renews via a dns hook, but no --dns-hook/--dns-cleanup were given on this run and none are recorded in config.json");
        let code = fail(
            out,
            Stage::Account,
            &core::Error::DnsProviderConfig { detail },
            &[name.to_string()],
            &hooks,
            None,
        );
        return CertOutcome::Failed(code);
    }

    let effective_links: Vec<LinkSpec> = if links.is_empty() {
        config.as_ref().map(|c| c.links.clone()).unwrap_or_default()
    } else {
        links.to_vec()
    };

    let ca_directory = effective_ca_directory(args, config.as_ref());
    let ca_host = store::host_from_url(&ca_directory).to_string();
    // The value actually written back to `config.json` on success — see
    // `RenewArgs::server`'s doc comment: "for this run only — does not
    // rewrite it." An explicit `--server` must not silently become the
    // certificate's permanent CA for every future automatic renewal.
    let persisted_ca_directory = persisted_ca_directory(args, config.as_ref(), &ca_directory);

    let http = match build_client(args) {
        Ok(c) => c,
        // `http` itself is what's failing to construct here — nothing to
        // hand `fail()`.
        Err(e) => {
            let code = fail(out, Stage::Account, &e, &[name.to_string()], &hooks, None);
            return CertOutcome::Failed(code);
        }
    };

    // One directory fetch per distinct CA per run, cached across
    // certificates — `renew --all` against a fleet issued from the same CA
    // must not re-fetch `/dir` once per certificate.
    let entry = match directories.entry(ca_directory.clone()) {
        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::hash_map::Entry::Vacant(slot) => {
            let response = http.request(certway_core::Method::Get, &ca_directory, None, None);
            let response = match response {
                Ok(r) => r,
                Err(e) => {
                    let code = fail(
                        out,
                        Stage::Account,
                        &e,
                        &[name.to_string()],
                        &hooks,
                        Some(&http),
                    );
                    return CertOutcome::Failed(code);
                }
            };
            if !*skew_checked {
                *skew_checked = true;
                if let Some(date_header) = response.headers.date() {
                    if let Some(skew) = skew_seconds(date_header, now) {
                        if skew.abs() > CLOCK_SKEW_WARNING_SECS && out.mode != Mode::Json {
                            let minutes = skew.unsigned_abs() / 60;
                            let direction = if skew > 0 { "behind" } else { "ahead of" };
                            let _ = out.raw_line(&format!("  ! time           local clock is {minutes} minutes {direction} the CA"));
                        }
                    }
                }
            }
            let json = match certway_core::Json::parse(&response.body) {
                Ok(j) => j,
                Err(e) => {
                    let code = fail(
                        out,
                        Stage::Account,
                        &e,
                        &[name.to_string()],
                        &hooks,
                        Some(&http),
                    );
                    return CertOutcome::Failed(code);
                }
            };
            let directory = match Directory::parse(&json) {
                Ok(d) => d,
                Err(e) => {
                    let code = fail(
                        out,
                        Stage::Account,
                        &e,
                        &[name.to_string()],
                        &hooks,
                        Some(&http),
                    );
                    return CertOutcome::Failed(code);
                }
            };
            // The `http` built above for this iteration is kept only when
            // it's the one that ends up cached; on the occupied-entry path
            // it's dropped in favor of the already-cached client (cheap —
            // no I/O had happened on it yet).
            slot.insert((http, directory))
        }
    };
    let (http, directory) = (&entry.0, &entry.1);

    let path = decide(&parsed, name, args.force, now, http, directory, cert_root);

    if args.explain && out.mode != Mode::Json {
        let _ = out.raw_line(&explain_line(&path));
    }

    let due = !matches!(path, RenewPath::NotDue { .. });
    if !due {
        if !args.explain {
            let _ = out.raw_line(&format!("  · {name:<20} not due"));
        }
        return CertOutcome::NotDue;
    }

    // A resolver is only needed for dns-01's propagation check. No
    // `--resolver` flag exists on `renew` — the env var precedence
    // `Resolver::discover` already implements (`CERTWAY_RESOLVER`, then
    // `/etc/resolv.conf`) is what a scheduled `renew --all --quiet` run,
    // with no flags of its own, relies on.
    let resolver = if challenge_config.use_dns() {
        match Resolver::discover(None) {
            Ok(r) => Some(r),
            Err(e) => {
                let code = fail(
                    out,
                    Stage::Account,
                    &e,
                    &[name.to_string()],
                    &hooks,
                    Some(http),
                );
                return CertOutcome::Failed(code);
            }
        }
    } else {
        None
    };

    // `"cloudflare"` rebuilds from the environment, same as `issue`
    // (`CloudflareProvider::from_env`'s token lookup); `"hook"` uses the
    // command strings `effective_challenge_config` already resolved (this
    // run's flags, or `config.json`'s — the guard above already ruled out
    // "hook" with neither).
    let mut provider: Option<Box<dyn DnsTxtProvider + Send + '_>> = if !challenge_config.use_dns() {
        None
    } else if challenge_config.dns_provider.as_deref() == Some("cloudflare") {
        match CloudflareProvider::from_env(http) {
            Ok(p) => Some(Box::new(p)),
            Err(e) => {
                let code = fail(
                    out,
                    Stage::Account,
                    &e,
                    &[name.to_string()],
                    &hooks,
                    Some(http),
                );
                return CertOutcome::Failed(code);
            }
        }
    } else {
        let create = challenge_config.dns_hook.as_deref().unwrap_or_default();
        let cleanup = challenge_config.dns_cleanup.as_deref().unwrap_or_default();
        Some(Box::new(HookProvider::new(
            create,
            cleanup,
            hooks.hook_shell,
        )))
    };

    let account_paths = store::account_paths(data_root, &ca_host);
    let account_key = match store::load_or_generate_key(&account_paths, args.relax_permissions) {
        Ok((k, permissions_relaxed)) => {
            if permissions_relaxed {
                let _ = out.step_warned(
                    "permissions",
                    "account key/directory readable by group or other — continuing (--relax-permissions)",
                );
            }
            k
        }
        Err(e) => {
            let code = fail(
                out,
                Stage::Account,
                &e,
                &[name.to_string()],
                &hooks,
                Some(http),
            );
            return CertOutcome::Failed(code);
        }
    };

    let mut session = Session::new(directory, http, &account_key);
    let (_elapsed, result) = run_with_spinner(out, "account", {
        let session_ref = &mut session;
        move || ensure_account(session_ref, None, true)
    });
    if let Err(e) = result {
        let code = fail(
            out,
            Stage::Account,
            &e,
            &[name.to_string()],
            &hooks,
            Some(http),
        );
        return CertOutcome::Failed(code);
    }

    // Only the ARI path claims the rate-limit exemption: --force and
    // "already expired" both short-circuit the decision in `decide` before
    // renewalInfo is ever fetched, so there is no certID to claim it with —
    // sending `replaces` without having fetched renewalInfo first would
    // claim the exemption without actually satisfying the CA's condition
    // for granting it (a certID derived from a `renewalInfo` lookup), so
    // the CA could reject the order or silently count it against the
    // ordinary rate limit anyway.
    let replaces = match &path {
        RenewPath::Ari(_) => CertId::from_certificate(&parsed)
            .ok()
            .map(|id| id.as_str().to_string()),
        _ => None,
    };

    let session_ref = &mut session;
    let identifiers_ref = &parsed.sans;
    let replaces_ref = replaces.as_deref();
    let (elapsed, result) = run_with_spinner(out, "order", move || {
        new_order(session_ref, identifiers_ref, replaces_ref)
    });
    let order = match result {
        Ok(o) => o,
        Err(e) => {
            let code = fail(
                out,
                Stage::Order,
                &e,
                &[name.to_string()],
                &hooks,
                Some(http),
            );
            return CertOutcome::Failed(code);
        }
    };
    let _ = out.step_done("order", &format!("{} domains", parsed.sans.len()), elapsed);

    let port = args.http01_port;
    if let Err(ChallengeFailure { stage, err, dns }) = run_challenges(
        out,
        &mut session,
        &order,
        &account_key,
        challenge_config.use_dns(),
        provider.as_deref_mut(),
        resolver.as_ref(),
        port,
    ) {
        let code = if dns {
            dns01_fail(out, stage, &err, &[name.to_string()], &hooks, Some(http))
        } else {
            fail(out, stage, &err, &[name.to_string()], &hooks, Some(http))
        };
        return CertOutcome::Failed(code);
    }

    let reuse_key = args.reuse_key || config.as_ref().map(|c| c.reuse_key).unwrap_or(false);
    let session_ref = &mut session;
    let order_ref = &order;
    let identifiers_ref = &parsed.sans;
    let cert_root_owned = cert_root.to_path_buf();
    let persisted_ca_directory_ref = persisted_ca_directory.clone();
    let links_ref = &effective_links;
    let hooks_ref = &hooks;
    let exports_ref: &[store::ExportSpec] =
        config.as_ref().map(|c| c.exports.as_slice()).unwrap_or(&[]);
    let challenge_type = challenge_config.challenge;
    let dns_provider_ref = challenge_config.dns_provider.as_deref();
    let dns_hook_ref = challenge_config.dns_hook.as_deref();
    let dns_cleanup_ref = challenge_config.dns_cleanup.as_deref();
    let (elapsed, result) = run_with_spinner(out, "certificate", move || {
        renew_certificate(
            session_ref,
            order_ref,
            identifiers_ref,
            &cert_root_owned,
            reuse_key,
            &persisted_ca_directory_ref,
            challenge_type,
            dns_provider_ref,
            dns_hook_ref,
            dns_cleanup_ref,
            links_ref,
            hooks_ref,
            exports_ref,
        )
    });
    let paths = match result {
        Ok(v) => v,
        Err(e) => {
            let code = fail(
                out,
                Stage::Certificate,
                &e,
                &[name.to_string()],
                &hooks,
                Some(http),
            );
            return CertOutcome::Failed(code);
        }
    };
    let _ = out.step_done("certificate", "renewed", elapsed);

    // -- link/hook/reload, same post-write sequence as `cmd::issue::run`.
    if !effective_links.is_empty() {
        match store::apply_links(&paths, &effective_links, data_root, args.link_force) {
            Ok(used_platform_copy) => {
                let detail = format!("{} linked", effective_links.len());
                let _ = out.step_done("link", &detail, std::time::Duration::ZERO);
                if used_platform_copy {
                    let _ = out.step_warned(
                        "link",
                        "copied instead of linking — symlinks need elevation on this platform",
                    );
                }
            }
            Err(e) => {
                let _ = out.step_warned("link", &e.to_string());
            }
        }
    }
    // Runs between links and hooks: every export `certway export` recorded
    // for this certificate is regenerated against the file just written
    // above. Without this, an export written at issuance and never
    // refreshed points at the old certificate for the rest of its life —
    // the exact failure links exist to avoid, silently reintroduced for
    // exports. Best-effort per export, same as links/hooks: a failure here
    // must not roll back an already-good certificate.
    let exports: &[store::ExportSpec] =
        config.as_ref().map(|c| c.exports.as_slice()).unwrap_or(&[]);
    if !exports.is_empty() {
        match std::fs::read_to_string(&paths.fullchain) {
            Ok(fullchain) => {
                let mut regenerated = 0usize;
                for spec in exports {
                    match crate::cmd::export::regenerate(&paths, &fullchain, spec) {
                        Ok(()) => regenerated += 1,
                        Err(e) => {
                            let _ = out.step_warned("export", &format!("{}: {e}", spec.out));
                        }
                    }
                }
                if regenerated > 0 {
                    let _ = out.step_done(
                        "export",
                        &format!("{regenerated} regenerated"),
                        std::time::Duration::ZERO,
                    );
                }
            }
            Err(e) => {
                let _ = out.step_warned(
                    "export",
                    &format!("fullchain.pem unreadable for export regeneration: {e}"),
                );
            }
        }
    }

    let fullchain_path_str = paths.fullchain.display().to_string();
    let key_path_str = paths.privkey.display().to_string();
    let not_after = std::fs::read_to_string(&paths.fullchain)
        .ok()
        .and_then(|pem| ParsedCert::from_leaf_pem(&pem).ok())
        .map(|p| format_rfc3339(p.not_after))
        .unwrap_or_default();
    let hook_env = HookEnv {
        domains: name,
        cert_path: &fullchain_path_str,
        key_path: &key_path_str,
        not_after: &not_after,
    };
    if !hooks.is_empty() {
        hooks::run_success(out, http, &hooks, &hook_env);
    }

    CertOutcome::Renewed
}

fn effective_ca_directory(args: &RenewArgs, config: Option<&CertConfig>) -> String {
    if let Some(s) = &args.server {
        return s.clone();
    }
    if let Some(c) = config {
        if !c.ca_directory.is_empty() {
            return c.ca_directory.clone();
        }
    }
    STAGING_URL.to_string()
}

/// What to persist into `config.json`'s `ca_directory` field on a
/// successful renewal. An explicit `--server` is a this-run-only override
/// (see the doc comment on `RenewArgs::server`): when present, the
/// certificate's existing stored directory survives unchanged, falling
/// back to the effective directory only when there was nothing stored yet
/// to preserve (e.g. a certificate written before this field existed).
fn persisted_ca_directory(
    args: &RenewArgs,
    config: Option<&CertConfig>,
    effective: &str,
) -> String {
    if args.server.is_some() {
        if let Some(c) = config {
            if !c.ca_directory.is_empty() {
                return c.ca_directory.clone();
            }
        }
    }
    effective.to_string()
}

/// What actually drives this renewal's challenge provisioning, and what
/// gets persisted back into `config.json` afterwards (`renew_certificate`
/// passes every field straight through to `store::write_certificate`).
struct ChallengeConfig {
    challenge: &'static str, // "http-01" | "dns-01"
    dns_provider: Option<String>,
    dns_hook: Option<String>,
    dns_cleanup: Option<String>,
}

impl ChallengeConfig {
    fn use_dns(&self) -> bool {
        self.challenge == "dns-01"
    }
}

/// A `--dns`/`--dns-hook` flag on *this* invocation entirely overrides the
/// certificate's recorded challenge/provider, for this run only (never
/// rewrites `config.json` on its own — the same this-run-only rule
/// `--server` follows). Absent either flag, the certificate's own recorded
/// challenge/provider/hook commands carry the renewal — the only way
/// `renew --all --quiet`, the literal cron/systemd invocation
/// (`scheduler/cron.rs`, `scheduler/systemd.rs` — no flags, ever), can
/// renew a wildcard automatically. `dns_hook`/`dns_cleanup` are only ever
/// populated when the provider is `"hook"`; `"cloudflare"`'s token comes
/// from the environment at construction time, same as `issue`.
fn effective_challenge_config(args: &RenewArgs, config: Option<&CertConfig>) -> ChallengeConfig {
    if args.dns.is_some() || args.dns_hook.is_some() {
        let (challenge, dns_provider) = challenge_record(&args.dns, &args.dns_hook);
        return ChallengeConfig {
            challenge,
            dns_provider,
            dns_hook: args.dns_hook.clone(),
            dns_cleanup: args.dns_cleanup.clone(),
        };
    }
    if let Some(c) = config {
        if c.challenge == "dns-01" {
            return ChallengeConfig {
                challenge: "dns-01",
                dns_provider: c.dns_provider.clone(),
                dns_hook: c.dns_hook.clone(),
                dns_cleanup: c.dns_cleanup.clone(),
            };
        }
    }
    ChallengeConfig {
        challenge: "http-01",
        dns_provider: None,
        dns_hook: None,
        dns_cleanup: None,
    }
}

/// A wildcard identifier resolved to anything but dns-01 fails here,
/// locally — no `Client` has been built yet, no request has reached Let's
/// Encrypt.
fn wildcard_identifier(sans: &[Identifier]) -> Option<&str> {
    sans.iter().find_map(|id| match id {
        Identifier::Dns(d) if d.starts_with("*.") => Some(d.as_str()),
        _ => None,
    })
}

/// Renders `report::wildcard_needs_dns01` and fires failure hooks, exactly
/// like `fail()` does for a `core::Error` — this check never reaches one,
/// since it never contacts the CA to produce it. Exit 3 ("preflight
/// failed").
fn preflight_fail(
    out: &mut Out<impl Write>,
    identifier: &str,
    example_command: String,
    name: &str,
    hooks: &HookConfig,
) -> i32 {
    let block = report::wildcard_needs_dns01(identifier, example_command);
    if out.mode == Mode::Json {
        let _ = out.json_step_failed(block.label, "wildcard_requires_dns01", &block.summary);
        let _ = out.json_result_failed(block.label, "wildcard_requires_dns01", false);
    } else {
        let _ = out.step_failed(block.label, &block.subject);
        let _ = out.error_block(&block);
    }
    hooks::run_failure(hooks, None, name, block.label, &block.summary);
    3
}

fn build_client(args: &RenewArgs) -> Result<Client, core::Error> {
    match &args.ca_bundle {
        Some(path) => {
            let pem = std::fs::read_to_string(path).map_err(|e| core::Error::io(path, e))?;
            Client::with_ca_bundle(&pem)
        }
        None => Client::new(),
    }
}

/// The renewal-due decision, in order: `--force`, then "already expired",
/// then ARI, then the 30-day fallback. `--force` and "already expired"
/// both short-circuit *before* touching ARI at all — see the `replaces`
/// comment in `renew_one`.
fn decide(
    parsed: &ParsedCert,
    name: &str,
    force: bool,
    now: i64,
    http: &Client,
    directory: &Directory,
    cert_root: &Path,
) -> RenewPath {
    if force {
        return RenewPath::Forced;
    }
    if now >= parsed.not_after {
        return RenewPath::Expired;
    }

    if let Some(window) = fetch_or_use_cached_ari(parsed, name, now, http, directory, cert_root) {
        let moment = certway_core::renewal_moment(name, &window);
        if now >= moment {
            return RenewPath::Ari(window);
        }
        if parsed.not_after - now < THIRTY_DAYS_SECS {
            // Even inside a not-yet-open ARI window, an imminent hard
            // expiry still wins — the 30-day fallback exists precisely so
            // an ARI hiccup can never let a certificate lapse.
            return RenewPath::Fallback;
        }
        return RenewPath::NotDue {
            window: Some(window),
        };
    }

    if parsed.not_after - now < THIRTY_DAYS_SECS {
        return RenewPath::Fallback;
    }
    RenewPath::NotDue { window: None }
}

/// Reuses the cached window at `<cert>/ari.json` when it hasn't reached its
/// `Retry-After` deadline yet; otherwise fetches fresh and updates the
/// cache. `None` for any failure along the way (no `renewalInfo` in the
/// directory, no AKI to build a certID from, the fetch itself failing) —
/// the caller falls through to the 30-day rule in every one of those
/// cases.
fn fetch_or_use_cached_ari(
    parsed: &ParsedCert,
    name: &str,
    now: i64,
    http: &Client,
    directory: &Directory,
    cert_root: &Path,
) -> Option<RenewalWindow> {
    directory.renewal_info.as_ref()?;
    let cert_id = CertId::from_certificate(parsed).ok()?;

    let cache_path = store::ari_cache_path(cert_root);
    if let Some(cached) = store::read_ari_cache(&cache_path) {
        if now < cached.retry_after_deadline {
            return Some(cached);
        }
    }

    let _ = name; // seeding happens in the caller via renewal_moment; not needed here
    match certway_core::fetch_renewal_info(http, directory, &cert_id, now) {
        Ok(window) => {
            let _ = store::write_ari_cache(&cache_path, &window);
            Some(window)
        }
        Err(_) => None,
    }
}

fn explain_line(path: &RenewPath) -> String {
    match path {
        RenewPath::Forced => "  renewal      --force".to_string(),
        RenewPath::Expired => "  renewal      already expired".to_string(),
        RenewPath::Ari(window) => {
            format!(
                "  renewal      ARI window {}\u{2013}{}, exempt from rate limits",
                format_short_date(window.start),
                format_short_date(window.end)
            )
        }
        RenewPath::Fallback => {
            "  renewal      30-day fallback \u{2014} ARI unavailable".to_string()
        }
        RenewPath::NotDue { window: Some(w) } => {
            format!(
                "  renewal      not due \u{2014} ARI window {}\u{2013}{}",
                format_short_date(w.start),
                format_short_date(w.end)
            )
        }
        RenewPath::NotDue { window: None } => "  renewal      not due".to_string(),
    }
}

const MONTH_ABBREV: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `"12 Oct"` — day and abbreviated month, no year (matches the `RENEW`
/// column's window format, e.g. `12–19 Oct`).
pub(crate) fn format_short_date(epoch: i64) -> String {
    let (_, m, d) = civil_from_epoch(epoch);
    format!("{d} {}", MONTH_ABBREV[(m - 1) as usize])
}

/// `"29 Oct 2026"` — the `EXPIRES` column's format.
pub(crate) fn format_full_date(epoch: i64) -> String {
    let (y, m, d) = civil_from_epoch(epoch);
    format!("{d} {} {y}", MONTH_ABBREV[(m - 1) as usize])
}

/// `"2026-10-29T00:00:00Z"` — `CERTWAY_NOT_AFTER`'s format. RFC 3339 UTC,
/// matching this project's UTC-only stance elsewhere rather than inventing
/// a second date format just for hooks.
pub(crate) fn format_rfc3339(epoch: i64) -> String {
    let (y, m, d) = civil_from_epoch(epoch);
    let secs_of_day = epoch.rem_euclid(86_400);
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// The inverse of `cert::days_from_civil` — epoch seconds to a (year,
/// month, day) triple. Howard Hinnant's `civil_from_days`, the standard
/// companion algorithm to the one already used for the forward direction
/// (`certway-core::cert::days_from_civil`); transcribed here rather than
/// exposed from core, since date *formatting* is display logic and belongs
/// in the CLI, not `certway-core`.
pub(crate) fn civil_from_epoch(epoch: i64) -> (i64, u32, u32) {
    let days = epoch.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Same post-download sequence as `issue`: nothing touches disk until the
/// downloaded chain is verified — it parses, its SANs cover the request,
/// and its public key matches the private key. A
/// failed download or a failed check leaves the previous certificate
/// entirely intact (this function never opens `cert_root`'s files for
/// writing until every check above has already returned `Ok`).
#[allow(clippy::too_many_arguments)]
fn renew_certificate(
    session: &mut Session,
    order: &Order,
    identifiers: &[Identifier],
    cert_root: &Path,
    reuse_key: bool,
    ca_directory: &str,
    challenge_type: &str,
    dns_provider: Option<&str>,
    dns_hook: Option<&str>,
    dns_cleanup: Option<&str>,
    links: &[LinkSpec],
    hooks: &HookConfig,
    exports: &[store::ExportSpec],
) -> Result<store::CertPaths, core::Error> {
    let cert_key = if reuse_key {
        let existing = std::fs::read_to_string(cert_root.join("privkey.pem"))
            .map_err(|e| core::Error::io(cert_root.join("privkey.pem"), e))?;
        CertKey::from_pkcs8_pem(&existing)?
    } else {
        CertKey::generate()?
    };
    let csr_der = build_csr(&cert_key, identifiers)?;
    let finalized = finalize(session, order, &csr_der)?;
    let cert_url = finalized.certificate.as_ref().ok_or_else(|| {
        core::Error::io(
            "<order>",
            std::io::Error::other("order valid but no certificate url present"),
        )
    })?;
    let pem = download_certificate(session, cert_url)?;

    // Verify before anything touches disk.
    let downloaded = ParsedCert::from_leaf_pem(&pem)?;
    for wanted in identifiers {
        if !downloaded.sans.contains(wanted) {
            return Err(core::Error::io(
                cert_root,
                std::io::Error::other(
                    "downloaded certificate's SANs do not cover every requested identifier",
                ),
            ));
        }
    }
    if downloaded.public_key != cert_key.public_key_raw() {
        return Err(core::Error::io(
            cert_root,
            std::io::Error::other(
                "downloaded certificate's public key does not match the certificate key",
            ),
        ));
    }

    let key_pem = cert_key.to_pkcs8_pem();
    // `challenge_type`/`dns_provider`/`dns_hook`/`dns_cleanup` are exactly
    // what `run_challenges` was actually given for this renewal
    // (`effective_challenge_config`'s resolution) — recording anything else
    // here would be the same "wrong data sitting on disk" bug
    // `challenge_record`'s own doc comment (in `cmd::issue`) already
    // guards against for `issue`, just reintroduced on the renewal side.
    let paths = store::write_certificate(
        cert_root,
        &pem,
        &key_pem,
        challenge_type,
        dns_provider,
        dns_hook,
        dns_cleanup,
        "ecdsa-p256",
        reuse_key,
        ca_directory,
        links,
        hooks,
        exports,
    )?;

    // The cached window at `<cert>/ari.json`, if any, describes the
    // certificate just replaced — it must not survive to be misread as
    // still describing the new one (see `invalidate_ari_cache`'s doc
    // comment). A stale past window would otherwise make every future
    // `renew` on this certificate renew again unconditionally.
    store::invalidate_ari_cache(&store::ari_cache_path(cert_root));

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_cert(not_before: i64, not_after: i64) -> ParsedCert {
        ParsedCert {
            not_before,
            not_after,
            serial_der: vec![1],
            aki_key_id: Some(vec![0xaa; 20]),
            sans: vec![],
            public_key: vec![],
        }
    }

    // -- recorded_ca_directory_for_single_target: the header CA-label fix ---
    //
    // Bug found live: renewing a real production certificate with no
    // `--server` showed "(staging)" in the header even though the
    // certificate itself, and the renewal, were both production — the
    // header was guessing `STAGING_URL` instead of reading what
    // `config.json` already recorded.

    fn tmp_data_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-renew-header-ca-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_fixture_config(data_root: &Path, name: &str, ca_directory: &str) {
        let cert_dir = data_root.join(name);
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("fullchain.pem"), b"placeholder").unwrap();
        std::fs::write(
            cert_dir.join("config.json"),
            format!(
                r#"{{"challenge":"http-01","key_algorithm":"ecdsa-p256","ca_directory":"{ca_directory}"}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn recorded_ca_directory_reads_the_named_certificates_own_config() {
        let dir = tmp_data_root("named");
        write_fixture_config(&dir, "hossein.veraspeed.ir", "https://acme-v02.api.letsencrypt.org/directory");

        let args = RenewArgs {
            name: Some("hossein.veraspeed.ir".to_string()),
            ..Default::default()
        };
        assert_eq!(
            recorded_ca_directory_for_single_target(&dir, &args).as_deref(),
            Some("https://acme-v02.api.letsencrypt.org/directory")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recorded_ca_directory_is_none_for_all() {
        let dir = tmp_data_root("all");
        write_fixture_config(&dir, "example.com", "https://acme-v02.api.letsencrypt.org/directory");
        let args = RenewArgs {
            all: true,
            ..Default::default()
        };
        assert_eq!(recorded_ca_directory_for_single_target(&dir, &args), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recorded_ca_directory_is_none_when_the_certificate_does_not_exist() {
        let dir = tmp_data_root("missing");
        let args = RenewArgs {
            name: Some("nonexistent.example".to_string()),
            ..Default::default()
        };
        assert_eq!(recorded_ca_directory_for_single_target(&dir, &args), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recorded_ca_directory_resolves_a_sanitized_wildcard_name_too() {
        let dir = tmp_data_root("wildcard");
        write_fixture_config(&dir, "_.example.com", "https://acme-v02.api.letsencrypt.org/directory");
        let args = RenewArgs {
            name: Some("*.example.com".to_string()),
            ..Default::default()
        };
        assert_eq!(
            recorded_ca_directory_for_single_target(&dir, &args).as_deref(),
            Some("https://acme-v02.api.letsencrypt.org/directory")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- run_once: a data directory that does not exist yet ------------------
    //
    // Same bug family as `cmd::list`'s (found live, on a real fresh
    // install): `renew --all` against a data directory that was never
    // created failed with a raw "No such file or directory" instead of
    // treating "nothing to renew" as the normal no-op state for zero
    // certificates due.

    #[test]
    fn renew_all_on_a_nonexistent_data_directory_is_a_clean_noop_not_a_failure() {
        let dir = std::env::temp_dir().join(format!(
            "certway-renew-missing-dir-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!dir.exists());

        let args = RenewArgs {
            all: true,
            out_dir: Some(dir.to_string_lossy().to_string()),
            ..RenewArgs::default()
        };
        let mut buf = Vec::new();
        let caps = crate::caps::Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 100,
        };
        let code = {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            run_once(&args, &mut out)
        };

        assert_eq!(code, 0, "nothing due is not a failure");
        let text = String::from_utf8(buf).unwrap();
        assert!(!text.contains("account"), "must never claim the (wrong) \"account\" step label for a directory that was never touched: {text:?}");
        assert!(
            !dir.exists(),
            "renew --all with nothing to renew must not create the data directory either"
        );
    }

    // -- effective_challenge_config: CLI flag -> config.json -> default ----

    fn config_with_challenge(
        challenge: &str,
        dns_provider: Option<&str>,
        dns_hook: Option<&str>,
        dns_cleanup: Option<&str>,
    ) -> CertConfig {
        CertConfig {
            challenge: challenge.to_string(),
            dns_provider: dns_provider.map(str::to_string),
            dns_hook: dns_hook.map(str::to_string),
            dns_cleanup: dns_cleanup.map(str::to_string),
            key_algorithm: "ecdsa-p256".to_string(),
            reuse_key: false,
            ca_directory: "https://a".to_string(),
            links: Vec::new(),
            hooks: HookConfig::default(),
            exports: Vec::new(),
        }
    }

    #[test]
    fn effective_challenge_config_defaults_to_http01_with_no_flag_and_no_config() {
        let cc = effective_challenge_config(&RenewArgs::default(), None);
        assert_eq!(cc.challenge, "http-01");
        assert!(!cc.use_dns());
        assert!(cc.dns_provider.is_none());
    }

    #[test]
    fn effective_challenge_config_reads_dns01_cloudflare_from_config_json_absent_a_flag() {
        let config = config_with_challenge("dns-01", Some("cloudflare"), None, None);
        let cc = effective_challenge_config(&RenewArgs::default(), Some(&config));
        assert!(cc.use_dns());
        assert_eq!(cc.dns_provider.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn effective_challenge_config_reads_dns01_hook_commands_from_config_json_absent_a_flag() {
        // The whole point of persisting `dns_hook`/`dns_cleanup`
        // (`store::cert::CertConfig`'s doc comment): `renew --all --quiet`,
        // the literal scheduled invocation, gives no flags at all — this is
        // what lets a hook-based wildcard keep renewing automatically.
        let config = config_with_challenge(
            "dns-01",
            Some("hook"),
            Some("/bin/create"),
            Some("/bin/clean"),
        );
        let cc = effective_challenge_config(&RenewArgs::default(), Some(&config));
        assert!(cc.use_dns());
        assert_eq!(cc.dns_provider.as_deref(), Some("hook"));
        assert_eq!(cc.dns_hook.as_deref(), Some("/bin/create"));
        assert_eq!(cc.dns_cleanup.as_deref(), Some("/bin/clean"));
    }

    #[test]
    fn effective_challenge_config_a_dns_flag_this_run_overrides_a_recorded_http01_challenge() {
        let config = config_with_challenge("http-01", None, None, None);
        let args = RenewArgs {
            dns: Some("cloudflare".to_string()),
            ..RenewArgs::default()
        };
        let cc = effective_challenge_config(&args, Some(&config));
        assert!(cc.use_dns());
        assert_eq!(cc.dns_provider.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn effective_challenge_config_a_dns_hook_flag_this_run_overrides_a_recorded_cloudflare_provider(
    ) {
        // Mirrors `--server`'s this-run-only rule: whatever is given on the
        // command line wins outright over what was recorded, not merged
        // with it.
        let config = config_with_challenge("dns-01", Some("cloudflare"), None, None);
        let args = RenewArgs {
            dns_hook: Some("/bin/create".to_string()),
            dns_cleanup: Some("/bin/clean".to_string()),
            ..RenewArgs::default()
        };
        let cc = effective_challenge_config(&args, Some(&config));
        assert!(cc.use_dns());
        assert_eq!(cc.dns_provider.as_deref(), Some("hook"));
        assert_eq!(cc.dns_hook.as_deref(), Some("/bin/create"));
    }

    // -- wildcard_identifier -------------------------------------------------

    #[test]
    fn wildcard_identifier_finds_the_wildcard_among_plain_names() {
        let sans = vec![
            Identifier::Dns("wild.example".to_string()),
            Identifier::Dns("*.wild.example".to_string()),
        ];
        assert_eq!(wildcard_identifier(&sans), Some("*.wild.example"));
    }

    #[test]
    fn wildcard_identifier_is_none_when_there_is_no_wildcard() {
        let sans = vec![
            Identifier::Dns("example.com".to_string()),
            Identifier::Ip("203.0.113.7".parse().unwrap()),
        ];
        assert_eq!(wildcard_identifier(&sans), None);
    }

    // -- the wildcard preflight check, end to end through run_once ----------
    //
    // A wildcard certificate renewed with no dns-01 configured must fail
    // locally, never reaching the `account` step (which is where any CA
    // contact would first happen) — proven here by never giving this
    // certificate a `config.json` at all, so a bug that skipped the check
    // would fall through to the built-in http-01 default and visibly
    // attempt (and fail differently, at a later stage) rather than
    // stopping here.

    #[test]
    fn renew_of_a_wildcard_without_dns_configured_fails_locally_before_any_ca_contact() {
        let dir = tmp_cert_root("wildcard-preflight");
        let cert_root = dir.join("_.wild.example");
        std::fs::create_dir_all(&cert_root).unwrap();
        let key_path = cert_root.join("privkey.pem");
        let cert_path = cert_root.join("fullchain.pem");

        let status = std::process::Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key_path)
            .status()
            .expect("openssl must be on PATH for this test");
        assert!(status.success());
        let status = std::process::Command::new("openssl")
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key_path)
            .args([
                "-days",
                "90",
                "-subj",
                "/CN=wild.example",
                "-addext",
                "subjectAltName=DNS:*.wild.example",
                "-out",
            ])
            .arg(&cert_path)
            .status()
            .expect("openssl req");
        assert!(status.success());

        let args = RenewArgs {
            name: Some("_.wild.example".to_string()),
            out_dir: Some(dir.to_string_lossy().to_string()),
            ..RenewArgs::default()
        };
        let mut buf = Vec::new();
        let caps = crate::caps::Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 100,
        };
        let code = {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            run_once(&args, &mut out)
        };

        assert_eq!(code, 3, "preflight failure is exit 3");
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("preflight"), "{text}");
        assert!(text.contains("*.wild.example"), "{text}");
        assert!(
            text.contains("A wildcard certificate can only be validated over DNS."),
            "{text}"
        );
        assert!(
            text.contains("Stopped before contacting Let's Encrypt. No rate limit used."),
            "{text}"
        );
        assert!(
            text.contains("certway renew _.wild.example --dns cloudflare"),
            "{text}"
        );
        assert!(!text.contains("account"), "must never reach the account step -- no CA contact for a local preflight failure: {text:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- --watch wiring: run_watch_with -----------------------------------
    //
    // `scheduler::watch`'s own tests already prove the wake/shutdown
    // mechanics in isolation; this proves `renew`'s wiring actually calls
    // through it and re-runs a full pass, using an injected shutdown flag
    // (never the process-global `crate::signal::SHUTDOWN`, which every
    // other test in this binary implicitly assumes stays `false`).

    #[test]
    fn watch_runs_one_pass_immediately_even_when_shutdown_is_already_set() {
        let shutdown = std::sync::atomic::AtomicBool::new(true);
        let dir = tmp_cert_root("watch-immediate");
        let args = RenewArgs {
            all: true,
            out_dir: Some(dir.to_string_lossy().to_string()),
            ..RenewArgs::default()
        };
        let mut buf = Vec::new();
        let caps = crate::caps::Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 100,
        };
        let code = {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            run_watch_with(
                &args,
                &mut out,
                std::time::Duration::from_secs(9999),
                &shutdown,
            )
        };
        // No certificates exist under `dir`, so the pass itself is a no-op
        // (`resolve_targets` returns an empty list) — the point here is
        // only that exactly one pass ran before the loop honoured the
        // already-set shutdown flag, evidenced by the header this build
        // always prints once per pass.
        assert_eq!(code, 0);
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("certway "),
            "header must have printed exactly once, proving run_once actually ran: {text:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- civil_from_epoch / format_*_date -----------------------------------

    #[test]
    fn civil_from_epoch_matches_known_dates() {
        assert_eq!(civil_from_epoch(0), (1970, 1, 1));
        assert_eq!(civil_from_epoch(-1), (1969, 12, 31));
        // 2026-08-05 00:00:00Z: independently cross-checked with
        // `date -u -d '2026-08-05 00:00:00' +%s` -> 1785888000.
        assert_eq!(civil_from_epoch(1_785_888_000), (2026, 8, 5));
    }

    #[test]
    fn format_short_date_has_no_year() {
        let s = format_short_date(1_785_888_000); // 2026-08-05
        assert_eq!(s, "5 Aug");
    }

    #[test]
    fn format_full_date_has_year() {
        let s = format_full_date(1_785_888_000);
        assert_eq!(s, "5 Aug 2026");
    }

    #[test]
    fn format_rfc3339_matches_known_instant() {
        // 2026-08-05 00:00:00Z, same instant `civil_from_epoch_matches_known_dates`
        // cross-checks, plus a non-midnight instant so the time-of-day math
        // (not just the date math it shares with `format_full_date`) is covered.
        assert_eq!(format_rfc3339(1_785_888_000), "2026-08-05T00:00:00Z");
        assert_eq!(
            format_rfc3339(1_785_888_000 + 13 * 3600 + 5 * 60 + 9),
            "2026-08-05T13:05:09Z"
        );
    }

    /// The wiring `cmd::issue::run` and `run_once` both do — read back the
    /// fullchain file just written, parse it, format `not_after` — actually
    /// produces a populated `CERTWAY_NOT_AFTER`, not the empty string it
    /// silently fell back to before this test existed. Uses a real
    /// self-signed certificate (openssl subprocess, the same pattern
    /// `certway-core::cert`'s own tests use) rather than the placeholder
    /// `-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n`
    /// fixtures elsewhere in this file, which `ParsedCert::from_leaf_pem`
    /// cannot parse and would silently make this exact regression invisible.
    #[test]
    fn hook_env_not_after_is_populated_from_the_written_certificate() {
        let dir =
            std::env::temp_dir().join(format!("certway-not-after-wiring-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("key.pem");
        let cert_path = dir.join("fullchain.pem");

        let status = std::process::Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key_path)
            .status()
            .expect("openssl must be on PATH for this test");
        assert!(status.success());
        let status = std::process::Command::new("openssl")
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key_path)
            .args(["-days", "90", "-subj", "/CN=example.com", "-out"])
            .arg(&cert_path)
            .status()
            .expect("openssl req");
        assert!(status.success());

        let not_after = std::fs::read_to_string(&cert_path)
            .ok()
            .and_then(|pem| ParsedCert::from_leaf_pem(&pem).ok())
            .map(|p| format_rfc3339(p.not_after))
            .unwrap_or_default();

        assert!(
            !not_after.is_empty(),
            "the wired not_after must not silently fall back to empty for a real certificate"
        );
        assert_eq!(not_after.len(), "2026-08-05T00:00:00Z".len());
        assert!(not_after.ends_with('Z'));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- decide()'s branch order: --force and "already expired" both
    // short-circuit before ARI is ever touched, so `decide` is directly
    // callable here with a real `Client` (`Client::new()` does no network
    // I/O — it only parses the embedded root PEM) and a hand-built
    // `Directory` (the same `dummy_directory` pattern `acme.rs`'s own
    // tests use), never reaching either.

    fn dummy_directory() -> Directory {
        Directory {
            new_nonce: "https://a/nonce".to_string(),
            new_account: "https://a/acct".to_string(),
            new_order: "https://a/order".to_string(),
            revoke_cert: "https://a/revoke".to_string(),
            key_change: "https://a/key-change".to_string(),
            renewal_info: Some("https://a/ari".to_string()),
            terms_of_service: None,
            external_account_required: false,
        }
    }

    fn tmp_cert_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-renew-decide-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn force_wins_even_though_ari_is_advertised_and_cert_is_freshly_issued() {
        let cert = parsed_cert(0, 1_000_000_000);
        let http = Client::new().unwrap();
        let directory = dummy_directory();
        let cert_root = tmp_cert_root("force");
        let path = decide(
            &cert,
            "example.com",
            true,
            500,
            &http,
            &directory,
            &cert_root,
        );
        assert!(matches!(path, RenewPath::Forced));
        let _ = std::fs::remove_dir_all(&cert_root);
    }

    // -- persisted_ca_directory: `--server` overrides the CA for this run
    // only, per `RenewArgs::server`'s doc comment — it must never silently
    // become the certificate's stored, permanent CA.

    fn args_with_server(server: Option<&str>) -> RenewArgs {
        RenewArgs {
            server: server.map(str::to_string),
            ..RenewArgs::default()
        }
    }

    fn config_with_ca_directory(ca_directory: &str) -> CertConfig {
        CertConfig {
            challenge: "http-01".to_string(),
            dns_provider: None,
            dns_hook: None,
            dns_cleanup: None,
            key_algorithm: "ecdsa-p256".to_string(),
            reuse_key: false,
            ca_directory: ca_directory.to_string(),
            links: Vec::new(),
            hooks: HookConfig::default(),
            exports: Vec::new(),
        }
    }

    #[test]
    fn server_override_is_not_persisted_when_a_stored_directory_exists() {
        let args = args_with_server(Some(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        ));
        let config = config_with_ca_directory("https://acme-v02.api.letsencrypt.org/directory");
        let persisted = persisted_ca_directory(
            &args,
            Some(&config),
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        );
        assert_eq!(persisted, "https://acme-v02.api.letsencrypt.org/directory");
    }

    #[test]
    fn server_override_is_persisted_when_nothing_was_stored_yet() {
        let args = args_with_server(Some(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        ));
        let persisted = persisted_ca_directory(
            &args,
            None,
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        );
        assert_eq!(
            persisted,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn without_server_override_the_effective_directory_is_always_persisted() {
        let args = args_with_server(None);
        let config = config_with_ca_directory("https://acme-v02.api.letsencrypt.org/directory");
        let persisted = persisted_ca_directory(
            &args,
            Some(&config),
            "https://acme-v02.api.letsencrypt.org/directory",
        );
        assert_eq!(persisted, "https://acme-v02.api.letsencrypt.org/directory");
    }

    #[test]
    fn already_expired_wins_before_ari_is_ever_touched() {
        let cert = parsed_cert(0, 1000);
        let http = Client::new().unwrap();
        let directory = dummy_directory();
        let cert_root = tmp_cert_root("expired");
        // now (2000) is well past not_after (1000); the directory
        // advertises renewalInfo but decide() must never reach it — if it
        // tried, this call would hang or error trying to reach
        // "https://a/ari", not return Expired.
        let path = decide(
            &cert,
            "example.com",
            false,
            2000,
            &http,
            &directory,
            &cert_root,
        );
        assert!(matches!(path, RenewPath::Expired));
        let _ = std::fs::remove_dir_all(&cert_root);
    }
}
