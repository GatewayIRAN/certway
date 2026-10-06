// SPDX-License-Identifier: MIT

//! The `issue` command.
//!
//! This build's sequence starts at `account` — `preflight` and `rehearsal`
//! don't exist yet, so the success trailer and the error narrowing logic
//! below only ever have to account for the stages that do.
//!
//! ```text
//! account → order → challenge → validate → certificate
//! ```

use crate::args::IssueArgs;
use crate::hooks::{self, HookEnv};
use crate::render::{Mode, Out};
use crate::report::{self, Proven, Stage};
use crate::steps::{animate, plan_authorization, run_with_spinner, AuthzAction};
use crate::store;
use crate::store::{HookConfig, LinkSpec};
use crate::trailer;
use crate::webserver;
use certway_core::{
    self as core, answer_challenge, build_csr, download_certificate, ensure_account,
    fetch_authorization, fetch_directory, finalize, new_order, poll_authorization, AccountKey,
    AuthzStatus, CertKey, Client, CloudflareProvider, Dns01Solver, DnsTxtProvider, HookProvider,
    Http01Server, Identifier, Order, ParsedCert, Resolver, Session, Solver,
};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Staging by default in this build — a temporary development safety rail,
/// not intended as shipped behaviour. Production issuance requires an
/// explicit `--server`.
const STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// `certway issue --help` — every flag `args::ISSUE_FLAGS` (the real,
/// parsed set) actually accepts, grouped by function. A flag some
/// higher-level flag table lists for `issue` but this build doesn't parse
/// (`--webroot`, `--preferred-challenges`, every "Certificate shape" flag,
/// `--eab-kid`/`--eab-hmac-key`, `--config-dir`, `--timeout`, `--retry`,
/// `--explain`) is omitted rather than listed as if it worked — help text
/// must never promise a flag that silently does nothing. `--redirect` and
/// `--relax-permissions` used to be in that omitted set; both are real
/// flags now, so they're listed like any other.
const ISSUE_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway issue <domain>... [flags]",
    examples: &[
        "certway issue example.com",
        "certway issue \"*.example.com\" --dns cloudflare --agree-tos",
    ],
    groups: &[
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
            heading: "Stages",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--staging",
                    about: "Use Let's Encrypt's staging CA (the default in this build)",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--dry-run",
                    about: "Report every action and change nothing",
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
            heading: "After issuance",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--edit-nginx",
                    about: "Opt in to editing nginx's config directly",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--redirect",
                    about: "Also write an HTTP-to-HTTPS redirect (with --edit-nginx)",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--nginx",
                    about: "Force detection to nginx",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--apache",
                    about: "Force detection to Apache (advice only — never edited)",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--none",
                    about: "Edit nothing, even with --edit-nginx",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--reload <cmd>",
                    about: "Shorthand for the most common deploy hook",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--hook <cmd>",
                    about: "Run after a successful issuance",
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
                    flag: "--email <addr>",
                    about: "Account contact address",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--no-email",
                    about: "Register with no contact address",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--agree-tos",
                    about: "Accept the CA's terms without prompting",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Environment",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--resolver <ip>",
                    about: "DNS resolver to use",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--yes",
                    about: "Accept confirmation prompts",
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

pub fn run(args: IssueArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &ISSUE_HELP);
        return 0;
    }

    let directory_url = args
        .server
        .clone()
        .unwrap_or_else(|| STAGING_URL.to_string());
    let _ = out.header(env!("CARGO_PKG_VERSION"), Some(&directory_url));

    // Built once, up front, so every `fail()`/`dns01_fail()` call
    // site below can fire `--hook-failure`/`--hook-url` on the way out —
    // `hooks::run_failure` is best-effort and silent on its own failure,
    // never masking the real error being reported.
    let hooks = HookConfig {
        hook: args.hook.clone(),
        hook_failure: args.hook_failure.clone(),
        hook_url: args.hook_url.clone(),
        reload: args.reload.clone(),
        hook_shell: args.hook_shell,
    };
    let links = links_from_args(&args.link_to, &args.links, args.copy);

    // -- storage: resolve, lock, load-or-generate the account key ----------
    // `--out` overrides the whole resolved data root, not just the
    // certificate directory — the same root the account key lives under.
    // Locked for the entire command before any network I/O, so two
    // overlapping `certway` processes never both reach the account step.
    let data_root = match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
        Ok(p) => p,
        // No `Client` exists yet at any of these three failure points — the
        // http client is built further down, before any network I/O, so
        // `--hook-url` here can only ever use a fresh throwaway client
        // (`hooks::run_failure`'s `None` fallback).
        Err(e) => return fail(out, Stage::Account, &e, &args.domains, &hooks, None),
    };
    if let Err(e) = store::create_dir_secure(&data_root, 0o755) {
        return fail(out, Stage::Account, &e, &args.domains, &hooks, None);
    }
    let _lock = match store::acquire_exclusive(&data_root) {
        Ok(l) => l,
        Err(e) => return fail(out, Stage::Account, &e, &args.domains, &hooks, None),
    };

    // `--dns`/`--dns-hook` chooses dns-01 for every identifier in this
    // order, an explicit flag deciding the method for the whole order at
    // once — no per-domain method mixing, no automatic port-80/webroot
    // detection: that's the preflight/method-selection machinery a later
    // stage builds.
    // `args.rs` already rejects a wildcard domain when neither is set.
    let use_dns = args.dns.is_some() || args.dns_hook.is_some();
    let (challenge_type, dns_provider) = challenge_record(&args.dns, &args.dns_hook);

    // A resolver is discovered regardless of method — `http.rs`'s own
    // connector needs one for every non-literal, non-`/etc/hosts` host it
    // dials, dns-01's propagation check doubly so. Only dns-01 makes a
    // missing resolver fatal here: http-01 falls back to a fresh
    // per-connection `Resolver::discover(None)` (see `http::resolve_host`),
    // which is enough for a dev machine with a working `/etc/resolv.conf`
    // and keeps every existing http-01 pebble scenario working unmodified.
    let resolver = Resolver::discover(args.resolver);
    if use_dns {
        if let Err(e) = &resolver {
            return fail(out, Stage::Account, e, &args.domains, &hooks, None);
        }
    }
    let resolver = resolver.ok();

    // Building `http` is itself fallible (a bad `--ca-bundle` path/PEM, or
    // `Client::new()` failing to parse the embedded root) — on any of
    // these three paths `http` does not exist, by definition, so there is
    // no "run's own client" to hand `fail()` yet; `None` here is the
    // honest state, not a shortcut around it.
    let http = match &args.ca_bundle {
        Some(path) => {
            let pem = match std::fs::read_to_string(path) {
                Ok(p) => p,
                Err(e) => {
                    return fail(
                        out,
                        Stage::Account,
                        &core::Error::io(path, e),
                        &args.domains,
                        &hooks,
                        None,
                    )
                }
            };
            match Client::with_ca_bundle(&pem) {
                Ok(c) => c,
                Err(e) => return fail(out, Stage::Account, &e, &args.domains, &hooks, None),
            }
        }
        None => match Client::new() {
            Ok(c) => c,
            Err(e) => return fail(out, Stage::Account, &e, &args.domains, &hooks, None),
        },
    };
    let http = if let Some(r) = &resolver {
        http.with_resolver(r.clone())
    } else {
        http
    };

    // dns-01's provider — Cloudflare or the external hook, whichever flag
    // was given. Constructed before `account` so a bad Cloudflare token
    // fails before any signed ACME request, matching http-01's own
    // "nothing network-shaped happens before it's needed" shape as closely
    // as this build's stages allow without a real preflight stage to put
    // it in.
    let mut provider: Option<Box<dyn DnsTxtProvider + Send + '_>> = if !use_dns {
        None
    } else if args.dns.is_some() {
        match CloudflareProvider::from_env(&http) {
            Ok(p) => Some(Box::new(p)),
            Err(e) => return fail(out, Stage::Account, &e, &args.domains, &hooks, Some(&http)),
        }
    } else {
        let create = args.dns_hook.as_deref().unwrap_or_default();
        let cleanup = args.dns_cleanup.as_deref().unwrap_or_default();
        Some(Box::new(HookProvider::new(
            create,
            cleanup,
            args.hook_shell,
        )))
    };

    // Keyed by the directory URL's own hostname — staging and production
    // are separate worlds, and a key registered with one must never even
    // be tried against the other.
    let ca_host = store::host_from_url(&directory_url).to_string();
    let account_paths = store::account_paths(&data_root, &ca_host);
    // A present-but-unparseable account.key is a hard error here — see
    // `store::account::load_or_generate_key`'s doc comment — because
    // silently generating a fresh key would orphan whatever the CA has on
    // file for the existing one, leaving future requests signed with a key
    // the account was never registered under.
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
        Err(e) => return fail(out, Stage::Account, &e, &args.domains, &hooks, Some(&http)),
    };

    // -- account -----------------------------------------------------------
    // Two operations under one visible line: the directory fetch (no
    // Session exists yet to authenticate with) and ensure_account (which
    // does). Only the second gets a live spinner redraw via `animate` —
    // the first is a single unauthenticated GET, typically well under a
    // second. See steps.rs's `animate` doc comment for why this can't be
    // one closure.
    let _ = out.step_running("account");
    let account_start = std::time::Instant::now();
    let directory = match fetch_directory(&http, &directory_url) {
        Ok(d) => d,
        Err(e) => return fail(out, Stage::Account, &e, &args.domains, &hooks, Some(&http)),
    };

    let mut session = Session::new(&directory, &http, &account_key);
    let email = args.email.as_deref();
    let agree_tos = args.agree_tos;
    let session_ref = &mut session;
    let (_elapsed, result) = animate(out, "account", move || {
        ensure_account(session_ref, email, agree_tos)
    });
    let (kid, outcome) = match result {
        Ok(v) => v,
        Err(e) => return fail(out, Stage::Account, &e, &args.domains, &hooks, Some(&http)),
    };
    let account_detail = match outcome {
        core::AccountOutcome::New => "new",
        core::AccountOutcome::Existing => "existing",
    };
    let _ = out.step_done_with_metric(
        "account",
        account_detail,
        &short_thumbprint(&account_key),
        account_start.elapsed(),
    );

    // account.json is a record for humans and a future `doctor`/`list`,
    // never authority — `ensure_account` above already re-verified the
    // account with the CA itself via `onlyReturnExisting` regardless of
    // what this file says.
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Err(e) =
        store::save_account_record(&account_paths, &kid, email, agree_tos, now_unix_secs)
    {
        return fail(out, Stage::Account, &e, &args.domains, &hooks, Some(&http));
    }

    // -- order ---------------------------------------------------------------
    let identifiers: Vec<Identifier> = args.domains.iter().map(|d| to_identifier(d)).collect();
    let session_ref = &mut session;
    let identifiers_ref = &identifiers;
    let (elapsed, result) = run_with_spinner(out, "order", move || {
        new_order(session_ref, identifiers_ref, None)
    });
    let order = match result {
        Ok(o) => o,
        Err(e) => return fail(out, Stage::Order, &e, &args.domains, &hooks, Some(&http)),
    };
    let wildcard_count = args.domains.iter().filter(|d| d.starts_with("*.")).count();
    let _ = out.step_done(
        "order",
        &order_detail(args.domains.len(), wildcard_count),
        elapsed,
    );

    // -- challenge: dns-01 or http-01, and validate ------------------------
    // The one path `issue` and `renew` both call. See `run_challenges`'s
    // own doc comment.
    let port = args.http01_port;
    if let Err(ChallengeFailure { stage, err, dns }) = run_challenges(
        out,
        &mut session,
        &order,
        &account_key,
        use_dns,
        provider.as_deref_mut(),
        resolver.as_ref(),
        port,
    ) {
        return if dns {
            dns01_fail(out, stage, &err, &args.domains, &hooks, Some(&http))
        } else {
            fail(out, stage, &err, &args.domains, &hooks, Some(&http))
        };
    }

    // -- certificate -------------------------------------------------------------
    // Directory named by the first requested identifier (no `--cert-name`
    // flag in this build), wildcards sanitized to `_.example.com`, nested
    // under the resolved data root regardless of whether `--out` overrode
    // that root.
    let cert_root = data_root.join(store::cert_dir_name(&args.domains[0]));
    let session_ref = &mut session;
    let order_ref = &order;
    let identifiers_ref = &identifiers;
    let dry_run = args.dry_run;
    let directory_url_ref = directory_url.as_str();
    let links_ref = &links;
    let hooks_ref = &hooks;
    let dns_provider_ref = dns_provider.as_deref();
    let dns_hook_ref = args.dns_hook.as_deref();
    let dns_cleanup_ref = args.dns_cleanup.as_deref();
    let (elapsed, result) = run_with_spinner(out, "certificate", move || {
        issue_certificate(
            session_ref,
            order_ref,
            identifiers_ref,
            &cert_root,
            dry_run,
            directory_url_ref,
            challenge_type,
            dns_provider_ref,
            dns_hook_ref,
            dns_cleanup_ref,
            false,
            links_ref,
            hooks_ref,
        )
    });
    let paths = match result {
        Ok(v) => v,
        Err(e) => {
            return fail(
                out,
                Stage::Certificate,
                &e,
                &args.domains,
                &hooks,
                Some(&http),
            )
        }
    };
    // With `finalize`/`download` genuinely skipped under `--dry-run`,
    // "issued" would be actively false rather than merely wasteful —
    // nothing was issued. "would issue" is chosen for the same reason
    // `webserver::nginx`'s own dry-run step reads "dry run" rather than
    // "edited and reloaded": a dry run must describe what it did not do,
    // not borrow the wording of the real outcome.
    let certificate_detail = if dry_run { "would issue" } else { "issued" };
    let _ = out.step_done("certificate", certificate_detail, elapsed);
    let fullchain_path = paths.fullchain.display().to_string();
    let key_path = paths.privkey.display().to_string();

    // -- nginx ----------------------------------------------------------------
    // Runs unconditionally, even under `--dry-run` — `find_and_edit`'s own
    // transaction stops after printing a diff, but it still has to be
    // *reached* for that diff to ever be shown. `--dry-run` promises to
    // report every action; skipping the preview at this call site would be
    // the opposite of that. Deliberately outside the
    // `if !dry_run` block below, which guards work `--dry-run` genuinely
    // has nothing to show for (links/hooks point at files that were never
    // written).
    let cert_domain = args.domains[0].as_str();
    let detected_server = if args.force_apache {
        Some(webserver::Server::Apache)
    } else if args.force_nginx {
        Some(webserver::Server::Nginx)
    } else {
        webserver::detect()
    };
    let nginx_edit = maybe_edit_nginx(
        &args,
        detected_server,
        cert_domain,
        &fullchain_path,
        &key_path,
        &data_root,
    );
    let (webserver_edit_status, webserver_block, webserver_restore_failed) = match &nginx_edit {
        Some(result) => render_nginx_edit(out, result, cert_domain, &fullchain_path, &key_path),
        None => (trailer::WebServerEdit::NotAttempted, Vec::new(), false),
    };

    // -- link/hook/reload ---------------------------------------------------
    // The step sequence, when configured, continues: link, export, hook,
    // reload. `dry_run` skips every one of these — nothing was actually
    // written for a link to point at or a hook to report about.
    if !dry_run {
        if !links.is_empty() {
            match store::apply_links(&paths, &links, &data_root, args.link_force) {
                Ok(used_platform_copy) => {
                    let detail = format!("{} linked", links.len());
                    let _ = out.step_done("link", &detail, std::time::Duration::ZERO);
                    if used_platform_copy {
                        let _ = out.trailer_prose(&["certway copied instead of linking — symlinks need elevation on this platform."]);
                    }
                }
                Err(e) => {
                    let _ = out.step_warned("link", &e.to_string());
                }
            }
        }

        // Re-parses the file just written rather than threading `not_after`
        // through `issue_certificate`'s return value — the hook path is
        // best-effort and never rolls back the certificate on failure, so
        // a parse failure here just yields an empty field instead of
        // aborting an already-successful issuance.
        let not_after = std::fs::read_to_string(&paths.fullchain)
            .ok()
            .and_then(|pem| ParsedCert::from_leaf_pem(&pem).ok())
            .map(|p| crate::cmd::renew::format_rfc3339(p.not_after))
            .unwrap_or_default();
        let hook_env = HookEnv {
            domains: &args.domains.join(","),
            cert_path: &fullchain_path,
            key_path: &key_path,
            not_after: &not_after,
        };
        if !hooks.is_empty() {
            hooks::run_success(out, &http, &hooks, &hook_env);
        }
    }

    // -- trailer -----------------------------------------------------------------
    if out.mode == Mode::Json {
        let _ = out.json_result_issued(&args.domains, &fullchain_path, &key_path);
    } else {
        let _ = out.trailer_paths(&fullchain_path, &key_path);
        // No timer-installation step exists in this build (`install` is a
        // later stage), so `trailer::select` never sees `timer_installed:
        // true` here — see that module's doc comment on why that keeps
        // `TimerWebServerEditedAndReloaded` correctly unreachable rather
        // than a gap.
        let closing = trailer::select(dry_run, false, webserver_edit_status).line();
        let mut lines: Vec<String> = Vec::new();
        if !webserver_block.is_empty() {
            // A specific nginx outcome (a refusal's two lines, a dry-run
            // diff, a failure's stderr and restore notice) always beats
            // the generic advice below — it was opted into and answers a
            // more specific question.
            lines.extend(webserver_block);
            lines.push(String::new());
        } else if !dry_run && nginx_edit.is_none() && links.is_empty() {
            // Editing was never attempted at all — no `--edit-nginx`,
            // `--none`, or nothing resolved to nginx (including a forced
            // `--apache`, which always falls through here). This advice
            // output is skipped only when nothing was already told where
            // to find the files (`--link`/`--link-to`). Uses
            // `detected_server` (not a fresh `webserver::detect()` call) so
            // a forced `--nginx`/`--apache` is reflected here too, not just
            // in the editing gate.
            lines.extend(webserver::advice(
                detected_server,
                &fullchain_path,
                &key_path,
            ));
            lines.push(String::new());
        }
        lines.push(closing.to_string());
        let line_refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let _ = out.trailer_prose(&line_refs);
    }

    // Restore verification is not optional: a restore that itself fails is
    // reported at maximum severity because the user must intervene by
    // hand. None of these outcomes except `RestoreFailed` is an issuance
    // failure — the certificate itself is fine and already on disk (exit 0
    // for every other nginx outcome, including every other restore), but
    // this one leaves the live nginx config in an unverified state that
    // needs a human, which is what exit code 1 ("unexpected failure")
    // signals everywhere else in this program. This is a judgement call,
    // not a value pinned anywhere else — no exit code for this exact case
    // is specified.
    if webserver_restore_failed {
        1
    } else {
        0
    }
}

/// The nginx-editing gate. Editing stays opt-in: without `--edit-nginx`,
/// `None` here, unchanged from every build before this — the trailer's
/// advice-only fallback above is exactly what ran before. **The default
/// flips to auto-edit only once a confirmation prompt exists to ask
/// first** — editing a production `nginx.conf` with no prompt and no
/// explicit opt-in would be a destructive default nobody asked for.
/// Whoever adds that prompt is the one who should also flip this default;
/// until then, this gate is the one place that decision lives.
///
/// `--none` takes precedence over everything, including `--edit-nginx`.
/// `detected` is the caller's own forced-or-detected server (computed
/// once, shared with the advice fallback) — when it isn't `Nginx` (nothing
/// detected, or `--apache` forced), this returns `None` and the trailer's
/// advice path takes over; this stage never edits Apache, which is by far
/// the least-grounded part of the webserver-detection logic.
fn maybe_edit_nginx(
    args: &IssueArgs,
    detected: Option<webserver::Server>,
    domain: &str,
    fullchain_path: &str,
    key_path: &str,
    data_root: &std::path::Path,
) -> Option<Result<webserver::nginx::EditOutcome, core::Error>> {
    if !args.edit_nginx || args.none || detected != Some(webserver::Server::Nginx) {
        return None;
    }

    let install = webserver::nginx::detect_installation("nginx")?;
    let registry_path = data_root.join("edits.jsonl");
    let validator = webserver::nginx::transaction::NginxValidator {
        entry_config_path: Some(install.entry_config_path.clone()),
        nginx_bin: "nginx".to_string(),
    };
    let reloader = webserver::nginx::transaction::SystemReloader {
        nginx_bin: "nginx".to_string(),
    };
    let fs = webserver::nginx::parse::RealFs { root: None };
    let req = webserver::nginx::EditRequest {
        entry_config_path: &install.entry_config_path,
        prefix: &install.prefix,
        domain,
        fullchain_path,
        key_path,
        redirect: args.redirect,
        dry_run: args.dry_run,
        http2_supported: install.http2_supported,
        registry_path: Some(&registry_path),
        fs: &fs,
        validator: &validator,
        reloader: &reloader,
    };
    Some(webserver::nginx::find_and_edit(&req))
}

/// Renders every `EditOutcome` — a step line always, a block for the
/// outcomes that need one — and classifies it for `trailer::select`.
/// Returns `(classification, trailer block lines,
/// is_issuance_failure)` — the block is collected rather than printed
/// immediately because it belongs inside the same single `trailer_prose`
/// call as everything else in the closing paragraph (the same pattern
/// `webserver::advice`'s lines already used before this stage).
fn render_nginx_edit(
    out: &mut Out<impl Write>,
    outcome: &Result<webserver::nginx::EditOutcome, core::Error>,
    domain: &str,
    fullchain_path: &str,
    key_path: &str,
) -> (trailer::WebServerEdit, Vec<String>, bool) {
    use webserver::nginx::EditOutcome;

    let two_lines = || {
        vec![
            format!("    ssl_certificate      {fullchain_path};"),
            format!("    ssl_certificate_key  {key_path};"),
        ]
    };

    match outcome {
        // A wiring-level I/O failure (e.g. the config file vanished
        // between `find_and_edit`'s read and now) isn't one of
        // `EditOutcome`'s own cases. The certificate is already written,
        // so this is reported the same as "not edited," never as an
        // issuance failure this late.
        Err(e) => {
            let _ = out.step_warned("nginx", &e.to_string());
            (trailer::WebServerEdit::NotAttempted, Vec::new(), false)
        }
        Ok(EditOutcome::Edited { .. }) => {
            let _ = out.step_done("nginx", "edited and reloaded", std::time::Duration::ZERO);
            (trailer::WebServerEdit::EditedAndReloaded, Vec::new(), false)
        }
        Ok(EditOutcome::DryRun { diff }) => {
            let _ = out.step_done("nginx", "dry run", std::time::Duration::ZERO);
            let mut lines = vec!["--edit-nginx would make this change:".to_string(), String::new()];
            lines.extend(diff.lines().map(str::to_string));
            (trailer::WebServerEdit::NotAttempted, lines, false)
        }
        Ok(EditOutcome::NoMatchingBlock) => {
            let _ = out.step_warned("nginx", &format!("no server block for {domain}"));
            let mut lines = vec![
                "certway found nginx but no server block matching this domain.".to_string(),
                "Add these two lines to the right block yourself:".to_string(),
                String::new(),
            ];
            lines.extend(two_lines());
            (trailer::WebServerEdit::Refused, lines, false)
        }
        Ok(EditOutcome::Refused { reason }) => {
            let _ = out.step_warned("nginx", &refusal_reason_text(reason));
            let mut lines = vec![
                "Add these two lines to the right block yourself:".to_string(),
                String::new(),
            ];
            lines.extend(two_lines());
            (trailer::WebServerEdit::Refused, lines, false)
        }
        Ok(EditOutcome::PreexistingConfigInvalid { stderr }) => {
            let _ = out.step_warned("nginx", "configuration was already invalid");
            let mut lines = vec![
                "nginx -t failed before certway touched anything:".to_string(),
                String::new(),
            ];
            lines.extend(stderr.lines().map(str::to_string));
            (trailer::WebServerEdit::NotAttempted, lines, false)
        }
        Ok(EditOutcome::ValidationFailedRestored {
            backup_path,
            stderr,
        }) => {
            let _ = out.step_failed("nginx", "nginx rejected the change");
            let mut lines = vec![
                "nginx rejected the edit; the previous configuration was restored:".to_string(),
                String::new(),
            ];
            lines.extend(stderr.lines().map(str::to_string));
            lines.push(String::new());
            lines.push(format!("backup   {}", backup_path.display()));
            (trailer::WebServerEdit::NotAttempted, lines, false)
        }
        Ok(EditOutcome::ReloadFailedRestored {
            backup_path,
            reload_error,
        }) => {
            let _ = out.step_failed("nginx", "nginx accepted the change but reload failed");
            let mut lines = vec![
                "The reload failed; the previous configuration was restored:".to_string(),
                String::new(),
            ];
            lines.extend(reload_error.lines().map(str::to_string));
            lines.push(String::new());
            lines.push(format!("backup   {}", backup_path.display()));
            (trailer::WebServerEdit::NotAttempted, lines, false)
        }
        Ok(EditOutcome::RestoreFailed {
            backup_path,
            restore_stderr,
        }) => {
            let _ = out.step_failed("nginx", "restore failed — repair the config by hand");
            let mut lines = vec![
                "certway could not restore the previous configuration. Fix this by hand:"
                    .to_string(),
                String::new(),
            ];
            lines.extend(restore_stderr.lines().map(str::to_string));
            lines.push(String::new());
            lines.push(format!("backup   {}", backup_path.display()));
            (trailer::WebServerEdit::NotAttempted, lines, true)
        }
    }
}

/// The step line's `<reason>` for a `Refused` outcome — one sentence per
/// `matching.rs`'s `RefusalReason` (and `mod.rs`'s two edit-content
/// refusals). Covers the same ground as the refusal conditions themselves
/// ("intent is ambiguous," "cannot be evaluated statically," "cannot
/// choose safely," "`if` is notoriously non-local," "provenance unclear")
/// in substance, not verbatim — those name *why* certway refuses; this
/// names *what certway found*, for the line printed after `! nginx`.
fn refusal_reason_text(reason: &webserver::nginx::RefusalKind) -> String {
    use webserver::nginx::matching::RefusalReason;
    use webserver::nginx::RefusalKind;
    match reason {
        RefusalKind::Matching(RefusalReason::Regex) => {
            "the matching block is selected by a regex server_name".to_string()
        }
        RefusalKind::Matching(RefusalReason::VariableServerName) => {
            "the matching block's server_name contains a variable".to_string()
        }
        RefusalKind::Matching(RefusalReason::Ambiguous) => {
            "more than one server block matches this domain".to_string()
        }
        RefusalKind::Matching(RefusalReason::InsideIf) => {
            "the matching block is inside an `if`".to_string()
        }
        RefusalKind::Matching(RefusalReason::SymlinkOutsideTree) => {
            "the config file is a symlink outside nginx's config tree".to_string()
        }
        RefusalKind::AmbiguousCertificateDirectives => {
            "the block's existing certificate directives are ambiguous".to_string()
        }
        RefusalKind::MalformedBlock => "the matching block is malformed".to_string(),
    }
}

/// Expands `--link-to <dir>` into one `LinkSpec` per file
/// (`fullchain`/`cert`/`chain`/`privkey`, `<dir>/<name>.pem`) and appends
/// `--link <name>=<path>` (repeatable) on top — a later `--link` for the
/// same name replaces the `--link-to`-derived entry for it, the same
/// "last one wins" rule `args.rs`'s own value flags already use.
pub(crate) fn links_from_args(
    link_to: &Option<String>,
    explicit: &[(String, String)],
    copy: bool,
) -> Vec<LinkSpec> {
    let mut by_name: Vec<LinkSpec> = Vec::new();
    if let Some(dir) = link_to {
        for name in ["fullchain", "cert", "chain", "privkey"] {
            let target = format!("{}/{name}.pem", dir.trim_end_matches('/'));
            by_name.push(LinkSpec {
                name: name.to_string(),
                target,
                copy,
            });
        }
    }
    for (name, path) in explicit {
        by_name.retain(|l| &l.name != name);
        by_name.push(LinkSpec {
            name: name.clone(),
            target: path.clone(),
            copy,
        });
    }
    by_name
}

fn to_identifier(domain: &str) -> Identifier {
    match domain.parse::<std::net::IpAddr>() {
        Ok(ip) => Identifier::Ip(ip),
        Err(_) => Identifier::Dns(domain.to_string()),
    }
}

fn order_detail(n: usize, wildcards: usize) -> String {
    let noun = if n == 1 { "domain" } else { "domains" };
    if wildcards > 0 {
        format!("{n} {noun} ({wildcards} wildcard)")
    } else {
        format!("{n} {noun}")
    }
}

fn short_thumbprint(key: &AccountKey) -> String {
    let hex: String = key
        .thumbprint()
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    hex[..7].to_string()
}

pub(crate) type ServerHandle = (JoinHandle<()>, Arc<AtomicBool>);

/// The `challenge` step's work: fetch each authorization, skip the ones
/// already `valid` entirely — no provisioning, no challenge answered — and
/// for the rest, provision the http-01 response
/// and answer it. Returns the authorization URLs that still need polling,
/// how many were skipped as already-valid, and — if a responder was
/// needed — its background thread and stop flag, still running, for the
/// `validate` step to poll against and the caller to stop afterwards.
pub(crate) fn provision_challenges(
    session: &mut Session,
    order: &Order,
    account_key: &AccountKey,
    port: u16,
) -> Result<(Vec<String>, usize, Option<ServerHandle>), core::Error> {
    let mut to_poll = Vec::new();
    let mut skipped = 0usize;
    let mut server: Option<Http01Server> = None;

    for authz_url in &order.authorizations {
        let authz = fetch_authorization(session, authz_url)?;
        match plan_authorization(&authz, core::ChallengeType::Http01)? {
            AuthzAction::Skip => skipped += 1,
            AuthzAction::Answer(challenge) => {
                let key_auth =
                    certway_core::crypto::key_authorization(&challenge.token, account_key);
                if server.is_none() {
                    server = Some(Http01Server::bind(port)?);
                }
                if let Some(s) = server.as_mut() {
                    s.add(&challenge.token, &key_auth);
                }
                answer_challenge(session, &challenge.url)?;
                to_poll.push(authz_url.clone());
            }
        }
    }

    let handle = server.map(|s| {
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        let mut s = s;
        let thread = std::thread::spawn(move || {
            let _ = s.serve_until(&|| done_clone.load(Ordering::Relaxed));
        });
        (thread, done)
    });

    Ok((to_poll, skipped, handle))
}

/// The `dns` step's work: fetch every authorization first, skipping the
/// ones already `valid`, and build one `Task` per remaining one — then
/// hand the *whole* batch to `solver.prepare` in a single call before
/// answering any challenge. This is what makes the two-record wildcard
/// case (`example.com` + `*.example.com` sharing one order) correct rather
/// than accidental: only once every record exists does this start telling
/// ACME to validate — answering the first challenge before the second
/// record exists would leave that second validation racing DNS
/// propagation it has no way to wait for.
pub(crate) fn provision_dns_challenges(
    session: &mut Session,
    order: &Order,
    account_key: &AccountKey,
    solver: &mut Dns01Solver,
) -> Result<(Vec<String>, usize), core::Error> {
    let mut tasks = Vec::new();
    let mut challenge_urls = Vec::new();
    let mut to_poll = Vec::new();
    let mut skipped = 0usize;

    for authz_url in &order.authorizations {
        let authz = fetch_authorization(session, authz_url)?;
        match plan_authorization(&authz, core::ChallengeType::Dns01)? {
            AuthzAction::Skip => skipped += 1,
            AuthzAction::Answer(challenge) => {
                let key_authorization =
                    certway_core::crypto::key_authorization(&challenge.token, account_key);
                tasks.push(core::Task {
                    identifier: authz.identifier.clone(),
                    token: challenge.token.clone(),
                    key_authorization,
                });
                challenge_urls.push(challenge.url.clone());
                to_poll.push(authz_url.clone());
            }
        }
    }

    if !tasks.is_empty() {
        solver.prepare(&tasks)?;
        for url in &challenge_urls {
            answer_challenge(session, url)?;
        }
    }

    Ok((to_poll, skipped))
}

/// Runs `solver.cleanup()` and reports it: always attempted when records
/// were created, silent otherwise — cleanup is only worth a line when DNS
/// records were actually created, and the converse also holds, nothing to
/// say if nothing was ever created, e.g. `prepare` itself failed before
/// creating anything. A cleanup failure is reported as a warning, not an
/// error — it never replaces or masks whatever the caller is about to
/// report as the real failure.
fn run_dns_cleanup(out: &mut Out<impl Write>, solver: &mut Dns01Solver) {
    let created = solver.record_count();
    if created == 0 {
        return;
    }
    match solver.cleanup() {
        Ok(()) => {
            let _ = out.step_done(
                "cleanup",
                &format!("{created} records removed"),
                std::time::Duration::ZERO,
            );
        }
        Err(e) => {
            let _ = out.step_warned("cleanup", &format!("{created} records may remain: {e}"));
        }
    }
}

/// What failed, and how the caller should report it — `stage` for
/// `report::classify`, `dns` so the caller picks `dns01_fail` (the
/// signal-aware exit code) over plain `fail` exactly when `run_challenges`
/// took the dns-01 branch, matching what `issue::run` did inline before
/// this was extracted.
pub(crate) struct ChallengeFailure {
    pub stage: Stage,
    pub err: core::Error,
    pub dns: bool,
}

/// The challenge → validate sequence, dns-01 or http-01 — the one path
/// `issue` and `renew` both call. `use_dns` selects the branch;
/// `provider`/`resolver` are only read on the dns-01 one and must be
/// `Some` there — the caller decided `use_dns` from the same
/// flag/`config.json` precedence that built them, so a mismatch here is a
/// caller bug, not a runtime condition to handle gracefully.
///
/// Prints every step itself (`dns`/`propagate`/`challenge`/`validate`,
/// `cleanup` on the dns-01 branch) — the caller only needs the final
/// authorized count, or a `ChallengeFailure` to report and exit on.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_challenges<'p, 'd>(
    out: &mut Out<impl Write>,
    session: &mut Session,
    order: &Order,
    account_key: &AccountKey,
    use_dns: bool,
    // Two lifetimes, deliberately not tied together: `'p` is only how long
    // *this call* borrows the caller's `provider` slot; `'d` is however
    // long the concrete provider behind it (e.g. `CloudflareProvider<'d>`,
    // itself borrowing `&'d Client`) was built to live. Eliding this to one
    // lifetime forces `'d == 'p`, which then makes the compiler treat the
    // *call's* short borrow as if it had to survive as long as the
    // provider value itself does in the caller — past this function
    // returning, all the way to wherever the caller's `provider` binding is
    // finally dropped.
    provider: Option<&'p mut (dyn DnsTxtProvider + Send + 'd)>,
    resolver: Option<&Resolver>,
    http01_port: u16,
) -> Result<usize, ChallengeFailure> {
    let total = order.authorizations.len();

    if use_dns {
        let resolver_ref = resolver.expect("resolver required for dns-01, checked by the caller");
        let provider_ref = provider.expect("provider required for dns-01, checked by the caller");
        let mut solver = Dns01Solver::new(provider_ref, resolver_ref, &crate::signal::requested);

        // -- dns: create every TXT record for the order at once ------------
        let session_ref = &mut *session;
        let solver_ref = &mut solver;
        let (elapsed, result) = run_with_spinner(out, "dns", move || {
            provision_dns_challenges(session_ref, order, account_key, solver_ref)
        });
        let (authz_to_poll, already_valid) = match result {
            Ok(v) => v,
            Err(e) => {
                run_dns_cleanup(out, &mut solver);
                return Err(ChallengeFailure {
                    stage: Stage::Challenge,
                    err: e,
                    dns: true,
                });
            }
        };
        let _ = out.step_done(
            "dns",
            &format!("{} records created", solver.record_count()),
            elapsed,
        );

        // -- propagate: every authoritative nameserver agrees ---------------
        let solver_ref = &mut solver;
        let (elapsed, result) = run_with_spinner(out, "propagate", move || solver_ref.ready());
        if let Err(e) = result {
            run_dns_cleanup(out, &mut solver);
            return Err(ChallengeFailure {
                stage: Stage::Challenge,
                err: e,
                dns: true,
            });
        }
        let servers = solver.last_authoritative_server_count();
        let _ = out.step_done(
            "propagate",
            &format!("visible on {servers} nameservers"),
            elapsed,
        );

        // -- validate --------------------------------------------------------
        let session_ref = &mut *session;
        let authz_to_poll_ref = &authz_to_poll;
        let (elapsed, result) = run_with_spinner(out, "validate", move || {
            validate_authorizations(session_ref, authz_to_poll_ref, already_valid)
        });
        let valid_count = match result {
            Ok(n) => n,
            Err(e) => {
                run_dns_cleanup(out, &mut solver);
                return Err(ChallengeFailure {
                    stage: Stage::Validate,
                    err: e,
                    dns: true,
                });
            }
        };
        let _ = out.step_done(
            "validate",
            &format!("{valid_count} of {total} authorized"),
            elapsed,
        );

        // -- cleanup: always, once validation is decided either way ---------
        run_dns_cleanup(out, &mut solver);
        Ok(valid_count)
    } else {
        let session_ref = &mut *session;
        let (elapsed, result) = run_with_spinner(out, "challenge", move || {
            provision_challenges(session_ref, order, account_key, http01_port)
        });
        let (authz_to_poll, already_valid, server_handle) = match result {
            Ok(v) => v,
            Err(e) => {
                return Err(ChallengeFailure {
                    stage: Stage::Challenge,
                    err: e,
                    dns: false,
                })
            }
        };
        let challenge_detail = if authz_to_poll.is_empty() {
            "already authorized".to_string()
        } else {
            format!("http-01 on :{http01_port}")
        };
        let _ = out.step_done("challenge", &challenge_detail, elapsed);

        let session_ref = &mut *session;
        let authz_to_poll_ref = &authz_to_poll;
        let (elapsed, result) = run_with_spinner(out, "validate", move || {
            validate_authorizations(session_ref, authz_to_poll_ref, already_valid)
        });

        // Stop the http-01 responder now, regardless of outcome — Let's
        // Encrypt may have hit it any time up to this point, never after.
        if let Some((thread, done)) = server_handle {
            done.store(true, Ordering::Relaxed);
            let _ = thread.join();
        }

        let valid_count = match result {
            Ok(n) => n,
            Err(e) => {
                return Err(ChallengeFailure {
                    stage: Stage::Validate,
                    err: e,
                    dns: false,
                })
            }
        };
        let _ = out.step_done(
            "validate",
            &format!("{valid_count} of {total} authorized"),
            elapsed,
        );
        Ok(valid_count)
    }
}

/// `fail`, but overriding the exit code to 1 when a shutdown signal was
/// what actually ended this run — distinct from `report::exit_code`'s
/// ordinary classification of the error itself, which has no way to tell
/// "the DNS propagation wait was interrupted by SIGTERM" apart from "it
/// genuinely timed out": both surface as the same `PollExhausted` (see
/// `Dns01Solver::ready`'s doc comment on why no separate error variant
/// exists for this).
pub(crate) fn dns01_fail(
    out: &mut Out<impl Write>,
    stage: Stage,
    err: &core::Error,
    domains: &[String],
    hooks: &HookConfig,
    http: Option<&Client>,
) -> i32 {
    let code = fail(out, stage, err, domains, hooks, http);
    if crate::signal::requested() {
        1
    } else {
        code
    }
}

/// The `validate` step's work: poll every authorization that was answered
/// until it leaves pending/processing. `already_valid` is folded straight
/// into the count — those authorizations are already proven, by the same
/// already-`valid` check that skipped provisioning them in the first
/// place.
pub(crate) fn validate_authorizations(
    session: &mut Session,
    to_poll: &[String],
    already_valid: usize,
) -> Result<usize, core::Error> {
    let mut valid = already_valid;
    for url in to_poll {
        let authz = poll_authorization(session, url)?;
        if authz.status == AuthzStatus::Valid {
            valid += 1;
            continue;
        }
        let problem = authz.challenges.iter().find_map(|c| c.error.clone());
        return Err(match problem {
            Some(p) => core::Error::Acme(p),
            None => core::Error::io(
                url,
                std::io::Error::other(format!("authorization ended {:?}", authz.status)),
            ),
        });
    }
    Ok(valid)
}

/// What actually gets recorded into `config.json`'s `challenge`/
/// `dns_provider` fields, from the same two flags that decide `use_dns`
/// above — a pure function so it's unit-testable without a live ACME
/// session. Getting this wrong is not cosmetic: `config.json` is what
/// `renew` reads back, so a certificate actually issued via `dns-01` but
/// recorded as `http-01` would be wrong data sitting on disk, silently,
/// until something acts on it.
pub(crate) fn challenge_record(
    dns: &Option<String>,
    dns_hook: &Option<String>,
) -> (&'static str, Option<String>) {
    if let Some(provider) = dns {
        ("dns-01", Some(provider.clone()))
    } else if dns_hook.is_some() {
        ("dns-01", Some("hook".to_string()))
    } else {
        ("http-01", None)
    }
}

/// The `certificate` step's work: generate the certificate key, build and
/// finalize the CSR, download the chain, and write both files. Post-
/// download verification (chain parses, SANs cover every requested
/// identifier, leaf key matches ours) is certificate parsing, out of scope
/// for this function.
///
/// `dry_run` is checked *before* any of that, not after. `finalize` is
/// real Let's Encrypt's actual point of no return: it counts against the
/// domain's weekly issuance rate limit and hands back a real, valid,
/// downloadable certificate — it does not care whether the caller intends
/// to write the result to disk. The bug this guards against shipped and
/// was only caught by running `--dry-run` against real production Let's
/// Encrypt (never against Pebble, which doesn't enforce that limit
/// meaningfully): certway finalized the order, downloaded a real
/// certificate, then printed "Nothing was changed." A `--dry-run` that
/// silently spends the one scarce resource it exists to protect the user
/// from wasting is worse than doing nothing — `--dry-run` promises to
/// change nothing, and consuming rate-limit quota is a change.
/// `store::cert_paths` is pure path arithmetic, no I/O, so it's safe to
/// build even though the files it names don't exist yet.
#[allow(clippy::too_many_arguments)]
fn issue_certificate(
    session: &mut Session,
    order: &Order,
    identifiers: &[Identifier],
    cert_root: &std::path::Path,
    dry_run: bool,
    ca_directory: &str,
    challenge_type: &str,
    dns_provider: Option<&str>,
    dns_hook: Option<&str>,
    dns_cleanup: Option<&str>,
    reuse_key: bool,
    links: &[LinkSpec],
    hooks: &HookConfig,
) -> Result<store::CertPaths, core::Error> {
    if dry_run {
        return Ok(store::cert_paths(cert_root));
    }

    let cert_key = CertKey::generate()?;
    let csr_der = build_csr(&cert_key, identifiers)?;
    let finalized = finalize(session, order, &csr_der)?;
    let cert_url = match &finalized.certificate {
        Some(u) => u.clone(),
        None => {
            return Err(core::Error::io(
                "<order>",
                std::io::Error::other("order valid but no certificate url present"),
            ))
        }
    };
    let pem = download_certificate(session, &cert_url)?;
    let key_pem = cert_key.to_pkcs8_pem();

    // `key_algorithm` is fixed at "ecdsa-p256": `CertKey::generate` always
    // asks rcgen for its default, `PKCS_ECDSA_P256_SHA256` — no
    // `--key-alg` flag exists in this build. `exports` is always empty
    // here: issue-time export configuration has no flag — only the
    // standalone `export` command records one.
    store::write_certificate(
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
        &[],
    )
}

/// `http`: the run's own client, when one exists yet at the call site —
/// threaded through to `hooks::run_failure` so `--hook-url` on the failure
/// path reaches a sidecar behind a custom `--ca-bundle` the same way the
/// success path already does. `None` is correct (not a shortcut) at the
/// handful of call sites that fail before any `Client` could exist.
pub(crate) fn fail(
    out: &mut Out<impl Write>,
    stage: Stage,
    err: &core::Error,
    domains: &[String],
    hooks: &HookConfig,
    http: Option<&Client>,
) -> i32 {
    let subject = domains.join(", ");
    let block = report::classify(err, stage, Proven::default(), &subject);
    if out.mode == Mode::Json {
        let slug = report::error_slug(err);
        let _ = out.json_step_failed(stage.label(), &slug, &block.summary);
        // Deliberately narrow: creating an order consumes Let's Encrypt's
        // "new orders" limit, but the limit users mean by "quota" is
        // certificates issued per domain, which is only ever touched once
        // `finalize` runs in the `certificate` stage. A failure at `order`
        // or `challenge` should not read as having spent that budget.
        let quota_used = matches!(stage, Stage::Certificate);
        let _ = out.json_result_failed(stage.label(), &slug, quota_used);
    } else {
        let _ = out.step_failed(block.label, &block.subject);
        let _ = out.error_block(&block);
    }
    // `--hook-failure`/`--hook-url` fire on every failure. Best-effort —
    // `hooks::run_failure` swallows its own errors
    // rather than risk masking the real failure already reported above.
    hooks::run_failure(hooks, http, &subject, stage.label(), &block.summary);
    report::exit_code(err, stage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_detail_singular_no_wildcard() {
        assert_eq!(order_detail(1, 0), "1 domain");
    }

    #[test]
    fn order_detail_plural_with_wildcard() {
        assert_eq!(order_detail(2, 1), "2 domains (1 wildcard)");
    }

    #[test]
    fn to_identifier_recognises_ip_literal() {
        assert!(matches!(to_identifier("203.0.113.9"), Identifier::Ip(_)));
        assert!(matches!(to_identifier("example.com"), Identifier::Dns(_)));
    }

    // -- challenge_record: what gets recorded into config.json ---------------

    #[test]
    fn challenge_record_is_http01_with_no_provider_by_default() {
        let (challenge, provider) = challenge_record(&None, &None);
        assert_eq!(challenge, "http-01");
        assert!(provider.is_none());
    }

    #[test]
    fn challenge_record_is_dns01_with_the_named_provider_for_dash_dash_dns() {
        let (challenge, provider) = challenge_record(&Some("cloudflare".to_string()), &None);
        assert_eq!(challenge, "dns-01");
        assert_eq!(provider.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn challenge_record_is_dns01_for_dash_dash_dns_hook_too() {
        let (challenge, provider) =
            challenge_record(&None, &Some("/usr/local/bin/my-dns-hook".to_string()));
        assert_eq!(challenge, "dns-01");
        assert_eq!(provider.as_deref(), Some("hook"));
    }

    /// `write_certificate` was once always called with the literal
    /// `"http-01"`, so a `--dns-hook` issuance recorded the wrong challenge
    /// type — wrong data sitting on disk, waiting for a future `renew` that
    /// reads it. This test goes through the real `challenge_record` decision
    /// and the real `write_certificate`/`read_config` round-trip, not a
    /// value either side supplies to itself — the same class of tautology
    /// that once let `CERTWAY_NOT_AFTER` ship empty.
    #[test]
    fn a_dns_hook_issuance_records_dns01_in_config_json_not_http01() {
        let (challenge_type, dns_provider) =
            challenge_record(&None, &Some("/usr/local/bin/my-dns-hook".to_string()));

        let root = std::env::temp_dir().join(format!(
            "certway-challenge-record-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let cert_root = root.join(store::cert_dir_name("example.com"));
        let fullchain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";

        let paths = store::write_certificate(
            &cert_root,
            fullchain,
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            challenge_type,
            dns_provider.as_deref(),
            None,
            None,
            "ecdsa-p256",
            false,
            "https://acme-staging-v02.api.letsencrypt.org/directory",
            &[],
            &store::HookConfig::default(),
            &[],
        )
        .unwrap();

        let config = store::read_config(&paths.config).unwrap();
        assert_eq!(config.challenge, "dns-01");
        assert_ne!(
            config.challenge, "http-01",
            "a dns-01 issuance must never be recorded as http-01"
        );
        assert_eq!(config.dns_provider.as_deref(), Some("hook"));

        let _ = std::fs::remove_dir_all(&root);
    }

    fn dummy_session_pieces() -> (core::Directory, Client, AccountKey) {
        let directory = core::Directory {
            new_nonce: "https://a/nonce".to_string(),
            new_account: "https://a/acct".to_string(),
            new_order: "https://a/order".to_string(),
            revoke_cert: "https://a/revoke".to_string(),
            key_change: "https://a/key-change".to_string(),
            renewal_info: None,
            terms_of_service: None,
            external_account_required: false,
        };
        // Client::new() parses only the embedded PEM and builds a local
        // rustls config — no network I/O, so this is safe in a unit test.
        let http = Client::new().expect("client construction with embedded root");
        let key = AccountKey::generate().expect("account key generation");
        (directory, http, key)
    }

    /// The claim at the level that actually ships: when every authorization
    /// was already valid, `challenge` never touches the session or the
    /// network, and `validate` reports all of them authorized purely from
    /// the count carried over — no polling call is made (`to_poll` is
    /// empty), which this test proves by using a session that would error
    /// on any real request (its URLs are not servers).
    #[test]
    fn validate_authorizations_counts_already_valid_without_polling() {
        let (directory, http, key) = dummy_session_pieces();
        let mut session = Session::new(&directory, &http, &key);
        let result = validate_authorizations(&mut session, &[], 2);
        assert_eq!(result.unwrap(), 2);
    }

    /// The bug found live against real production Let's Encrypt: a
    /// `--dry-run` issuance finalized the order and downloaded a real
    /// certificate before ever checking `dry_run`, silently spending a
    /// real weekly rate-limit slot while telling the user "Nothing was
    /// changed." `order.finalize` here points at an unreachable host — if
    /// `issue_certificate` ever calls `finalize()` before its `dry_run`
    /// check, this errors (DNS/connection failure) instead of returning
    /// `Ok`, so this test fails exactly the way the real bug would have,
    /// without needing a live CA to prove it.
    #[test]
    fn issue_certificate_under_dry_run_never_calls_finalize_or_download() {
        let (directory, http, key) = dummy_session_pieces();
        let mut session = Session::new(&directory, &http, &key);
        let order = core::Order {
            url: "https://a/order/1".to_string(),
            status: core::OrderStatus::Ready,
            authorizations: vec![],
            finalize: "https://a/finalize/1".to_string(),
            certificate: None,
        };
        let identifiers = vec![Identifier::Dns("example.com".to_string())];
        let root = std::env::temp_dir().join(format!(
            "certway-issue-dry-run-no-finalize-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);

        let result = issue_certificate(
            &mut session,
            &order,
            &identifiers,
            &root,
            true, // dry_run
            "https://acme-staging-v02.api.letsencrypt.org/directory",
            "http-01",
            None,
            None,
            None,
            false,
            &[],
            &store::HookConfig::default(),
        );

        if let Err(e) = &result {
            panic!("a dry run must never attempt to reach the CA at all: {e}");
        }
        assert!(
            !root.exists(),
            "a dry run must never create the certificate directory either"
        );
    }

    // Atomic-write and directory-mode coverage moved to `store::atomic`'s
    // own tests — `issue.rs` now delegates to `store::write_certificate`
    // rather than writing files itself.
}
