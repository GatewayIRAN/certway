// SPDX-License-Identifier: MIT

//! `find_and_edit` — the public façade tying `parse`/`matching`/`edit`/
//! `transaction` together into the one operation `webserver/mod.rs`'s
//! issuance orchestrator calls.
//!
//! Search order: a `:443 ssl` block for the domain, if found, is edited in
//! place. Only when *nothing* answers
//! `:443` is a plain `:80` block searched for, and a match there gets a
//! brand-new `:443` block appended after it. A `:80` match and a `:443`
//! match for the same domain existing simultaneously is the normal case,
//! not ambiguity — `matching::find_server_block` is scoped per port for
//! exactly this reason.

pub mod edit;
pub mod matching;
pub mod parse;
pub mod registry;
pub mod tokenize;
pub mod transaction;
pub mod version;

use certway_core::{self as core};
use parse::Directive;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub enum EditOutcome {
    Edited {
        backup_path: PathBuf,
        redirect: RedirectOutcome,
    },
    /// Neither a `:443` nor a `:80` block names this domain — not a
    /// failure of issuance, this is the "add these two lines yourself"
    /// case.
    NoMatchingBlock,
    Refused {
        reason: RefusalKind,
    },
    PreexistingConfigInvalid {
        stderr: String,
    },
    DryRun {
        diff: String,
    },
    ValidationFailedRestored {
        backup_path: PathBuf,
        stderr: String,
    },
    ReloadFailedRestored {
        backup_path: PathBuf,
        reload_error: String,
    },
    RestoreFailed {
        backup_path: PathBuf,
        restore_stderr: String,
    },
}

/// Every reason `find_and_edit` can decline to touch a file — a block-
/// selection refusal (`matching.rs`) or an edit-content refusal
/// (`edit.rs`'s ambiguous/malformed certificate-directive shapes). One
/// wrapping enum so callers handle "refused, report the two lines by
/// hand" as a single case regardless of which layer raised it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalKind {
    Matching(matching::RefusalReason),
    AmbiguousCertificateDirectives,
    MalformedBlock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectOutcome {
    /// `--redirect` was not given.
    NotRequested,
    Written,
    /// `--redirect` was given, but a `:80` block already names this exact
    /// domain — always true on the append-new-block path (that block *is*
    /// how the domain was found), sometimes true on the in-place path.
    /// Writing a second `:80 server_name <domain>` block would create the
    /// shadowing duplicate `transaction.rs`'s strict post-edit check
    /// exists to catch; skipped rather than risked.
    SkippedExistingHttpBlock,
    /// `--redirect` was given, but the independent `:80` search hit a
    /// refusal condition (regex/variable/ambiguous/inside-if) rather than
    /// a clean "nothing there" — too uncertain to safely add a competing
    /// block, so the redirect is skipped and only the certificate edit
    /// proceeds.
    SkippedRefused,
}

pub struct EditRequest<'a> {
    pub entry_config_path: &'a Path,
    /// The `nginx -V` compiled prefix — relative `include`s resolve
    /// against this, and it doubles as the config tree's root for the
    /// symlink-provenance check.
    pub prefix: &'a Path,
    pub domain: &'a str,
    pub fullchain_path: &'a str,
    pub key_path: &'a str,
    pub redirect: bool,
    pub dry_run: bool,
    /// Resolved once by the caller via
    /// `transaction::detect_http2_directive_support` — not re-detected
    /// here, so this module stays provable without invoking a real
    /// `nginx` binary.
    pub http2_supported: bool,
    /// Where to log a successful edit for `rollback`'s no-argument listing
    /// (`registry.rs`) — `None` skips registration entirely (every test
    /// below; a caller with no data root to log to).
    pub registry_path: Option<&'a Path>,
    pub fs: &'a dyn parse::ConfigFs,
    pub validator: &'a dyn transaction::Validator,
    pub reloader: &'a dyn transaction::Reloader,
}

/// Everything `EditRequest` needs to know about a live nginx binary,
/// resolved once from `nginx -V` — `detect` above only answers *whether*
/// nginx is present, never where its config tree lives.
pub struct Installation {
    /// `EditRequest.prefix`: the symlink-provenance check's root, and
    /// where a truly relative `include` resolves. **Not the raw compiled
    /// `--prefix`** — `entry_config_path`'s own parent directory, where
    /// the config tree (`sites-available`/`sites-enabled`/`conf.d`)
    /// actually lives. Found live on a real Ubuntu box: with
    /// `--prefix=/usr/share/nginx` and `--conf-path=/etc/nginx/nginx.conf`
    /// independent, using the raw `--prefix` here reported Debian/Ubuntu's
    /// own stock `sites-enabled -> sites-available` symlink — the standard
    /// way Debian/Ubuntu package and enable nginx sites — as "outside the
    /// config tree" and refused to edit it. For the pinned container this
    /// is a no-op: `<prefix>/nginx.conf`'s parent is `prefix` itself.
    pub prefix: PathBuf,
    /// `--conf-path`, when the build set one distinct from `--prefix`;
    /// otherwise `<prefix>/nginx.conf`. **Not always the same question** —
    /// found live on a real Ubuntu box's packaged nginx
    /// (`version::parse_configure_arguments`'s doc comment has the full
    /// story): `--prefix=/usr/share/nginx` and
    /// `--conf-path=/etc/nginx/nginx.conf` there are independent, and
    /// `<prefix>/nginx.conf` resolves to a path that doesn't exist. Verify
    /// an assumption like "prefix implies conf-path" against a real
    /// install rather than trusting the pinned test container alone — the
    /// two can diverge in ways a single container pin will never surface.
    pub entry_config_path: PathBuf,
    /// Whether this build is new enough for the separate `http2 on;`
    /// directive (`version::supports_http2_directive`) — `EditRequest`'s
    /// own doc comment on why this is resolved here, once, rather than
    /// re-invoking `nginx` from inside the provably-testable edit path.
    pub http2_supported: bool,
}

/// Runs `nginx -V`, and returns `None` when it can't be run or its
/// stderr doesn't parse (`version::parse_configure_arguments`/
/// `parse_version` are already total over garbage input — this just
/// declines to guess a prefix rather than editing against one). The
/// caller's honest fallback on `None` is the same advice-only path a host
/// with no nginx at all gets, never a crash or an assumed `/etc/nginx`.
pub fn detect_installation(nginx_bin: &str) -> Option<Installation> {
    let output = Command::new(nginx_bin).arg("-V").output().ok()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let configure = version::parse_configure_arguments(&stderr)?;
    let compiled_prefix = PathBuf::from(configure.prefix?);
    // `--conf-path` first — see `Installation::entry_config_path`'s doc
    // comment for why `<prefix>/nginx.conf` is a fallback, not the
    // default assumption.
    let entry_config_path = match configure.conf_path {
        Some(path) => PathBuf::from(path),
        None => compiled_prefix.join("nginx.conf"),
    };
    // `Installation::prefix`'s doc comment has the full story: the config
    // *tree* — where `sites-available`/`sites-enabled`/`conf.d` actually
    // live — is the entry file's own directory, not necessarily the
    // compiled `--prefix`. Found live: Ubuntu's real `sites-enabled ->
    // sites-available` symlink, Debian/Ubuntu's standard site-management
    // convention, was reported as escaping the config tree, because
    // `--prefix=/usr/share/nginx` shares nothing with where `/etc/nginx/
    // sites-available` actually resolves. This is a no-op for the pinned
    // container (`<prefix>/nginx.conf`'s parent is `prefix` itself).
    let prefix = entry_config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(compiled_prefix);
    let http2_supported = version::parse_version(&stderr)
        .map(version::supports_http2_directive)
        .unwrap_or(false);
    Some(Installation {
        prefix,
        entry_config_path,
        http2_supported,
    })
}

pub fn find_and_edit(req: &EditRequest) -> Result<EditOutcome, core::Error> {
    // A config this parser can't make sense of is defence #4 ("refuse to
    // edit anything not understood"), not a hard error — the caller
    // reports it the same as "no matching block."
    let Ok(directives) = parse::parse_file(req.entry_config_path, req.prefix, req.fs) else {
        return Ok(EditOutcome::NoMatchingBlock);
    };

    match matching::find_server_block(&directives, req.domain, matching::PortScope::Tls443) {
        matching::FindResult::Matched(tls_block) => edit_in_place(req, &directives, tls_block),
        matching::FindResult::Refused(reason) => Ok(EditOutcome::Refused {
            reason: RefusalKind::Matching(reason),
        }),
        matching::FindResult::NoMatch => {
            match matching::find_server_block(&directives, req.domain, matching::PortScope::Plain80)
            {
                matching::FindResult::Matched(plain_block) => append_new_block(req, plain_block),
                matching::FindResult::Refused(reason) => Ok(EditOutcome::Refused {
                    reason: RefusalKind::Matching(reason),
                }),
                matching::FindResult::NoMatch => Ok(EditOutcome::NoMatchingBlock),
            }
        }
    }
}

fn edit_in_place(
    req: &EditRequest,
    directives: &[Directive],
    tls_block: &Directive,
) -> Result<EditOutcome, core::Error> {
    if is_symlink_outside_tree(&tls_block.file, req.prefix) {
        return Ok(EditOutcome::Refused {
            reason: RefusalKind::Matching(matching::RefusalReason::SymlinkOutsideTree),
        });
    }

    let source = req
        .fs
        .read_to_string(&tls_block.file)
        .map_err(|e| core::Error::io(&tls_block.file, e))?;

    // Appending the redirect block (if any) BEFORE the cert edit is
    // deliberate, not arbitrary: the redirect is inserted strictly after
    // `tls_block.span.end`, so it can never shift any offset the cert
    // edit relies on (every one of those lies inside `tls_block`, i.e.
    // strictly before that same position) — the two edits compose safely
    // without re-parsing between them.
    let redirect_outcome = classify_redirect(req, directives);
    let with_redirect = if redirect_outcome == RedirectOutcome::Written {
        edit::build_redirect_block(&source, tls_block, req.domain)
    } else {
        source.clone()
    };

    let new_content = match edit::build_in_place_edit(
        &with_redirect,
        tls_block,
        req.fullchain_path,
        req.key_path,
    ) {
        Ok(c) => c,
        Err(reason) => {
            return Ok(EditOutcome::Refused {
                reason: refusal_from_edit(reason),
            })
        }
    };

    run_transaction(req, &tls_block.file, new_content, redirect_outcome)
}

fn append_new_block(
    req: &EditRequest,
    plain_block: &Directive,
) -> Result<EditOutcome, core::Error> {
    if is_symlink_outside_tree(&plain_block.file, req.prefix) {
        return Ok(EditOutcome::Refused {
            reason: RefusalKind::Matching(matching::RefusalReason::SymlinkOutsideTree),
        });
    }

    let source = req
        .fs
        .read_to_string(&plain_block.file)
        .map_err(|e| core::Error::io(&plain_block.file, e))?;
    let new_content = edit::build_appended_block(
        &source,
        plain_block,
        req.domain,
        req.fullchain_path,
        req.key_path,
        req.http2_supported,
    );

    // `plain_block` is itself the `:80` block that already names this
    // domain — a redirect here would always collide with it, by
    // construction of how this function is reached.
    let redirect_outcome = if req.redirect {
        RedirectOutcome::SkippedExistingHttpBlock
    } else {
        RedirectOutcome::NotRequested
    };

    run_transaction(req, &plain_block.file, new_content, redirect_outcome)
}

fn classify_redirect(req: &EditRequest, directives: &[Directive]) -> RedirectOutcome {
    if !req.redirect {
        return RedirectOutcome::NotRequested;
    }
    match matching::find_server_block(directives, req.domain, matching::PortScope::Plain80) {
        matching::FindResult::NoMatch => RedirectOutcome::Written,
        matching::FindResult::Matched(_) => RedirectOutcome::SkippedExistingHttpBlock,
        matching::FindResult::Refused(_) => RedirectOutcome::SkippedRefused,
    }
}

fn refusal_from_edit(reason: edit::EditRefusal) -> RefusalKind {
    match reason {
        edit::EditRefusal::AmbiguousCertificateDirectives => {
            RefusalKind::AmbiguousCertificateDirectives
        }
        edit::EditRefusal::MalformedBlock => RefusalKind::MalformedBlock,
    }
}

fn run_transaction(
    req: &EditRequest,
    target_file: &Path,
    new_content: String,
    redirect: RedirectOutcome,
) -> Result<EditOutcome, core::Error> {
    let registration = req
        .registry_path
        .map(|registry_path| transaction::EditRegistration {
            registry_path,
            domain: req.domain,
        });
    let result = transaction::run(
        target_file,
        new_content.as_bytes(),
        req.validator,
        req.reloader,
        req.dry_run,
        registration,
    )?;
    Ok(match result {
        transaction::EditOutcome::Edited { backup_path } => EditOutcome::Edited {
            backup_path,
            redirect,
        },
        transaction::EditOutcome::DryRun { diff } => EditOutcome::DryRun { diff },
        transaction::EditOutcome::PreexistingConfigInvalid { stderr } => {
            EditOutcome::PreexistingConfigInvalid { stderr }
        }
        transaction::EditOutcome::ValidationFailedRestored {
            backup_path,
            stderr,
        } => EditOutcome::ValidationFailedRestored {
            backup_path,
            stderr,
        },
        transaction::EditOutcome::ReloadFailedRestored {
            backup_path,
            reload_error,
        } => EditOutcome::ReloadFailedRestored {
            backup_path,
            reload_error,
        },
        transaction::EditOutcome::RestoreFailed {
            backup_path,
            restore_stderr,
        } => EditOutcome::RestoreFailed {
            backup_path,
            restore_stderr,
        },
    })
}

/// True only when `file` is, or is reached through, a symlink whose real
/// target escapes `config_root` — checked against the **real** filesystem
/// directly, never through the `ConfigFs` seam, since provenance is a
/// property of the actual inode, not of the parser's virtual view of it.
/// A `file` that doesn't exist on the real filesystem at all (true for
/// every fixture under a virtual test root) is treated as "not a
/// symlink" — there is no real inode to have escaped anything, so this
/// check is a no-op in that environment rather than a false refusal.
fn is_symlink_outside_tree(file: &Path, config_root: &Path) -> bool {
    let Ok(canonical_root) = std::fs::canonicalize(config_root) else {
        return false;
    };
    let Ok(canonical_file) = std::fs::canonicalize(file) else {
        return false;
    };
    !canonical_file.starts_with(&canonical_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse::RealFs;
    use transaction::test_support::{ScriptedReloader, ScriptedValidator};
    use transaction::ValidateOutcome;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-nginx-mod-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ok() -> ValidateOutcome {
        ValidateOutcome {
            success: true,
            stderr: String::new(),
        }
    }

    #[test]
    fn in_place_edit_end_to_end_against_a_real_temp_directory() {
        let dir = tmp_dir("in-place");
        let conf = dir.join("nginx.conf");
        std::fs::write(&conf, "http { server { listen 443 ssl; server_name example.com; ssl_certificate /old/fullchain.pem; ssl_certificate_key /old/privkey.pem; } }").unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/new/fullchain.pem",
            key_path: "/new/privkey.pem",
            redirect: false,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        match result {
            EditOutcome::Edited { redirect, .. } => {
                assert_eq!(redirect, RedirectOutcome::NotRequested)
            }
            other => panic!("expected Edited, got {other:?}"),
        }
        let after = std::fs::read_to_string(&conf).unwrap();
        assert!(after.contains("/new/fullchain.pem"));
        assert!(after.contains("/new/privkey.pem"));
    }

    #[test]
    fn a_successful_edit_with_registry_path_is_readable_by_cmd_rollback() {
        // Closes the loop `find_and_edit` -> `run_transaction` ->
        // `transaction::run` -> `registry::append`, through the same
        // public `EditRequest.registry_path` field `cmd::rollback`'s
        // future `issue`-side caller will set — proving the two ends of
        // the wiring actually agree, not just each side in isolation.
        let dir = tmp_dir("registry-wiring");
        let conf = dir.join("nginx.conf");
        std::fs::write(&conf, "http { server { listen 443 ssl; server_name example.com; ssl_certificate /old; ssl_certificate_key /old-key; } }").unwrap();
        let registry_path = dir.join("edits.jsonl");

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/new/fullchain.pem",
            key_path: "/new/privkey.pem",
            redirect: false,
            dry_run: false,
            http2_supported: true,
            registry_path: Some(&registry_path),
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        let EditOutcome::Edited { backup_path, .. } = result else {
            panic!("expected Edited, got {result:?}")
        };

        let records = registry::read_all(&registry_path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "example.com");
        assert_eq!(records[0].file, conf);
        assert_eq!(records[0].backup_path, backup_path);
    }

    #[test]
    fn append_new_block_end_to_end_against_a_real_temp_directory() {
        let dir = tmp_dir("append");
        let conf = dir.join("nginx.conf");
        std::fs::write(
            &conf,
            "http { server { listen 80; server_name example.com; } }",
        )
        .unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/var/lib/certway/example.com/fullchain.pem",
            key_path: "/var/lib/certway/example.com/privkey.pem",
            redirect: false,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        assert!(matches!(result, EditOutcome::Edited { .. }));
        let after = std::fs::read_to_string(&conf).unwrap();
        assert!(after.contains("# managed by certway — example.com"));
        assert!(
            after.contains("listen 80;"),
            "the original :80 block must survive untouched"
        );
    }

    #[test]
    fn append_new_block_never_writes_a_redirect_even_when_requested() {
        let dir = tmp_dir("append-redirect");
        let conf = dir.join("nginx.conf");
        std::fs::write(
            &conf,
            "http { server { listen 80; server_name example.com; } }",
        )
        .unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/f",
            key_path: "/k",
            redirect: true,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        match result {
            EditOutcome::Edited { redirect, .. } => {
                assert_eq!(redirect, RedirectOutcome::SkippedExistingHttpBlock)
            }
            other => panic!("expected Edited, got {other:?}"),
        }
        let after = std::fs::read_to_string(&conf).unwrap();
        assert_eq!(
            after.matches("return 301").count(),
            0,
            "must never write a competing :80 block for a domain that already has one"
        );
    }

    #[test]
    fn in_place_edit_writes_a_redirect_when_no_plain_80_block_exists() {
        let dir = tmp_dir("redirect-written");
        let conf = dir.join("nginx.conf");
        std::fs::write(&conf, "http { server { listen 443 ssl; server_name example.com; ssl_certificate /a; ssl_certificate_key /b; } }").unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/f",
            key_path: "/k",
            redirect: true,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        match result {
            EditOutcome::Edited { redirect, .. } => assert_eq!(redirect, RedirectOutcome::Written),
            other => panic!("expected Edited, got {other:?}"),
        }
        let after = std::fs::read_to_string(&conf).unwrap();
        assert!(after.contains("return 301 https://$host$request_uri;"));
        assert!(
            after.contains("/f"),
            "the cert edit must also have taken effect alongside the redirect"
        );
    }

    #[test]
    fn in_place_edit_skips_redirect_when_a_plain_80_block_already_exists() {
        let dir = tmp_dir("redirect-skipped");
        let conf = dir.join("nginx.conf");
        std::fs::write(
            &conf,
            "http { \
             server { listen 80; server_name example.com; } \
             server { listen 443 ssl; server_name example.com; ssl_certificate /a; ssl_certificate_key /b; } \
             }",
        )
        .unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/f",
            key_path: "/k",
            redirect: true,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        match result {
            EditOutcome::Edited { redirect, .. } => {
                assert_eq!(redirect, RedirectOutcome::SkippedExistingHttpBlock)
            }
            other => panic!("expected Edited, got {other:?}"),
        }
        let after = std::fs::read_to_string(&conf).unwrap();
        assert_eq!(
            after.matches("return 301").count(),
            0,
            "must not create a second :80 server_name for the same domain"
        );
    }

    #[test]
    fn no_match_at_either_port_is_reported_as_no_matching_block() {
        let dir = tmp_dir("no-match");
        let conf = dir.join("nginx.conf");
        std::fs::write(
            &conf,
            "http { server { listen 8080; server_name unrelated.com; } }",
        )
        .unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/f",
            key_path: "/k",
            redirect: false,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        assert!(matches!(
            find_and_edit(&req).unwrap(),
            EditOutcome::NoMatchingBlock
        ));
    }

    #[test]
    fn a_matching_reason_refusal_passes_through_untouched() {
        let dir = tmp_dir("refused");
        let conf = dir.join("nginx.conf");
        std::fs::write(
            &conf,
            "http { server { listen 443 ssl; server_name ~^www\\.example\\.com$; } }",
        )
        .unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "www.example.com",
            fullchain_path: "/f",
            key_path: "/k",
            redirect: false,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        assert_eq!(
            result_refusal(&result),
            Some(RefusalKind::Matching(matching::RefusalReason::Regex))
        );
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "http { server { listen 443 ssl; server_name ~^www\\.example\\.com$; } }",
            "a refused file must be byte-identical afterward"
        );
    }

    #[test]
    fn ambiguous_certificate_directives_refuses_without_touching_the_file() {
        let dir = tmp_dir("ambiguous-cert");
        let conf = dir.join("nginx.conf");
        let original =
            "http { server { listen 443 ssl; server_name example.com; ssl_certificate /a; } }";
        std::fs::write(&conf, original).unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/f",
            key_path: "/k",
            redirect: false,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        assert_eq!(
            result_refusal(&result),
            Some(RefusalKind::AmbiguousCertificateDirectives)
        );
        assert_eq!(std::fs::read_to_string(&conf).unwrap(), original);
    }

    #[test]
    fn symlink_target_outside_the_prefix_is_refused() {
        let dir = tmp_dir("symlink-outside");
        let outside = tmp_dir("symlink-outside-target");
        let real_target = outside.join("real.conf");
        std::fs::write(&real_target, "http { server { listen 443 ssl; server_name example.com; ssl_certificate /a; ssl_certificate_key /b; } }").unwrap();

        let conf = dir.join("nginx.conf");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_target, &conf).unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/f",
            key_path: "/k",
            redirect: false,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        assert_eq!(
            result_refusal(&result),
            Some(RefusalKind::Matching(
                matching::RefusalReason::SymlinkOutsideTree
            ))
        );
        assert_eq!(std::fs::read_to_string(&real_target).unwrap(), "http { server { listen 443 ssl; server_name example.com; ssl_certificate /a; ssl_certificate_key /b; } }");
    }

    /// The concrete attack this guard exists for, asked for directly:
    /// `/etc/nginx/sites-enabled/evil -> /etc/passwd` (here: a symlink
    /// placed inside a `sites-enabled/`-style included directory,
    /// pointing at a file outside the config tree entirely) must never
    /// be edited, even though the attacker's target contains perfectly
    /// valid, matching nginx syntax — the content alone is not what
    /// saves us here (defence #4, "can't parse it," is a different,
    /// weaker guard that a well-formed malicious block would sail
    /// straight past); only `is_symlink_outside_tree` stands between an
    /// attacker-placed symlink and a root-privileged write. Written after
    /// the atomic-write symlink fix specifically to prove that fix never
    /// touched this check — see the module doc comment on why that's a
    /// real risk, not a formality, when both features share the same
    /// "resolve a symlink" code shape.
    #[cfg(unix)]
    #[test]
    fn a_symlink_reached_through_an_included_directory_pointing_outside_the_tree_is_refused() {
        let prefix_dir = tmp_dir("attack-config-tree");
        std::fs::create_dir_all(prefix_dir.join("sites-enabled")).unwrap();
        let nginx_conf = prefix_dir.join("nginx.conf");
        std::fs::write(&nginx_conf, "http { include sites-enabled/*; }").unwrap();

        // Outside the tree entirely — stands in for `/etc/passwd`: a real
        // file, a real path, nowhere near `prefix_dir`. Its content is
        // valid nginx syntax matching our domain — an attacker who can
        // place a symlink but not write inside the tree would craft
        // exactly this, to make the block look legitimate.
        let outside_dir = tmp_dir("attack-outside-target");
        let evil_target = outside_dir.join("passwd");
        let evil_content = "server { listen 443 ssl; server_name example.com; ssl_certificate /a; ssl_certificate_key /b; }";
        std::fs::write(&evil_target, evil_content).unwrap();

        let evil_symlink = prefix_dir.join("sites-enabled").join("evil");
        std::os::unix::fs::symlink(&evil_target, &evil_symlink).unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &nginx_conf,
            prefix: &prefix_dir,
            domain: "example.com",
            fullchain_path: "/f",
            key_path: "/k",
            redirect: false,
            dry_run: false,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        assert_eq!(
            result_refusal(&result),
            Some(RefusalKind::Matching(
                matching::RefusalReason::SymlinkOutsideTree
            )),
            "a symlink resolving outside the config tree must be refused, not edited: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&evil_target).unwrap(),
            evil_content,
            "the file outside the tree must never be written to, under any outcome"
        );
    }

    #[test]
    fn dry_run_never_writes_and_reports_a_diff() {
        let dir = tmp_dir("dry-run");
        let conf = dir.join("nginx.conf");
        let original = "http {\n    server {\n        listen 443 ssl;\n        server_name example.com;\n        ssl_certificate /old;\n        ssl_certificate_key /old-key;\n    }\n}";
        std::fs::write(&conf, original).unwrap();

        let fs = RealFs { root: None };
        let validator = ScriptedValidator::always(ok());
        let reloader = ScriptedReloader { result: Ok(()) };
        let req = EditRequest {
            entry_config_path: &conf,
            prefix: &dir,
            domain: "example.com",
            fullchain_path: "/new",
            key_path: "/new-key",
            redirect: false,
            dry_run: true,
            http2_supported: true,
            registry_path: None,
            fs: &fs,
            validator: &validator,
            reloader: &reloader,
        };

        let result = find_and_edit(&req).unwrap();
        match result {
            EditOutcome::DryRun { diff } => {
                assert!(
                    diff.contains("+        ssl_certificate /new;"),
                    "diff shows the new value being added: {diff}"
                );
                assert!(
                    diff.contains("-        ssl_certificate /old;"),
                    "diff shows the old value being removed: {diff}"
                );
            }
            other => panic!("expected DryRun, got {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            original,
            "dry-run must never touch the file"
        );
    }

    fn result_refusal(result: &EditOutcome) -> Option<RefusalKind> {
        match result {
            EditOutcome::Refused { reason } => Some(reason.clone()),
            _ => None,
        }
    }

    // -- detect_installation --------------------------------------------------

    /// A throwaway `nginx` stand-in: a shell script printing fixed `-V`
    /// stderr, exactly the pinned container's real output
    /// (`version.rs`'s own `PINNED_V_OUTPUT`) — proves the parsing wiring
    /// without a real nginx binary; `nginx_container_proofs.rs` covers the
    /// real one.
    #[cfg(unix)]
    fn scripted_nginx_v(tag: &str, stderr: &str) -> PathBuf {
        let dir = tmp_dir(tag);
        let script = dir.join("nginx");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho -n '{stderr}' >&2\n"),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script
    }

    #[cfg(unix)]
    #[test]
    fn detect_installation_parses_prefix_and_entry_config_from_a_real_shaped_v_output() {
        let stderr = "nginx version: nginx/1.29.3\nconfigure arguments: --prefix=/etc/nginx --with-http_ssl_module --with-http_v2_module\n";
        let script = scripted_nginx_v("detect-install-ok", stderr);

        let install = detect_installation(script.to_str().unwrap()).unwrap();
        assert_eq!(install.prefix, PathBuf::from("/etc/nginx"));
        assert_eq!(install.entry_config_path, PathBuf::from("/etc/nginx/nginx.conf"));
        assert!(install.http2_supported);
    }

    /// The bug found live on a real Ubuntu 26.04 box: Ubuntu's packaged
    /// nginx sets `--prefix=/usr/share/nginx` and `--conf-path=/etc/
    /// nginx/nginx.conf` as two independent values.
    /// `<prefix>/nginx.conf` would have resolved to `/usr/share/nginx/
    /// nginx.conf` — a path that does not exist — silently failing to
    /// find any Debian/Ubuntu install's real config at all.
    #[cfg(unix)]
    #[test]
    fn detect_installation_uses_conf_path_when_the_build_sets_it_separately_from_prefix() {
        let stderr = "nginx version: nginx/1.28.3 (Ubuntu)\nconfigure arguments: --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --with-http_ssl_module\n";
        let script = scripted_nginx_v("detect-install-ubuntu", stderr);

        let install = detect_installation(script.to_str().unwrap()).unwrap();
        assert_eq!(
            install.entry_config_path,
            PathBuf::from("/etc/nginx/nginx.conf"),
            "must use --conf-path, not <prefix>/nginx.conf, when the build set it separately"
        );
        // The second real bug this same Ubuntu box surfaced: `prefix`
        // must be the entry file's own directory (`/etc/nginx`, where
        // `sites-available`/`sites-enabled` actually live), never the
        // raw compiled `--prefix` (`/usr/share/nginx`) once the two
        // diverge — `Installation::prefix`'s doc comment has the full
        // story (a stock Debian/Ubuntu symlink reported as "outside the
        // config tree" and refused).
        assert_eq!(
            install.prefix,
            PathBuf::from("/etc/nginx"),
            "prefix must be the entry config's own directory, not the raw compiled --prefix"
        );
    }

    #[cfg(unix)]
    #[test]
    fn detect_installation_reports_no_http2_support_below_the_1_25_1_cutoff() {
        let stderr =
            "nginx version: nginx/1.24.0\nconfigure arguments: --prefix=/etc/nginx\n";
        let script = scripted_nginx_v("detect-install-old", stderr);

        let install = detect_installation(script.to_str().unwrap()).unwrap();
        assert!(!install.http2_supported);
    }

    #[test]
    fn detect_installation_is_none_when_the_binary_does_not_exist() {
        assert!(detect_installation("/no/such/nginx-binary-anywhere").is_none());
    }
}
