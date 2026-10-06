// SPDX-License-Identifier: MIT

//! The `list` command.
//!
//! Read-only: takes a shared lock, never contacts the CA. Expiry, serial,
//! and SANs are read from each certificate's own `fullchain.pem` — the
//! certificate itself is the source of truth for what's actually
//! installed — never from `config.json`, whose only use here is
//! recovering the `RENEW` column's cached ARI window (`ari.json`, also
//! read-only) and, when that cache is empty, nothing at all: the 30-day
//! fallback needs only `notAfter`, already in hand from the certificate.

use crate::args::ListArgs;
use crate::cmd::renew::{format_full_date, format_short_date};
use crate::render::{pad_field, pad_field_right, Mode, Out, FAILURE, MUTED, RESET, WARNING};
use crate::scheduler;
use crate::store;
use certway_core::json::{write_object, JsonVal};
use certway_core::{self as core, ParsedCert};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const THIRTY_DAYS_SECS: i64 = 30 * 86_400;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `list`'s own minimal failure rendering. Deliberately not the four-part
/// error block `cmd::issue::fail` builds: the step labels and state lines
/// used elsewhere are all defined for `issue`/`renew`'s issuance stages,
/// and inventing a step label or state line for a read-only command like
/// `list` risks it silently colliding with a real one later ("a label
/// not on the defined list is a defect waiting to happen"). Rather than
/// inventing either, this prints a plain message with no step glyph and
/// no state line, matching how `main.rs` already reports an argument
/// error outside the step/error-block machinery. This is a genuine gap
/// in what's defined for read-only commands, not a judgement call made
/// lightly.
fn fail(out: &mut Out<impl Write>, err: &core::Error) -> i32 {
    if out.mode == Mode::Json {
        let _ = out.json_raw_line(&write_object(&[("error", JsonVal::Str(&err.to_string()))]));
        return 1;
    }
    let _ = out.raw_line("");
    let _ = out.raw_line(&format!("  certway: {err}"));
    let _ = out.raw_line("");
    1
}

/// `certway list --help` — see `cmd::issue::ISSUE_HELP`'s doc comment
/// for the shape every command's help follows.
const LIST_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway list [flags]",
    examples: &["certway list", "certway list --json"],
    groups: &[crate::cmd::command_help::FlagGroup {
        heading: "",
        flags: &[
            crate::cmd::command_help::FlagHelp {
                flag: "--out <dir>",
                about: "Override the data directory",
            },
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

pub fn run(args: ListArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &LIST_HELP);
        return 0;
    }

    // `list` never contacts a CA, so the header prints bare `certway
    // {version}` with no CA-status suffix.
    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    let data_root = match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
        Ok(p) => p,
        Err(e) => return fail(out, &e),
    };
    // A missing data directory is not a failure for a read-only command —
    // it is the answer "zero certificates." `acquire_shared` fails to even
    // open `<data>/.lock` in that case (its parent doesn't exist), and the
    // fix is deliberately *not* to create the directory here (a read
    // command must not create state): only the lock-open step is skipped,
    // and the empty-state rendering below is reached exactly as if
    // `read_dir` below had found nothing, because it will.
    let _lock = match store::acquire_shared(&data_root) {
        Ok(l) => Some(l),
        Err(e) if store::is_missing_data_dir(&e) => None,
        Err(e) => return fail(out, &e),
    };

    let mut dirs = match std::fs::read_dir(&data_root) {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .filter(|p| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                name != "account" && !name.starts_with('.') && p.join("fullchain.pem").exists()
            })
            .collect::<Vec<PathBuf>>(),
        Err(_) => Vec::new(),
    };
    dirs.sort();

    if dirs.is_empty() {
        if out.mode == Mode::Json {
            let _ = out.json_raw_line(&write_object(&[("certificates", JsonVal::Array(vec![]))]));
        } else {
            let _ = out.raw_line("");
            let _ = out.raw_line("  No certificates yet.");
            let _ = out.raw_line("");
            let _ = out.raw_line("    certway issue example.com");
            let _ = out.raw_line("");
            let _ = out.raw_line(&format!("  {}", data_root.display()));
            let _ = out.raw_line("");
        }
        return 0;
    }

    let now = now_unix();
    // Presence only — not `systemctl is-enabled` — deliberately: this must
    // stay a plain, side-effect-free filesystem check reading the exact
    // path `install` writes to (`scheduler::systemd::resolve_unit_dir`), so
    // it can never diverge from what `install` actually did. That's a
    // weaker guarantee than "is this timer actually active" — a unit file
    // existing on disk doesn't prove systemd has it enabled or that it
    // last ran successfully — but checking the file is unambiguous and
    // never has side effects, while querying systemd's live state would.
    let auto = scheduler::systemd::is_installed(&scheduler::systemd::resolve_unit_dir());

    let mut rows = Vec::new();
    for dir in &dirs {
        if let Some(row) = build_row(dir, now) {
            rows.push(row);
        }
    }

    if out.mode == Mode::Json {
        // Each row's object is built into an owned `String` first (kept
        // alive in `cert_jsons` for the rest of this block) so the outer
        // `write_object` call can borrow them as `JsonVal::Raw` — the same
        // two-pass shape `acme::new_order` already uses for a nested array
        // of objects.
        let cert_jsons: Vec<String> = rows
            .iter()
            .map(|r| {
                write_object(&[
                    ("domain", JsonVal::Str(&r.domain)),
                    ("expires", JsonVal::Str(&r.expires)),
                    ("days", JsonVal::Raw(&r.days_raw)),
                    ("renew", JsonVal::Str(&r.renew)),
                    ("auto", JsonVal::Bool(auto)),
                ])
            })
            .collect();
        let cert_vals: Vec<JsonVal> = cert_jsons
            .iter()
            .map(|s| JsonVal::Raw(s.as_str()))
            .collect();
        let _ = out.json_raw_line(&write_object(&[(
            "certificates",
            JsonVal::Array(cert_vals),
        )]));
        return 0;
    }

    let color = out.caps.color;
    let unicode = out.caps.unicode;
    let _ = out.raw_line("");
    let header = format!(
        "{}{}{}{}AUTO",
        pad_field("DOMAIN", 27, unicode),
        pad_field("EXPIRES", 15, unicode),
        pad_field_right("DAYS", 4),
        pad_field("  RENEW", 13, unicode)
    );
    // Column headers print in muted colour, uppercase.
    let _ = out.raw_line(&format!("  {}", colorize(color, MUTED, &header)));
    for row in &rows {
        // Expired shows `--` in DAYS (already `row.days_display`) and
        // the row's EXPIRES in failure colour; a not-yet-expired count
        // under 30 days is DAYS itself in warning colour.
        let expired = row_is_expired(&row.days_display);
        let under_30 = row_is_under_30(&row.days_display);
        let expires_field = pad_field(&row.expires, 15, unicode);
        let expires_field = if expired {
            colorize(color, FAILURE, &expires_field)
        } else {
            expires_field
        };
        let days_field = pad_field_right(&row.days_display, 4);
        let days_field = if under_30 {
            colorize(color, WARNING, &days_field)
        } else {
            days_field
        };
        let _ = out.raw_line(&format!(
            "  {}{}{}  {}{}",
            pad_field(&row.domain, 27, unicode),
            expires_field,
            days_field,
            pad_field(&row.renew, 11, unicode),
            if auto { "yes" } else { "no" }
        ));
    }
    let _ = out.raw_line("");

    0
}

/// Expired rows show `--` in `DAYS` — the only sentinel
/// `Row::days_display` ever carries other than a plain non-negative integer.
fn row_is_expired(days_display: &str) -> bool {
    days_display == "--"
}

/// Not expired, and under the 30-day threshold — `DAYS` in warning
/// colour.
fn row_is_under_30(days_display: &str) -> bool {
    !row_is_expired(days_display) && days_display.parse::<i64>().is_ok_and(|d| d < 30)
}

/// Wraps `text` in `color`/`RESET` when colour is enabled, unchanged
/// otherwise — the same gate every colour use in `render.rs` follows
/// (`Caps::color`).
fn colorize(enabled: bool, color: &str, text: &str) -> String {
    if enabled {
        format!("{color}{text}{RESET}")
    } else {
        text.to_string()
    }
}

struct Row {
    domain: String,
    expires: String,
    days_display: String,
    days_raw: String,
    renew: String,
}

fn build_row(cert_dir: &Path, now: i64) -> Option<Row> {
    let fullchain = std::fs::read_to_string(cert_dir.join("fullchain.pem")).ok()?;
    let parsed = ParsedCert::from_leaf_pem(&fullchain).ok()?;

    let dir_name = cert_dir.file_name()?.to_str()?.to_string();
    let domain = match dir_name.strip_prefix("_.") {
        Some(rest) => format!("*.{rest}"),
        None => dir_name,
    };

    let expired = now >= parsed.not_after;
    let days_remaining = (parsed.not_after - now).div_euclid(86_400);

    let expires = format_full_date(parsed.not_after);
    let (days_display, days_raw) = if expired {
        ("--".to_string(), "null".to_string())
    } else {
        (days_remaining.to_string(), days_remaining.to_string())
    };

    let due = expired || days_remaining < 30;
    let renew = if due {
        "now".to_string()
    } else if let Some(window) = store::read_ari_cache(&store::ari_cache_path(cert_dir)) {
        format!(
            "{}\u{2013}{}",
            format_short_date(window.start),
            format_short_date(window.end)
        )
    } else {
        format_short_date(parsed.not_after - THIRTY_DAYS_SECS)
    };

    Some(Row {
        domain,
        expires,
        days_display,
        days_raw,
        renew,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;
    use certway_core::RenewalWindow;

    // -- run(): a data directory that does not exist yet ---------------------
    //
    // Bug found live, on a real fresh install: `certway list` on a machine
    // with zero certificates errored ("io error on
    // /var/lib/certway/.lock: No such file or directory") instead of
    // showing the "no certificates yet" empty state. Root cause:
    // `acquire_shared` opening `<data>/.lock` fails `NotFound` when
    // `<data>` itself doesn't exist yet — nothing had ever created it,
    // since `list` (correctly) never does.

    fn tmp_nonexistent_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-list-missing-dir-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir // deliberately never created
    }

    #[test]
    fn a_nonexistent_data_directory_shows_the_empty_state_not_an_error() {
        let dir = tmp_nonexistent_dir("human");
        assert!(
            !dir.exists(),
            "the test's own premise: this directory must not exist"
        );

        let args = ListArgs {
            out_dir: Some(dir.to_string_lossy().to_string()),
            json: false,
            no_color: true,
            help: false,
        };
        let mut buf = Vec::new();
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 100,
        };
        let code = {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            run(args, &mut out)
        };

        assert_eq!(
            code, 0,
            "a missing data directory is zero certificates, not a failure"
        );
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("No certificates yet."),
            "must show the empty-state message: {text:?}"
        );
        assert!(
            !text.contains("account"),
            "must never claim the (nonexistent, issue-only) \"account\" step label: {text:?}"
        );
        assert!(
            !dir.exists(),
            "a read-only command must never create the data directory"
        );
    }

    #[test]
    fn a_nonexistent_data_directory_in_json_mode_shows_an_empty_array_not_an_error() {
        let dir = tmp_nonexistent_dir("json");
        let args = ListArgs {
            out_dir: Some(dir.to_string_lossy().to_string()),
            json: true,
            no_color: true,
            help: false,
        };
        let mut buf = Vec::new();
        let caps = Caps {
            color: false,
            unicode: false,
            animation: false,
            width: 100,
        }
        .force_json();
        let code = {
            let mut out = Out::new(&mut buf, caps, Mode::Json);
            run(args, &mut out)
        };
        assert_eq!(code, 0);
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("\"certificates\":[]"), "{text:?}");
        assert!(!dir.exists());
    }

    #[test]
    fn colorize_wraps_only_when_enabled() {
        assert_eq!(colorize(true, WARNING, "12"), format!("{WARNING}12{RESET}"));
        assert_eq!(colorize(false, WARNING, "12"), "12");
    }

    #[test]
    fn colorize_disabled_never_emits_escape_bytes() {
        // The piped, non-tty case (`Caps::color == false`) — `list`'s
        // primary output path when redirected or captured — must be
        // byte-for-byte free of ANSI, not merely visually equivalent.
        let out = colorize(false, FAILURE, "11 Aug 2026");
        assert!(!out.contains('\u{1b}'));
        assert_eq!(out, "11 Aug 2026");
    }

    // -- build_row -----------------------------------------------------
    //
    // One real self-signed fixture certificate (structure is all
    // `build_row` reads; SAN/CN content is irrelevant to it), reused across
    // cases by varying `now` relative to its fixed `not_after` — the same
    // technique `renew.rs`'s own `decide()` tests use for "days remaining."

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-list-build-row-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Writes a self-signed fixture at `<dir>/fullchain.pem` and returns its
    /// `not_after` epoch, so callers can place `now` at a known offset from
    /// expiry.
    fn write_fixture_cert(dir: &Path) -> i64 {
        let cert_path = dir.join("fullchain.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                "/dev/null",
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "90",
                "-subj",
                "/CN=fixture.example",
            ])
            .status()
            .expect("openssl must be on PATH for this test");
        assert!(
            status.success(),
            "openssl req -x509 failed generating the list.rs test fixture"
        );
        let pem = std::fs::read_to_string(&cert_path).unwrap();
        ParsedCert::from_leaf_pem(&pem).unwrap().not_after
    }

    const DAY: i64 = 86_400;

    #[test]
    fn far_from_expiry_shows_the_thirty_day_fallback_date_and_no_warning() {
        let dir = tmp_dir("far");
        let not_after = write_fixture_cert(&dir);
        let now = not_after - 89 * DAY;
        let row = build_row(&dir, now).unwrap();
        assert_eq!(row.days_display, "89");
        assert_eq!(row.days_raw, "89");
        assert!(!row_is_expired(&row.days_display));
        assert!(!row_is_under_30(&row.days_display));
        assert_eq!(row.renew, format_short_date(not_after - THIRTY_DAYS_SECS));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn under_thirty_days_is_due_now_and_flagged_for_warning_colour() {
        let dir = tmp_dir("soon");
        let not_after = write_fixture_cert(&dir);
        let now = not_after - 9 * DAY;
        let row = build_row(&dir, now).unwrap();
        assert_eq!(row.days_display, "9");
        assert_eq!(row.renew, "now");
        assert!(!row_is_expired(&row.days_display));
        assert!(
            row_is_under_30(&row.days_display),
            "9 days remaining must be flagged for the DAYS warning colour"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_shows_dashes_null_and_is_flagged_for_expires_failure_colour() {
        let dir = tmp_dir("expired");
        let not_after = write_fixture_cert(&dir);
        let now = not_after + DAY;
        let row = build_row(&dir, now).unwrap();
        assert_eq!(row.days_display, "--");
        assert_eq!(
            row.days_raw, "null",
            "JSON mode's `days` must serialize as null, not the string \"--\""
        );
        assert_eq!(row.renew, "now");
        assert!(row_is_expired(&row.days_display));
        assert!(
            !row_is_under_30(&row.days_display),
            "an expired row is its own case, not also flagged as the under-30 warning"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cached_ari_window_is_shown_instead_of_the_thirty_day_fallback() {
        let dir = tmp_dir("ari-window");
        let not_after = write_fixture_cert(&dir);
        let window = RenewalWindow {
            start: not_after - 60 * DAY,
            end: not_after - 55 * DAY,
            explanation_url: None,
            retry_after_deadline: 0,
        };
        store::write_ari_cache(&store::ari_cache_path(&dir), &window).unwrap();
        let now = not_after - 89 * DAY; // still far out, so the cache — not the 30-day fallback — decides RENEW
        let row = build_row(&dir, now).unwrap();
        assert_eq!(
            row.renew,
            format!(
                "{}\u{2013}{}",
                format_short_date(window.start),
                format_short_date(window.end)
            )
        );
        assert_ne!(
            row.renew,
            format_short_date(not_after - THIRTY_DAYS_SECS),
            "an ARI window in cache must win over the 30-day fallback date"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bug found live against a real domain (`certway-nginx-edit-
    /// proof.example`, 27+ chars against a 27-column `DOMAIN` field): the
    /// row ran the domain straight into `EXPIRES` with zero separation.
    /// `pad_field` now truncates before padding — proven here through the
    /// real `run()` path, not just `pad_field` in isolation, so a future
    /// change to how `list` builds its row can't reintroduce the bug
    /// without this failing too.
    #[test]
    fn a_domain_name_longer_than_the_column_width_stays_aligned_with_expires() {
        let dir = tmp_dir("long-domain");
        let long_domain = "a-genuinely-long-subdomain-name.internal.example.com";
        assert!(
            long_domain.len() > 27,
            "test premise: domain must exceed the DOMAIN column width"
        );
        let cert_dir = dir.join(long_domain);
        std::fs::create_dir_all(&cert_dir).unwrap();
        write_fixture_cert(&cert_dir);

        let args = ListArgs {
            out_dir: Some(dir.to_string_lossy().to_string()),
            json: false,
            no_color: true,
            help: false,
        };
        let mut buf = Vec::new();
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 100,
        };
        let code = {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            run(args, &mut out)
        };
        assert_eq!(code, 0);
        let text = String::from_utf8(buf).unwrap();

        let row_line = text
            .lines()
            .find(|l| l.contains("a-genuinely-long"))
            .unwrap_or_else(|| panic!("no row for the long domain found in:\n{text}"));

        // DOMAIN is a fixed 27 display columns after the 2-column margin,
        // regardless of the domain's real length.
        let after_margin: String = row_line.chars().skip(2).collect();
        let domain_field: String = after_margin.chars().take(27).collect();
        assert_eq!(
            crate::render::display_width(&domain_field),
            27,
            "DOMAIN field must be exactly 27 columns: {domain_field:?}"
        );
        assert!(
            domain_field.ends_with('…'),
            "a domain this long must show the truncation ellipsis, not run past its column: {domain_field:?}"
        );

        // Whatever follows the DOMAIN field must be EXPIRES, not another
        // fragment of the domain — the row must stay fully parseable, not
        // two columns fused into one string (this test's own name for the
        // bug: "does not collide with EXPIRES").
        let rest: String = after_margin.chars().skip(27).collect();
        assert!(
            rest.trim_start()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit()),
            "EXPIRES must start immediately after the DOMAIN field, not a domain fragment: {rest:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wildcard_directory_name_is_unescaped_to_a_leading_star() {
        // `build_row` derives `domain` from `cert_dir`'s own leaf name (the
        // same sanitization `store::cert_dir_name` applies on write), so the
        // fixture's leaf directory itself must be `_.example.com` — not
        // merely contain that string.
        let parent = tmp_dir("wildcard-parent");
        let dir = parent.join("_.example.com");
        std::fs::create_dir_all(&dir).unwrap();
        let not_after = write_fixture_cert(&dir);
        let row = build_row(&dir, not_after - 89 * DAY).unwrap();
        assert_eq!(row.domain, "*.example.com");
        let _ = std::fs::remove_dir_all(&parent);
    }
}
