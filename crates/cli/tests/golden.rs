// SPDX-License-Identifier: MIT

//! Golden output tests: output is compared byte-for-byte against stored
//! fixtures. These fixtures cover the reduced screen from `account`
//! through `certificate` only — `preflight` and `rehearsal` steps are not
//! exercised here.
//!
//! Each case renders through the real `Out` and `report::classify`, with a
//! stubbed backend: scripted step outcomes instead of a network call, so
//! the renderer and the classifier can be exercised without a live ACME
//! server. Output is compared byte-for-byte against a stored fixture
//! file under `tests/golden/`.

use certway::caps::Caps;
use certway::render::{Mode, Out};
use certway::report::{self, Proven, Stage};
use certway_core::{Problem, ProblemKind};
use std::time::Duration;

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

/// Compares `actual` to the stored fixture. Set `CERTWAY_BLESS=1` to
/// (re)write the fixture from `actual` instead of asserting — the normal
/// golden-test workflow: generate once, hand-review the diff, commit.
fn assert_golden(name: &str, actual: &[u8]) {
    let path = fixture_path(name);
    if std::env::var_os("CERTWAY_BLESS").is_some() {
        std::fs::write(&path, actual).expect("write golden fixture");
        return;
    }
    let expected = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("missing golden fixture: {}", path.display()));
    assert_eq!(
        String::from_utf8_lossy(actual),
        String::from_utf8_lossy(&expected),
        "golden mismatch for {name} (rerun with CERTWAY_BLESS=1 after reviewing the diff to update)"
    );
}

fn render_success(caps: Caps, mode: Mode) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, caps, mode);
        let _ = out.header(env!("CARGO_PKG_VERSION"), Some("https://acme-staging-v02.api.letsencrypt.org/directory"));
        let _ = out.step_done_with_metric("account", "new", "a8f3c21", Duration::from_millis(200));
        let _ = out.step_done("order", "1 domain", Duration::from_millis(300));
        let _ = out.step_done("challenge", "http-01 on :80", Duration::from_millis(150));
        let _ = out.step_done("validate", "1 of 1 authorized", Duration::from_millis(6100));
        let _ = out.step_done("certificate", "issued", Duration::from_millis(900));
        if mode == Mode::Json {
            let _ = out.json_result_issued(
                &["example.com".to_string()],
                "./certs/fullchain.pem",
                "./certs/privkey.pem",
            );
        } else {
            let _ = out.trailer_paths("./certs/fullchain.pem", "./certs/privkey.pem");
            let _ = out.trailer_prose(&["Run `certway install` to renew automatically."]);
        }
    }
    buf
}

fn render_failure_privileged_port(caps: Caps, mode: Mode) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, caps, mode);
        let _ = out.header(env!("CARGO_PKG_VERSION"), Some("https://acme-staging-v02.api.letsencrypt.org/directory"));
        let _ = out.step_done_with_metric("account", "new", "a8f3c21", Duration::from_millis(200));
        let _ = out.step_done("order", "1 domain", Duration::from_millis(300));
        let err = certway_core::Error::PrivilegedPort { port: 80 };
        let block = report::classify(&err, Stage::Challenge, Proven::default(), "example.com");
        if mode == Mode::Json {
            let slug = report::error_slug(&err);
            let _ = out.json_step_failed("challenge", &slug, &block.summary);
            let _ = out.json_result_failed("challenge", &slug, false);
        } else {
            let _ = out.step_failed(block.label, &block.subject);
            let _ = out.error_block(&block);
        }
    }
    buf
}

fn render_failure_unauthorized(caps: Caps, mode: Mode) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, caps, mode);
        let _ = out.header(env!("CARGO_PKG_VERSION"), Some("https://acme-staging-v02.api.letsencrypt.org/directory"));
        let _ =
            out.step_done_with_metric("account", "existing", "a8f3c21", Duration::from_millis(200));
        let _ = out.step_done("order", "1 domain", Duration::from_millis(300));
        let _ = out.step_done("challenge", "http-01 on :80", Duration::from_millis(150));
        let err = certway_core::Error::Acme(Problem {
            kind: ProblemKind::Unauthorized,
            detail: Some("example.com".to_string()),
            subproblems: vec![],
        });
        let block = report::classify(&err, Stage::Validate, Proven::default(), "example.com");
        if mode == Mode::Json {
            let slug = report::error_slug(&err);
            let _ = out.json_step_failed("validate", &slug, &block.summary);
            let _ = out.json_result_failed("validate", &slug, false);
        } else {
            let _ = out.step_failed(block.label, &block.subject);
            let _ = out.error_block(&block);
        }
    }
    buf
}

fn render_failure_ca_unreachable(caps: Caps, mode: Mode) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, caps, mode);
        let _ = out.header(env!("CARGO_PKG_VERSION"), Some("https://acme-staging-v02.api.letsencrypt.org/directory"));
        let err = certway_core::Error::Connect {
            host: "acme-staging-v02.api.letsencrypt.org".to_string(),
            port: 443,
            source: std::io::Error::other("connection refused"),
        };
        let block = report::classify(
            &err,
            Stage::Account,
            Proven::default(),
            "acme-staging-v02.api.letsencrypt.org",
        );
        if mode == Mode::Json {
            let slug = report::error_slug(&err);
            let _ = out.json_step_failed("account", &slug, &block.summary);
            let _ = out.json_result_failed("account", &slug, false);
        } else {
            let _ = out.step_failed(block.label, &block.subject);
            let _ = out.error_block(&block);
        }
    }
    buf
}

fn render_failure_agree_tos(caps: Caps, mode: Mode) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, caps, mode);
        let _ = out.header(env!("CARGO_PKG_VERSION"), Some("https://acme-staging-v02.api.letsencrypt.org/directory"));
        let err = certway_core::Error::Acme(Problem {
            kind: ProblemKind::Malformed,
            detail: Some("must agree to terms of service".to_string()),
            subproblems: vec![],
        });
        // The detail text identifies a cause more specific than
        // `malformed`'s type-based sentence, and the subject is the
        // requested domain, not a fragment of the detail text.
        let block = report::classify(&err, Stage::Account, Proven::default(), "example.com");
        if mode == Mode::Json {
            let slug = report::error_slug(&err);
            let _ = out.json_step_failed("account", &slug, &block.summary);
            let _ = out.json_result_failed("account", &slug, false);
        } else {
            let _ = out.step_failed(block.label, &block.subject);
            let _ = out.error_block(&block);
        }
    }
    buf
}

const FULL_TTY: Caps = Caps {
    color: true,
    unicode: true,
    animation: true,
    width: 100,
};
const NO_COLOR: Caps = Caps {
    color: false,
    unicode: true,
    animation: false,
    width: 100,
};
const NO_UNICODE: Caps = Caps {
    color: true,
    unicode: false,
    animation: true,
    width: 100,
};
// "Piped" alone doesn't say which locale — the two are genuinely different,
// both real: unicode support is a locale property, not tied to TTY-vs-pipe.
// ASCII-locale piping (cron, many CI images, `LANG=C`) gets ASCII glyphs;
// UTF-8-locale piping (a Linux host redirecting stdout to a log file, the
// common case) keeps `✓`/`✗` — confirmed live.
const PIPED_ASCII_LOCALE: Caps = Caps {
    color: false,
    unicode: false,
    animation: false,
    width: 100,
};
const PIPED_UTF8_LOCALE: Caps = Caps {
    color: false,
    unicode: true,
    animation: false,
    width: 100,
};
const JSON_CAPS: Caps = Caps {
    color: false,
    unicode: false,
    animation: false,
    width: 100,
};

#[test]
fn success_full_tty() {
    assert_golden(
        "success_full_tty.txt",
        &render_success(FULL_TTY, Mode::Human),
    );
}

#[test]
fn success_no_color() {
    assert_golden(
        "success_no_color.txt",
        &render_success(NO_COLOR, Mode::Human),
    );
}

#[test]
fn success_no_unicode() {
    assert_golden(
        "success_no_unicode.txt",
        &render_success(NO_UNICODE, Mode::Human),
    );
}

#[test]
fn success_piped_ascii_locale() {
    assert_golden(
        "success_piped_ascii_locale.txt",
        &render_success(PIPED_ASCII_LOCALE, Mode::Human),
    );
}

#[test]
fn success_piped_utf8_locale() {
    let out = render_success(PIPED_UTF8_LOCALE, Mode::Human);
    assert_golden("success_piped_utf8_locale.txt", &out);
    let text = String::from_utf8(out).expect("valid utf8");
    assert!(
        text.contains('✓'),
        "unicode glyph must survive a pipe under a UTF-8 locale"
    );
    assert!(
        !text.contains('\u{1b}'),
        "no ANSI escape byte when color/animation are off, even piped"
    );
}

#[test]
fn failure_piped_utf8_locale() {
    let out = render_failure_unauthorized(PIPED_UTF8_LOCALE, Mode::Human);
    assert_golden("failure_unauthorized_piped_utf8_locale.txt", &out);
    let text = String::from_utf8(out).expect("valid utf8");
    assert!(
        text.contains('✗'),
        "unicode glyph must survive a pipe under a UTF-8 locale"
    );
    assert!(
        !text.contains('\u{1b}'),
        "no ANSI escape byte when color/animation are off, even piped"
    );
}

#[test]
fn success_json() {
    assert_golden("success_json.txt", &render_success(JSON_CAPS, Mode::Json));
}

#[test]
fn success_quiet_prints_nothing() {
    let buf = render_success(NO_COLOR, Mode::Quiet);
    assert!(buf.is_empty(), "quiet mode must print nothing on success");
}

#[test]
fn failure_privileged_port_tty() {
    assert_golden(
        "failure_privileged_port_tty.txt",
        &render_failure_privileged_port(FULL_TTY, Mode::Human),
    );
}

#[test]
fn failure_privileged_port_json() {
    assert_golden(
        "failure_privileged_port_json.txt",
        &render_failure_privileged_port(JSON_CAPS, Mode::Json),
    );
}

#[test]
fn failure_unauthorized_piped_ascii_locale() {
    assert_golden(
        "failure_unauthorized_piped_ascii_locale.txt",
        &render_failure_unauthorized(PIPED_ASCII_LOCALE, Mode::Human),
    );
}

#[test]
fn failure_ca_unreachable_no_color() {
    assert_golden(
        "failure_ca_unreachable_no_color.txt",
        &render_failure_ca_unreachable(NO_COLOR, Mode::Human),
    );
}

#[test]
fn failure_agree_tos_full_tty() {
    assert_golden(
        "failure_agree_tos_full_tty.txt",
        &render_failure_agree_tos(FULL_TTY, Mode::Human),
    );
}

#[test]
fn failure_shows_in_quiet_mode_but_earlier_success_lines_do_not() {
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, NO_COLOR, Mode::Quiet);
        let _ = out.header(env!("CARGO_PKG_VERSION"), Some("https://acme-staging-v02.api.letsencrypt.org/directory"));
        let _ = out.step_done_with_metric("account", "new", "a8f3c21", Duration::from_millis(200));
        let err = certway_core::Error::PrivilegedPort { port: 80 };
        let block = report::classify(&err, Stage::Challenge, Proven::default(), "example.com");
        let _ = out.step_failed(block.label, &block.subject);
        let _ = out.error_block(&block);
    }
    let text = String::from_utf8(buf).unwrap();
    assert!(
        !text.contains("account"),
        "quiet mode must not show the earlier successful step"
    );
    assert!(
        text.contains("challenge"),
        "quiet mode must still show the failing step"
    );
    assert!(text.contains("permission"));
}

#[test]
fn no_color_mode_never_emits_an_escape_byte() {
    let buf = render_success(NO_COLOR, Mode::Human);
    assert!(
        !buf.contains(&0x1b),
        "NO_COLOR output must contain no ANSI escape byte, not even a reset"
    );

    let fail_buf = render_failure_unauthorized(NO_COLOR, Mode::Human);
    assert!(!fail_buf.contains(&0x1b));
}

// -- Width matrix (>=72 shows all columns, 48-71 omits the metric, <48
// omits detail and metric) ------------------------------------------------

fn one_line(width: u16) -> String {
    let caps = Caps {
        color: false,
        unicode: true,
        animation: false,
        width,
    };
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, caps, Mode::Human);
        let _ = out.step_done("validate", "1 of 1 authorized", Duration::from_millis(6100));
    }
    String::from_utf8(buf).unwrap()
}

#[test]
fn width_100_shows_all_three_columns() {
    let line = one_line(100);
    assert!(line.contains("validate"));
    assert!(line.contains("1 of 1 authorized"));
    assert!(line.contains("6.1s"));
}

#[test]
fn width_72_shows_all_three_columns() {
    let line = one_line(72);
    assert!(line.contains("1 of 1 authorized"));
    assert!(line.contains("6.1s"));
}

#[test]
fn width_60_omits_metric_only() {
    let line = one_line(60);
    assert!(line.contains("1 of 1 authorized"));
    assert!(!line.contains("6.1s"));
}

#[test]
fn width_40_omits_detail_and_metric() {
    let line = one_line(40);
    assert!(line.contains("validate"));
    assert!(!line.contains("1 of 1 authorized"));
    assert!(!line.contains("6.1s"));
}

#[test]
fn width_20_is_the_floor_and_still_renders() {
    let caps = Caps {
        color: false,
        unicode: true,
        animation: false,
        width: 20,
    };
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, caps, Mode::Human);
        let _ = out.step_done("validate", "1 of 1 authorized", Duration::from_millis(6100));
    }
    let line = String::from_utf8(buf).unwrap();
    assert!(line.contains("validate"));
}

#[test]
fn wide_character_domain_keeps_columns_aligned_at_width_100() {
    let caps = Caps {
        color: false,
        unicode: true,
        animation: false,
        width: 100,
    };
    let mut buf = Vec::new();
    {
        let mut out = Out::new(&mut buf, caps, Mode::Human);
        let _ = out.step_done("order", "例え.com control", Duration::from_millis(1200));
        let _ = out.step_done("validate", "1 of 1 authorized", Duration::from_millis(6100));
    }
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    // Both lines' metric text must start at the same display column,
    // regardless of the wide characters in the first line's detail field —
    // this is the test that catches str::len used for padding. The metric
    // is always the line's trailing bytes with nothing after it, so its
    // start column is the line's total display width minus the metric's
    // own display width.
    let metric_col = |line: &str, metric: &str| -> usize {
        assert!(line.ends_with(metric));
        certway::render::display_width(line) - certway::render::display_width(metric)
    };
    assert_eq!(metric_col(lines[0], "1.2s"), metric_col(lines[1], "6.1s"));
}
