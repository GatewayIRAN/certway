// SPDX-License-Identifier: MIT

//! The single writer. One type owns every byte written to stdout.
//! Nothing else in this crate calls `print!` or writes to stdout
//! directly.

use crate::caps::Caps;
use certway_core::json::{write_object, JsonVal};
use std::io::{self, Write};

// ---------------------------------------------------------------------
// Display width. Padding is measured in columns, not bytes and not `char`
// count. The ranges below are a fixed, hand-curated set for this project's
// terminal output — not a general Unicode East-Asian-Width table, so don't
// expect it to match what a general-purpose width crate reports.
// ---------------------------------------------------------------------

fn is_combining(cp: u32) -> bool {
    matches!(cp,
        0x0300..=0x036F | 0x0483..=0x0489 | 0x0591..=0x05BD | 0x1AB0..=0x1AFF |
        0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F | 0x200B..=0x200F | 0xFEFF)
}

fn is_wide(cp: u32) -> bool {
    matches!(cp,
        0x1100..=0x115F |
        0x2E80..=0x303E |
        0x3041..=0x33FF |
        0x3400..=0x4DBF |
        0x4E00..=0x9FFF |
        0xA000..=0xA4CF |
        0xAC00..=0xD7A3 |
        0xF900..=0xFAFF |
        0xFE30..=0xFE6F |
        0xFF00..=0xFF60 |
        0xFFE0..=0xFFE6 |
        0x1F300..=0x1F64F |
        0x1F900..=0x1F9FF |
        0x20000..=0x3FFFD)
}

fn char_width(c: char) -> usize {
    let cp = c as u32;
    if cp == 0 {
        return 0;
    }
    if is_combining(cp) {
        return 0;
    }
    if is_wide(cp) {
        return 2;
    }
    1
}

/// Display width in terminal columns, using the fixed combining/wide-char
/// ranges above.
pub fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// Truncates `s` to fit within `max_width` display columns, appending the
/// ellipsis (`…` unicode, `...` ascii) as the final character when
/// truncation happens. Never wraps.
pub fn truncate_to_width(s: &str, max_width: usize, unicode: bool) -> String {
    if display_width(s) <= max_width {
        return s.to_string();
    }
    let ellipsis = if unicode { "…" } else { "..." };
    let ellipsis_width = display_width(ellipsis);
    let budget = max_width.saturating_sub(ellipsis_width);

    let mut out = String::new();
    let mut w = 0usize;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw > budget {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push_str(ellipsis);
    out
}

/// Pads `s` with spaces up to `width` display columns — truncating first
/// when it's already longer, so a field is always exactly `width` columns
/// wide, never more. Truncation lives here, not in each caller: a caller
/// that padded raw user data (`cmd::list`'s `DOMAIN` column, once) without
/// truncating first ran straight into the next column with no separator —
/// found live against a real domain name, `monitoring.internal.example
/// .com` (32 chars) against a 27-column field. `truncate_to_width` was
/// already sitting unused for exactly this; every `pad_field` caller gets
/// the fix at once, and any future one gets it by construction rather
/// than by remembering to call `truncate_to_width` first.
pub(crate) fn pad_field(s: &str, width: usize, unicode: bool) -> String {
    let truncated = truncate_to_width(s, width, unicode);
    let w = display_width(&truncated);
    if w >= width {
        truncated
    } else {
        let mut out = String::with_capacity(truncated.len() + (width - w));
        out.push_str(&truncated);
        out.push_str(&" ".repeat(width - w));
        out
    }
}

/// Right-aligns `s` within `width` display columns — used for the `DAYS`
/// column, the one field in `list`'s output that's right- rather than
/// left-aligned.
pub(crate) fn pad_field_right(s: &str, width: usize) -> String {
    let w = display_width(s);
    if w >= width {
        s.to_string()
    } else {
        let mut out = String::with_capacity(s.len() + (width - w));
        out.push_str(&" ".repeat(width - w));
        out.push_str(s);
        out
    }
}

// ---------------------------------------------------------------------
// Grid
// ---------------------------------------------------------------------

pub const LABEL_WIDTH: usize = 14;
pub const DETAIL_WIDTH: usize = 28;
pub const WIDE_MIN: u16 = 72;
pub const MID_MIN: u16 = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyph {
    Running,
    Done,
    Warned,
    Failed,
    Skipped,
}

// Colour sequences. Only the 16 basic ANSI colours are used.
const SUCCESS: &str = "\x1b[32m";
// `list` colours its header row, `DAYS`, and `EXPIRES` itself rather than
// going through `render_status_line`, so these three are widened for it —
// always pair with `RESET` and gate on `Caps::color`, the same rule every
// other colour use in this module already follows.
pub(crate) const FAILURE: &str = "\x1b[31m";
pub(crate) const WARNING: &str = "\x1b[33m";
pub(crate) const MUTED: &str = "\x1b[2m";
const ACTION: &str = "\x1b[36m";
pub(crate) const RESET: &str = "\x1b[0m";

fn glyph_char(g: Glyph, unicode: bool, spinner_frame: usize) -> String {
    if g == Glyph::Running {
        return spinner_char(unicode, spinner_frame).to_string();
    }
    match (g, unicode) {
        (Glyph::Done, true) => "✓".to_string(),
        (Glyph::Done, false) => "+".to_string(),
        (Glyph::Failed, true) => "✗".to_string(),
        (Glyph::Failed, false) => "x".to_string(),
        (Glyph::Warned, _) => "!".to_string(),
        (Glyph::Skipped, true) => "·".to_string(),
        (Glyph::Skipped, false) => "-".to_string(),
        (Glyph::Running, _) => unreachable!(),
    }
}

const SPINNER_UNICODE: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const SPINNER_ASCII: [char; 4] = ['-', '\\', '|', '/'];

pub fn spinner_char(unicode: bool, frame: usize) -> char {
    if unicode {
        SPINNER_UNICODE[frame % SPINNER_UNICODE.len()]
    } else {
        SPINNER_ASCII[frame % SPINNER_ASCII.len()]
    }
}

/// 80ms/frame for the unicode spinner, 120ms/frame for the ASCII one.
pub fn spinner_interval_ms(unicode: bool) -> u64 {
    if unicode {
        80
    } else {
        120
    }
}

fn glyph_color(g: Glyph) -> Option<&'static str> {
    match g {
        Glyph::Running | Glyph::Skipped => Some(MUTED),
        Glyph::Done => Some(SUCCESS),
        Glyph::Warned => Some(WARNING),
        Glyph::Failed => Some(FAILURE),
    }
}

/// Renders one status line's byte content (without the trailing newline).
/// Degrades by terminal width: below `MID_MIN`, glyph + label only; below
/// `WIDE_MIN`, add the truncated detail field but drop the metric; at or
/// above `WIDE_MIN`, show the full row including the metric.
#[allow(clippy::too_many_arguments)]
pub fn render_status_line(
    glyph: Glyph,
    label: &str,
    detail: &str,
    metric: Option<&str>,
    caps: &Caps,
    spinner_frame: usize,
) -> String {
    let mut out = String::new();
    out.push_str("  "); // margin, cols 1-2

    let gc = glyph_char(glyph, caps.unicode, spinner_frame);
    if caps.color {
        if let Some(color) = glyph_color(glyph) {
            out.push_str(color);
            out.push_str(&gc);
            out.push_str(RESET);
        } else {
            out.push_str(&gc);
        }
    } else {
        out.push_str(&gc);
    }
    out.push(' '); // gap, col 4

    let label_field = pad_field(label, LABEL_WIDTH, caps.unicode);
    out.push_str(&label_field);

    if caps.width < MID_MIN {
        return out.trim_end().to_string();
    }

    out.push(' '); // separator before detail field
    let detail_truncated = truncate_to_width(detail, DETAIL_WIDTH, caps.unicode);
    let detail_field = pad_field(&detail_truncated, DETAIL_WIDTH, caps.unicode);

    if caps.width < WIDE_MIN || metric.is_none() {
        out.push_str(detail_field.trim_end());
        return out;
    }

    out.push_str(&detail_field);
    if let Some(m) = metric {
        out.push_str(m);
    }
    out
}

// ---------------------------------------------------------------------
// Metric formatting
// ---------------------------------------------------------------------

/// `None` under 1.0s. One decimal + `s` from 1.0-59.9s. Minutes and whole
/// seconds at 60s and over — including exactly 60s, which is `1m 0s`.
pub fn duration_metric(elapsed: std::time::Duration) -> Option<String> {
    let secs = elapsed.as_secs_f64();
    if secs < 1.0 {
        None
    } else if secs < 60.0 {
        Some(format!("{secs:.1}s"))
    } else {
        let total = elapsed.as_secs();
        let mins = total / 60;
        let rem = total % 60;
        Some(format!("{mins}m {rem}s"))
    }
}

// ---------------------------------------------------------------------
// Out — the single stdout writer
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Human,
    Json,
    Quiet,
}

pub struct Out<W: Write> {
    pub caps: Caps,
    pub mode: Mode,
    writer: W,
    /// Whether a running (spinner) line is currently on-screen, unterminated
    /// by a newline. Tracked so the next write knows whether to `\r` + erase
    /// first.
    line_open: bool,
}

/// Let's Encrypt's own two directory URLs — matched by exact identity, not
/// a substring. The previous rule (`directory_url.contains("staging")`)
/// mislabelled any custom `--server` that didn't happen to contain that
/// word as production Let's Encrypt — a false statement about who issued
/// a certificate, not a missing hint. `cmd::issue`/`cmd::renew` keep their
/// own copy of the staging URL (their default-`--server` value, resolved
/// before a `Client` exists); these exist so `header`'s classification
/// never depends on that literal matching elsewhere by coincidence.
const LETS_ENCRYPT_PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// `header`'s CA label: Let's Encrypt's two directories by exact match,
/// or — never guessed, never inferred from a substring — the URL's own
/// host for anything else, including Pebble, a private ACME server, or a
/// typo. If certway cannot name the CA with certainty, it shows what the
/// user gave it instead of asserting a brand.
fn ca_label(directory_url: &str) -> String {
    if directory_url == LETS_ENCRYPT_PRODUCTION_URL {
        "Let's Encrypt".to_string()
    } else if directory_url == LETS_ENCRYPT_STAGING_URL {
        "Let's Encrypt (staging)".to_string()
    } else {
        crate::store::host_from_url(directory_url).to_string()
    }
}

impl<W: Write> Out<W> {
    pub fn new(writer: W, caps: Caps, mode: Mode) -> Out<W> {
        Out {
            caps,
            mode,
            writer,
            line_open: false,
        }
    }

    fn write_raw(&mut self, s: &str) -> io::Result<()> {
        self.writer.write_all(s.as_bytes())
    }

    fn clear_open_line(&mut self) -> io::Result<()> {
        if self.line_open {
            if self.caps.animation {
                self.write_raw("\r\x1b[K")?;
            }
            self.line_open = false;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Writes one already-formatted line (e.g. from a fixed-string screen
    /// like the no-argument help) followed by a newline. Suppressed in
    /// `Json` mode, since human screens have no JSON equivalent.
    pub fn raw_line(&mut self, s: &str) -> io::Result<()> {
        if self.mode == Mode::Json {
            return Ok(());
        }
        self.write_raw(s)?;
        self.write_raw("\n")
    }

    /// Writes one already-serialized JSON line, only in `Json` mode — for
    /// screens (`list`) that assemble their own `write_object` calls
    /// rather than going through a dedicated `json_*` method per field
    /// shape. Still the one path every byte flows through: callers never
    /// touch stdout directly.
    pub fn json_raw_line(&mut self, s: &str) -> io::Result<()> {
        if self.mode != Mode::Json {
            return Ok(());
        }
        self.write_raw(s)?;
        self.write_raw("\n")?;
        self.flush()
    }

    // -- Header -----------------------------------------------------------------

    /// `ca_directory_url`: `None` for commands that never contact a CA
    /// (`list`/`install`/`export`/`rollback` show bare `certway {version}`,
    /// no suffix at all); `Some(url)` for `issue`/`renew`, which do.
    pub fn header(&mut self, version: &str, ca_directory_url: Option<&str>) -> io::Result<()> {
        if self.mode == Mode::Json {
            return Ok(());
        }
        if self.mode == Mode::Quiet {
            // Quiet suppresses everything but the eventual error block; the
            // header is not part of that block.
            return Ok(());
        }
        self.write_raw("\n  ")?;
        self.write_raw(&format!("certway {version}"))?;
        if let Some(url) = ca_directory_url {
            let ca = ca_label(url);
            // The header separator is a "·", but no ASCII fallback for it
            // is written down anywhere. The `unicode` capability exists so
            // that no UTF-8 byte is ever emitted when it's false, so this
            // dot is treated as covered by that same rule and falls back
            // to "-" rather than being kept as fixed prose.
            let sep = if self.caps.unicode { "·" } else { "-" };
            if self.caps.color {
                self.write_raw(MUTED)?;
                self.write_raw(&format!(" {sep} {ca}"))?;
                self.write_raw(RESET)?;
            } else {
                self.write_raw(&format!(" {sep} {ca}"))?;
            }
        }
        self.write_raw("\n\n")?;
        self.flush()
    }

    // -- Steps ------------------------------------------------------------------

    /// Called once when a step starts. Only ever produces visible output
    /// when animation is on and the mode is not JSON (JSON streams only on
    /// completion; quiet still shows the transient spinner, since nothing
    /// persists from it on success).
    pub fn step_running(&mut self, label: &'static str) -> io::Result<()> {
        if self.mode == Mode::Json || !self.caps.animation {
            return Ok(());
        }
        let line = render_status_line(Glyph::Running, label, "", None, &self.caps, 0);
        self.write_raw(&line)?;
        self.line_open = true;
        self.flush()
    }

    /// Redraws the running line with the next spinner frame. No-op unless
    /// animation is active.
    pub fn step_frame(&mut self, label: &'static str, frame: usize) -> io::Result<()> {
        if self.mode == Mode::Json || !self.caps.animation {
            return Ok(());
        }
        self.write_raw("\r\x1b[K")?;
        let line = render_status_line(Glyph::Running, label, "", None, &self.caps, frame);
        self.write_raw(&line)?;
        self.line_open = true;
        self.flush()
    }

    /// A step completed successfully. `elapsed` drives both the human
    /// metric column (omitted under 1.0s, one decimal from 1.0-59.9s,
    /// `Nm Ns` at 60s and over) and the `ms` field in `--json` mode, so the
    /// two representations cannot drift apart.
    pub fn step_done(
        &mut self,
        label: &'static str,
        detail: &str,
        elapsed: std::time::Duration,
    ) -> io::Result<()> {
        let ms = elapsed.as_millis().to_string();
        self.step_done_inner(label, detail, duration_metric(elapsed), Some(ms))
    }

    /// A step completed successfully, with an explicit metric string rather
    /// than a duration — the `account` step's identifier metric (first 7
    /// hex characters of the account key thumbprint) is not a duration and
    /// must not be confused with one.
    pub fn step_done_with_metric(
        &mut self,
        label: &'static str,
        detail: &str,
        metric: &str,
        elapsed: std::time::Duration,
    ) -> io::Result<()> {
        self.step_done_inner(
            label,
            detail,
            Some(metric.to_string()),
            Some(elapsed.as_millis().to_string()),
        )
    }

    fn step_done_inner(
        &mut self,
        label: &'static str,
        detail: &str,
        metric: Option<String>,
        json_ms: Option<String>,
    ) -> io::Result<()> {
        match self.mode {
            Mode::Json => {
                let mut fields: Vec<(&str, JsonVal)> = vec![
                    ("step", JsonVal::Str(label)),
                    ("state", JsonVal::Str("done")),
                ];
                if let Some(ms) = &json_ms {
                    fields.push(("ms", JsonVal::Raw(ms)));
                }
                if !detail.is_empty() {
                    fields.push(("detail", JsonVal::Str(detail)));
                }
                let obj = write_object(&fields);
                self.write_raw(&obj)?;
                self.write_raw("\n")?;
                self.flush()
            }
            Mode::Quiet => {
                // Nothing on success in quiet mode. Only clear a spinner
                // line if one was left open.
                self.clear_open_line()
            }
            Mode::Human => {
                self.clear_open_line()?;
                let line = render_status_line(
                    Glyph::Done,
                    label,
                    detail,
                    metric.as_deref(),
                    &self.caps,
                    0,
                );
                self.write_raw(&line)?;
                self.write_raw("\n")?;
                self.flush()
            }
        }
    }

    /// A step failed. This is the leading line of the error block and is
    /// printed even in quiet mode.
    pub fn step_failed(&mut self, label: &'static str, subject: &str) -> io::Result<()> {
        if self.mode == Mode::Json {
            return Ok(());
        }
        self.clear_open_line()?;
        let line = render_status_line(Glyph::Failed, label, subject, None, &self.caps, 0);
        self.write_raw(&line)?;
        self.write_raw("\n")?;
        self.flush()
    }

    /// A step that did nothing because there was nothing to do — the `·`
    /// glyph. `install`'s container screen is this build's only user of
    /// it: "no scheduler — container detected" is reported, not an error.
    pub fn step_skipped(&mut self, label: &'static str, detail: &str) -> io::Result<()> {
        match self.mode {
            Mode::Json => {
                let obj = write_object(&[
                    ("step", JsonVal::Str(label)),
                    ("state", JsonVal::Str("skipped")),
                    ("detail", JsonVal::Str(detail)),
                ]);
                self.write_raw(&obj)?;
                self.write_raw("\n")?;
                self.flush()
            }
            Mode::Quiet => self.clear_open_line(),
            Mode::Human => {
                self.clear_open_line()?;
                let line = render_status_line(Glyph::Skipped, label, detail, None, &self.caps, 0);
                self.write_raw(&line)?;
                self.write_raw("\n")?;
                self.flush()
            }
        }
    }

    /// A step that succeeded but needs attention — the `!` glyph. Surfaced
    /// even in quiet mode (unlike `step_skipped`/success), matching
    /// `step_failed`'s precedent: a warning is exactly the kind of thing
    /// `--quiet` must not hide (`install`'s "no volume detected" case, for
    /// example).
    pub fn step_warned(&mut self, label: &'static str, detail: &str) -> io::Result<()> {
        match self.mode {
            Mode::Json => {
                let obj = write_object(&[
                    ("step", JsonVal::Str(label)),
                    ("state", JsonVal::Str("warned")),
                    ("detail", JsonVal::Str(detail)),
                ]);
                self.write_raw(&obj)?;
                self.write_raw("\n")?;
                self.flush()
            }
            Mode::Quiet | Mode::Human => {
                self.clear_open_line()?;
                let line = render_status_line(Glyph::Warned, label, detail, None, &self.caps, 0);
                self.write_raw(&line)?;
                self.write_raw("\n")?;
                self.flush()
            }
        }
    }

    pub fn json_step_failed(
        &mut self,
        label: &'static str,
        error: &str,
        detail: &str,
    ) -> io::Result<()> {
        if self.mode != Mode::Json {
            return Ok(());
        }
        let obj = write_object(&[
            ("step", JsonVal::Str(label)),
            ("state", JsonVal::Str("failed")),
            ("error", JsonVal::Str(error)),
            ("detail", JsonVal::Str(detail)),
        ]);
        self.write_raw(&obj)?;
        self.write_raw("\n")?;
        self.flush()
    }

    // -- Error block --------------------------------------------------------------

    pub fn error_block(&mut self, block: &crate::report::ErrorBlock) -> io::Result<()> {
        if self.mode == Mode::Json {
            return Ok(());
        }
        self.write_raw("\n")?;
        self.write_raw("    ")?;
        self.write_raw(&block.summary)?;
        self.write_raw("\n")?;

        if !block.evidence.is_empty() {
            self.write_raw("\n")?;
            for line in &block.evidence {
                self.write_evidence_line(line)?;
            }
        }

        if !block.causes.is_empty() {
            self.write_raw("\n")?;
            self.write_raw("    ")?;
            self.write_raw(block.narrowing)?;
            self.write_raw("\n\n")?;
            let bullet = if self.caps.unicode { "·" } else { "*" };
            for cause in &block.causes {
                self.write_raw(&format!("      {bullet} {cause}\n"))?;
            }
        }

        if let Some(action) = &block.action {
            self.write_raw("\n")?;
            self.write_raw("    ")?;
            self.write_raw(action.line)?;
            self.write_raw("\n")?;
            // Some actions are one plain-language sentence with nothing
            // runnable to show (e.g. "pass --agree-tos") — skip the blank
            // line + command row reserved for an actual command.
            if !action.command.is_empty() {
                self.write_raw("\n")?;
                self.write_command_line(&action.command)?;
            }
        }

        self.write_raw("\n  ")?;
        self.write_raw(block.state_line)?;
        self.write_raw("\n\n")?;
        self.flush()
    }

    fn write_evidence_line(&mut self, s: &str) -> io::Result<()> {
        if self.caps.color {
            self.write_raw(&format!("      {MUTED}{s}{RESET}\n"))
        } else {
            self.write_raw(&format!("      {s}\n"))
        }
    }

    fn write_command_line(&mut self, s: &str) -> io::Result<()> {
        if self.caps.color {
            self.write_raw(&format!("      {ACTION}{s}{RESET}\n"))
        } else {
            self.write_raw(&format!("      {s}\n"))
        }
    }

    pub fn json_result_failed(
        &mut self,
        stage: &str,
        error: &str,
        quota_used: bool,
    ) -> io::Result<()> {
        if self.mode != Mode::Json {
            return Ok(());
        }
        let obj = write_object(&[
            ("result", JsonVal::Str("failed")),
            ("stage", JsonVal::Str(stage)),
            ("error", JsonVal::Str(error)),
            ("quota_used", JsonVal::Bool(quota_used)),
        ]);
        self.write_raw(&obj)?;
        self.write_raw("\n")?;
        self.flush()
    }

    // -- Success trailer ----------------------------------------------------------

    pub fn trailer_paths(&mut self, fullchain: &str, key: &str) -> io::Result<()> {
        if self.mode != Mode::Human {
            return Ok(());
        }
        self.write_raw("\n")?;
        self.write_path_line("fullchain", fullchain)?;
        self.write_path_line("key", key)?;
        self.flush()
    }

    fn write_path_line(&mut self, label: &str, path: &str) -> io::Result<()> {
        let padded = pad_field(label, 12, self.caps.unicode);
        if self.caps.color {
            self.write_raw(&format!("    {padded}{ACTION}{path}{RESET}\n"))
        } else {
            self.write_raw(&format!("    {padded}{path}\n"))
        }
    }

    pub fn trailer_prose(&mut self, lines: &[&str]) -> io::Result<()> {
        if self.mode != Mode::Human {
            return Ok(());
        }
        self.write_raw("\n")?;
        for line in lines {
            self.write_raw(&format!("    {line}\n"))?;
        }
        self.write_raw("\n")?;
        self.flush()
    }

    pub fn json_result_issued(
        &mut self,
        domains: &[String],
        fullchain: &str,
        key: &str,
    ) -> io::Result<()> {
        if self.mode != Mode::Json {
            return Ok(());
        }
        let domain_vals: Vec<JsonVal> = domains.iter().map(|d| JsonVal::Str(d.as_str())).collect();
        let obj = write_object(&[
            ("result", JsonVal::Str("issued")),
            ("domains", JsonVal::Array(domain_vals)),
            ("fullchain", JsonVal::Str(fullchain)),
            ("key", JsonVal::Str(key)),
        ]);
        self.write_raw(&obj)?;
        self.write_raw("\n")?;
        self.flush()
    }

    pub fn json_result_account(&mut self, ca: &str, url: &str) -> io::Result<()> {
        if self.mode != Mode::Json {
            return Ok(());
        }
        let obj = write_object(&[
            ("result", JsonVal::Str("account")),
            ("ca", JsonVal::Str(ca)),
            ("url", JsonVal::Str(url)),
        ]);
        self.write_raw(&obj)?;
        self.write_raw("\n")?;
        self.flush()
    }

    pub fn json_result_deleted(&mut self, name: &str) -> io::Result<()> {
        if self.mode != Mode::Json {
            return Ok(());
        }
        let obj = write_object(&[
            ("result", JsonVal::Str("deleted")),
            ("name", JsonVal::Str(name)),
        ]);
        self.write_raw(&obj)?;
        self.write_raw("\n")?;
        self.flush()
    }

    pub fn json_result_imported(&mut self, name: &str, fullchain: &str) -> io::Result<()> {
        if self.mode != Mode::Json {
            return Ok(());
        }
        let obj = write_object(&[
            ("result", JsonVal::Str("imported")),
            ("name", JsonVal::Str(name)),
            ("fullchain", JsonVal::Str(fullchain)),
        ]);
        self.write_raw(&obj)?;
        self.write_raw("\n")?;
        self.flush()
    }

    pub fn json_result_revoked(&mut self, name: &str) -> io::Result<()> {
        if self.mode != Mode::Json {
            return Ok(());
        }
        let obj = write_object(&[
            ("result", JsonVal::Str("revoked")),
            ("name", JsonVal::Str(name)),
        ]);
        self.write_raw(&obj)?;
        self.write_raw("\n")?;
        self.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_string_width_equals_len() {
        assert_eq!(display_width("preflight"), 9);
    }

    #[test]
    fn cjk_characters_count_as_two_columns() {
        assert_eq!(display_width("你好"), 4);
    }

    #[test]
    fn combining_mark_counts_as_zero() {
        // 'e' + combining acute accent (U+0301)
        let s = "e\u{0301}";
        assert_eq!(display_width(s), 1);
    }

    #[test]
    fn cyrillic_and_hebrew_combining_marks_count_as_zero() {
        // Cyrillic 'а' + COMBINING CYRILLIC TITLO (U+0483); Hebrew 'ב' +
        // HEBREW POINT HIRIQ (U+05B4, inside this file's is_combining
        // 0x0591..=0x05BD range).
        assert_eq!(display_width("а\u{0483}"), 1);
        assert_eq!(display_width("ב\u{05B4}"), 1);
    }

    #[test]
    fn hebrew_and_cyrillic_combining_marks_do_not_consume_padding() {
        // pad_field uses display_width internally, so re-measuring its
        // output with display_width can't catch a bug in display_width
        // itself — it would just agree with itself. Count real trailing
        // space characters instead: 4 visible codepoints ('a', 'b', Hebrew
        // 'ב', 'ג') plus 2 zero-width combining marks. If either combining
        // mark were miscounted as width 1, padding would fall short by
        // exactly that many columns.
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 100,
        };
        let detail = "ab\u{0483}ב\u{05B4}ג";
        let line = render_status_line(Glyph::Done, "order", detail, Some("1.2s"), &caps, 0);
        let up_to_metric = &line[..line.len() - "1.2s".len()];
        let trailing_spaces = up_to_metric.chars().rev().take_while(|c| *c == ' ').count();
        assert_eq!(trailing_spaces, DETAIL_WIDTH - 4);
    }

    #[test]
    fn truncate_appends_unicode_ellipsis() {
        let s = truncate_to_width("this is a very long label indeed", 10, true);
        assert_eq!(display_width(&s), 10);
        assert!(s.ends_with('…'));
    }

    #[test]
    fn truncate_appends_ascii_ellipsis() {
        let s = truncate_to_width("this is a very long label indeed", 10, false);
        assert_eq!(display_width(&s), 10);
        assert!(s.ends_with("..."));
    }

    #[test]
    fn wide_char_domain_keeps_columns_aligned() {
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 100,
        };
        let line = render_status_line(
            Glyph::Done,
            "order",
            "例え.com 1 domain",
            Some("1.2s"),
            &caps,
            0,
        );
        // metric must start exactly at display column 48 (1-indexed) => index 47.
        let up_to_metric = &line[..line.len() - "1.2s".len()];
        assert_eq!(display_width(up_to_metric), 47);
    }

    #[test]
    fn duration_under_one_second_has_no_metric() {
        assert_eq!(duration_metric(std::time::Duration::from_millis(400)), None);
    }

    #[test]
    fn duration_one_point_one_seconds() {
        assert_eq!(
            duration_metric(std::time::Duration::from_millis(1100)),
            Some("1.1s".to_string())
        );
    }

    #[test]
    fn duration_exactly_60_seconds_is_1m_0s() {
        assert_eq!(
            duration_metric(std::time::Duration::from_secs(60)),
            Some("1m 0s".to_string())
        );
    }

    #[test]
    fn duration_over_a_minute() {
        assert_eq!(
            duration_metric(std::time::Duration::from_secs(72)),
            Some("1m 12s".to_string())
        );
    }

    // -- pad_field truncates before padding ---------------------------------

    #[test]
    fn pad_field_pads_a_short_value_unchanged() {
        assert_eq!(pad_field("abc", 6, true), "abc   ");
    }

    /// The bug found live: `certway-nginx-edit-proof.example` — 27+
    /// characters against a 27-column `DOMAIN` field — used to run
    /// straight into the next column with zero separation. A field is
    /// now always exactly `width` columns, never more.
    #[test]
    fn pad_field_truncates_a_value_longer_than_its_width_instead_of_overflowing_it() {
        let out = pad_field("monitoring.internal.example.com", 10, true);
        assert_eq!(display_width(&out), 10);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn pad_field_truncation_uses_the_ascii_ellipsis_when_unicode_is_off() {
        let out = pad_field("monitoring.internal.example.com", 10, false);
        assert_eq!(display_width(&out), 10);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn pad_field_at_exactly_the_width_is_unchanged() {
        let s = "1234567890";
        assert_eq!(pad_field(s, 10, true), s);
    }

    // -- ca_label / header ---------------------------------------------------

    #[test]
    fn ca_label_names_lets_encrypt_production_by_exact_url_only() {
        assert_eq!(
            ca_label("https://acme-v02.api.letsencrypt.org/directory"),
            "Let's Encrypt"
        );
    }

    #[test]
    fn ca_label_names_lets_encrypt_staging_by_exact_url_only() {
        assert_eq!(
            ca_label("https://acme-staging-v02.api.letsencrypt.org/directory"),
            "Let's Encrypt (staging)"
        );
    }

    /// The bug this replaces: `directory_url.contains("staging")` labelled
    /// any custom `--server` not literally containing that word as
    /// production Let's Encrypt — a false claim, not a missing hint. A
    /// local Pebble instance must show its own host, never "Let's
    /// Encrypt".
    #[test]
    fn ca_label_never_infers_lets_encrypt_from_a_substring() {
        assert_eq!(ca_label("https://localhost:14000/dir"), "localhost");
        assert_eq!(
            ca_label("https://acme.internal.example.com/directory"),
            "acme.internal.example.com"
        );
        assert_eq!(
            ca_label("https://not-staging-really.example/directory"),
            "not-staging-really.example"
        );
    }

    fn captured_header(ca_directory_url: Option<&str>) -> String {
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 80,
        };
        let mut buf = Vec::new();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            out.header("1.0.0", ca_directory_url).unwrap();
        }
        String::from_utf8(buf).unwrap()
    }

    /// `list`/`install`/`export`/`rollback` show bare `certway {version}`
    /// — no CA suffix, since none of those commands ever contact one.
    #[test]
    fn header_with_no_ca_directory_omits_the_suffix_entirely() {
        let text = captured_header(None);
        assert!(text.contains("certway 1.0.0"));
        assert!(!text.contains("·"));
        assert!(!text.contains("Let's Encrypt"));
    }

    #[test]
    fn header_with_a_ca_directory_shows_its_label() {
        let text = captured_header(Some("https://acme-staging-v02.api.letsencrypt.org/directory"));
        assert!(text.contains("certway 1.0.0 · Let's Encrypt (staging)"));
    }
}
