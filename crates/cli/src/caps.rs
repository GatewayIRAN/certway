// SPDX-License-Identifier: MIT

//! Terminal capability detection.
//!
//! Resolved once at startup, before any output, and never recomputed.

use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub color: bool,
    pub unicode: bool,
    pub animation: bool,
    pub width: u16,
}

const MIN_WIDTH: u16 = 20;
const DEFAULT_WIDTH: u16 = 80;

impl Caps {
    /// Pure resolution from explicit inputs — the testable core. `detect`
    /// below supplies the real process environment.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        stdout_is_tty: bool,
        no_color_set: bool,
        term: Option<&str>,
        lc_all: Option<&str>,
        lc_ctype: Option<&str>,
        lang: Option<&str>,
        ci_set: bool,
        columns: Option<&str>,
    ) -> Caps {
        let term_is_dumb = term == Some("dumb");

        let color = stdout_is_tty && !no_color_set && !term_is_dumb;

        let locale_value = lc_all
            .filter(|s| !s.is_empty())
            .or(lc_ctype.filter(|s| !s.is_empty()))
            .or(lang);
        let unicode = locale_value
            .map(|v| {
                v.to_ascii_uppercase().contains("UTF-8") || v.to_ascii_lowercase().contains("utf8")
            })
            .unwrap_or(false);

        let animation = color && !ci_set && !term_is_dumb;

        let width = columns
            .and_then(|c| c.trim().parse::<u16>().ok())
            .filter(|w| *w > 0)
            .map(|w| w.max(MIN_WIDTH))
            .unwrap_or(DEFAULT_WIDTH);

        Caps {
            color,
            unicode,
            animation,
            width,
        }
    }

    /// Reads the real process environment and stdout's TTY status. The only
    /// impure entry point in this module — called exactly once, at startup.
    pub fn detect() -> Caps {
        let stdout_is_tty = std::io::stdout().is_terminal();
        let no_color_set = std::env::var_os("NO_COLOR").is_some();
        let term = std::env::var("TERM").ok();
        let lc_all = std::env::var("LC_ALL").ok();
        let lc_ctype = std::env::var("LC_CTYPE").ok();
        let lang = std::env::var("LANG").ok();
        let ci_set = std::env::var_os("CI").is_some();
        let columns = std::env::var("COLUMNS").ok();

        Caps::resolve(
            stdout_is_tty,
            no_color_set,
            term.as_deref(),
            lc_all.as_deref(),
            lc_ctype.as_deref(),
            lang.as_deref(),
            ci_set,
            columns.as_deref(),
        )
    }

    /// `--json` forces color, unicode, and animation all off.
    pub fn force_json(self) -> Caps {
        Caps {
            color: false,
            unicode: false,
            animation: false,
            ..self
        }
    }

    /// `--no-color` forces color and animation off.
    pub fn force_no_color(self) -> Caps {
        Caps {
            color: false,
            animation: false,
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_counts_as_set_when_empty() {
        let caps = Caps::resolve(true, true, None, None, None, None, false, None);
        assert!(!caps.color);
    }

    #[test]
    fn color_requires_tty() {
        let caps = Caps::resolve(false, false, None, None, None, None, false, None);
        assert!(!caps.color);
    }

    #[test]
    fn term_dumb_disables_color() {
        let caps = Caps::resolve(true, false, Some("dumb"), None, None, None, false, None);
        assert!(!caps.color);
    }

    #[test]
    fn animation_requires_color_and_no_ci() {
        let with_ci = Caps::resolve(true, false, None, None, None, None, true, None);
        assert!(with_ci.color);
        assert!(!with_ci.animation);
    }

    #[test]
    fn unicode_from_lc_all_first() {
        let caps = Caps::resolve(
            true,
            false,
            None,
            Some("en_US.UTF-8"),
            Some("C"),
            Some("C"),
            false,
            None,
        );
        assert!(caps.unicode);
    }

    #[test]
    fn unicode_false_without_any_utf8_locale() {
        let caps = Caps::resolve(
            true,
            false,
            None,
            Some("C"),
            Some("C"),
            Some("C"),
            false,
            None,
        );
        assert!(!caps.unicode);
    }

    #[test]
    fn width_defaults_to_80_when_undetectable() {
        let caps = Caps::resolve(true, false, None, None, None, None, false, None);
        assert_eq!(caps.width, 80);
    }

    #[test]
    fn width_from_columns_env() {
        let caps = Caps::resolve(true, false, None, None, None, None, false, Some("100"));
        assert_eq!(caps.width, 100);
    }

    #[test]
    fn width_clamped_to_minimum_20() {
        let caps = Caps::resolve(true, false, None, None, None, None, false, Some("5"));
        assert_eq!(caps.width, 20);
    }

    #[test]
    fn force_json_disables_all_three() {
        let caps = Caps::resolve(
            true,
            false,
            None,
            Some("en_US.UTF-8"),
            None,
            None,
            false,
            None,
        )
        .force_json();
        assert!(!caps.color && !caps.unicode && !caps.animation);
    }

    #[test]
    fn force_no_color_keeps_unicode() {
        let caps = Caps::resolve(
            true,
            false,
            None,
            Some("en_US.UTF-8"),
            None,
            None,
            false,
            None,
        )
        .force_no_color();
        assert!(!caps.color && !caps.animation && caps.unicode);
    }
}
