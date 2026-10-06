// SPDX-License-Identifier: MIT

//! The success trailer: the closing line printed after a certificate is
//! issued, telling the user the one thing (if anything) they still need to
//! do. `Nothing else to do.` is the most valuable line this program can
//! print, and the most dangerous one to get wrong — it must appear when,
//! and only when, it is actually true. Everything below exists to make
//! that guarantee checkable rather than just asserted.
//!
//! `Trailer::line` maps each `Trailer` variant to its exact printed text.
//! `select` is the decision function: it looks at three inputs —
//! `dry_run`, `timer_installed`, and a `WebServerEdit` (the outcome of
//! `cmd::issue`'s nginx-editing step, collapsed down to just what `select`
//! needs) — and picks the one `Trailer` that honestly describes what
//! happened.
//!
//! **Ordering: `WebServerEditRefused` is checked before `timer_installed`.**
//! A refused web-server edit is reported regardless of whether a timer is
//! installed — the two facts are independent, and a user who declined the
//! nginx edit needs to know that regardless of their renewal schedule.
//! Checking it first also means `WebServerEditRefused` is reachable even in
//! a build where `timer_installed` is always `false` (see below).
//!
//! **`TimerWebServerEditedAndReloaded` is currently unreachable from
//! `cmd::issue::run`, and that is correct, not a bug.** Selecting it
//! requires `timer_installed: true`, but there is no on-disk signal today
//! that `certway install` ever ran — `cmd::install` writes a systemd unit
//! or a crontab entry, not a marker file this crate reads back — so
//! `cmd::issue::run` always passes `timer_installed: false`. Printing
//! `Nothing else to do.` without ever having confirmed a timer exists would
//! be exactly the false-confidence failure this module exists to prevent.
//! `select` itself is unconditionally correct for every input (its test
//! suite proves this exhaustively); it's only the caller's hardcoded
//! `false` that keeps this one branch from firing until timer detection is
//! implemented.
//!
//! **A successful hook/reload is not the same thing as a successful web
//! server edit, and the two must not be conflated.** A successful
//! `--hook`/`--reload` command only proves the command exited 0 — it
//! proves nothing about whether the web server it reloaded is actually
//! serving certway's files. A user who passes `--reload "systemctl reload
//! nginx"` against a server that was never configured to use these files
//! would see the reload "succeed" and, if this module conflated the two,
//! would be told `Nothing else to do.` while nothing was actually done.
//! So hook/reload success alone never selects
//! `TimerWebServerEditedAndReloaded` — only a real
//! `webserver::nginx::EditOutcome::Edited`, surfaced here as
//! `WebServerEdit::EditedAndReloaded`, does.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trailer {
    NoTimer,
    TimerWebServerEditedAndReloaded,
    TimerWebServerNotEdited,
    WebServerEditRefused,
    DryRun,
}

impl Trailer {
    pub fn line(self) -> &'static str {
        match self {
            Trailer::NoTimer => "Run `certway install` to renew automatically.",
            Trailer::TimerWebServerEditedAndReloaded => "Nothing else to do.",
            Trailer::TimerWebServerNotEdited => {
                "Point your web server at these files, then reload it."
            }
            Trailer::WebServerEditRefused => "Add the two lines above to your config, then reload.",
            Trailer::DryRun => "Nothing was changed.",
        }
    }
}

/// The nginx-editing outcome, collapsed to exactly what `select` needs to
/// choose a closing line — `cmd::issue`'s rendering of a
/// `webserver::nginx::EditOutcome` produces one of these.
/// `NotAttempted` covers every case that isn't a clean success or a
/// reported refusal: editing was never opted into, `--none` was given,
/// nothing resolved to nginx, or `find_and_edit` came back with one of
/// the restore/invalid-baseline outcomes — none of those name "the two
/// lines above" the way `Refused`/`NoMatchingBlock` do, so
/// `TimerWebServerNotEdited`'s more general "point your web server at
/// these files" is the honest closing line for all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebServerEdit {
    NotAttempted,
    EditedAndReloaded,
    Refused,
}

/// Selects this build's trailer. `timer_installed` is always `false` from
/// `cmd::issue::run` today (see the module doc) — the parameter exists so
/// the selection logic is complete and unit-tested against every input
/// now, rather than needing a signature change once `install` detection
/// exists.
pub fn select(dry_run: bool, timer_installed: bool, web_server: WebServerEdit) -> Trailer {
    if dry_run {
        return Trailer::DryRun;
    }
    if web_server == WebServerEdit::Refused {
        return Trailer::WebServerEditRefused;
    }
    if !timer_installed {
        return Trailer::NoTimer;
    }
    if web_server == WebServerEdit::EditedAndReloaded {
        return Trailer::TimerWebServerEditedAndReloaded;
    }
    Trailer::TimerWebServerNotEdited
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_WEB_SERVER: [WebServerEdit; 3] = [
        WebServerEdit::NotAttempted,
        WebServerEdit::EditedAndReloaded,
        WebServerEdit::Refused,
    ];

    #[test]
    fn dry_run_always_wins() {
        for timer_installed in [false, true] {
            for web_server in ALL_WEB_SERVER {
                assert_eq!(select(true, timer_installed, web_server), Trailer::DryRun);
            }
        }
    }

    #[test]
    fn no_timer_installed_suggests_install_unless_refused_or_dry_run() {
        assert_eq!(
            select(false, false, WebServerEdit::NotAttempted),
            Trailer::NoTimer
        );
        assert_eq!(
            select(false, false, WebServerEdit::EditedAndReloaded),
            Trailer::NoTimer
        );
    }

    #[test]
    fn timer_installed_without_web_server_editing_points_at_the_files() {
        assert_eq!(
            select(false, true, WebServerEdit::NotAttempted),
            Trailer::TimerWebServerNotEdited
        );
    }

    /// A web-server-edit refusal is reported regardless of timer state,
    /// and regardless of `dry_run`'s absence — it is not qualified on
    /// anything else.
    #[test]
    fn web_server_edit_refused_wins_over_timer_state_but_not_over_dry_run() {
        for timer_installed in [false, true] {
            assert_eq!(
                select(false, timer_installed, WebServerEdit::Refused),
                Trailer::WebServerEditRefused
            );
        }
        assert_eq!(
            select(true, false, WebServerEdit::Refused),
            Trailer::DryRun
        );
    }

    /// Replaces the old "unreachable by this build" test: `select` itself
    /// must select `Nothing else to do.` in exactly one cell of the input
    /// space — certificate written (implicit: `select` is only ever
    /// called on the success path), timer installed, and nginx edited and
    /// reloaded — and never in any other. `cmd::issue::run` still can't
    /// reach `timer_installed: true` today (see the module doc); this
    /// proves the function is correct for when it can.
    #[test]
    fn nothing_else_to_do_is_selected_exactly_when_all_three_conditions_hold() {
        for dry_run in [false, true] {
            for timer_installed in [false, true] {
                for web_server in ALL_WEB_SERVER {
                    let expected = !dry_run
                        && timer_installed
                        && web_server == WebServerEdit::EditedAndReloaded;
                    let got = select(dry_run, timer_installed, web_server)
                        == Trailer::TimerWebServerEditedAndReloaded;
                    assert_eq!(
                        got, expected,
                        "dry_run={dry_run} timer_installed={timer_installed} web_server={web_server:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_line_matches_the_documented_wording_verbatim() {
        assert_eq!(
            Trailer::NoTimer.line(),
            "Run `certway install` to renew automatically."
        );
        assert_eq!(
            Trailer::TimerWebServerEditedAndReloaded.line(),
            "Nothing else to do."
        );
        assert_eq!(
            Trailer::TimerWebServerNotEdited.line(),
            "Point your web server at these files, then reload it."
        );
        assert_eq!(
            Trailer::WebServerEditRefused.line(),
            "Add the two lines above to your config, then reload."
        );
        assert_eq!(Trailer::DryRun.line(), "Nothing was changed.");
    }
}
