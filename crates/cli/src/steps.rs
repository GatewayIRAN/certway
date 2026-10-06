// SPDX-License-Identifier: MIT

//! Step lifecycle and the spinner.
//!
//! The spinner thread owns only the frame counter; all writing happens on
//! the main thread — a background thread must never write to stdout
//! itself, only signal the main thread to redraw, so output stays
//! ordered and terminal state stays consistent. `Http01Server`
//! already establishes the pattern of a dedicated worker thread for one
//! well-scoped job in this codebase (`crates/core/src/challenge.rs`) — this
//! is the same shape, not a departure from this project's general policy
//! against thread pools.

use crate::render::{spinner_interval_ms, Mode, Out};
use certway_core::{self as core, Authorization, AuthzStatus, Challenge, ChallengeType};
use std::io::Write;
use std::time::{Duration, Instant};

/// Redraws the spinner on the main thread while `work` runs on a scoped
/// helper thread, and returns the elapsed wall time alongside `work`'s
/// result. Does **not** print the step's running line itself — call
/// `Out::step_running` first, or use `run_with_spinner` below, which does
/// both.
///
/// Uses `std::thread::scope` (stable since 1.63) rather than a `'static`
/// bound, deliberately: the ACME `Session` this crate threads through every
/// step borrows `Directory`/`Client`/`AccountKey` owned by the caller and
/// cannot be `'static` (see `cmd/issue.rs`), and `core::Session` exposes no
/// way to reconstruct one with a previously-established `kid` from outside
/// `certway-core` — so the *same* session value must survive across steps,
/// borrowed rather than moved. A plain `std::thread::spawn` cannot express
/// that.
pub fn animate<T, F>(
    out: &mut Out<impl Write>,
    label: &'static str,
    work: F,
) -> (Duration, Result<T, core::Error>)
where
    F: FnOnce() -> Result<T, core::Error> + Send,
    T: Send,
{
    let start = Instant::now();

    if !out.caps.animation || out.mode == Mode::Json {
        return (start.elapsed(), work());
    }

    let interval = Duration::from_millis(spinner_interval_ms(out.caps.unicode));
    let result = std::thread::scope(|scope| {
        let handle = scope.spawn(work);
        let mut frame = 0usize;
        loop {
            if handle.is_finished() {
                break;
            }
            std::thread::sleep(interval);
            frame += 1;
            let _ = out.step_frame(label, frame);
        }
        // A panic inside `work` would only happen if a #[cfg(test)]-only
        // unwrap somehow ran in release code, which the standing no-panic
        // rule forbids; fail closed rather than propagate the panic.
        handle.join().unwrap_or(Err(core::Error::Signing))
    });

    (start.elapsed(), result)
}

/// `animate`, plus printing the step's running line first. The common case
/// for a step that is exactly one unit of work (`order`, `challenge`,
/// `validate`, `certificate`). `account` calls `step_running` and `animate`
/// separately because its work spans two operations, only the second of
/// which holds a live `Session` — see `cmd/issue.rs`.
pub fn run_with_spinner<T, F>(
    out: &mut Out<impl Write>,
    label: &'static str,
    work: F,
) -> (Duration, Result<T, core::Error>)
where
    F: FnOnce() -> Result<T, core::Error> + Send,
    T: Send,
{
    let _ = out.step_running(label);
    animate(out, label, work)
}

// ---------------------------------------------------------------------
// The already-valid skip. Pure decision, independent
// of any I/O, so it is directly unit-testable.
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum AuthzAction<'a> {
    /// Already valid — no provisioning, no challenge answered.
    Skip,
    /// Needs answering via this challenge, of whichever type was asked for.
    Answer(&'a Challenge),
}

/// Decides what to do with one authorization: an
/// authorization already `valid` is skipped entirely — no reason to
/// provision a response or answer a challenge for something the server has
/// already accepted. Errors if the server
/// did not offer a `wanted`-type challenge and the authorization still
/// needs answering. `wanted` is `ChallengeType::Http01` for every caller
/// this build has except DNS-01 provisioning, which asks for `Dns01`.
pub fn plan_authorization(
    authz: &Authorization,
    wanted: ChallengeType,
) -> Result<AuthzAction<'_>, core::Error> {
    if authz.status == AuthzStatus::Valid {
        return Ok(AuthzAction::Skip);
    }
    Ok(AuthzAction::Answer(authz.challenge(wanted)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use certway_core::{ChallengeStatus, Identifier};

    fn authz(status: AuthzStatus, challenges: Vec<Challenge>) -> Authorization {
        Authorization {
            status,
            identifier: Identifier::Dns("example.com".to_string()),
            wildcard: false,
            challenges,
        }
    }

    fn http01_challenge() -> Challenge {
        Challenge {
            url: "https://a/chall/1".to_string(),
            kind: ChallengeType::Http01,
            token: "tok".to_string(),
            status: ChallengeStatus::Pending,
            error: None,
        }
    }

    #[test]
    fn already_valid_authorization_is_skipped_entirely() {
        let a = authz(AuthzStatus::Valid, vec![]);
        assert!(matches!(
            plan_authorization(&a, ChallengeType::Http01).unwrap(),
            AuthzAction::Skip
        ));
    }

    #[test]
    fn already_valid_authorization_is_skipped_even_with_challenges_present() {
        // The point of the rule: valid means valid, regardless of what
        // challenges the server still lists.
        let a = authz(AuthzStatus::Valid, vec![http01_challenge()]);
        assert!(matches!(
            plan_authorization(&a, ChallengeType::Http01).unwrap(),
            AuthzAction::Skip
        ));
    }

    #[test]
    fn pending_authorization_is_answered() {
        let a = authz(AuthzStatus::Pending, vec![http01_challenge()]);
        match plan_authorization(&a, ChallengeType::Http01).unwrap() {
            AuthzAction::Answer(c) => assert_eq!(c.kind, ChallengeType::Http01),
            AuthzAction::Skip => panic!("expected Answer"),
        }
    }

    #[test]
    fn pending_authorization_without_http01_errors() {
        let a = authz(AuthzStatus::Pending, vec![]);
        assert!(matches!(
            plan_authorization(&a, ChallengeType::Http01),
            Err(core::Error::ChallengeUnavailable { .. })
        ));
    }

    #[test]
    fn pending_authorization_asked_for_dns01_returns_the_dns01_challenge() {
        let dns01_challenge = Challenge {
            url: "https://a/chall/2".to_string(),
            kind: ChallengeType::Dns01,
            token: "tok2".to_string(),
            status: ChallengeStatus::Pending,
            error: None,
        };
        let a = authz(
            AuthzStatus::Pending,
            vec![http01_challenge(), dns01_challenge],
        );
        match plan_authorization(&a, ChallengeType::Dns01).unwrap() {
            AuthzAction::Answer(c) => assert_eq!(c.kind, ChallengeType::Dns01),
            AuthzAction::Skip => panic!("expected Answer"),
        }
    }
}
