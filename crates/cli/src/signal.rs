// SPDX-License-Identifier: MIT

//! The shutdown flag, backed by a real signal handler.
//!
//! `libc` is this project's seventh dependency, added for exactly one
//! thing: `signal(2)` registration. Nothing else in this crate or
//! `certway-core` uses it — this project otherwise avoids adding
//! dependencies for routine conveniences (base64, HTTP, argument parsing),
//! reasoning that std can do those by hand; that policy doesn't apply here,
//! since signal registration is a capability `std` genuinely does not
//! expose at all.
//!
//! **`signal(2)`, not `sigaction(2)`, deliberately.** `signal()`'s
//! semantics — whether the handler resets to `SIG_DFL` after firing once,
//! whether interrupted syscalls restart — are notoriously
//! platform-dependent (the classic "unreliable signals" problem);
//! `sigaction()` is deterministic everywhere. That ambiguity would matter
//! here, since a handler reset after the first signal would route a
//! *second* `SIGTERM` to the OS default (kill) instead of back into
//! `handle`, silently losing the "second signal exits 130" path this
//! module implements. Two things make `signal()` the right call anyway on
//! this project's one actual target: this build only ever targets
//! `x86_64-unknown-linux-musl`, and musl's `signal()` is
//! documented and widely cited to always implement BSD "reliable" signal
//! semantics (handler persists, syscalls restart) rather than the
//! ambiguous historical behavior — unlike glibc, which is configurable and
//! has actually shipped both over time. musl gives us `sigaction`'s
//! determinism through a plain `signal()` call, on the
//! target that ships. `sigaction()` would also roughly double this
//! module's unsafe surface (a `sigaction` struct to zero-initialize
//! correctly, a `sigset_t` built via `sigemptyset`, a handler stored
//! through a union field) for a guarantee musl already gives `signal()`
//! for free here. **Caveat, stated plainly: this reasoning about musl
//! specifically comes from general knowledge of musl's design, not a
//! verified primary source — treat it as informed but unconfirmed.** If
//! this build is ever compiled against glibc (a debug build on a dev
//! machine, say — which is exactly what manual testing during development
//! actually ran against) the semantics are
//! usually the same, but "usually" is not "always"; if that target
//! commitment ever changes, this whole comment is the thing to revisit
//! first.
//!
//! `SIGINT`, `SIGTERM`, `SIGHUP` all route to the same handler: set the
//! shutdown flag, or — if it was already set, meaning this is the
//! *second* signal received during cleanup — exit immediately with code
//! 130. `SIGPIPE` is deliberately left untouched,
//! at Rust's runtime default (`SIG_IGN`); `tests/sigpipe.rs` is why that's
//! already correct.

use std::sync::atomic::{AtomicBool, Ordering};

pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Registers the real handler for `SIGINT`/`SIGTERM`/`SIGHUP`. Call once,
/// at startup, before anything else — before argument parsing, before any
/// I/O, so a signal arriving early in the program's life is still caught.
///
/// Returns `false` if *any* of the three registrations failed
/// (`signal(2)` returns `SIG_ERR` on failure — e.g. an uncatchable
/// signal). Every one is still attempted independently even if an earlier
/// one failed, so a single bad registration doesn't silently drop
/// coverage for the other two. The caller must surface a `false` result:
/// silently discarding it would leave the program believing it has
/// interrupt-cleanup protection it does not have — exactly the kind of
/// silent, false-confidence failure clippy's unused-`Result` lint does not
/// catch inside `unsafe` blocks.
#[must_use]
pub fn install() -> bool {
    raw::install()
}

/// Test-only: never called from production code (nothing in this build
/// needs to *simulate* a signal — real ones are now caught for real). Lets
/// `crate::cmd::renew`'s and `crate::scheduler::watch`'s own tests prove
/// their check-point plumbing stops promptly without waiting on an actual
/// `kill`.
#[cfg(test)]
pub fn request() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// The only unsafe code in this crate (`certway-core` has none either —
/// `#![forbid(unsafe_code)]` stays in force in both, this module is the
/// one carve-out). `libc::signal` is a raw FFI call: unsafe by definition,
/// since its signature only promises the C ABI, not that `handle` below is
/// valid signal-handler code (that's on us to get right, not on the
/// compiler to check) — and there is no safe wrapper in `std`.
mod raw {
    #![allow(unsafe_code)]

    use super::{Ordering, SHUTDOWN};

    /// The actual signal handler, installed for `SIGINT`/`SIGTERM`/
    /// `SIGHUP`. Must be async-signal-safe: only operations
    /// `signal-safety(7)` documents as safe to call from inside a signal
    /// handler — an atomic swap, and on the second call, `_exit`. No
    /// allocation, no `std::io`, no locking, no `println!` (not
    /// signal-safe: it can allocate and it locks stdout internally).
    extern "C" fn handle(_signum: libc::c_int) {
        // `swap`, not `store`: this one atomic operation both sets the
        // flag *and* reports whether it was already set — i.e. whether
        // this is a second signal arriving during cleanup, which must
        // exit immediately rather than wait for cleanup to finish.
        let already_requested = SHUTDOWN.swap(true, Ordering::SeqCst);
        if already_requested {
            // `_exit`, not `std::process::exit`: `_exit` is the
            // async-signal-safe primitive (`signal-safety(7)` lists it
            // explicitly) — it skips `atexit` handlers, destructors, and
            // Rust's own shutdown machinery, none of which are safe to run
            // from inside a signal handler.
            unsafe { libc::_exit(130) };
        }
    }

    /// Registers `handle` for `signum`, reporting whether the call
    /// actually succeeded. `signal(2)` returns `SIG_ERR` (not an `Err`,
    /// not a panic, not `errno` alone) on failure — a return value with no
    /// `#[must_use]` on the raw FFI binding, which is exactly why this was
    /// silently dropped in the first version of this module and exactly
    /// why clippy's own unused-`Result`-style lints don't catch it: the
    /// call sits inside an `unsafe` block, which is precisely where the
    /// linter is weakest.
    fn register(signum: libc::c_int) -> bool {
        // SAFETY: `handle` is `extern "C" fn(c_int)`, matching exactly
        // what `signal(2)` requires, and does only async-signal-safe work
        // (see its own doc comment) — the two preconditions `libc::signal`
        // itself cannot verify.
        let previous = unsafe { libc::signal(signum, handle as *const () as libc::sighandler_t) };
        previous != libc::SIG_ERR
    }

    pub(super) fn install() -> bool {
        // Every signal is registered regardless of an earlier failure —
        // three independent attempts, not a short-circuiting chain, so one
        // bad registration can't silently drop coverage for the other two.
        let sigint_ok = register(libc::SIGINT);
        let sigterm_ok = register(libc::SIGTERM);
        let sighup_ok = register(libc::SIGHUP);
        // `SIGPIPE` is not registered here: it stays at Rust's own
        // startup-time `SIG_IGN`, which is already the behavior this
        // module wants for it.
        sigint_ok && sigterm_ok && sighup_ok
    }

    #[cfg(test)]
    pub(super) fn register_for_test(signum: libc::c_int) -> bool {
        register(signum)
    }

    /// Test-only cleanup: restores `signum`'s default disposition. Kept
    /// here, not in `mod tests`, so `mod tests` itself never needs its own
    /// `#![allow(unsafe_code)]` — the isolation stays exactly as narrow as
    /// asked for.
    #[cfg(test)]
    pub(super) fn reset_for_test(signum: libc::c_int) {
        // SAFETY: `SIG_DFL` is a valid disposition constant for any
        // signal; this only ever restores a signal this test binary
        // itself registered moments earlier.
        unsafe {
            libc::signal(signum, libc::SIG_DFL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_reflects_the_flag() {
        // Runs in the same process as every other lib test, so leave the
        // flag exactly as found — false, the value every other test
        // (including `scheduler::watch`'s, which build their own local
        // `AtomicBool` rather than touching this global one) implicitly
        // assumes.
        let was_set = requested();
        request();
        assert!(requested());
        SHUTDOWN.store(was_set, Ordering::SeqCst);
    }

    /// The actual regression test for the dropped-`SIG_ERR` bug.
    /// `SIGKILL` cannot be caught, blocked, or ignored by any process —
    /// `signal(2)` reliably returns `SIG_ERR` for it, the one portable way
    /// to exercise the failure path without breaking real signal handling
    /// for the rest of this test binary (unlike, say, passing an invalid
    /// signal number, which is UB territory this test has no business
    /// going anywhere near).
    #[test]
    fn register_reports_failure_for_an_uncatchable_signal() {
        assert!(!raw::register_for_test(libc::SIGKILL), "SIGKILL cannot be caught — registration must be reported as failed, not silently ignored");
    }

    #[test]
    fn register_reports_success_for_a_real_catchable_signal() {
        // SIGUSR1 — catchable, and not one this module registers in
        // production, so re-registering it here for a real success case
        // can't interfere with SIGINT/SIGTERM/SIGHUP's own registration.
        assert!(raw::register_for_test(libc::SIGUSR1));
        // Restore the default disposition rather than leaving this test
        // binary's SIGUSR1 pointed at `handle` for the rest of the run.
        raw::reset_for_test(libc::SIGUSR1);
    }
}
