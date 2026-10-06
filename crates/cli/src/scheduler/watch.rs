// SPDX-License-Identifier: MIT

//! Watch mode.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Base wake interval: every 12 hours.
pub const BASE_INTERVAL: Duration = Duration::from_secs(12 * 3600);
/// Plus up to 60 minutes of hostname-derived jitter, added to
/// `BASE_INTERVAL` so machines don't all wake at the exact same moment
/// twice a day.
pub const MAX_JITTER: Duration = Duration::from_secs(60 * 60);
/// Sleep in short ticks rather than one long sleep, so a shutdown
/// request (via `crate::signal`) stays responsive and a wall-clock
/// jump can't produce a wake storm or a missed wake.
pub const TICK: Duration = Duration::from_secs(1);

pub fn jitter(hostname: &str) -> Duration {
    let minutes = hash64(hostname, "watch-jitter") % 61; // 0..=60 inclusive
    Duration::from_secs(minutes * 60)
}

pub fn wake_interval(hostname: &str) -> Duration {
    BASE_INTERVAL + jitter(hostname)
}

/// Whether it's time to wake, given a **monotonic** elapsed duration
/// since the last wake and the interval to wait. This signature is the
/// actual guarantee behind "a clock jump backwards does not cause a
/// wake storm": it structurally cannot take a wall-clock timestamp —
/// only a `Duration` a caller can only have produced from
/// `Instant::elapsed()` — so an NTP correction or a suspended container
/// simply cannot reach this decision at all.
pub fn due(elapsed: Duration, interval: Duration) -> bool {
    elapsed >= interval
}

/// One wake per `interval`, forever, until `shutdown` is observed true
/// at a tick boundary. `work` runs once per wake — re-reading every
/// certificate and recomputing from scratch is `work`'s job, not this
/// loop's: the loop itself carries no state across wakes.
pub fn run(interval: Duration, shutdown: &AtomicBool, mut work: impl FnMut()) {
    loop {
        work();
        let start = Instant::now();
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            let elapsed = start.elapsed();
            if due(elapsed, interval) {
                break;
            }
            let remaining = interval - elapsed;
            std::thread::sleep(TICK.min(remaining));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_at_exactly_the_interval() {
        assert!(due(Duration::from_secs(10), Duration::from_secs(10)));
        assert!(due(Duration::from_secs(11), Duration::from_secs(10)));
        assert!(!due(Duration::from_secs(9), Duration::from_secs(10)));
    }

    #[test]
    fn wake_interval_is_between_12_and_13_hours() {
        for host in ["a", "example", "my-host-123", ""] {
            let d = wake_interval(host);
            assert!(d >= BASE_INTERVAL, "{host}: {d:?} below the 12h floor");
            assert!(
                d <= BASE_INTERVAL + MAX_JITTER,
                "{host}: {d:?} above the 13h ceiling"
            );
        }
    }

    #[test]
    fn wake_interval_is_deterministic_for_the_same_hostname() {
        assert_eq!(wake_interval("stable-host"), wake_interval("stable-host"));
    }

    #[test]
    fn different_hostnames_usually_land_on_different_jitter() {
        // Not a hard guarantee (a hash collision is possible), but
        // asserts the derivation actually varies with input rather
        // than being a constant in disguise.
        let a = jitter("host-one");
        let b = jitter("host-two");
        let c = jitter("host-three");
        assert!(
            a != b || b != c,
            "jitter must depend on the hostname, not be a fixed constant"
        );
    }

    /// The loop wakes repeatedly, and a shutdown request (set from
    /// inside `work`, standing in for a real signal) stops it promptly
    /// rather than after a long sleep — the property that makes
    /// `TICK`'s short polling interval worth the extra wakeups.
    #[test]
    fn run_wakes_repeatedly_and_stops_promptly_on_shutdown() {
        let shutdown = AtomicBool::new(false);
        let wakes = std::sync::atomic::AtomicUsize::new(0);
        let interval = Duration::from_millis(5);

        let start = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                run(interval, &shutdown, || {
                    let n = wakes.fetch_add(1, Ordering::SeqCst) + 1;
                    if n >= 3 {
                        shutdown.store(true, Ordering::SeqCst);
                    }
                });
            });
        });
        assert!(wakes.load(Ordering::SeqCst) >= 3);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "shutdown must stop the loop promptly, not after a long sleep"
        );
    }

    /// A restart is treated identically to a wake. `work()` runs before
    /// the shutdown check by design — a wake always completes its pass
    /// — so calling `run` fresh with a shutdown flag that is *already*
    /// true must still run `work` exactly once before returning, rather
    /// than skipping the pass entirely.
    #[test]
    fn a_wake_always_runs_its_pass_even_if_shutdown_is_already_set() {
        let shutdown = AtomicBool::new(true);
        let wakes = std::sync::atomic::AtomicUsize::new(0);
        run(Duration::from_secs(9999), &shutdown, || {
            wakes.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
    }
}
