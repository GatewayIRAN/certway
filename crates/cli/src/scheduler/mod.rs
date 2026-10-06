// SPDX-License-Identifier: MIT

//! Scheduling: systemd timers, cron, and watch mode.
//!
//! Each mechanism is its own submodule. All of them keep the same shape:
//! pure, directly-testable content/decision functions, plus a thin impure
//! edge (a `std::process::Command` call, a real sleep) that those
//! functions never need to know about.

use certway_core::{self as core};
use std::path::Path;

/// FNV-1a over `"<salt>:<seed>"`. Deliberately hand-rolled (no crate is
/// permitted) and deliberately *not* cryptographic — this only needs to
/// spread installations across a window, not resist an adversary. Shared by
/// `cron::minute` and `watch::jitter` so both derive from the same hostname
/// the same way, with different salts keeping the two values independent.
fn hash64(seed: &str, salt: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in salt
        .bytes()
        .chain(std::iter::once(b':'))
        .chain(seed.bytes())
    {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Reads the hostname the container-safe way: `/proc/sys/kernel/hostname`
/// rather than libc's `gethostname(2)` (no safe std wrapper exists, and
/// neither `unsafe` nor a new crate is available). Falls back to a fixed
/// string rather than failing — every caller only uses this for
/// load-spreading, where a wrong-but-stable value is better than an
/// error.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string())
}

pub mod cron;
pub mod systemd;
pub mod watch;
