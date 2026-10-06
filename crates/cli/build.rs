// SPDX-License-Identifier: MIT

//! Bakes three build-time facts into `certway version`'s screen — meant to
//! be the first line every bug report should contain: the commit, the
//! build date, and the target triple. No crate — this is
//! `std::process::Command` and `std::env`, following this project's own
//! preference for writing small things by hand instead of pulling in a
//! dependency, applied here to the build script itself, just running at
//! build time instead of runtime.
//!
//! Every var is set unconditionally, even on failure (`"unknown"`) — a
//! build script that fails outright over a missing `.git` (a tarball
//! release, not a clone) or a missing `git`/`date` binary would block a
//! release for a cosmetic line, which is worse than that line saying
//! "unknown".
//!
//! `CERTWAY_BUILD_DATE` prefers `SOURCE_DATE_EPOCH` (the reproducible-
//! builds convention that release tooling — cargo-dist, sigstore
//! — cares about) over the wall-clock `date` a plain `cargo build` would
//! otherwise embed; two builds of the same commit should be able to
//! agree on this line, not merely happen to.

use std::process::Command;

fn main() {
    // Bug found live: `.git/HEAD` is a symbolic ref ("ref:
    // refs/heads/master") on a normal checkout — a same-branch commit
    // updates `.git/refs/heads/master`, never `.git/HEAD` itself, so
    // watching only `HEAD` meant cargo never saw a reason to rerun this
    // script after the first build, and every later build silently kept
    // baking in the *first* commit's hash. Confirmed live: `certway
    // version` reported the previous commit after a real commit + rebuild.
    // Watching the resolved ref file too (when `HEAD` is symbolic, not
    // detached) is what actually tracks new commits on the checked-out
    // branch. `packed-refs` (a ref folded into that single file rather
    // than kept loose under `.git/refs/`) isn't watched — a real gap on a
    // repo that's been `git gc`'d, accepted rather than solved here.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    if let Ok(head) = std::fs::read_to_string("../../.git/HEAD") {
        if let Some(ref_path) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed=../../.git/{ref_path}");
        }
    }
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let commit = git_short_head().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=CERTWAY_COMMIT={commit}");

    let built = build_date().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=CERTWAY_BUILD_DATE={built}");

    // Cargo sets `TARGET` for every build script invocation — the actual
    // compilation target, not the host running the build (what matters
    // for cross-compilation via tools like cargo-zigbuild or cross).
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=CERTWAY_TARGET={target}");
}

fn git_short_head() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let hash = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if hash.is_empty() {
        None
    } else {
        Some(hash)
    }
}

/// `SOURCE_DATE_EPOCH` (Unix seconds, UTC) when set — the reproducible-
/// builds standard — else the system `date` command's own idea of today,
/// UTC, `YYYY-MM-DD`.
fn build_date() -> Option<String> {
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        let output = Command::new("date")
            .args(["-u", "-d", &format!("@{epoch}"), "+%Y-%m-%d"])
            .output()
            .ok()?;
        if output.status.success() {
            let date = String::from_utf8(output.stdout).ok()?.trim().to_string();
            if !date.is_empty() {
                return Some(date);
            }
        }
    }
    let output = Command::new("date").args(["-u", "+%Y-%m-%d"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let date = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if date.is_empty() {
        None
    } else {
        Some(date)
    }
}
