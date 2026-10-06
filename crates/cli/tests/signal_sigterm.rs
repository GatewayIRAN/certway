// SPDX-License-Identifier: MIT

//! Proves signal *registration* actually works. `crate::signal`'s own unit
//! test (`signal::tests::requested_reflects_the_flag`) only proves the
//! flag/check-point plumbing given a manually-set flag via
//! `crate::signal::request` — it never touches `libc::signal` at all. This
//! test sends a real `SIGTERM` to a real running `certway` process and
//! confirms `signal::install`'s registration is what actually stops it,
//! not the OS's default disposition (which would also terminate the
//! process, just via `WIFSIGNALED`, not by exiting cleanly through
//! `main`'s normal `std::process::exit` path with the fixed exit code a
//! graceful SIGTERM shutdown produces).
//!
//! `renew --all --watch` is the target: with zero certificates, each pass
//! is a near-instant no-op, so the process spends effectively all its time
//! inside `scheduler::watch::run`'s tick loop — exactly where the shutdown
//! check point lives.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp_empty_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("certway-sigterm-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_real_sigterm_stops_watch_mode_promptly_and_exits_zero() {
    let data_root = tmp_empty_dir("watch");
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_certway"));

    let mut child = Command::new(&exe)
        .args([
            "renew",
            "--all",
            "--watch",
            "--out",
            data_root.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn certway renew --all --watch");

    // Let it run its first pass and settle into the tick loop before
    // signalling — this isn't load-bearing for correctness (the handler is
    // installed at the very top of `main`, before argument parsing even
    // happens) but avoids racing process startup for no reason.
    std::thread::sleep(Duration::from_millis(300));

    let pid = child.id();
    let kill_status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("run `kill -TERM`");
    assert!(kill_status.success(), "sending SIGTERM itself must succeed");

    let start = Instant::now();
    let output = loop {
        if let Some(_status) = child.try_wait().expect("try_wait") {
            break child.wait_with_output().expect("collect output after exit");
        }
        assert!(start.elapsed() < Duration::from_secs(10), "certway did not exit within 10s of receiving a real SIGTERM — registration did not take effect");
        std::thread::sleep(Duration::from_millis(50));
    };

    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        output.status.signal(),
        None,
        "must exit normally through main()'s own std::process::exit, caught and handled by our registered handler — not killed by the signal's default disposition (stderr: {})",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0), "SIGTERM during watch mode finishes or rolls back the current pass, then exits 0");

    let _ = std::fs::remove_dir_all(&data_root);
}

/// Two `SIGTERM`s in immediate succession: the first is caught by the
/// registered handler (setting the flag); the second must be seen by the
/// *same* handler as "already requested" and call `_exit` with code 130
/// immediately — the whole point of the swap-based handler being able to
/// observe its own prior invocation.
#[test]
fn a_second_sigterm_during_cleanup_exits_immediately_with_code_130() {
    let data_root = tmp_empty_dir("double-signal");
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_certway"));

    let mut child = Command::new(&exe)
        .args([
            "renew",
            "--all",
            "--watch",
            "--out",
            data_root.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn certway renew --all --watch");

    std::thread::sleep(Duration::from_millis(300));
    let pid = child.id().to_string();

    // Two signals back to back, deliberately not waiting for the first to
    // be processed — that's the scenario "during cleanup" describes: the
    // second one lands while the process is still reacting to the first.
    assert!(Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("first kill -TERM")
        .success());
    assert!(Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("second kill -TERM")
        .success());

    let start = Instant::now();
    let output = loop {
        if let Some(_status) = child.try_wait().expect("try_wait") {
            break child.wait_with_output().expect("collect output after exit");
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "certway did not exit within 10s of a second SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    use std::os::unix::process::ExitStatusExt;
    assert_eq!(output.status.signal(), None, "the second signal's handler calls _exit(130) itself — the process must not be torn down by the signal's default disposition");
    assert_eq!(
        output.status.code(),
        Some(130),
        "a second signal during cleanup exits immediately, code 130"
    );

    let _ = std::fs::remove_dir_all(&data_root);
}
