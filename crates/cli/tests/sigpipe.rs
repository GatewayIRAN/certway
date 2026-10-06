// SPDX-License-Identifier: MIT

//! `SIGPIPE` is left at Rust's default: `std` already sets its disposition
//! to `SIG_IGN` at process startup, so a write into a closed pipe becomes
//! an ordinary `EPIPE` `io::Error` rather than a signal that kills the
//! process. This is why every write in `render.rs` is
//! `let _ = out.write_raw(...)`: the error is expected and deliberately
//! ignored, not something that needs handling.
//!
//! `certway list | head -1` is the literal case: `head` reads one line,
//! exits, and closes its end of the pipe while `certway list` may still
//! have more rows queued to write. Without `SIG_IGN`, that write would
//! raise `SIGPIPE` and the default disposition would kill the process —
//! bash reports that as exit 141 (`128 + SIGPIPE`). This test reproduces
//! the two-process pipeline for real (not through a shell, so it can read
//! `certway`'s own exit status directly rather than the pipeline's last
//! stage) and generates enough rows that the write genuinely has to happen
//! after `head` has already exited and closed the pipe — a small output
//! would fit entirely in the kernel pipe buffer and prove nothing.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn tmp_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("certway-sigpipe-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One real self-signed cert, copied into many distinctly-named certificate
/// directories — `list`'s row content doesn't depend on the cert being
/// unique, only on `fullchain.pem` parsing, so this avoids spawning
/// `openssl` thousands of times just to get enough output volume.
fn seed_many_certificates(data_root: &std::path::Path, count: usize) {
    let seed = data_root.join("_seed");
    std::fs::create_dir_all(&seed).unwrap();
    let seed_cert = seed.join("fullchain.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "/dev/null",
            "-out",
            seed_cert.to_str().unwrap(),
            "-days",
            "90",
            "-subj",
            "/CN=fixture.example",
        ])
        .status()
        .expect("openssl must be on PATH for this test");
    assert!(status.success());

    for i in 0..count {
        let dir = data_root.join(format!("cert{i}.example"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(&seed_cert, dir.join("fullchain.pem")).unwrap();
    }
    let _ = std::fs::remove_dir_all(&seed);
}

#[test]
fn list_piped_into_head_does_not_die_to_sigpipe() {
    let data_root = tmp_dir("data");
    // ~2000 rows comfortably exceeds a 64KB pipe buffer, so `certway`
    // genuinely blocks on a write after `head` has already exited —
    // without SIG_IGN this is exactly the write that would raise SIGPIPE.
    seed_many_certificates(&data_root, 2000);

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_certway"));
    let mut certway = Command::new(&exe)
        .args(["list", "--out", data_root.to_str().unwrap(), "--no-color"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn certway");

    let certway_stdout = certway.stdout.take().expect("piped stdout");
    let mut head = Command::new("head")
        .args(["-n", "1"])
        .stdin(certway_stdout) // transfers the read end to `head`; this
        // process holds no copy of it after this call, exactly matching a
        // real shell pipeline's fd ownership.
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn head — required on PATH for this test");

    let head_status = head.wait().expect("wait for head");
    assert!(head_status.success(), "head -n 1 itself must exit cleanly");

    let output = certway.wait_with_output().expect("wait for certway");

    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        output.status.signal(),
        None,
        "certway must not be killed by a signal (SIGPIPE would show here) — got {:?}",
        output.status
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "certway list must still exit 0 despite the closed pipe — stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_dir_all(&data_root);
}

/// Same property, `--json` mode — `list`'s JSON output is one line per
/// invocation today (all certificates in a single array), so this doesn't
/// exercise the same "write after the reader is gone" race as the human
/// mode test above; kept anyway as a cheap regression check that JSON mode
/// at least doesn't panic or hang when its single write target is already
/// closed.
#[test]
fn list_json_into_a_closed_pipe_does_not_panic_or_hang() {
    let data_root = tmp_dir("data-json");
    seed_many_certificates(&data_root, 5);

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_certway"));
    let mut certway = Command::new(&exe)
        .args(["list", "--out", data_root.to_str().unwrap(), "--json"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn certway");

    // Close the read end immediately, without reading anything at all —
    // the harshest version of "the reader is already gone."
    drop(certway.stdout.take());

    let status = certway.wait().expect("wait for certway");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), None);
    assert_eq!(status.code(), Some(0));

    let _ = std::fs::remove_dir_all(&data_root);
}
