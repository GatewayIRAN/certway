// SPDX-License-Identifier: MIT

//! Proves that the path `install` writes a systemd timer to and the path
//! `list`'s `AUTO` column probes are the *same* path — not just
//! similarly-named constants that could drift apart.
//!
//! Exercised through `scheduler::systemd::write_units` (the exact function
//! `cmd::install`'s systemd branch calls) plus the real `cmd::list::run`
//! entry point, redirected via `CERTWAY_SYSTEMD_DIR` — a testing-only
//! override (see `scheduler::systemd`'s doc comment), never a user-facing
//! flag. This deliberately never calls `cmd::install::run` itself or a
//! real `systemctl`: a real `/etc/systemd/system` write needs root this
//! suite must not assume, and `systemctl enable` always targets the real
//! system manager regardless of the override, so "enable" can't be
//! exercised safely here. Actually writing to `/etc/systemd/system` and
//! calling `systemctl enable` are therefore not covered by this test and
//! need manual verification on a real system.

use certway::args::ListArgs;
use certway::caps::Caps;
use certway::render::{Mode, Out};
use certway::scheduler;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// This crate's other integration test binaries (golden.rs, pebble_e2e.rs)
// run as separate processes, so this lock only needs to guard the
// `#[test]` functions inside *this* file against each other — but this
// file intentionally has just the one test, so the lock is here mostly to
// keep that invariant explicit if a second test is ever added.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "certway-install-list-agreement-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Same fixture-generation shape `cmd::list`'s own tests use: a real
/// self-signed cert is enough to make `list` treat the directory as a
/// certificate at all — `AUTO` doesn't depend on its content.
fn write_fixture_cert(cert_dir: &Path) {
    std::fs::create_dir_all(cert_dir).unwrap();
    let cert_path = cert_dir.join("fullchain.pem");
    let status = std::process::Command::new("openssl")
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
            cert_path.to_str().unwrap(),
            "-days",
            "90",
            "-subj",
            "/CN=fixture.example",
        ])
        .status()
        .expect("openssl must be on PATH for this test");
    assert!(
        status.success(),
        "openssl req -x509 failed generating the fixture certificate"
    );
}

fn run_list_json(args: &ListArgs) -> String {
    let mut buf = Vec::new();
    let caps = Caps {
        color: false,
        unicode: false,
        animation: false,
        width: 100,
    }
    .force_json();
    let mut out = Out::new(&mut buf, caps, Mode::Json);
    certway::cmd::list::run(args.clone(), &mut out);
    String::from_utf8(buf).unwrap()
}

#[test]
fn install_writer_and_list_auto_probe_agree_on_the_same_unit_path() {
    let _lock = ENV_LOCK.lock().unwrap();

    let unit_dir = tmp_dir("units");
    let data_dir = tmp_dir("data");
    write_fixture_cert(&data_dir.join("example.com"));

    std::env::set_var(scheduler::systemd::UNIT_DIR_ENV, &unit_dir);

    let list_args = ListArgs {
        out_dir: Some(data_dir.to_string_lossy().to_string()),
        json: true,
        no_color: true,
        help: false,
    };

    // Before install: nothing has been written at the (redirected) unit
    // path yet, so AUTO must read "no".
    let before = run_list_json(&list_args);
    assert!(
        before.contains("\"auto\":false"),
        "AUTO must read no before install writes anything: {before}"
    );

    // The exact write `cmd::install::run`'s systemd branch performs, called
    // directly here rather than through `cmd::install::run` so this test
    // never touches real `systemctl`.
    scheduler::systemd::write_units(&unit_dir, Path::new("/usr/local/bin/certway"))
        .expect("write the timer/service pair");

    // After install: `list` resolves the unit directory and probes for the
    // timer through the exact same `scheduler::systemd` functions the
    // writer above just used — so this is a genuine same-path proof, not
    // two independently-hardcoded strings that happen to match today.
    let after = run_list_json(&list_args);
    assert!(
        after.contains("\"auto\":true"),
        "AUTO must read yes once install has written the timer at the path list probes: {after}"
    );

    std::env::remove_var(scheduler::systemd::UNIT_DIR_ENV);
    let _ = std::fs::remove_dir_all(&unit_dir);
    let _ = std::fs::remove_dir_all(&data_dir);
}
