// SPDX-License-Identifier: MIT

//! Two proofs the mocked/scripted test suites in `webserver/nginx/`
//! (`ScriptedValidator`, exact hand-typed strings) can't provide on their
//! own: certway's real code driven against a real `nginx:1.29.3` binary,
//! reached via `docker exec` so no nginx install is required on the host
//! running `cargo test`.
//!
//! (a) `shadowing_duplicate_from_a_real_append_is_caught_by_a_real_nginx`
//!     — `edit::build_appended_block` (the actual writer, not a
//!     reimplementation) produces a config with a genuine duplicate exact
//!     `server_name` on `:443`. The real `nginx -t` inside the container
//!     exits 0 for this — confirmed live here, not assumed — and the
//!     assertion is that `transaction::run`'s strict stderr check still
//!     treats it as a failure, restores, and never reports `Edited`.
//! (b) `restore_and_verify_against_a_real_container` — a real edit through
//!     `transaction::run`, the live file corrupted directly on disk
//!     afterward, then `transaction::restore_and_verify` (the routine
//!     `cmd::rollback` will also use) run against the real binary:
//!     `nginx -t` must pass afterward and the bytes must match the
//!     pre-edit snapshot exactly.
//!
//! Both bind-mount a host temp directory as the container's `/etc/nginx`,
//! so certway (a host process) edits the file directly while `docker exec
//! ... nginx -t` / `-s reload` validates and reloads the same bytes from
//! inside the container — the same bind-mount methodology used to extract
//! the real-world fixtures in `tests/fixtures/nginx/real/`.

use certway::webserver::nginx::parse::{parse_file, RealFs};
use certway::webserver::nginx::transaction::Validator;
use certway::webserver::nginx::{edit, transaction};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const IMAGE: &str = "nginx:1.29.3";

macro_rules! skip_unless_docker {
    () => {
        if !docker_available() {
            eprintln!("SKIPPED: docker not reachable — real-container nginx proofs require Docker");
            return;
        }
    };
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

struct ContainerGuard {
    name: String,
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

/// Starts `IMAGE` with `host_dir` bind-mounted as `/etc/nginx`, waits for
/// nginx to actually be up (a fresh mount plus the image's own entrypoint
/// takes a moment), and returns a guard that force-removes the container
/// on drop regardless of how the test exits.
fn start_container(name: &str, host_dir: &Path) -> ContainerGuard {
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
    let mount = format!("{}:/etc/nginx:rw", host_dir.display());
    let status = Command::new("docker")
        .args(["run", "-d", "--name", name, "-v", &mount, IMAGE])
        .status()
        .expect("docker run must succeed");
    assert!(status.success(), "failed to start container {name}");
    let guard = ContainerGuard {
        name: name.to_string(),
    };

    for _ in 0..30 {
        if Command::new("docker")
            .args(["exec", name, "nginx", "-t"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return guard;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("nginx inside container {name} never became ready");
}

struct DockerValidator {
    container: String,
}

impl transaction::Validator for DockerValidator {
    fn validate(&self) -> transaction::ValidateOutcome {
        match Command::new("docker")
            .args(["exec", &self.container, "nginx", "-t"])
            .output()
        {
            Ok(o) => transaction::ValidateOutcome {
                success: o.status.success(),
                stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            },
            Err(e) => transaction::ValidateOutcome {
                success: false,
                stderr: format!("docker exec failed: {e}"),
            },
        }
    }
}

struct DockerReloader {
    container: String,
}

impl transaction::Reloader for DockerReloader {
    fn reload(&self) -> Result<(), String> {
        match Command::new("docker")
            .args(["exec", &self.container, "nginx", "-s", "reload"])
            .output()
        {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).into_owned()),
            Err(e) => Err(format!("docker exec failed: {e}")),
        }
    }
}

fn tmp_host_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "certway-nginx-container-proof-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("certs")).unwrap();
    dir
}

/// A real self-signed cert/key pair, generated together in one `openssl`
/// invocation so the key genuinely matches the cert — a mismatched pair
/// (or a missing file) fails `nginx -t` on its own, independent of
/// anything this test is trying to prove, so this has to be a real pair.
fn generate_self_signed_cert(dir: &Path) {
    let cert = dir.join("certs/dummy.pem");
    let key = dir.join("certs/dummy.key");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=example.com",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("openssl must be on PATH");
    assert!(
        status.status.success(),
        "failed to generate self-signed cert: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn shadowing_duplicate_from_a_real_append_is_caught_by_a_real_nginx() {
    skip_unless_docker!();

    let dir = tmp_host_dir("shadow");
    generate_self_signed_cert(&dir);

    // Baseline: one :443 block already names example.com; a separate :80
    // block also names it (the normal, expected case matching.rs treats
    // as two independent scopes, not ambiguity). Valid on its own.
    let original = "events {}\nhttp {\n    server {\n        listen 443 ssl;\n        server_name example.com;\n        ssl_certificate /etc/nginx/certs/dummy.pem;\n        ssl_certificate_key /etc/nginx/certs/dummy.key;\n    }\n    server {\n        listen 80;\n        server_name example.com;\n    }\n}\n";
    let conf = dir.join("nginx.conf");
    std::fs::write(&conf, original).unwrap();

    let container = "certway-proof-shadow";
    let _guard = start_container(container, &dir);

    let baseline = DockerValidator {
        container: container.to_string(),
    }
    .validate();
    assert!(
        baseline.success,
        "baseline config must be valid before the proof begins: {}",
        baseline.stderr
    );

    // The REAL writer, not a reimplementation: append a new :443 block
    // after the existing :80 one — this is exactly what `find_and_edit`
    // would do if the :443 search had come back NoMatch for some other
    // reason (unusual include structure, matching-refused elsewhere). The
    // point of this proof is transaction.rs's own defense, independent of
    // how the block got selected.
    let fs = RealFs { root: None };
    let directives = parse_file(&conf, &dir, &fs).unwrap();
    let http_block = directives.iter().find(|d| d.name == "http").unwrap();
    let plain_block =
        http_block
            .block
            .as_ref()
            .unwrap()
            .iter()
            .find(|d| {
                d.name == "server"
                    && d.block.as_ref().unwrap().iter().any(|c| {
                        c.name == "listen" && c.args.first().map(String::as_str) == Some("80")
                    })
            })
            .unwrap();

    let new_content = edit::build_appended_block(
        original,
        plain_block,
        "example.com",
        "/etc/nginx/certs/dummy.pem",
        "/etc/nginx/certs/dummy.key",
        true,
    );
    assert_eq!(new_content.matches("server_name example.com;").count(), 3, "sanity: the append must create a second :443 block naming example.com (plus the untouched :80 one) — 3 total occurrences");

    let validator = DockerValidator {
        container: container.to_string(),
    };
    let reloader = DockerReloader {
        container: container.to_string(),
    };
    let result = transaction::run(
        &conf,
        new_content.as_bytes(),
        &validator,
        &reloader,
        false,
        None,
    )
    .unwrap();

    match &result {
        transaction::EditOutcome::ValidationFailedRestored { stderr, .. } => {
            assert!(stderr.contains("conflicting server name"), "expected the real nginx warning text, got: {stderr}");
            eprintln!("confirmed live: real nginx -t stderr for this case = {stderr:?}");
        }
        other => panic!("expected ValidationFailedRestored despite a real nginx -t exit code of 0, got {other:?} — the exact false-confidence failure this design exists to prevent"),
    }
    assert!(
        !matches!(result, transaction::EditOutcome::Edited { .. }),
        "must never report success over a shadowed block"
    );
    assert_eq!(
        std::fs::read_to_string(&conf).unwrap(),
        original,
        "the file must be restored byte-identical to its pre-edit state"
    );

    // The restored file must itself still be genuinely valid — a real
    // `nginx -t`, not just "the bytes match".
    let restored_check = validator.validate();
    assert!(
        restored_check.success,
        "restored config must pass a real nginx -t: {}",
        restored_check.stderr
    );
}

#[test]
fn restore_and_verify_against_a_real_container() {
    skip_unless_docker!();

    let dir = tmp_host_dir("restore");
    generate_self_signed_cert(&dir);

    let original = "events {}\nhttp {\n    server {\n        listen 443 ssl;\n        server_name example.com;\n        ssl_certificate /etc/nginx/certs/old.pem;\n        ssl_certificate_key /etc/nginx/certs/old.key;\n    }\n}\n";
    let conf = dir.join("nginx.conf");
    // The "old" cert paths referenced above don't need to exist for THIS
    // baseline — only the post-edit content (below) needs a real,
    // loadable cert, since that's the one a real nginx actually parses
    // during this test's baseline/validate calls.
    std::fs::copy(dir.join("certs/dummy.pem"), dir.join("certs/old.pem")).unwrap();
    std::fs::copy(dir.join("certs/dummy.key"), dir.join("certs/old.key")).unwrap();
    std::fs::write(&conf, original).unwrap();

    let container = "certway-proof-restore";
    let _guard = start_container(container, &dir);

    let validator = DockerValidator {
        container: container.to_string(),
    };
    let reloader = DockerReloader {
        container: container.to_string(),
    };

    // A real edit through the real transaction, against the real
    // container — this is the state restore is being tested from.
    let new_content = original
        .replace("old.pem", "dummy.pem")
        .replace("old.key", "dummy.key");
    let edited = transaction::run(
        &conf,
        new_content.as_bytes(),
        &validator,
        &reloader,
        false,
        None,
    )
    .unwrap();
    let backup_path = match edited {
        transaction::EditOutcome::Edited { backup_path } => backup_path,
        other => panic!("expected the setup edit to succeed, got {other:?}"),
    };
    let post_edit_bytes = std::fs::read(&conf).unwrap();
    assert_eq!(post_edit_bytes, new_content.as_bytes());

    // Corrupt the live file directly on disk — not through certway at
    // all, simulating disk corruption / an out-of-band bad edit.
    std::fs::write(&conf, b"this is not a valid nginx config {{{ garbage").unwrap();
    let corrupted_check = validator.validate();
    assert!(
        !corrupted_check.success,
        "sanity: the corrupted file must actually fail a real nginx -t"
    );

    // The real restore path — the same routine cmd::rollback will call,
    // run here against the real binary.
    let restore_result = transaction::restore_and_verify(&conf, &backup_path, &validator).unwrap();
    assert_eq!(restore_result, transaction::RestoreOutcome::Restored);

    // `backup_path` is a snapshot of the file as it stood BEFORE the edit
    // above (that's what "backup" means — taken at transaction step 2,
    // before the new content is written), so restoring from it returns to
    // the pre-edit state, not the post-edit one — exactly what was asked
    // for: "the bytes match the pre-edit snapshot exactly."
    let restored_bytes = std::fs::read(&conf).unwrap();
    assert_eq!(
        restored_bytes,
        original.as_bytes(),
        "restored bytes must match the pre-edit snapshot exactly"
    );

    let final_check = validator.validate();
    assert!(
        final_check.success,
        "nginx -t must pass on the restored file: {}",
        final_check.stderr
    );
}
