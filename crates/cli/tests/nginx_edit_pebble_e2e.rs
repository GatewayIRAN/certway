// SPDX-License-Identifier: MIT

//! End-to-end: a real `certway issue --edit-nginx` against Pebble,
//! editing a real `nginx:1.29.3`, proven by a real client actually
//! receiving the new certificate — not just a file on disk.
//!
//! **Why the `certway` binary runs *inside* the nginx container, on
//! `certway-pebble-net`, rather than on the host** (the same reasoning
//! `pebble_dns01_e2e.rs` already documents for its own scenarios): the
//! nginx-editing gate this stage wires up calls the real `nginx` on
//! `PATH` (`webserver::detect`'s `/proc` scan, `nginx -V`/`-t`/`-s
//! reload`) — those all have to be the *container's* nginx, not
//! whatever nginx (if any) happens to be on this sandbox's host, or the
//! test would either edit the wrong tree or prove nothing. Running
//! `certway` itself inside the container, via `docker exec`, makes every
//! one of those resolve to the one real nginx this test controls, and
//! lets Pebble's HTTP-01 validator reach certway's `:80` responder by
//! plain container-to-container IP — no host-gateway trick needed.
//!
//! The container's baseline `nginx.conf` has a `:443 ssl` block for the
//! test domain and deliberately **no** `:80` block, so port 80 is free
//! for certway's own HTTP-01 listener; `find_and_edit` takes the
//! "existing `listen ... ssl`, replace in place" path, never the
//! append-new-block one.
//!
//! Skips (never fails) when the pebble/challtestsrv stack, the musl
//! build, or Docker itself isn't reachable — the same "reports the skip,
//! never passes silently" rule every other file under `tests/*_e2e.rs`
//! already follows. Requires `tests/pebble/run.sh`'s stack to already be
//! up (this file does not bring it up itself) and the release musl
//! binary built (`cargo build --release --target
//! x86_64-unknown-linux-musl --bin certway`).

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const NETWORK: &str = "certway-pebble-net";
const PEBBLE_CONTAINER: &str = "certway-pebble";
const NGINX_IMAGE: &str = "nginx:1.29.3";
const CHALLTESTSRV: &str = "http://localhost:8055";
const ALPINE_IMAGE: &str = "alpine:3.20";

macro_rules! skip_unless_ready {
    () => {
        if !docker_available() {
            eprintln!("SKIPPED: docker not reachable");
            return;
        }
        if !pebble_reachable() {
            eprintln!(
                "SKIPPED: pebble not reachable at localhost:14000 — run tests/pebble/run.sh (or `docker compose up -d` in tests/pebble/)"
            );
            return;
        }
        if !musl_binary_path().exists() {
            eprintln!(
                "SKIPPED: musl certway binary not built — run `cargo build --release --target x86_64-unknown-linux-musl --bin certway`"
            );
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

fn pebble_reachable() -> bool {
    TcpStream::connect_timeout(
        &"127.0.0.1:14000".parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn ca_bundle_path() -> PathBuf {
    repo_root().join("tests/pebble/pebble.minica.pem")
}

fn musl_binary_path() -> PathBuf {
    repo_root().join("target/x86_64-unknown-linux-musl/release/certway")
}

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("docker must be on PATH")
}

fn openssl_stdout(args: &[&str]) -> String {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl must be on PATH");
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The container's IPv4 address on `NETWORK` — dot-field access can't
/// reach a map key containing a hyphen, hence `index` (same trick
/// `pebble_dns01_e2e.rs` already uses).
fn container_ip(name: &str) -> String {
    let out = docker(&[
        "inspect",
        "-f",
        &format!("{{{{(index .NetworkSettings.Networks \"{NETWORK}\").IPAddress}}}}"),
        name,
    ]);
    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        !ip.is_empty(),
        "could not determine {name}'s address on {NETWORK}: {out:?}"
    );
    ip
}

/// Overrides just `localhost` -> `pebble_ip` (Pebble's own TLS cert only
/// covers the name `localhost`, `docs/ref/pebble-v2.10.1.md`) so
/// `--server https://localhost:14000/dir` keeps working unchanged from
/// inside a container whose own loopback is not Pebble's.
fn write_hosts_override(pebble_ip: &str, tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "certway-nginx-edit-e2e-hosts-{tag}-{}",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!("{pebble_ip}\tlocalhost\n127.0.0.1\tlocalhost.localdomain\n::1\tip6-localhost\n"),
    )
    .unwrap();
    path
}

fn tmp_host_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "certway-nginx-edit-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("certs")).unwrap();
    dir
}

/// A real self-signed placeholder pair — genuinely loadable by nginx, and
/// (crucially) a genuinely *different* certificate from whatever Pebble
/// issues, so "the new certificate is served" is provable rather than
/// vacuous (a stale baseline that happened to already be the same cert
/// would make the fingerprint check meaningless).
fn generate_self_signed_cert(dir: &Path) {
    let cert = dir.join("certs/dummy.pem");
    let key = dir.join("certs/dummy.key");
    let status = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj",
            "/CN=placeholder.invalid", "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("openssl must be on PATH");
    assert!(
        status.status.success(),
        "failed to generate self-signed placeholder cert: {}",
        String::from_utf8_lossy(&status.stderr)
    );
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

/// Starts `NGINX_IMAGE` on `NETWORK`, `host_dir` bind-mounted as
/// `/etc/nginx` (so certway, a host-visible process via the bind mount,
/// and the test's own byte-comparisons, all see the identical file the
/// container's nginx reads), plus the musl binary, CA bundle, and a
/// `localhost`-override `/etc/hosts` — everything a containerized
/// `certway issue --edit-nginx` invocation needs, mounted once at
/// container start (an `/etc/hosts` bind mount cannot be added later via
/// `docker exec`). Runs as the image's default root — nginx needs it to
/// bind :80/:443 and certway's HTTP-01 responder needs it to bind :80
/// too; `/out`'s ownership is why every assertion below reads issued
/// files via `docker cp`, not a direct host path read.
fn start_container(
    name: &str,
    host_dir: &Path,
    hosts_file: &Path,
    out_dir: &Path,
) -> ContainerGuard {
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
    let binary = musl_binary_path();
    let ca = ca_bundle_path();
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            name,
            "--network",
            NETWORK,
            "-v",
            &format!("{}:/etc/nginx:rw", host_dir.display()),
            "-v",
            &format!("{}:/certway:ro", binary.display()),
            "-v",
            &format!("{}:/ca.pem:ro", ca.display()),
            "-v",
            &format!("{}:/etc/hosts:ro", hosts_file.display()),
            "-v",
            &format!("{}:/out", out_dir.display()),
            NGINX_IMAGE,
        ])
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

/// Registers `domain` with challtestsrv so Pebble's VA resolves it
/// straight to the nginx container's own address on `NETWORK` — plain
/// container-to-container routing, no host-gateway trick needed (unlike
/// `pebble_e2e.rs`'s host-run scenarios).
fn register_a_record(domain: &str, ip: &str) {
    let body = format!(r#"{{"host":"{domain}","addresses":["{ip}"]}}"#);
    let out = Command::new("curl")
        .args([
            "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
            &format!("{CHALLTESTSRV}/add-a"), "-d", &body,
        ])
        .output()
        .expect("curl must be on PATH");
    let code = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, "200", "challtestsrv /add-a for {domain} failed (http {code})");
}

struct IssueResult {
    status: std::process::ExitStatus,
    stdout: String,
}

fn run_certway_in_container(container: &str, extra_args: &[&str], domain: &str) -> IssueResult {
    let mut args: Vec<String> = vec!["exec".into(), container.into(), "/certway".into(), "issue".into(), domain.into()];
    args.extend([
        "--server".to_string(),
        "https://localhost:14000/dir".to_string(),
        "--ca-bundle".to_string(),
        "/ca.pem".to_string(),
        "--agree-tos".to_string(),
        "--no-email".to_string(),
        "--out".to_string(),
        "/out".to_string(),
        // Pebble's own bundled default config (the image's
        // `/test/config/pebble-config.json` — this compose stack never
        // overrides `httpPort`, only `validityPeriod`) validates HTTP-01
        // against port 5002, not 80 — the same reason every scenario in
        // `pebble_e2e.rs` passes this too. Confirmed live: without it,
        // Pebble's VA logs "Attempting to validate w/ HTTP:
        // http://<domain>:5002/..." and certway's :80 responder never
        // gets a connection.
        "--http-01-port".to_string(),
        "5002".to_string(),
        "--json".to_string(),
    ]);
    args.extend(extra_args.iter().map(|s| s.to_string()));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = docker(&arg_refs);
    IssueResult {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// Minimal `"field":"value"` extractor for this test's own JSON lines —
/// deliberately not certway_core's own parser, so these assertions stay
/// independent of certway's own code (the same rule `pebble_e2e.rs`'s
/// from-scratch helpers already follow).
fn extract_json_string(haystack: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":\"");
    let start = haystack.find(&needle)? + needle.len();
    let end = start + haystack[start..].find('"')?;
    Some(haystack[start..end].replace("\\/", "/"))
}

fn baseline_conf(domain: &str) -> String {
    format!(
        "events {{}}\nhttp {{\n    server {{\n        listen 443 ssl;\n        server_name {domain};\n        ssl_certificate /etc/nginx/certs/dummy.pem;\n        ssl_certificate_key /etc/nginx/certs/dummy.key;\n        location / {{ return 200 \"ok\\n\"; }}\n    }}\n}}\n"
    )
}

/// SHA-256 fingerprint (openssl's own `-fingerprint -sha256` line) of a
/// PEM file's leaf certificate.
fn fingerprint_of_pem_file(path: &Path) -> String {
    openssl_stdout(&["x509", "-in", path.to_str().unwrap(), "-noout", "-fingerprint", "-sha256"])
        .trim()
        .to_string()
}

/// Just the hex digest, case- and label-normalized — Debian/host openssl
/// prints `SHA256 Fingerprint=`, Alpine's prints `sha256 Fingerprint=`
/// (confirmed live: same digest, different label casing), so comparing
/// the raw lines would fail on a cosmetic difference that has nothing to
/// do with whether the two sides are the same certificate.
fn normalized_fingerprint(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let after = lower
        .split_once("fingerprint=")
        .map(|(_, hex)| hex)
        .unwrap_or(&lower);
    after.trim().to_string()
}

// `#[ignore]`, run only via `tests/pebble/run.sh` (updated to include this
// file), serialized with `--test-threads=1` — same as every other
// scenario in `pebble_e2e.rs`/`pebble_dns01_e2e.rs`, and for the same
// reason: this shares live state (challtestsrv's registered A records,
// Pebble's account/order db) with whatever else runs against the same
// stack. Confirmed live: running this file's two tests concurrently
// under plain `cargo test --workspace` produced a real `unauthorized`
// failure from Pebble, not a flake in this test's own logic — Pebble's
// own default config attempts authz reuse "50% of the time" per its
// startup log, which is only safe under the same one-at-a-time discipline
// the rest of this project's Pebble-backed suite already enforces.
#[test]
#[ignore]
fn issue_with_edit_nginx_edits_a_real_nginx_and_serves_the_new_certificate() {
    skip_unless_ready!();

    let domain = "certway-nginx-edit-proof.example";
    let dir = tmp_host_dir("edit");
    let out_dir = tmp_host_dir("edit-out");
    generate_self_signed_cert(&dir);
    let conf = dir.join("nginx.conf");
    let baseline = baseline_conf(domain);
    std::fs::write(&conf, &baseline).unwrap();

    let pebble_ip = container_ip(PEBBLE_CONTAINER);
    let hosts_file = write_hosts_override(&pebble_ip, "edit");

    let container = "certway-nginx-edit-proof";
    let _guard = start_container(container, &dir, &hosts_file, &out_dir);
    let nginx_ip = container_ip(container);
    register_a_record(domain, &nginx_ip);

    let result = run_certway_in_container(container, &["--edit-nginx", "--nginx", "--yes"], domain);
    assert!(
        result.status.success(),
        "certway issue --edit-nginx failed (exit {:?}):\n{}",
        result.status.code(),
        result.stdout
    );

    // The nginx step reports Edited, not a refusal or a silent skip.
    assert!(
        result.stdout.contains("\"step\":\"nginx\"") && result.stdout.contains("\"state\":\"done\""),
        "expected a done nginx step in:\n{}",
        result.stdout
    );
    assert!(
        result.stdout.contains("\"detail\":\"edited and reloaded\""),
        "expected the Edited detail text in:\n{}",
        result.stdout
    );

    let fullchain_container_path = extract_json_string(&result.stdout, "fullchain")
        .unwrap_or_else(|| panic!("no fullchain field in:\n{}", result.stdout));

    // -- the config was genuinely edited: the dummy paths are gone, the
    // issued paths are in, and a backup sibling exists (the transaction
    // was actually run, not merely reported).
    let after = std::fs::read_to_string(&conf).unwrap();
    assert_ne!(after, baseline, "the config must have changed");
    assert!(!after.contains("dummy.pem"), "the old placeholder paths must be gone:\n{after}");
    assert!(
        after.contains(&fullchain_container_path),
        "the new fullchain path must be written into the config:\n{after}"
    );
    let backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("nginx.conf.certway-backup-"))
        })
        .collect();
    assert_eq!(backups.len(), 1, "expected exactly one backup sibling");

    // `nginx -t` on the live config actually passes after the edit.
    let check = docker(&["exec", container, "nginx", "-t"]);
    assert!(
        check.status.success(),
        "nginx -t failed after the edit: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    // The strongest proof here: a real client, via a real
    // `curl --resolve`, actually receives the new certificate — not just
    // "a file changed on disk."
    let curl_check = docker(&[
        "run", "--rm", "--network", NETWORK, ALPINE_IMAGE, "sh", "-c",
        &format!(
            "apk add --no-cache curl >/dev/null 2>&1 && curl -sk --resolve {domain}:443:{nginx_ip} https://{domain}/ -o /dev/null -w '%{{http_code}}'"
        ),
    ]);
    let http_code = String::from_utf8_lossy(&curl_check.stdout).to_string();
    assert_eq!(
        http_code, "200",
        "curl --resolve against the edited nginx did not get a 200: {}",
        String::from_utf8_lossy(&curl_check.stderr)
    );

    // Independent identity proof, `openssl s_client`/`x509`, never
    // certway's own parser: the leaf nginx actually serves must
    // fingerprint-match the leaf certway wrote.
    let served_fp_out = docker(&[
        "run", "--rm", "--network", NETWORK, ALPINE_IMAGE, "sh", "-c",
        &format!(
            "apk add --no-cache openssl >/dev/null 2>&1 && openssl s_client -connect {nginx_ip}:443 -servername {domain} </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256"
        ),
    ]);
    let served_fp_raw = String::from_utf8_lossy(&served_fp_out.stdout)
        .trim()
        .to_string();
    assert!(
        served_fp_raw.to_ascii_lowercase().contains("fingerprint="),
        "could not read the served certificate's fingerprint: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&served_fp_out.stdout),
        String::from_utf8_lossy(&served_fp_out.stderr)
    );
    let served_fp = normalized_fingerprint(&served_fp_raw);

    let issued_local = std::env::temp_dir().join(format!(
        "certway-nginx-edit-e2e-fullchain-{}.pem",
        std::process::id()
    ));
    let cp = docker(&[
        "cp",
        &format!("{container}:{fullchain_container_path}"),
        issued_local.to_str().unwrap(),
    ]);
    assert!(
        cp.status.success(),
        "docker cp of the issued fullchain failed: {}",
        String::from_utf8_lossy(&cp.stderr)
    );
    let issued_fp = normalized_fingerprint(&fingerprint_of_pem_file(&issued_local));
    let _ = std::fs::remove_file(&issued_local);

    assert_eq!(
        served_fp, issued_fp,
        "nginx must be serving exactly the certificate certway just issued and wrote"
    );

    let _ = std::fs::remove_file(&hosts_file);
}

#[test]
#[ignore]
fn issue_without_edit_nginx_leaves_the_config_byte_identical() {
    skip_unless_ready!();

    let domain = "certway-nginx-noedit-proof.example";
    let dir = tmp_host_dir("noedit");
    let out_dir = tmp_host_dir("noedit-out");
    generate_self_signed_cert(&dir);
    let conf = dir.join("nginx.conf");
    let baseline = baseline_conf(domain);
    std::fs::write(&conf, &baseline).unwrap();

    let pebble_ip = container_ip(PEBBLE_CONTAINER);
    let hosts_file = write_hosts_override(&pebble_ip, "noedit");

    let container = "certway-nginx-noedit-proof";
    let _guard = start_container(container, &dir, &hosts_file, &out_dir);
    let nginx_ip = container_ip(container);
    register_a_record(domain, &nginx_ip);

    // No `--edit-nginx` at all: without that flag, today's advice output
    // must be unchanged.
    let result = run_certway_in_container(container, &[], domain);
    assert!(
        result.status.success(),
        "certway issue (no --edit-nginx) failed (exit {:?}):\n{}",
        result.status.code(),
        result.stdout
    );
    assert!(
        !result.stdout.contains("\"step\":\"nginx\""),
        "no nginx step should be reported at all when editing was never opted into:\n{}",
        result.stdout
    );

    let after = std::fs::read_to_string(&conf).unwrap();
    assert_eq!(after, baseline, "the config must be byte-identical without --edit-nginx");

    // Byte-identity alone doesn't distinguish "the gate short-circuited
    // before ever calling the transaction" from "it reached the
    // transaction and rolled back to the same bytes" — the absence of any
    // backup sibling is what proves the former.
    let backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("nginx.conf.certway-backup-"))
        })
        .collect();
    assert!(
        backups.is_empty(),
        "no backup file must appear when the edit was never attempted: {backups:?}"
    );

    let _ = std::fs::remove_file(&hosts_file);
}
