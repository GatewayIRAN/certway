// SPDX-License-Identifier: MIT

//! DNS-01 end-to-end scenarios against Pebble + challtestsrv.
//!
//! Requires the same stack `tests/pebble/docker-compose.yml` brings up for
//! `pebble_e2e.rs`, plus challtestsrv's DNS server listening on `:53`
//! *inside* the docker network (see that compose file's own comment on
//! `challtestsrv`'s `command:` line).
//!
//! **Why these scenarios run the `certway` binary inside a throwaway
//! container instead of on the host, unlike every scenario in
//! `pebble_e2e.rs`:** `crates/core/src/dns.rs` only ever queries port 53 —
//! `--resolver <ip>` takes no port (RFC 1035 defines no port syntax, and
//! inventing an `ip:port` extension would be a made-up flag surface).
//! Publishing challtestsrv's DNS server to *this*
//! sandbox's host on port 53 is blocked by something in the WSL2/Docker
//! Desktop networking stack — verified live with a raw UDP client against
//! both `127.0.0.1` and the WSL VM's own address, both timing out even
//! though the exact same container answers fine on a non-standard
//! host-published port. Container-to-container traffic on the
//! `certway-pebble-net` bridge this compose file defines never touches
//! that path, so the fix here is to run the certway binary itself inside a
//! container on that network, reaching `challtestsrv:53` directly — not to
//! invent resolver syntax certway itself would never actually have.
//!
//! Skips (never fails) when the stack, the musl build, or Docker itself
//! isn't available — same "reports the skip, never passes silently" rule
//! `pebble_e2e.rs` documents for itself.

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const CHALLTESTSRV_DNS_PORT: u16 = 8053; // host-published, for THIS test's own verification only
const NETWORK: &str = "certway-pebble-net";
const ALPINE_IMAGE: &str = "alpine:3.20";
const PEBBLE_CONTAINER: &str = "certway-pebble";
const PEBBLE_IMAGE: &str = "ghcr.io/letsencrypt/pebble:2.10.1";
const DIR_URL: &str = "https://localhost:14000/dir";

macro_rules! skip_unless_ready {
    () => {
        if !stack_ready() {
            eprintln!("SKIPPED: pebble/challtestsrv stack not reachable — run `docker compose up -d` in tests/pebble/");
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

fn stack_ready() -> bool {
    std::net::TcpStream::connect_timeout(
        &"127.0.0.1:14000".parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
        && std::net::TcpStream::connect_timeout(
            &"127.0.0.1:8055".parse().unwrap(),
            Duration::from_millis(500),
        )
        .is_ok()
}

fn wait_for_pebble() {
    let ca = ca_bundle_path();
    let ca = ca.to_str().unwrap();
    for _ in 0..60 {
        let out = Command::new("curl")
            .args(["-sf", "--max-time", "2", "--cacert", ca, DIR_URL])
            .output();
        if out.map(|o| o.status.success()).unwrap_or(false) {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("pebble did not become reachable at {DIR_URL} after restart");
}

/// Restarts the pebble container alone (challtestsrv, and everything
/// registered with it, keeps running) with an explicit, complete
/// environment — same pattern `pebble_e2e.rs`'s own `restart_pebble` uses.
/// Only `scenario15` needs this: `PEBBLE_AUTHZREUSE` defaults to 50%
/// (`docs/ref/pebble-v2.10.1.md`), so without forcing it to `0` a
/// `--force` renewal of the same two identifiers issuance just validated
/// would non-deterministically reuse zero, one, or both authorizations —
/// exactly the "not fully deterministic" trap that file's own notes warn
/// about, and precisely the flakiness `scenario15`'s "both records
/// simultaneously present" assertion cannot tolerate.
fn restart_pebble(env: &[(&str, &str)]) {
    let _ = Command::new("docker")
        .args(["rm", "-f", PEBBLE_CONTAINER])
        .output();
    let env_strings: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut args: Vec<&str> = vec![
        "run",
        "-d",
        "--name",
        PEBBLE_CONTAINER,
        "--network",
        NETWORK,
        "-p",
        "14000:14000",
        "-p",
        "15000:15000",
    ];
    for e in &env_strings {
        args.push("-e");
        args.push(e);
    }
    args.push(PEBBLE_IMAGE);
    args.extend([
        "-config",
        "/test/config/pebble-config.json",
        "-dnsserver",
        "challtestsrv:8053",
    ]);
    let status = Command::new("docker")
        .args(&args)
        .status()
        .expect("docker run certway-pebble");
    assert!(status.success(), "failed to restart the pebble container");
    wait_for_pebble();
}

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("certway-dns01-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The container's IPv4 address on `certway-pebble-net` — used for both
/// pebble (fed into `write_hosts_override`) and challtestsrv (`--resolver`).
fn container_ip(name: &str) -> String {
    // Dot-field access in Go templates can't reach a map key containing a
    // hyphen (`certway-pebble-net`) — `index` is the escape hatch.
    let out = docker(&[
        "inspect",
        "-f",
        &format!("{{{{(index .NetworkSettings.Networks \"{NETWORK}\").IPAddress}}}}"),
        name,
    ]);
    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        !ip.is_empty(),
        "could not determine {name}'s address on {NETWORK}: {:?}",
        out
    );
    ip
}

/// A minimal `/etc/hosts` overriding just `localhost` -> `pebble_ip`,
/// mounted into the containerized certway run in place of the image's own
/// (which would otherwise map `localhost` to the *container's own*
/// loopback, not pebble's real address on the bridge network) — pebble's
/// own TLS listener certificate (`test/certs/localhost/cert.pem`, per
/// `docs/ref/pebble-v2.10.1.md`) only covers the name `localhost`, so this
/// is what lets `--server https://localhost:14000/dir` keep working
/// unchanged from every `pebble_e2e.rs` scenario while still routing to
/// the right container.
fn write_hosts_override(pebble_ip: &str, tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "certway-dns01-e2e-hosts-{tag}-{}",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!("{pebble_ip}\tlocalhost\n127.0.0.1\tlocalhost.localdomain\n::1\tip6-localhost\n"),
    )
    .unwrap();
    path
}

fn host_uid_gid() -> (String, String) {
    let uid = String::from_utf8_lossy(&Command::new("id").arg("-u").output().unwrap().stdout)
        .trim()
        .to_string();
    let gid = String::from_utf8_lossy(&Command::new("id").arg("-g").output().unwrap().stdout)
        .trim()
        .to_string();
    (uid, gid)
}

struct IssueResult {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

/// Builds the fixed part of a containerized `certway` invocation: binary,
/// CA bundle, hosts override, and the output directory, all bind-mounted
/// read-only except `--out`. Runs as the host's own uid/gid so files
/// `certway` writes under `--out` (mode 0600/0700) are still readable by
/// this test process afterward — a plain root-owned
/// write from inside the container would not be. `env` is extra `-e
/// NAME=value` pairs — empty for every `issue` scenario so far; the
/// wildcard-renewal scenario uses it for `CERTWAY_RESOLVER`, standing in
/// for what a real deployment sets once in its scheduler's environment
/// rather than repeating `--resolver` (`renew` has no such flag —
/// `cmd::renew`'s own doc comment on `effective_challenge_config`).
#[allow(clippy::too_many_arguments)]
fn base_docker_args<'a>(
    hosts_file: &'a Path,
    out_dir: &'a Path,
    uid_gid: &'a str,
    binary: &'a Path,
    ca: &'a Path,
    env: &[(&str, &str)],
) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        NETWORK.to_string(),
        "--user".to_string(),
        uid_gid.to_string(),
    ];
    for (k, v) in env {
        args.push("-e".to_string());
        args.push(format!("{k}={v}"));
    }
    args.extend([
        "-v".to_string(),
        format!("{}:/certway:ro", binary.display()),
        "-v".to_string(),
        format!("{}:/ca.pem:ro", ca.display()),
        "-v".to_string(),
        format!("{}:/etc/hosts:ro", hosts_file.display()),
        "-v".to_string(),
        format!("{}:/out", out_dir.display()),
        ALPINE_IMAGE.to_string(),
        "/certway".to_string(),
    ]);
    args
}

/// The `--dns-hook`/`--dns-cleanup` scripts: plain BusyBox `wget` (alpine's
/// only HTTP client without an `apk add`) calling challtestsrv's
/// `/set-txt`/`/clear-txt` directly — container-to-container, so
/// `challtestsrv` resolves via Docker's own embedded DNS regardless of
/// certway's own resolver (a *hook subprocess* is not certway itself; it's
/// exempt from the "never touch the system resolver" rule that governs
/// certway's own connections). `$CERTWAY_RECORD_NAME`/`$CERTWAY_RECORD_VALUE`
/// are the env vars certway's dns-01 hook contract sets for the hook script.
fn create_hook_cmd() -> &'static str {
    r#"wget -q -O- --post-data='{"host":"'"$CERTWAY_RECORD_NAME"'.","value":"'"$CERTWAY_RECORD_VALUE"'"}' http://challtestsrv:8055/set-txt"#
}

fn cleanup_hook_cmd() -> &'static str {
    r#"wget -q -O- --post-data='{"host":"'"$CERTWAY_RECORD_NAME"'."}' http://challtestsrv:8055/clear-txt"#
}

// ---------------------------------------------------------------------
// A hand-written raw DNS TXT query — deliberately independent of
// certway_core::dns, so these assertions stay independent of certway's own
// code (the same rule pebble_e2e.rs's own from-scratch certID/base64
// helpers already follow). Queries the host-published :8053,
// never :53 — this is the test harness checking challtestsrv's actual
// state, not certway's own resolution path.
// ---------------------------------------------------------------------

fn skip_name(buf: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= buf.len() {
            return pos;
        }
        let b = buf[pos];
        if b & 0xC0 == 0xC0 {
            return pos + 2;
        }
        if b == 0 {
            return pos + 1;
        }
        pos += 1 + b as usize;
    }
}

fn parse_txt_answers(buf: &[u8]) -> Vec<String> {
    if buf.len() < 12 {
        return vec![];
    }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let mut pos = skip_name(buf, 12) + 4; // + QTYPE/QCLASS
    let mut out = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos);
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > buf.len() {
            break;
        }
        if rtype == 16 {
            let end = pos + rdlength;
            let mut p = pos;
            let mut s = Vec::new();
            while p < end {
                let len = buf[p] as usize;
                p += 1;
                if p + len > end {
                    break;
                }
                s.extend_from_slice(&buf[p..p + len]);
                p += len;
            }
            out.push(String::from_utf8_lossy(&s).to_string());
        }
        pos += rdlength;
    }
    out
}

fn query_txt(name_no_dot: &str) -> Vec<String> {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).expect("bind udp socket");
    sock.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x1234u16.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    for label in name_no_dot.trim_end_matches('.').split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&16u16.to_be_bytes()); // TXT
    msg.extend_from_slice(&1u16.to_be_bytes()); // IN
    if sock
        .send_to(&msg, ("127.0.0.1", CHALLTESTSRV_DNS_PORT))
        .is_err()
    {
        return vec![];
    }
    let mut buf = [0u8; 4096];
    match sock.recv(&mut buf) {
        Ok(n) => parse_txt_answers(&buf[..n]),
        Err(_) => vec![],
    }
}

fn run_containerized(args: &[String], hosts_file: &Path, out_dir: &Path) -> IssueResult {
    run_containerized_with_env(args, hosts_file, out_dir, &[])
}

fn run_containerized_with_env(
    args: &[String],
    hosts_file: &Path,
    out_dir: &Path,
    env: &[(&str, &str)],
) -> IssueResult {
    let binary = musl_binary_path();
    let ca = ca_bundle_path();
    let (uid, gid) = host_uid_gid();
    let uid_gid = format!("{uid}:{gid}");
    let mut full_args = base_docker_args(hosts_file, out_dir, &uid_gid, &binary, &ca, env);
    full_args.extend(args.iter().cloned());

    let output = Command::new("docker")
        .args(&full_args)
        .output()
        .expect("docker run certway container");
    IssueResult {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn common_issue_args(
    domains: &[&str],
    resolver_ip: &str,
    dns_hook: &str,
    dns_cleanup: &str,
) -> Vec<String> {
    let mut args = vec!["issue".to_string()];
    args.extend(domains.iter().map(|d| d.to_string()));
    args.extend([
        "--server".to_string(),
        "https://localhost:14000/dir".to_string(),
        "--ca-bundle".to_string(),
        "/ca.pem".to_string(),
        "--agree-tos".to_string(),
        "--no-email".to_string(),
        "--out".to_string(),
        "/out".to_string(),
        "--resolver".to_string(),
        resolver_ip.to_string(),
        "--dns-hook".to_string(),
        dns_hook.to_string(),
        "--dns-cleanup".to_string(),
        dns_cleanup.to_string(),
        "--hook-shell".to_string(),
    ]);
    args
}

#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {path:?}: {e}"))
        .permissions()
        .mode()
        & 0o777
}

// ---------------------------------------------------------------------
// Scenario 10 — DNS-01 for a single domain via the external hook
// ---------------------------------------------------------------------

#[test]
#[ignore]
fn scenario10_dns01_single_domain_via_external_hook() {
    skip_unless_ready!();
    let pebble_ip = container_ip("certway-pebble");
    let challtestsrv_ip = container_ip("certway-challtestsrv");
    let hosts_file = write_hosts_override(&pebble_ip, "s10");
    let out_dir = tmp_dir("s10-out");

    let args = common_issue_args(
        &["dns10.example"],
        &challtestsrv_ip,
        create_hook_cmd(),
        cleanup_hook_cmd(),
    );
    let result = run_containerized(&args, &hosts_file, &out_dir);
    println!("=== scenario10 stdout ===\n{}", result.stdout);
    println!("=== scenario10 stderr ===\n{}", result.stderr);
    assert!(
        result.status.success(),
        "exit code {:?}",
        result.status.code()
    );

    let fullchain = out_dir.join("dns10.example").join("fullchain.pem");
    let key = out_dir.join("dns10.example").join("privkey.pem");
    assert!(fullchain.exists(), "fullchain.pem missing");
    assert!(key.exists(), "privkey.pem missing");
    assert_eq!(file_mode(&key), 0o600);

    // Cleanup already ran as part of `issue` — nothing left in the zone.
    let remaining = query_txt("_acme-challenge.dns10.example");
    assert!(
        remaining.is_empty(),
        "expected no TXT records left after a successful run: {remaining:?}"
    );

    let _ = std::fs::remove_file(&hosts_file);
}

// ---------------------------------------------------------------------
// Scenario 11 — example.com AND *.example.com in one order: both TXT
// records must exist *simultaneously*, not merely each at some point.
// ---------------------------------------------------------------------

#[test]
#[ignore]
fn scenario11_wildcard_pair_both_records_exist_simultaneously() {
    skip_unless_ready!();
    let pebble_ip = container_ip("certway-pebble");
    let challtestsrv_ip = container_ip("certway-challtestsrv");
    let hosts_file = write_hosts_override(&pebble_ip, "s11");
    let out_dir = tmp_dir("s11-out");

    let record_name = "_acme-challenge.wild11.example";
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let max_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (stop_clone, max_seen_clone) = (
        std::sync::Arc::clone(&stop),
        std::sync::Arc::clone(&max_seen),
    );
    let record_name_owned = record_name.to_string();
    let poller = std::thread::spawn(move || {
        while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            let n = query_txt(&record_name_owned).len();
            let prev = max_seen_clone.load(std::sync::atomic::Ordering::Relaxed);
            if n > prev {
                max_seen_clone.store(n, std::sync::atomic::Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let args = common_issue_args(
        &["wild11.example", "*.wild11.example"],
        &challtestsrv_ip,
        create_hook_cmd(),
        cleanup_hook_cmd(),
    );
    let result = run_containerized(&args, &hosts_file, &out_dir);

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    poller.join().unwrap();

    println!("=== scenario11 stdout ===\n{}", result.stdout);
    println!("=== scenario11 stderr ===\n{}", result.stderr);
    assert!(
        result.status.success(),
        "exit code {:?}",
        result.status.code()
    );

    let peak = max_seen.load(std::sync::atomic::Ordering::Relaxed);
    println!("=== scenario11: peak simultaneous TXT record count for {record_name} = {peak} ===");
    assert_eq!(
        peak, 2,
        "both records must have been visible at the same instant, not just each at some point"
    );

    let remaining = query_txt(record_name);
    assert!(
        remaining.is_empty(),
        "expected no TXT records left after cleanup: {remaining:?}"
    );

    let _ = std::fs::remove_file(&hosts_file);
}

// ---------------------------------------------------------------------
// Scenario 12 — cleanup after success: no TXT records remain
// ---------------------------------------------------------------------

#[test]
#[ignore]
fn scenario12_cleanup_after_success_leaves_no_txt_records() {
    skip_unless_ready!();
    let pebble_ip = container_ip("certway-pebble");
    let challtestsrv_ip = container_ip("certway-challtestsrv");
    let hosts_file = write_hosts_override(&pebble_ip, "s12");
    let out_dir = tmp_dir("s12-out");

    let args = common_issue_args(
        &["dns12.example"],
        &challtestsrv_ip,
        create_hook_cmd(),
        cleanup_hook_cmd(),
    );
    let result = run_containerized(&args, &hosts_file, &out_dir);
    println!("=== scenario12 stdout ===\n{}", result.stdout);
    assert!(
        result.status.success(),
        "exit code {:?}",
        result.status.code()
    );
    assert!(
        result.stdout.contains(r#""step":"cleanup""#) || result.stdout.contains("cleanup"),
        "expected a cleanup step to be reported:\n{}",
        result.stdout
    );

    let remaining = query_txt("_acme-challenge.dns12.example");
    assert!(
        remaining.is_empty(),
        "expected no TXT records left: {remaining:?}"
    );

    let _ = std::fs::remove_file(&hosts_file);
}

// ---------------------------------------------------------------------
// Scenario 13 — cleanup after failure: no TXT records remain
// ---------------------------------------------------------------------
//
// The create hook deliberately fails for the *second* domain only (after
// the first domain's record was genuinely created via a real /set-txt
// call) — `prepare` fails partway through, exactly the case
// `challenge::Dns01Solver::prepare`'s own regression test
// (`prepare_failure_still_attempts_cleanup_of_every_task`) exists for at
// the unit level. This proves the same property live: cleanup still
// removes what was actually created, and never creates anything for the
// domain whose hook failed.

#[test]
#[ignore]
fn scenario13_cleanup_after_failure_leaves_no_txt_records() {
    skip_unless_ready!();
    let pebble_ip = container_ip("certway-pebble");
    let challtestsrv_ip = container_ip("certway-challtestsrv");
    let hosts_file = write_hosts_override(&pebble_ip, "s13");
    let out_dir = tmp_dir("s13-out");

    let failing_create_cmd = format!(
        r#"if [ "$CERTWAY_DOMAIN" = "s13b.example" ]; then exit 7; fi; {}"#,
        create_hook_cmd()
    );

    let args = common_issue_args(
        &["s13a.example", "s13b.example"],
        &challtestsrv_ip,
        &failing_create_cmd,
        cleanup_hook_cmd(),
    );
    let result = run_containerized(&args, &hosts_file, &out_dir);
    println!("=== scenario13 stdout ===\n{}", result.stdout);
    println!("=== scenario13 stderr ===\n{}", result.stderr);
    assert!(
        !result.status.success(),
        "expected issuance to fail when a create hook fails, got exit 0"
    );

    let remaining_a = query_txt("_acme-challenge.s13a.example");
    let remaining_b = query_txt("_acme-challenge.s13b.example");
    assert!(
        remaining_a.is_empty(),
        "domain a's record (genuinely created) must have been cleaned up: {remaining_a:?}"
    );
    assert!(
        remaining_b.is_empty(),
        "domain b's record (hook failed) must never have existed: {remaining_b:?}"
    );

    let _ = std::fs::remove_file(&hosts_file);
}

// ---------------------------------------------------------------------
// Scenario 14 — SIGTERM mid-challenge: records removed before exit
// ---------------------------------------------------------------------
//
// The create hook publishes a value that can never match what certway
// itself expects (certway checks the published TXT value against the
// expected authorization value with a set-equality check), so
// `Dns01Solver::ready`'s propagation poll never succeeds on its own —
// guaranteeing the container is still blocked in that interruptible loop
// (the one place in this build's dns-01 path that actually checks
// `signal::requested()`) whenever the signal arrives, rather than racing
// a fast natural completion.

#[test]
#[ignore]
fn scenario14_sigterm_mid_challenge_removes_records_before_exit() {
    skip_unless_ready!();
    let pebble_ip = container_ip("certway-pebble");
    let challtestsrv_ip = container_ip("certway-challtestsrv");
    let hosts_file = write_hosts_override(&pebble_ip, "s14");
    let out_dir = tmp_dir("s14-out");

    let never_matches_create_cmd = r#"wget -q -O- --post-data='{"host":"'"$CERTWAY_RECORD_NAME"'.","value":"deliberately-wrong-value-for-scenario14"}' http://challtestsrv:8055/set-txt"#;

    let container_name = format!("certway-dns01-s14-{}", std::process::id());
    let _ = docker(&["rm", "-f", &container_name]);

    let binary = musl_binary_path();
    let ca = ca_bundle_path();
    let (uid, gid) = host_uid_gid();
    let mut args = vec![
        "run".to_string(),
        "--name".to_string(),
        container_name.clone(),
        "--network".to_string(),
        NETWORK.to_string(),
        "--user".to_string(),
        format!("{uid}:{gid}"),
        "-v".to_string(),
        format!("{}:/certway:ro", binary.display()),
        "-v".to_string(),
        format!("{}:/ca.pem:ro", ca.display()),
        "-v".to_string(),
        format!("{}:/etc/hosts:ro", hosts_file.display()),
        "-v".to_string(),
        format!("{}:/out", out_dir.display()),
        ALPINE_IMAGE.to_string(),
        "/certway".to_string(),
    ];
    args.extend(common_issue_args(
        &["s14.example"],
        &challtestsrv_ip,
        never_matches_create_cmd,
        cleanup_hook_cmd(),
    ));

    let start = Instant::now();
    let mut child = Command::new("docker")
        .args(&args)
        .spawn()
        .expect("spawn containerized certway");

    // Enough time for account/order/dns to finish against a local, fast
    // Pebble — well short of the 300s propagation cap this is testing an
    // early exit from. If the signal lands before `propagate` is even
    // reached, `signal::requested()` is still sticky true by the time the
    // interrupt-check loop is reached, so this isn't a tight race.
    std::thread::sleep(Duration::from_secs(4));
    let kill_status = docker(&["kill", "-s", "TERM", &container_name]).status;
    assert!(kill_status.success(), "docker kill -s TERM failed");

    let exit_status = child.wait().expect("wait for containerized certway");
    let elapsed = start.elapsed();
    println!(
        "=== scenario14: exited {:?} after start (SIGTERM sent at ~4s); exit={:?} ===",
        elapsed,
        exit_status.code()
    );

    assert!(
        elapsed < Duration::from_secs(20),
        "must exit promptly after SIGTERM, not wait out the 300s propagation cap: {elapsed:?}"
    );
    assert!(
        !exit_status.success(),
        "a signal-interrupted run must not exit 0"
    );

    std::thread::sleep(Duration::from_millis(500));
    let remaining = query_txt("_acme-challenge.s14.example");
    assert!(
        remaining.is_empty(),
        "cleanup must have removed the record before exit: {remaining:?}"
    );

    let _ = docker(&["rm", "-f", &container_name]);
    let _ = std::fs::remove_file(&hosts_file);
}

// ---------------------------------------------------------------------
// Scenario 15 — a wildcard renews via dns-01, driven entirely by
// `config.json` — no `--dns`/`--dns-hook`/`--dns-cleanup` on the renew
// invocation at all.
//
// This is the motivating bug this behavior fixes, end to end: before
// `config.json` persisted the dns-01 hook config, `renew` had no DNS-01
// path whatsoever, so a wildcard issued via `--dns-hook` could never
// renew — every automatic attempt ran http-01,
// which a wildcard authorization never offers, until the certificate
// expired. `--force` stands in for "the certificate happens to be due";
// the interesting assertion is *how* the renewal validated, not why it
// ran. The peak-simultaneous-TXT-record check (the same proof
// `scenario11` uses for issuance) is what makes this stronger than "it
// created some TXT record at some point": a renewal that somehow
// succeeded via a different path would not show two records present at
// once for a two-identifier order.
//
// The only thing given the containerized renew invocation beyond `--out`/
// `--ca-bundle` (network/environment details, not challenge selection) is
// `CERTWAY_RESOLVER` via the environment — standing in for what a real
// deployment's systemd unit/cron entry sets once, since `renew --all
// --quiet` (`scheduler/cron.rs`, `scheduler/systemd.rs`) never carries
// flags of its own.
// ---------------------------------------------------------------------

#[test]
#[ignore]
fn scenario15_wildcard_renewal_uses_dns01_from_config_json_alone() {
    skip_unless_ready!();
    restart_pebble(&[("PEBBLE_WFE_NONCEREJECT", "0"), ("PEBBLE_AUTHZREUSE", "0")]);
    let pebble_ip = container_ip("certway-pebble");
    let challtestsrv_ip = container_ip("certway-challtestsrv");
    let hosts_file = write_hosts_override(&pebble_ip, "s15");
    let out_dir = tmp_dir("s15-out");

    // -- issue: wild15.example + *.wild15.example, via --dns-hook ---------
    let issue_args = common_issue_args(
        &["wild15.example", "*.wild15.example"],
        &challtestsrv_ip,
        create_hook_cmd(),
        cleanup_hook_cmd(),
    );
    let issued = run_containerized(&issue_args, &hosts_file, &out_dir);
    println!("=== scenario15 issue stdout ===\n{}", issued.stdout);
    println!("=== scenario15 issue stderr ===\n{}", issued.stderr);
    assert!(
        issued.status.success(),
        "issuance exit code {:?}",
        issued.status.code()
    );

    let fullchain_path = out_dir.join("wild15.example").join("fullchain.pem");
    let original_pem = std::fs::read_to_string(&fullchain_path).expect("original fullchain.pem");

    let config_text = std::fs::read_to_string(out_dir.join("wild15.example").join("config.json"))
        .expect("config.json");
    assert!(
        config_text.contains(r#""challenge":"dns-01""#),
        "{config_text}"
    );
    assert!(
        config_text.contains(r#""dns_hook""#),
        "config.json must persist the hook command for zero-flag renewal: {config_text}"
    );

    // -- renew: --force, --out/--ca-bundle only, no DNS flags at all ------
    let record_name = "_acme-challenge.wild15.example";
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let max_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (stop_clone, max_seen_clone) = (
        std::sync::Arc::clone(&stop),
        std::sync::Arc::clone(&max_seen),
    );
    let record_name_owned = record_name.to_string();
    let poller = std::thread::spawn(move || {
        while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            let n = query_txt(&record_name_owned).len();
            let prev = max_seen_clone.load(std::sync::atomic::Ordering::Relaxed);
            if n > prev {
                max_seen_clone.store(n, std::sync::atomic::Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let renew_args = vec![
        "renew".to_string(),
        "wild15.example".to_string(),
        "--force".to_string(),
        "--out".to_string(),
        "/out".to_string(),
        "--ca-bundle".to_string(),
        "/ca.pem".to_string(),
    ];
    let renewed = run_containerized_with_env(
        &renew_args,
        &hosts_file,
        &out_dir,
        &[("CERTWAY_RESOLVER", &challtestsrv_ip)],
    );

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    poller.join().unwrap();

    println!("=== scenario15 renew stdout ===\n{}", renewed.stdout);
    println!("=== scenario15 renew stderr ===\n{}", renewed.stderr);
    assert!(
        renewed.status.success(),
        "renewal exit code {:?}",
        renewed.status.code()
    );
    assert!(
        renewed.stdout.contains("dns") || renewed.stdout.contains("propagate"),
        "expected dns-01's own steps in the renewal output:\n{}",
        renewed.stdout
    );

    // The assertion that matters: both records existed *simultaneously*
    // during the renewal, proving dns-01 actually drove it — a renewal
    // that "succeeded" via some other path could not produce this.
    let peak = max_seen.load(std::sync::atomic::Ordering::Relaxed);
    println!("=== scenario15: peak simultaneous TXT record count for {record_name} during renewal = {peak} ===");
    assert_eq!(peak, 2, "both records must have been visible at the same instant during the *renewal*, not just at issuance");

    let remaining = query_txt(record_name);
    assert!(
        remaining.is_empty(),
        "expected no TXT records left after the renewal's cleanup: {remaining:?}"
    );

    let renewed_pem = std::fs::read_to_string(&fullchain_path).expect("renewed fullchain.pem");
    assert_ne!(
        original_pem, renewed_pem,
        "the renewed certificate must differ from the one issuance produced"
    );

    let _ = std::fs::remove_file(&hosts_file);
}
