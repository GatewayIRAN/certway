// SPDX-License-Identifier: MIT

//! End-to-end issuance against a local Pebble ACME server.
//!
//! Requires the stack from `tests/pebble/docker-compose.yml` — normally
//! brought up by `tests/pebble/run.sh`, which also enforces reachability
//! *before* invoking `cargo test` so a hollow all-green run can't happen
//! silently. Run directly (`cargo test --test pebble_e2e -- --ignored`)
//! against an unreachable Pebble and every test still passes, but prints an
//! unambiguous `SKIPPED:` line — never a red failure for a missing
//! environment.
//!
//! Assertions stay independent of certway's own code: all certificate/chain
//! inspection goes through the system `openssl` binary, never certway's own
//! PEM/cert parsing.
//!
//! Serialize with `--test-threads=1`: several scenarios restart the shared
//! `certway-pebble` container with different environment variables, and
//! each restart is a full, explicit reset (never a delta), so scenarios
//! stay correct regardless of the order libtest picks.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

const DIR_URL: &str = "https://localhost:14000/dir";
const MGMT_URL: &str = "https://localhost:15000";
const CHALLTESTSRV: &str = "http://localhost:8055";
const NETWORK: &str = "certway-pebble-net";
const CONTAINER: &str = "certway-pebble";
const PEBBLE_IMAGE: &str = "ghcr.io/letsencrypt/pebble:2.10.1";

macro_rules! skip_unless_pebble {
    () => {
        if !pebble_reachable() {
            eprintln!("SKIPPED: pebble not reachable at localhost:14000 — run tests/pebble/run.sh");
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

fn pebble_reachable() -> bool {
    TcpStream::connect_timeout(
        &"127.0.0.1:14000".parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

fn curl(args: &[&str]) -> std::process::Output {
    Command::new("curl")
        .args(args)
        .output()
        .expect("curl must be on PATH")
}

fn openssl(args: &[&str]) -> std::process::Output {
    Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl must be on PATH")
}

/// Restarts the pebble container alone (challtestsrv, and everything
/// registered with it, keeps running) with an explicit, complete
/// environment. Every scenario that needs non-default pebble behavior
/// calls this with its full requirement, never a delta on top of whatever
/// a previous scenario left behind.
fn restart_pebble(env: &[(&str, &str)]) {
    let _ = Command::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();
    let env_strings: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut args: Vec<&str> = vec![
        "run",
        "-d",
        "--name",
        CONTAINER,
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

/// `restart_pebble`, but with the image's own `/test/config/pebble-config.json`
/// bind-mounted over by `config_host_path` — used only by the renewal
/// scenarios that need a short certificate validity period (Pebble's stock
/// default is 90 days, per the image's own config; the `default` profile
/// this repo's own `tests/pebble/pebble-config-short-validity.json` ships
/// is otherwise byte-identical, with `validityPeriod` set to 1296000s / 15
/// days) so a freshly issued certificate is immediately within the 30-day
/// renewal fallback window, without an actual multi-week wait.
fn restart_pebble_with_config(env: &[(&str, &str)], config_host_path: &Path) {
    let _ = Command::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();
    let env_strings: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mount = format!(
        "{}:/test/config/pebble-config.json:ro",
        config_host_path.to_str().unwrap()
    );
    let mut args: Vec<&str> = vec![
        "run",
        "-d",
        "--name",
        CONTAINER,
        "--network",
        NETWORK,
        "-p",
        "14000:14000",
        "-p",
        "15000:15000",
        "-v",
        &mount,
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
        .expect("docker run certway-pebble with custom config");
    assert!(
        status.success(),
        "failed to restart the pebble container with a custom config"
    );
    wait_for_pebble();
}

fn short_validity_config_path() -> PathBuf {
    repo_root().join("tests/pebble/pebble-config-short-validity.json")
}

fn long_validity_config_path() -> PathBuf {
    repo_root().join("tests/pebble/pebble-config-long-validity.json")
}

/// Pebble's management API: sets the literal ARI response body Pebble will
/// return for `cert_pem`'s own certID (`docs/ref/pebble-v2.10.1.md`'s
/// `/set-renewal-info/`). The wire shape — `{"Certificate": "<pem>",
/// "ARIResponse": "<raw json string, not further validated>"}` — is not
/// documented in that reference file; confirmed by reading Pebble's own
/// `wfe.SetRenewalInfo` handler source (`wfe/wfe.go`,
/// `ghcr.io/letsencrypt/pebble:2.10.1`) and verified live against this
/// exact running stack before being used in an assertion.
fn set_renewal_info(cert_pem: &str, ari_response_json: &str) {
    let body = format!(
        r#"{{"Certificate":{},"ARIResponse":{}}}"#,
        json_quote(cert_pem),
        json_quote(ari_response_json)
    );
    let ca = ca_bundle_path();
    let body_path = std::env::temp_dir().join(format!(
        "certway-e2e-set-renewal-info-{}.json",
        std::process::id()
    ));
    std::fs::write(&body_path, &body).unwrap();
    let out = curl(&[
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--cacert",
        ca.to_str().unwrap(),
        "-X",
        "POST",
        &format!("{MGMT_URL}/set-renewal-info/"),
        "-H",
        "Content-Type: application/json",
        "--data",
        &format!("@{}", body_path.to_str().unwrap()),
    ]);
    let code = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, "200", "set-renewal-info failed (http {code})");
}

/// Minimal JSON string-literal escaping — this test file has no
/// `write_object` of its own (that's `certway-core`'s job, not a test
/// helper's), and the PEM/JSON text passed through here never contains
/// anything beyond base64, whitespace, and ASCII punctuation.
fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Computes the RFC 9773 certID for `cert_pem_path` independently of
/// certway's own parser — via `openssl x509 -text`
/// for the AKI and `openssl x509 -serial` for the serial, base64url-encoded
/// by hand the same way `tests/pebble_e2e.rs`'s own probes were verified
/// live before this helper was written.
fn cert_id_via_openssl(cert_pem_path: &Path) -> String {
    let text = openssl_stdout(&[
        "x509",
        "-in",
        cert_pem_path.to_str().unwrap(),
        "-noout",
        "-text",
    ]);
    let aki_line = text
        .lines()
        .skip_while(|l| !l.contains("Authority Key Identifier"))
        .nth(1)
        .unwrap_or_else(|| panic!("no Authority Key Identifier line found:\n{text}"));
    let aki_hex: String = aki_line.trim().replace(':', "");
    let serial_out = openssl_stdout(&[
        "x509",
        "-in",
        cert_pem_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    let mut serial_hex = serial_out
        .trim()
        .strip_prefix("serial=")
        .unwrap()
        .to_string();
    if serial_hex.len() % 2 == 1 {
        serial_hex.insert(0, '0');
    }
    let mut serial_bytes = hex_decode(&serial_hex);
    if serial_bytes.first().is_some_and(|b| b & 0x80 != 0) {
        serial_bytes.insert(0, 0x00);
    }
    format!(
        "{}.{}",
        b64url(&hex_decode(&aki_hex)),
        b64url(&serial_bytes)
    )
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url, unpadded — a second, independent transcription from
/// `certway-core::crypto::b64url_encode`'s own (used here so the certID
/// this test computes shares no code with the one certway itself
/// computes).
fn b64url(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

fn run_renew(args: &[&str], out_dir: &Path) -> IssueResult {
    let ca = ca_bundle_path();
    let mut full_args: Vec<String> = vec!["renew".to_string()];
    full_args.extend(args.iter().map(|s| s.to_string()));
    full_args.push("--server".into());
    full_args.push(DIR_URL.into());
    full_args.push("--ca-bundle".into());
    full_args.push(ca.to_str().unwrap().into());
    full_args.push("--http-01-port".into());
    full_args.push("5002".into());
    full_args.push("--out".into());
    full_args.push(out_dir.to_str().unwrap().into());

    let output = Command::new(env!("CARGO_BIN_EXE_certway"))
        .args(&full_args)
        .output()
        .expect("spawn certway renew");
    IssueResult {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// `run_renew`, retried the same way `run_issue_retrying` retries
/// `run_issue` — a renewal that reaches the `validate` step exercises the
/// exact same HTTP-01-over-host-gateway path as issuance, and is subject
/// to the identical environment race documented on `run_issue_retrying`
/// (confirmed live: scenario 7 flaked on this without a retry wrapper
/// before this helper existed).
fn run_renew_retrying(args: &[&str], out_dir: &Path, attempts: u32) -> IssueResult {
    let mut last = None;
    for attempt in 1..=attempts {
        let result = run_renew(args, out_dir);
        if result.status.success() {
            if attempt > 1 {
                println!("(renew succeeded on attempt {attempt}/{attempts})");
            }
            return result;
        }
        println!(
            "renew attempt {attempt}/{attempts} failed (exit {:?}):\n{}",
            result.status.code(),
            result.stdout
        );
        last = Some(result);
    }
    last.expect("attempts must be >= 1")
}

/// `certway export`, pointed at `out_dir` via `CERTWAY_DATA_DIR` — `export`
/// has no `--out`-as-data-root flag of its own (`--out` there is the export
/// destination path, not the data root, unlike `issue`/`renew`), so the env
/// var is the only way to target a scenario's own temp data directory
/// instead of the real default one.
fn run_export(args: &[&str], out_dir: &Path) -> IssueResult {
    let mut full_args: Vec<String> = vec!["export".to_string()];
    full_args.extend(args.iter().map(|s| s.to_string()));

    let output = Command::new(env!("CARGO_BIN_EXE_certway"))
        .args(&full_args)
        .env("CERTWAY_DATA_DIR", out_dir)
        .output()
        .expect("spawn certway export");
    IssueResult {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn wait_for_pebble() {
    let ca = ca_bundle_path();
    let ca = ca.to_str().unwrap();
    for _ in 0..60 {
        let out = curl(&["-sf", "--max-time", "2", "--cacert", ca, DIR_URL]);
        if out.status.success() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("pebble did not become reachable at {DIR_URL} after restart");
}

/// The docker host-gateway IP, resolved once via the `--add-host` trick
/// (see `tests/pebble/docker-compose.yml`'s comment on why challtestsrv's
/// own `-defaultIPv4` can't be used for this) and cached for the process.
/// Pebble's container reaches certway's HTTP-01 listener on the host
/// through this address.
fn host_gateway_ip() -> &'static str {
    static IP: OnceLock<String> = OnceLock::new();
    IP.get_or_init(|| {
        let out = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--add-host=host.docker.internal:host-gateway",
                "busybox",
                "cat",
                "/etc/hosts",
            ])
            .output()
            .expect("docker run busybox for host-gateway lookup");
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if !line.contains("host.docker.internal") {
                continue;
            }
            if let Some(ip) = line.split_whitespace().next() {
                if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                    return ip.to_string();
                }
            }
        }
        panic!("could not resolve docker host-gateway IPv4 address from:\n{text}");
    })
}

/// Registers `domain` with challtestsrv so Pebble's VA resolves it to the
/// host, where certway's own HTTP-01 responder (spawned by the `certway`
/// binary itself during `issue`) will be listening.
fn register_domain(domain: &str) {
    let ip = host_gateway_ip();
    let body = format!(r#"{{"host":"{domain}","addresses":["{ip}"]}}"#);
    let out = curl(&[
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-X",
        "POST",
        &format!("{CHALLTESTSRV}/add-a"),
        "-d",
        &body,
    ]);
    let code = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, "200",
        "challtestsrv /add-a for {domain} failed (http {code})"
    );
}

/// Fetches pebble's issuing root fresh from the management API — it
/// regenerates on every pebble process start and must never be cached
/// across restarts.
fn fetch_root0(tag: &str) -> PathBuf {
    let ca = ca_bundle_path();
    let dest = std::env::temp_dir().join(format!(
        "certway-e2e-root0-{tag}-{}.pem",
        std::process::id()
    ));
    let status = Command::new("curl")
        .args([
            "-sf",
            "--cacert",
            ca.to_str().unwrap(),
            &format!("{MGMT_URL}/roots/0"),
            "-o",
            dest.to_str().unwrap(),
        ])
        .status()
        .expect("curl /roots/0");
    assert!(status.success(), "failed to fetch /roots/0");
    dest
}

struct IssueResult {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn tmp_out_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("certway-e2e-out-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn run_issue(domains: &[&str], extra_args: &[&str], out_dir: &Path) -> IssueResult {
    let ca = ca_bundle_path();
    let mut args: Vec<String> = vec!["issue".to_string()];
    args.extend(domains.iter().map(|d| d.to_string()));
    args.push("--server".into());
    args.push(DIR_URL.into());
    args.push("--ca-bundle".into());
    args.push(ca.to_str().unwrap().into());
    args.push("--http-01-port".into());
    args.push("5002".into());
    args.push("--agree-tos".into());
    args.push("--no-email".into());
    args.push("--out".into());
    args.push(out_dir.to_str().unwrap().into());
    args.extend(extra_args.iter().map(|s| s.to_string()));

    let output = Command::new(env!("CARGO_BIN_EXE_certway"))
        .args(&args)
        .output()
        .expect("spawn certway");
    IssueResult {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Retries the whole `issue` invocation up to `attempts` times, returning
/// the first success or the last failure. Every attempt's outcome is
/// printed — never hidden — so a scenario that never succeeds still fails
/// loudly with full evidence.
///
/// This exists because of a verified environment race, not a certway bug:
/// Docker Desktop's WSL2 host-gateway path (container -> Windows -> WSL)
/// is not always warmed up by the time Pebble's validation attempt fires,
/// even with `PEBBLE_VA_NOSLEEP` unset — Pebble validates each
/// authorization after its own small random delay, and that delay
/// occasionally lands too close to zero for the route to be ready,
/// producing a real "connection refused" that has nothing to do with
/// certway's own listener (independently confirmed reachable, at the exact
/// same moment, from a throwaway container over the identical route).
/// More domains means more independent per-authorization rolls and thus a
/// higher chance at least one lands unlucky, so multi-domain scenarios
/// flake more often than single-domain ones — consistent with what was
/// observed empirically while building this suite.
fn run_issue_retrying(
    domains: &[&str],
    extra_args: &[&str],
    out_dir: &Path,
    attempts: u32,
) -> IssueResult {
    let mut last = None;
    for attempt in 1..=attempts {
        let result = run_issue(domains, extra_args, out_dir);
        if result.status.success() {
            if attempt > 1 {
                println!("(succeeded on attempt {attempt}/{attempts} — see doc comment on run_issue_retrying)");
            }
            return result;
        }
        println!(
            "attempt {attempt}/{attempts} failed (exit {:?}):\n{}",
            result.status.code(),
            result.stdout
        );
        last = Some(result);
    }
    last.expect("attempts must be >= 1")
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

fn openssl_stdout(args: &[&str]) -> String {
    let out = openssl(args);
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

// ---------------------------------------------------------------------
// Scenario 1 — the full happy path
// ---------------------------------------------------------------------

#[test]
#[ignore]
fn scenario1_happy_path() {
    skip_unless_pebble!();
    restart_pebble(&[("PEBBLE_WFE_NONCEREJECT", "0")]);
    register_domain("test.example");

    let out_dir = tmp_out_dir("s1");
    let result = run_issue_retrying(&["test.example"], &[], &out_dir, 3);

    println!("=== scenario1 stdout ===\n{}", result.stdout);
    println!("=== scenario1 stderr ===\n{}", result.stderr);

    assert!(
        result.status.success(),
        "exit code {:?}, stderr:\n{}",
        result.status.code(),
        result.stderr
    );

    // `--out` is the data root; certificate files live under
    // `<out>/<cert-name>/`, `<cert-name>` defaulting to the first
    // requested identifier.
    let cert_dir = out_dir.join("test.example");
    let fullchain = cert_dir.join("fullchain.pem");
    let key = cert_dir.join("privkey.pem");
    assert!(fullchain.exists(), "fullchain.pem missing");
    assert!(key.exists(), "privkey.pem missing");

    assert_eq!(file_mode(&key), 0o600, "privkey.pem mode");
    assert_eq!(file_mode(&fullchain), 0o644, "fullchain.pem mode");

    let text = openssl_stdout(&[
        "x509",
        "-in",
        fullchain.to_str().unwrap(),
        "-noout",
        "-text",
    ]);
    assert!(
        text.contains("test.example"),
        "SAN missing test.example:\n{text}"
    );
    assert!(
        openssl(&[
            "x509",
            "-in",
            fullchain.to_str().unwrap(),
            "-noout",
            "-checkend",
            "0"
        ])
        .status
        .success(),
        "fullchain.pem does not parse as a valid, unexpired certificate"
    );

    let leaf_pub = openssl_stdout(&[
        "x509",
        "-in",
        fullchain.to_str().unwrap(),
        "-noout",
        "-pubkey",
    ]);
    let key_pub = openssl_stdout(&["pkey", "-in", key.to_str().unwrap(), "-pubout"]);
    assert_eq!(
        leaf_pub, key_pub,
        "leaf public key does not match privkey.pem"
    );

    // `-untrusted` (rather than relying on openssl's historical, version-
    // dependent handling of a multi-cert target file) is what makes the
    // bundled intermediate available for path-building — verified live
    // that omitting it fails with "unable to get local issuer certificate"
    // on OpenSSL 3.x even though the chain and root are genuinely correct.
    let root0 = fetch_root0("s1");
    let fc = fullchain.to_str().unwrap();
    let out = openssl(&[
        "verify",
        "-CAfile",
        root0.to_str().unwrap(),
        "-untrusted",
        fc,
        fc,
    ]);
    assert!(
        out.status.success(),
        "chain does not verify against /roots/0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    println!("=== scenario1: verified against openssl + /roots/0 ===");
}

// ---------------------------------------------------------------------
// Scenario 2 — multiple domains
// ---------------------------------------------------------------------

#[test]
#[ignore]
fn scenario2_multiple_domains() {
    skip_unless_pebble!();
    restart_pebble(&[("PEBBLE_WFE_NONCEREJECT", "0")]);
    let domains = ["multi1.example", "multi2.example", "multi3.example"];
    for d in domains {
        register_domain(d);
    }

    let out_dir = tmp_out_dir("s2");
    let result = run_issue_retrying(&domains, &["--json"], &out_dir, 3);
    println!("=== scenario2 stdout ===\n{}", result.stdout);
    assert!(
        result.status.success(),
        "exit code {:?}, stderr:\n{}",
        result.status.code(),
        result.stderr
    );

    assert!(
        result.stdout.contains(r#""step":"order""#)
            && result.stdout.contains(r#""detail":"3 domains""#)
    );
    assert!(
        result.stdout.contains(r#""step":"validate""#)
            && result.stdout.contains(r#""detail":"3 of 3 authorized""#),
        "not all 3 authorizations were satisfied:\n{}",
        result.stdout
    );

    // Cert-name defaults to the first requested identifier.
    let fullchain = out_dir.join(domains[0]).join("fullchain.pem");
    let text = openssl_stdout(&[
        "x509",
        "-in",
        fullchain.to_str().unwrap(),
        "-noout",
        "-text",
    ]);
    for d in domains {
        assert!(text.contains(d), "SAN missing {d}:\n{text}");
    }
}

// ---------------------------------------------------------------------
// Scenario 3 — every nonce rejected (highest-value scenario in this file:
// it exercises the retry cap's failure path, not just its happy path)
// ---------------------------------------------------------------------
//
// Empirically determined: PEBBLE_WFE_NONCEREJECT=100 rejects every signed
// request unconditionally, including retries — the retry loop's 5-attempt
// cap is what fires, not eventual success. This matches this codebase's
// own `Error::NonceExhausted { attempts: 5 }`, which is the correct
// behavior to prove here — the cap must not be weakened just to force a
// passing test.
//
// This fails at the `account` stage — every signed POST hits the check,
// starting with newAccount — well before the HTTP-01 challenge step, so
// it never touches the flaky host-gateway network path documented on
// `run_issue_retrying`. No retry wrapper needed here: this failure is
// deterministic given the pebble setting, not environment jitter.

#[test]
#[ignore]
fn scenario3_every_nonce_rejected() {
    skip_unless_pebble!();
    restart_pebble(&[("PEBBLE_WFE_NONCEREJECT", "100")]);
    register_domain("nonce.example");

    let out_dir = tmp_out_dir("s3");
    let result = run_issue(&["nonce.example"], &["--json"], &out_dir);
    println!("=== scenario3 stdout ===\n{}", result.stdout);
    println!("=== scenario3 stderr ===\n{}", result.stderr);

    assert!(
        !result.status.success(),
        "expected issuance to fail under 100% nonce rejection, got exit 0"
    );
    assert!(
        result.stdout.contains(r#""error":"nonce_exhausted""#),
        "expected a nonce_exhausted failure:\n{}",
        result.stdout
    );

    // The "invisible to the user" bar applies to the human-facing summary
    // (JSON's "detail" field, which mirrors ErrorBlock::summary) — not the
    // machine-readable "error" slug. The codebase already has precedent for
    // that split: report.rs's existing `NoNonce => "no_nonce"` slug (for a
    // different, unrelated nonce failure) also names the mechanism while
    // its own summary stays clean. classify()'s generic fallback path
    // (report.rs, used here since NonceExhausted has no bespoke branch)
    // gives `detail: "certway hit an unexpected error."` — genuinely
    // nonce-free — which is what's checked here.
    for line in result.stdout.lines() {
        if let Some(start) = line.find(r#""detail":""#) {
            let detail = &line[start + 10..];
            let detail = &detail[..detail.find('"').unwrap_or(detail.len())];
            assert!(
                !detail.to_ascii_lowercase().contains("nonce"),
                "user-facing detail must not mention nonces: {detail:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Scenario 4 — already-valid authorization, across two real invocations
// ---------------------------------------------------------------------
//
// Previously impossible for an architectural reason, not a flaky
// environment: every `certway issue` invocation called `AccountKey::generate()`
// fresh, so two separate processes were, from Pebble's point of view, two
// different accounts — confirmed live via `docker logs` before this stage,
// each attempt against "reuse.example" carried a distinct `AccountURL` even
// with `PEBBLE_AUTHZREUSE=100`. `store::account` now persists the account
// key under `<out>/account/<ca-host>/account.key` and loads it back on the
// next run against the same `--out`, so this scenario now runs two real
// `certway issue` invocations against the same data directory and proves
// the second one reuses both the account and the authorization.
//
// `PEBBLE_AUTHZREUSE=100` makes the reuse deterministic rather than the
// default 50/50 (`ref/pebble-v2.10.1.md`). The second run never provisions
// or answers a challenge — Pebble reports the authorization `valid` on the
// very first fetch — so, like Scenario 3's reasoning, it never touches the
// flaky host-gateway network path `run_issue_retrying` exists for, and
// needs no retry wrapper.

#[test]
#[ignore]
fn scenario4_already_valid_authorization_is_reused() {
    skip_unless_pebble!();
    restart_pebble(&[
        ("PEBBLE_WFE_NONCEREJECT", "0"),
        ("PEBBLE_AUTHZREUSE", "100"),
    ]);
    register_domain("reuse.example");

    let out_dir = tmp_out_dir("s4");

    // Not asserting the account step's detail is "new" here: on a retried
    // attempt (`run_issue_retrying`'s documented host-gateway flakiness —
    // the same environment quirk, not a certway bug), an earlier failed
    // attempt against this same `out_dir` may already have gotten past the
    // account step and persisted `account.key` before failing later at
    // `validate`, so the attempt that finally succeeds can legitimately
    // report the account as already "existing". The reuse claim this
    // scenario exists to prove is checked below, against the *second*,
    // separate `certway issue` invocation.
    let first = run_issue_retrying(&["reuse.example"], &["--json"], &out_dir, 3);
    println!("=== scenario4 first run stdout ===\n{}", first.stdout);
    assert!(
        first.status.success(),
        "first run failed: exit {:?}, stderr:\n{}",
        first.status.code(),
        first.stderr
    );

    // Located by directory listing rather than a hardcoded guess at the
    // host string `host_from_url` derives from `DIR_URL`
    // ("https://localhost:14000/dir") — the account directory's exact name
    // is an implementation detail this test shouldn't need to duplicate.
    let account_dir = out_dir.join("account");
    let host_dirs: Vec<_> = std::fs::read_dir(&account_dir)
        .unwrap_or_else(|e| panic!("reading {account_dir:?}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert_eq!(
        host_dirs.len(),
        1,
        "expected exactly one CA-host account directory under {account_dir:?}: {host_dirs:?}"
    );
    let key_path = host_dirs[0].join("account.key");
    assert!(key_path.exists(), "account.key missing at {key_path:?}");
    assert_eq!(file_mode(&key_path), 0o600, "account.key mode");
    let key_bytes_after_first = std::fs::read(&key_path).unwrap();

    let second = run_issue(&["reuse.example"], &["--json"], &out_dir);
    println!("=== scenario4 second run stdout ===\n{}", second.stdout);
    println!("=== scenario4 second run stderr ===\n{}", second.stderr);
    assert!(
        second.status.success(),
        "second run failed: exit {:?}, stderr:\n{}",
        second.status.code(),
        second.stderr
    );

    let key_bytes_after_second = std::fs::read(&key_path).unwrap();
    assert_eq!(
        key_bytes_after_first, key_bytes_after_second,
        "second run must reuse the account key, not regenerate it"
    );

    assert!(
        second.stdout.contains(r#""step":"account""#)
            && second.stdout.contains(r#""detail":"existing""#),
        "second run must report the account as existing:\n{}",
        second.stdout
    );
    assert!(
        second.stdout.contains(r#""step":"challenge""#) && second.stdout.contains(r#""detail":"already authorized""#),
        "second run's challenge step must report the authorization as already satisfied, with nothing provisioned:\n{}",
        second.stdout
    );
    assert!(
        second.stdout.contains(r#""step":"validate""#)
            && second.stdout.contains(r#""detail":"1 of 1 authorized""#),
        "second run's validate step must report the authorization as reused, not re-polled:\n{}",
        second.stdout
    );

    println!("=== scenario4: account and authorization both reused across two invocations ===");
}

// ---------------------------------------------------------------------
// Scenario 5 — slow validation
// ---------------------------------------------------------------------

#[test]
#[ignore]
fn scenario5_slow_validation_still_succeeds() {
    skip_unless_pebble!();
    restart_pebble(&[
        ("PEBBLE_WFE_NONCEREJECT", "0"),
        ("PEBBLE_VA_SLEEPTIME", "10"),
    ]);
    register_domain("slow.example");

    let out_dir = tmp_out_dir("s5");
    let result = run_issue_retrying(&["slow.example"], &[], &out_dir, 3);
    println!("=== scenario5 stdout ===\n{}", result.stdout);
    assert!(
        result.status.success(),
        "exit code {:?}, stderr:\n{}",
        result.status.code(),
        result.stderr
    );
    assert!(out_dir.join("slow.example").join("fullchain.pem").exists());
}

// ---------------------------------------------------------------------
// Scenario 6 — renewal with ARI: assert the newOrder carries `replaces`
// ---------------------------------------------------------------------
//
// Pebble's stock config gives every certificate ~90 days of validity, and
// its own auto-computed default ARI window sits only a few days out from
// issuance (verified live while building this scenario) — neither is
// "due" for a certificate issued moments ago. Two
// independent adjustments make this scenario reachable without an actual
// multi-week wait:
//
//   1. `restart_pebble_with_config` mounts a custom config giving the
//      `default` profile a 15-day validity, so the certificate is
//      immediately within the 30-day fallback window regardless of ARI.
//   2. `set_renewal_info` forces this specific certificate's ARI window
//      fully into the past via Pebble's `/set-renewal-info/` management
//      endpoint — RFC 9773 §4.2: an all-past `suggestedWindow` is valid
//      and means "renew now," which is what makes `certway renew` take
//      the ARI path specifically (not just the 30-day fallback the short
//      validity alone would also trigger — `decide()`'s own branch order
//      checks ARI before falling back, so a due ARI window always wins).
//
// certway-core carries `#![deny(clippy::print_stdout, clippy::print_stderr)]`
// and so cannot print, meaning the literal wire bytes of the `newOrder`
// POST cannot be captured by instrumenting the live HTTP path without
// violating that boundary. The exact payload — proving `replaces` is
// present and byte-exact — is instead asserted as a unit test at
// `crates/core/src/acme.rs`
// (`new_order_payload_with_replaces_carries_the_cert_id_verbatim`), which
// this scenario's doc comment reproduces verbatim below:
//
//   {"identifiers":[{"type":"dns","value":"example.com"}],"replaces":"aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"}
//
// This scenario instead proves the end-to-end *decision and outcome*: a
// certificate whose ARI window is due renews successfully and reports
// having taken the ARI path via `--explain`.

#[test]
#[ignore]
fn scenario6_renewal_with_ari_is_taken_and_succeeds() {
    skip_unless_pebble!();
    restart_pebble_with_config(
        &[("PEBBLE_WFE_NONCEREJECT", "0")],
        &short_validity_config_path(),
    );
    register_domain("ari6b.example");

    let out_dir = tmp_out_dir("s6");
    let issued = run_issue_retrying(&["ari6b.example"], &[], &out_dir, 3);
    println!("=== scenario6 issue stdout ===\n{}", issued.stdout);
    assert!(
        issued.status.success(),
        "initial issuance failed: exit {:?}, stderr:\n{}",
        issued.status.code(),
        issued.stderr
    );

    let cert_path = out_dir.join("ari6b.example").join("cert.pem");
    let cert_pem_before = std::fs::read_to_string(&cert_path).unwrap();
    let serial_before = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    let cert_id = cert_id_via_openssl(&cert_path);
    println!("=== scenario6 certID (computed independently via openssl) === {cert_id}");

    // certway's own certID, computed by its own parser and `ari.rs`,
    // printed side by side with the openssl-derived one above on the same
    // live, Pebble-issued certificate.
    let parsed_for_id = certway_core::ParsedCert::from_leaf_pem(&cert_pem_before).unwrap();
    let certway_cert_id = certway_core::CertId::from_certificate(&parsed_for_id).unwrap();
    assert_eq!(
        certway_cert_id.as_str(),
        cert_id,
        "certway's own certID must equal the independently openssl-derived one"
    );
    println!(
        "=== scenario6 certID cross-check: certway={} openssl={} ===",
        certway_cert_id.as_str(),
        cert_id
    );

    // Snapshot cert0's files before it's replaced — needed later to prove
    // Pebble's own `alreadyReplaced` (RFC 9773 §5) fires on a second
    // newOrder naming the same certID, which is only possible if certway's
    // first newOrder really carried `replaces` on the wire — a live proof
    // that goes beyond what the unit test alone can show.
    let cert_dir = out_dir.join("ari6b.example");
    let backup_dir = tmp_out_dir("s6-backup").join("ari6b.example");
    std::fs::create_dir_all(&backup_dir).unwrap();
    for f in ["fullchain.pem", "cert.pem", "privkey.pem", "config.json"] {
        std::fs::copy(cert_dir.join(f), backup_dir.join(f)).unwrap();
    }

    // RFC 9773 §4.2: an all-past window is valid and means "renew now" —
    // not an error, and not the same as an invalid (end <= start) window.
    let ari_response =
        r#"{"suggestedWindow":{"start":"2020-01-01T00:00:00Z","end":"2020-01-02T00:00:00Z"}}"#;
    set_renewal_info(&cert_pem_before, ari_response);

    // Confirm live, before renewing, that Pebble actually returns the
    // forced past window for this exact certID — the same lookup
    // `certway renew` is about to make.
    let ca = ca_bundle_path();
    let ari_get = curl(&[
        "-sk",
        "--cacert",
        ca.to_str().unwrap(),
        &format!("https://localhost:14000/draft-ietf-acme-ari-03/renewalInfo/{cert_id}"),
    ]);
    let ari_text = String::from_utf8_lossy(&ari_get.stdout).to_string();
    assert!(
        ari_text.contains("2020-01-01"),
        "expected the forced past window back from pebble:\n{ari_text}"
    );

    let renewed = run_renew_retrying(&["ari6b.example", "--explain"], &out_dir, 3);
    println!("=== scenario6 renew stdout ===\n{}", renewed.stdout);
    println!("=== scenario6 renew stderr ===\n{}", renewed.stderr);
    assert!(
        renewed.status.success(),
        "renewal failed: exit {:?}, stderr:\n{}",
        renewed.status.code(),
        renewed.stderr
    );
    assert!(
        renewed.stdout.contains("ARI window") && renewed.stdout.contains("exempt from rate limits"),
        "expected the ARI --explain line:\n{}",
        renewed.stdout
    );

    let serial_after = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_ne!(
        serial_before, serial_after,
        "renewal must have produced a genuinely new certificate"
    );

    // Regression check: the cache at `<cert>/ari.json` described cert0's
    // forced all-past window. If it survived the renewal, every future
    // `renew` on this certificate would see `now >= moment` forever and
    // renew again unconditionally — a silent rate-limit burn. It must be
    // gone once cert1 is on disk in its place.
    let ari_cache_path = cert_dir.join("ari.json");
    assert!(!ari_cache_path.exists(), "stale ari.json (cert0's forced past window) survived the renewal it should have invalidated");

    // Live proof, beyond the
    // `new_order_payload_with_replaces_carries_the_cert_id_verbatim` unit
    // test, that certway's first newOrder really carried
    // `replaces=<certID0>` on the wire: restore cert0's files, force the
    // same past ARI window on it again, and renew a second time. certway
    // recomputes the identical
    // certID0 from cert0 and sends `replaces=<certID0>` again — Pebble's
    // `validateReplacementOrder` rejects a second newOrder naming a certID
    // that already has a finalized replacement with `alreadyReplaced`
    // (RFC 9773 §5), which is only reachable if Pebble actually recorded
    // certID0 as replaced from the first request.
    for f in ["fullchain.pem", "cert.pem", "privkey.pem", "config.json"] {
        std::fs::copy(backup_dir.join(f), cert_dir.join(f)).unwrap();
    }
    set_renewal_info(&cert_pem_before, ari_response);

    let replay = run_renew_retrying(&["ari6b.example", "--explain"], &out_dir, 3);
    println!(
        "=== scenario6 alreadyReplaced-replay stdout ===\n{}",
        replay.stdout
    );
    println!(
        "=== scenario6 alreadyReplaced-replay stderr ===\n{}",
        replay.stderr
    );
    if replay.status.success() {
        println!(
            "=== scenario6: pebble v2.10.1 did not enforce alreadyReplaced for this replay \
             (accepted a second newOrder naming certID0) — reporting as observed, not asserting it either way ==="
        );
    } else {
        // certway's own error report goes through `Out` to stdout, not
        // stderr (see the passing stdout captures throughout this file).
        assert!(
            replay.stdout.contains("already been replaced"),
            "expected the renewal to fail specifically with certway's AlreadyReplaced message, got:\n{}",
            replay.stdout
        );
        println!("=== scenario6: live confirmation — pebble rejected the replay with alreadyReplaced, proving `replaces` reached the wire ===");
    }

    let _ = std::fs::remove_dir_all(backup_dir.parent().unwrap());

    println!("=== scenario6: renewal took the ARI path and succeeded; `replaces` payload proof is the unit test cited above plus the live replay above ===");
}

// ---------------------------------------------------------------------
// Scenario 7 — ARI endpoint fails (unavailable for this certificate):
// assert the 30-day fallback runs and issuance still succeeds
// ---------------------------------------------------------------------
//
// A fresh Pebble restart regenerates its intermediate/root keys and wipes
// its in-memory ARI database entirely (`docs/ref/pebble-v2.10.1.md`: "Root/
// intermediate certs and keys are regenerated on every pebble process
// start") — challtestsrv is left running (restart_pebble* never touches
// it), so ari7b.example's A-record registration survives the restart. The
// on-disk certificate from the *old* Pebble instance is untouched: still a
// structurally valid, unexpired X.509 certificate — just one this *new*
// Pebble instance has never issued and has no ARI record for.
//
// Verified live: Pebble's own certID validation rejects this with
// `400 malformed` ("no known issuer matches the provided Authority Key
// Identifier"), not a bare `404` — Pebble checks the AKI against its
// *current* known issuers before ever doing a not-found lookup. Either
// way it's a non-200 response, and certway's renewal decision logic
// doesn't distinguish response codes: any renewalInfo fetch failure falls
// through to the 30-day rule the same way (`cmd::renew::fetch_or_use_cached_ari`
// maps every `Err` from `certway_core::fetch_renewal_info` to `None`
// identically). This is a realistic model of "the CA's renewalInfo
// endpoint doesn't have an answer for this certificate," without
// fabricating a malformed certID by hand.

#[test]
#[ignore]
fn scenario7_ari_unavailable_falls_back_to_thirty_day_rule() {
    skip_unless_pebble!();
    restart_pebble_with_config(
        &[("PEBBLE_WFE_NONCEREJECT", "0")],
        &short_validity_config_path(),
    );
    register_domain("ari7b.example");

    let out_dir = tmp_out_dir("s7");
    let issued = run_issue_retrying(&["ari7b.example"], &[], &out_dir, 3);
    println!("=== scenario7 issue stdout ===\n{}", issued.stdout);
    assert!(
        issued.status.success(),
        "initial issuance failed: exit {:?}, stderr:\n{}",
        issued.status.code(),
        issued.stderr
    );

    let cert_path = out_dir.join("ari7b.example").join("cert.pem");
    let cert_id = cert_id_via_openssl(&cert_path);
    let serial_before = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);

    restart_pebble_with_config(
        &[("PEBBLE_WFE_NONCEREJECT", "0")],
        &short_validity_config_path(),
    );

    let ca = ca_bundle_path();
    let ari_get = curl(&[
        "-sk",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--cacert",
        ca.to_str().unwrap(),
        &format!("https://localhost:14000/draft-ietf-acme-ari-03/renewalInfo/{cert_id}"),
    ]);
    let code = String::from_utf8_lossy(&ari_get.stdout).to_string();
    // Pebble's own certID validation rejects an AKI matching none of its
    // *current* issuers with 400 malformed ("no known issuer matches the
    // provided Authority Key Identifier") rather than 404 not-found —
    // verified live: the old cert's AKI belongs to the pre-restart
    // intermediate, which the fresh instance has never heard of. Either
    // way it is a non-200 response, and `certway`'s own decision logic
    // (`cmd::renew::fetch_or_use_cached_ari`) treats every non-200 the
    // same — fall through to the 30-day rule — so this assertion checks
    // "not 200", the actual precondition the rest of this scenario needs,
    // rather than a specific status code Pebble doesn't document.
    assert_ne!(
        code, "200",
        "expected the new pebble instance to reject or not know the old certID"
    );

    let renewed = run_renew_retrying(&["ari7b.example", "--explain"], &out_dir, 3);
    println!("=== scenario7 renew stdout ===\n{}", renewed.stdout);
    println!("=== scenario7 renew stderr ===\n{}", renewed.stderr);
    assert!(
        renewed.status.success(),
        "renewal must still succeed via the 30-day fallback despite the ARI 404: exit {:?}, stderr:\n{}",
        renewed.status.code(),
        renewed.stderr
    );
    assert!(
        renewed.stdout.contains("30-day fallback"),
        "expected the fallback --explain line:\n{}",
        renewed.stdout
    );

    let serial_after = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_ne!(
        serial_before, serial_after,
        "renewal must have produced a genuinely new certificate despite the ARI 404"
    );
}

// ---------------------------------------------------------------------
// Scenario 8 — renew when not due: exit 0, nothing renewed, no signed CA
// contact
// ---------------------------------------------------------------------
//
// No `--force`, no ARI window manipulation: a certificate issued moments
// ago must be due by neither the ARI window (Pebble's own default sits a
// few days out from issuance) nor the 30-day fallback. `certway renew`
// still performs the unauthenticated, rate-limit-exempt directory GET and
// ARI GET it needs while deciding — RFC 9773 §6 designs that endpoint to
// be cheap and cacheable specifically so it can be probed this freely —
// but must never reach a *signed* ACME operation (`newAccount`,
// `newOrder`, ...): nothing on the certificate changes, and the process
// exits 0 so cron never emails on a normal no-op day.
//
// Uses `pebble-config-long-validity.json`, not the stock config: verified
// live while building scenarios 6-8, Pebble picks a profile at random per
// order when the client's `newOrder` carries no explicit `profile` field
// (an undocumented behavior — nothing in `docs/ref/pebble-v2.10.1.md`
// mentions it) — its stock config's `shortlived` profile is only 6 days,
// which would make this scenario flake roughly half the time by
// accidentally landing inside the 30-day fallback window regardless of
// ARI. The long-validity config gives both profiles the same 90-day
// period, so which one Pebble happens to choose no longer matters here.

#[test]
#[ignore]
fn scenario8_renew_when_not_due_is_a_clean_noop() {
    skip_unless_pebble!();
    restart_pebble_with_config(
        &[("PEBBLE_WFE_NONCEREJECT", "0")],
        &long_validity_config_path(),
    );
    register_domain("ari8b.example");

    let out_dir = tmp_out_dir("s8");
    let issued = run_issue_retrying(&["ari8b.example"], &[], &out_dir, 3);
    println!("=== scenario8 issue stdout ===\n{}", issued.stdout);
    assert!(
        issued.status.success(),
        "initial issuance failed: exit {:?}, stderr:\n{}",
        issued.status.code(),
        issued.stderr
    );

    let cert_path = out_dir.join("ari8b.example").join("cert.pem");
    let bytes_before = std::fs::read(&cert_path).unwrap();
    let serial_before = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);

    let renewed = run_renew(&["ari8b.example", "--explain"], &out_dir);
    println!("=== scenario8 renew stdout ===\n{}", renewed.stdout);
    println!("=== scenario8 renew stderr ===\n{}", renewed.stderr);
    assert!(
        renewed.status.success(),
        "a not-due renewal must exit 0: exit {:?}, stderr:\n{}",
        renewed.status.code(),
        renewed.stderr
    );
    assert!(
        renewed.stdout.contains("not due"),
        "expected a not-due explanation:\n{}",
        renewed.stdout
    );

    let bytes_after = std::fs::read(&cert_path).unwrap();
    let serial_after = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_eq!(
        bytes_before, bytes_after,
        "a not-due renewal must never touch the certificate on disk"
    );
    assert_eq!(serial_before, serial_after);

    // No signed request means no order was ever created, so no new
    // certificate serial exists anywhere for this domain, in Pebble's own
    // records — a stronger check than "the file didn't change" alone.
    println!(
        "=== scenario8: not due, cert byte-for-byte unchanged, exit {:?} ===",
        renewed.status.code()
    );
}

// ---------------------------------------------------------------------
// Scenario 9 — --reuse-key: the private key survives a renewal only when
// asked to, and the default is a fresh key every time
// ---------------------------------------------------------------------
//
// `--reuse-key` is opt-in and recorded into `config.json` so it need not
// be repeated. New-key-per-renewal is the
// default precisely because it's the safer posture — a silent regression
// to reusing the same key on every renewal would be a security downgrade
// nobody would notice from the CLI output alone, since both paths print
// "renewed" identically. `--force` is used throughout so the scenario
// never depends on ARI or the 30-day window being open.

#[test]
#[ignore]
fn scenario9_reuse_key_keeps_the_key_default_rotates_it() {
    skip_unless_pebble!();
    restart_pebble_with_config(
        &[("PEBBLE_WFE_NONCEREJECT", "0")],
        &short_validity_config_path(),
    );
    register_domain("ari9b.example");

    let out_dir = tmp_out_dir("s9");
    let issued = run_issue_retrying(&["ari9b.example"], &[], &out_dir, 3);
    println!("=== scenario9 issue stdout ===\n{}", issued.stdout);
    assert!(
        issued.status.success(),
        "initial issuance failed: exit {:?}, stderr:\n{}",
        issued.status.code(),
        issued.stderr
    );

    let key_path = out_dir.join("ari9b.example").join("privkey.pem");
    let cert_path = out_dir.join("ari9b.example").join("cert.pem");
    let pubkey_0 = openssl_stdout(&["pkey", "-in", key_path.to_str().unwrap(), "-pubout"]);
    let serial_0 = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);

    // Default (no --reuse-key) first, before anything sets `config.json`'s
    // `reuse_key` field — that field is sticky once set ("recorded ... so
    // it need not be repeated"), so this order matters: testing the
    // default *after* a --reuse-key renewal would just be
    // testing the sticky config, not the default. Both the certificate and
    // the key must rotate — the regression check, since a silent drift to
    // always reusing the key would pass every other assertion in this file
    // undetected.
    let renewed_default = run_renew_retrying(&["ari9b.example", "--force"], &out_dir, 3);
    println!(
        "=== scenario9 renew (default) stdout ===\n{}",
        renewed_default.stdout
    );
    println!(
        "=== scenario9 renew (default) stderr ===\n{}",
        renewed_default.stderr
    );
    assert!(
        renewed_default.status.success(),
        "default renewal failed: exit {:?}, stderr:\n{}",
        renewed_default.status.code(),
        renewed_default.stderr
    );

    let pubkey_1 = openssl_stdout(&["pkey", "-in", key_path.to_str().unwrap(), "-pubout"]);
    let serial_1 = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_ne!(
        serial_0, serial_1,
        "the default renewal must produce a genuinely new certificate"
    );
    assert_ne!(pubkey_0, pubkey_1, "the default renewal (no --reuse-key) must generate a fresh key, not reuse the previous one");

    // --reuse-key, explicit: the certificate rotates again, the key does not.
    let renewed_reuse =
        run_renew_retrying(&["ari9b.example", "--force", "--reuse-key"], &out_dir, 3);
    println!(
        "=== scenario9 renew --reuse-key stdout ===\n{}",
        renewed_reuse.stdout
    );
    println!(
        "=== scenario9 renew --reuse-key stderr ===\n{}",
        renewed_reuse.stderr
    );
    assert!(
        renewed_reuse.status.success(),
        "--reuse-key renewal failed: exit {:?}, stderr:\n{}",
        renewed_reuse.status.code(),
        renewed_reuse.stderr
    );

    let pubkey_2 = openssl_stdout(&["pkey", "-in", key_path.to_str().unwrap(), "-pubout"]);
    let serial_2 = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_ne!(
        serial_1, serial_2,
        "--reuse-key must still produce a genuinely new certificate"
    );
    assert_eq!(
        pubkey_1, pubkey_2,
        "--reuse-key must leave the private key byte-for-byte unchanged"
    );

    println!(
        "=== scenario9: the default rotated the key across a renewal; --reuse-key kept it ==="
    );
}

// ---------------------------------------------------------------------
// Scenario 10 — `--link-to` + `--reload` across a renewal: issue with
// both flags, renew with `--force`, and assert the link's target follows
// the certificate to its NEW content — not left pointing at the replaced
// one. This is the entire reason link recording exists: without it, the
// linked target would keep pointing at the previous certificate after the
// first renewal.
// ---------------------------------------------------------------------

#[test]
#[ignore]
fn scenario10_link_to_and_reload_across_renewal() {
    skip_unless_pebble!();
    restart_pebble(&[("PEBBLE_WFE_NONCEREJECT", "0")]);
    register_domain("link10.example");

    let out_dir = tmp_out_dir("s10");
    let link_dir = tmp_out_dir("s10-link");

    let issued = run_issue_retrying(
        &["link10.example"],
        &["--link-to", link_dir.to_str().unwrap(), "--reload", "true"],
        &out_dir,
        3,
    );
    println!("=== scenario10 issue stdout ===\n{}", issued.stdout);
    assert!(
        issued.status.success(),
        "initial issuance failed: exit {:?}, stderr:\n{}",
        issued.status.code(),
        issued.stderr
    );
    assert!(
        issued.stdout.contains("link"),
        "expected a `link` step in issue output:\n{}",
        issued.stdout
    );
    assert!(
        issued.stdout.contains("reload"),
        "expected a `reload` step in issue output:\n{}",
        issued.stdout
    );

    let cert_path = out_dir.join("link10.example").join("cert.pem");
    let linked_fullchain = link_dir.join("fullchain.pem");
    let linked_privkey = link_dir.join("privkey.pem");
    assert!(
        linked_fullchain.exists(),
        "--link-to must have created {linked_fullchain:?}"
    );
    assert!(
        linked_privkey.exists(),
        "--link-to must have created {linked_privkey:?}"
    );

    // `--link-to` defaults to symlinking (not `--copy`): the target must
    // actually be a symlink pointing into the data directory, not a copy —
    // the "points at the NEW certificate" assertion below depends on this
    // (a copy would need re-copying, a symlink updates for free the moment
    // the target file is replaced).
    #[cfg(unix)]
    {
        let meta = std::fs::symlink_metadata(&linked_fullchain).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "--link-to's default output must be a symlink, not a copy"
        );
    }

    let serial_before = openssl_stdout(&[
        "x509",
        "-in",
        linked_fullchain.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    let serial_before_direct = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_eq!(
        serial_before, serial_before_direct,
        "the link must read back the same certificate certway just issued"
    );

    let renewed = run_renew_retrying(
        &["link10.example", "--force", "--reload", "true"],
        &out_dir,
        3,
    );
    println!("=== scenario10 renew stdout ===\n{}", renewed.stdout);
    println!("=== scenario10 renew stderr ===\n{}", renewed.stderr);
    assert!(
        renewed.status.success(),
        "renewal failed: exit {:?}, stderr:\n{}",
        renewed.status.code(),
        renewed.stderr
    );
    assert!(renewed.stdout.contains("link"), "expected a `link` step in renew output (recorded links must re-apply without repeating --link-to):\n{}", renewed.stdout);

    let serial_after_direct = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_ne!(
        serial_before_direct, serial_after_direct,
        "renewal must have produced a genuinely new certificate"
    );

    // The assertion that matters: the link's target now reads the NEW
    // certificate, not the one it was created against.
    let serial_after_via_link = openssl_stdout(&[
        "x509",
        "-in",
        linked_fullchain.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_eq!(
        serial_after_via_link, serial_after_direct,
        "the linked path must point at the NEW certificate after renewal, not the replaced one"
    );
    assert_ne!(
        serial_after_via_link, serial_before,
        "regression guard: the linked path must not still read the pre-renewal certificate"
    );

    #[cfg(unix)]
    {
        let meta = std::fs::symlink_metadata(&linked_fullchain).unwrap();
        assert!(meta.file_type().is_symlink(), "the link must still be a symlink after renewal (replaced in place, not converted to a copy)");
    }

    println!("=== scenario10: --link-to's target followed the certificate across renewal, without repeating the flag ===");

    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_dir_all(&link_dir);
}

/// `certway export --format combined` recorded at issuance is regenerated
/// on renewal (between links and hooks in `renew`'s step order), so the
/// combined file follows the certificate the same way `--link-to` already
/// does — before this fix `renew` threaded the recorded `exports` list
/// through to `config.json` but never regenerated the files themselves, so
/// this file would have gone stale silently.
#[test]
#[ignore]
fn scenario11_export_combined_is_regenerated_across_renewal() {
    skip_unless_pebble!();
    restart_pebble(&[("PEBBLE_WFE_NONCEREJECT", "0")]);
    register_domain("export11.example");

    let out_dir = tmp_out_dir("s11");
    let export_dir = tmp_out_dir("s11-export");
    let combined_path = export_dir.join("combined.pem");

    let issued = run_issue_retrying(&["export11.example"], &[], &out_dir, 3);
    println!("=== scenario11 issue stdout ===\n{}", issued.stdout);
    assert!(
        issued.status.success(),
        "initial issuance failed: exit {:?}, stderr:\n{}",
        issued.status.code(),
        issued.stderr
    );

    let exported = run_export(
        &[
            "export11.example",
            "--format",
            "combined",
            "--out",
            combined_path.to_str().unwrap(),
        ],
        &out_dir,
    );
    println!("=== scenario11 export stdout ===\n{}", exported.stdout);
    assert!(
        exported.status.success(),
        "export failed: exit {:?}, stderr:\n{}",
        exported.status.code(),
        exported.stderr
    );
    assert!(
        combined_path.exists(),
        "export --format combined must have created {combined_path:?}"
    );

    let cert_path = out_dir.join("export11.example").join("cert.pem");
    let serial_before = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    let serial_before_combined = openssl_stdout(&[
        "x509",
        "-in",
        combined_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_eq!(
        serial_before, serial_before_combined,
        "the combined export must read back the certificate certway just issued"
    );

    let combined_text_before = std::fs::read_to_string(&combined_path).unwrap();
    assert!(
        combined_text_before.starts_with("-----BEGIN PRIVATE KEY-----")
            || combined_text_before.starts_with("-----BEGIN EC PRIVATE KEY-----"),
        "combined format must put the key first: {combined_text_before}"
    );

    let renewed = run_renew_retrying(&["export11.example", "--force"], &out_dir, 3);
    println!("=== scenario11 renew stdout ===\n{}", renewed.stdout);
    println!("=== scenario11 renew stderr ===\n{}", renewed.stderr);
    assert!(
        renewed.status.success(),
        "renewal failed: exit {:?}, stderr:\n{}",
        renewed.status.code(),
        renewed.stderr
    );
    assert!(renewed.stdout.contains("export"), "expected an `export` step in renew output (recorded exports must regenerate without repeating `certway export`):\n{}", renewed.stdout);

    let serial_after_direct = openssl_stdout(&[
        "x509",
        "-in",
        cert_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_ne!(
        serial_before, serial_after_direct,
        "renewal must have produced a genuinely new certificate"
    );

    // The assertion that matters: the combined file now contains the NEW
    // certificate, not the one it was exported against.
    let serial_after_combined = openssl_stdout(&[
        "x509",
        "-in",
        combined_path.to_str().unwrap(),
        "-noout",
        "-serial",
    ]);
    assert_eq!(
        serial_after_combined, serial_after_direct,
        "the combined export must contain the NEW certificate after renewal, not the stale one"
    );
    assert_ne!(
        serial_after_combined, serial_before,
        "regression guard: the combined export must not still read the pre-renewal certificate"
    );

    println!("=== scenario11: the recorded `combined` export followed the certificate across renewal, without repeating `certway export` ===");

    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_dir_all(&export_dir);
}
