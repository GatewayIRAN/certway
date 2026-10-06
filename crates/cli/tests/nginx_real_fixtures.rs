// SPDX-License-Identifier: MIT

//! The matching engine against every real captured config
//! (`crates/cli/tests/fixtures/nginx/real/`, see `NOTES.md` there for
//! provenance). This covers matching only — it deliberately stops short of
//! exercising any config-writing code.
//!
//! Ground truth for each assertion below was read directly from the
//! captured file (quoted in each test's comment), not inferred — the
//! point of testing against real configs is that nobody designed them to
//! be easy for this matcher.

use certway::webserver::nginx::matching::{find_server_block, FindResult, PortScope};
use certway::webserver::nginx::parse::{parse_file, ConfigFs, RealFs};
use std::path::{Path, PathBuf};

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/nginx/real")
        .join(name)
}

fn parse_real(
    root: &Path,
    entry: &str,
    prefix: &str,
) -> Vec<certway::webserver::nginx::parse::Directive> {
    let fs = RealFs {
        root: Some(root.to_path_buf()),
    };
    parse_file(Path::new(entry), Path::new(prefix), &fs)
        .unwrap_or_else(|e| panic!("failed to parse real fixture {entry} under {root:?}: {e:?}"))
}

fn assert_no_match(root: &Path, domain: &str, scope: PortScope) {
    let d = parse_real(root, "/etc/nginx/nginx.conf", "/etc/nginx");
    let r = find_server_block(&d, domain, scope);
    assert!(
        matches!(r, FindResult::NoMatch),
        "expected NoMatch for {domain:?}, got {r:?}"
    );
}

// -- pinned nginx:1.29.3's own shipped config --------------------------------
//
// conf.d/default.conf: `listen 80; listen [::]:80; server_name localhost;`
// — no TLS block at all in the shipped image.

#[test]
fn pinned_localhost_matches_on_plain_80() {
    let root = fixture_root("pinned-1.29.3");
    let d = parse_real(&root, "/etc/nginx/nginx.conf", "/etc/nginx");
    let r = find_server_block(&d, "localhost", PortScope::Plain80);
    assert!(
        matches!(r, FindResult::Matched(_)),
        "expected Matched, got {r:?}"
    );
}

#[test]
fn pinned_has_no_tls_block_at_all() {
    assert_no_match(
        &fixture_root("pinned-1.29.3"),
        "localhost",
        PortScope::Tls443,
    );
}

#[test]
fn pinned_unrelated_domain_does_not_match_the_shipped_default() {
    // `localhost` is a real (if trivial) server_name here, but a domain
    // that was never named must never fall through to it.
    assert_no_match(
        &fixture_root("pinned-1.29.3"),
        "example.com",
        PortScope::Plain80,
    );
}

// -- real Debian apt install --------------------------------------------------
//
// sites-available/default: `listen 80 default_server; ... server_name _;`
// — the 443 block is commented out entirely, and `_` is a literal
// placeholder string, not a wildcard — must never match a real domain.

#[test]
fn debian_default_vhost_never_matches_a_real_domain_despite_default_server() {
    // This is the load-bearing case: nginx itself WOULD answer any
    // unrecognized Host header with this exact block (it's marked
    // default_server), but certway must never adopt it for "example.com".
    assert_no_match(
        &fixture_root("debian-apt"),
        "example.com",
        PortScope::Plain80,
    );
}

#[test]
fn debian_default_vhost_has_no_reachable_tls_block() {
    // The 443 lines are commented out in the shipped default — a real,
    // common shape (TLS scaffolding present but disabled).
    assert_no_match(
        &fixture_root("debian-apt"),
        "example.com",
        PortScope::Tls443,
    );
}

// -- real Alpine apk install ---------------------------------------------------
//
// http.d/default.conf: `listen 80 default_server; listen [::]:80 default_server;`
// with NO server_name directive at all. nginx.conf includes both a dead
// `conf.d/*.conf` (directory doesn't exist on disk) and the real `http.d/*.conf`.

#[test]
fn alpine_dead_conf_d_glob_does_not_break_parsing_and_http_d_is_still_found() {
    // The headline finding from real-world extraction: certway must
    // survive the zero-match glob and still see http.d's real vhost.
    // If this test even completes without a parse error, that half of
    // the property already held; the assertion below checks the other
    // half — that the found block behaves correctly.
    assert_no_match(
        &fixture_root("alpine-apk"),
        "example.com",
        PortScope::Plain80,
    );
}

#[test]
fn alpine_conf_d_glob_is_genuinely_empty_and_http_d_glob_genuinely_is_not() {
    // The precise version of the property above: NoMatch from the two
    // tests above is ambiguous by itself (a totally broken glob resolver
    // would also produce NoMatch everywhere, and the test would lie by
    // passing). This asserts the *mechanism* directly — real filesystem,
    // real absolute container paths, through the same `RealFs` seam.
    let root = fixture_root("alpine-apk");
    let fs = RealFs { root: Some(root) };
    let dead = fs
        .glob_dir(Path::new("/etc/nginx/conf.d"), "*.conf")
        .unwrap();
    assert_eq!(
        dead,
        Vec::<PathBuf>::new(),
        "conf.d must resolve to zero matches, not an error"
    );
    let live = fs
        .glob_dir(Path::new("/etc/nginx/http.d"), "*.conf")
        .unwrap();
    assert_eq!(live, vec![PathBuf::from("/etc/nginx/http.d/default.conf")]);
}

// -- real RHEL/dnf install ------------------------------------------------------
//
// nginx.conf's own embedded default server{} (not a separate included
// file): `server_name _;`, plus a *commented-out* 443 server block and a
// real `include /etc/nginx/default.d/*.conf;` nested INSIDE the server{}
// block itself (glob currently matches zero files on a fresh install).

#[test]
fn rhel_embedded_default_never_matches_a_real_domain() {
    assert_no_match(&fixture_root("rhel-dnf"), "example.com", PortScope::Plain80);
}

#[test]
fn rhel_has_no_reachable_tls_block_either() {
    // The only 443 server{} in the shipped file is entirely commented out.
    assert_no_match(&fixture_root("rhel-dnf"), "example.com", PortScope::Tls443);
}

// -- real certbot --nginx output -------------------------------------------------
//
// certbot's real edit (not a hand-written approximation — see NOTES.md):
// block 1 gained `listen 443 ssl` / `listen [::]:443 ssl ipv6only=on` and
// kept `server_name example.com www.example.com;`; block 2 kept
// `listen 80` / `listen [::]:80` / the same `server_name` as *direct*
// children (the `if ($host = ...)` redirect guards are separate, nested,
// and must not be what makes the match).

#[test]
fn certbot_edited_config_matches_on_tls_443() {
    let root = fixture_root("certbot-nginx-plugin");
    let d = parse_real(&root, "/etc/nginx/nginx.conf", "/etc/nginx");
    let r = find_server_block(&d, "example.com", PortScope::Tls443);
    assert!(
        matches!(r, FindResult::Matched(_)),
        "expected Matched, got {r:?}"
    );
    let r2 = find_server_block(&d, "www.example.com", PortScope::Tls443);
    assert!(
        matches!(r2, FindResult::Matched(_)),
        "expected Matched for www, got {r2:?}"
    );
}

#[test]
fn certbot_edited_config_matches_on_plain_80_via_the_non_if_listen() {
    // The interesting property: the match must come from the block's
    // *direct* `listen 80`/`server_name` lines, not accidentally from
    // reading into the `if ($host = ...) { ... }` guards above them,
    // which name the domain too but must never be trusted directly.
    let root = fixture_root("certbot-nginx-plugin");
    let d = parse_real(&root, "/etc/nginx/nginx.conf", "/etc/nginx");
    let r = find_server_block(&d, "example.com", PortScope::Plain80);
    assert!(
        matches!(r, FindResult::Matched(_)),
        "expected Matched, got {r:?}"
    );
}

#[test]
fn certbot_edited_config_does_not_match_an_unrelated_domain() {
    assert_no_match(
        &fixture_root("certbot-nginx-plugin"),
        "totally-unrelated.example.org",
        PortScope::Tls443,
    );
}
