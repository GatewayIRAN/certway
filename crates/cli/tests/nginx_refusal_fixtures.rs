// SPDX-License-Identifier: MIT

//! Every refusal condition `matching.rs` currently implements, each as its
//! own fixture file under `tests/fixtures/nginx/refuse/`. For each: the
//! file's bytes are snapshotted before matching, `find_server_block` is
//! asserted to return the expected `Refused` reason, and the file's bytes
//! are asserted byte-identical afterward.
//!
//! No writer exists yet in this crate — this covers matching and refusal
//! only, before `edit.rs` exists — so the "afterward" read is currently
//! guaranteed to match by construction: nothing in this crate can write to
//! these files yet. The point of having this test now, rather than
//! waiting for the writer, is the contract itself: once `edit.rs` exists,
//! these same assertions are exactly what proves a refusal never touches
//! the file, with no rewrite needed here.

use certway::webserver::nginx::matching::{
    find_server_block, FindResult, PortScope, RefusalReason,
};
use certway::webserver::nginx::parse::{parse_file, RealFs};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/nginx/refuse")
        .join(name)
}

/// Reads the file, matches `domain` against it, asserts the refusal
/// reason, then re-reads the file and asserts the bytes are identical.
fn assert_refused_and_untouched(file_name: &str, domain: &str, expected: RefusalReason) {
    let path = fixture(file_name);
    let before = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));

    let fs = RealFs { root: None };
    let directives = parse_file(&path, path.parent().unwrap(), &fs)
        .unwrap_or_else(|e| panic!("parse {path:?}: {e:?}"));
    let result = find_server_block(&directives, domain, PortScope::Tls443);
    match &result {
        FindResult::Refused(reason) => {
            assert_eq!(
                *reason, expected,
                "{file_name}: wrong refusal reason for {domain:?}: got {result:?}"
            );
        }
        other => {
            panic!("{file_name}: expected Refused({expected:?}) for {domain:?}, got {other:?}")
        }
    }

    let after = std::fs::read(&path).unwrap_or_else(|e| panic!("re-read {path:?}: {e}"));
    assert_eq!(
        before, after,
        "{file_name}: bytes changed across a refused match — must never happen"
    );
}

#[test]
fn regex_selected_block_is_refused_untouched() {
    assert_refused_and_untouched(
        "regex-selected.conf",
        "www.example.com",
        RefusalReason::Regex,
    );
}

#[test]
fn variable_server_name_is_refused_untouched() {
    assert_refused_and_untouched(
        "variable-server-name.conf",
        "example.com",
        RefusalReason::VariableServerName,
    );
}

#[test]
fn duplicate_exact_server_name_is_refused_untouched() {
    assert_refused_and_untouched(
        "ambiguous-duplicate-exact.conf",
        "example.com",
        RefusalReason::Ambiguous,
    );
}

#[test]
fn tied_wildcard_specificity_is_refused_untouched() {
    assert_refused_and_untouched(
        "ambiguous-tied-wildcard.conf",
        "www.example.com",
        RefusalReason::Ambiguous,
    );
}

#[test]
fn server_name_only_inside_if_is_refused_untouched() {
    assert_refused_and_untouched(
        "inside-if.conf",
        "debug.example.com",
        RefusalReason::InsideIf,
    );
}

/// The companion property, proven on the same fixture as the InsideIf
/// case: a domain named directly (not just inside the `if`) still
/// matches normally — the `if` refusal is specific to the domain that
/// only appears inside it, not a blanket refusal on the whole file.
#[test]
fn a_domain_named_outside_the_if_still_matches_normally() {
    let path = fixture("inside-if.conf");
    let fs = RealFs { root: None };
    let directives = parse_file(&path, path.parent().unwrap(), &fs).unwrap();
    let result = find_server_block(&directives, "other.example.com", PortScope::Tls443);
    assert!(
        matches!(result, FindResult::Matched(_)),
        "expected Matched, got {result:?}"
    );
}
