#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The project's test gate. Run this before every commit that touches
# crates/ — CI, once it exists, should run exactly this and nothing more
# lenient.
#
# Host tests run on whatever toolchain is default here (glibc, on every
# dev machine this has actually been run on so far). That is not the
# ship target: README-FIRST.md pins x86_64-unknown-linux-musl, and musl's
# signal(2) semantics (handler persists after firing, no reset) are the
# one uncited assumption crates/cli/src/signal.rs's own doc comment names
# outright — a wrong assumption there means SIGTERM's second-signal path
# falls through to the OS default kill instead of exit 130, silently, on
# the one target that matters. So the musl-target run below is not
# optional and not just "more coverage" — it is the one check that
# actually exercises the target the whole signal-handling design leans
# on. No docs/ref/ file covers musl's signal(2) behavior; that gap is
# exactly why this is a real test run rather than a comment asserting
# it's fine.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "== cargo test --workspace (host) =="
cargo test --workspace

echo "== cargo clippy --workspace --all-targets -- -D warnings =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== cargo tree --duplicates (must be empty) =="
if [ -n "$(cargo tree --duplicates)" ]; then
    echo "cargo tree --duplicates is non-empty — see output above" >&2
    exit 1
fi

echo "== cargo tree | grep ring/aws-lc (ring only, never aws-lc) =="
if cargo tree | grep -qi 'aws-lc'; then
    echo "aws-lc-rs present in the dependency tree — see README-FIRST.md" >&2
    exit 1
fi
cargo tree | grep -i ring >/dev/null

echo "== cargo test --target x86_64-unknown-linux-musl --test signal_sigterm =="
echo "   (the real ship target: musl's signal() semantics are the one"
echo "   assumption crates/cli/src/signal.rs's doc comment names as"
echo "   uncited — this is what verifies it, not just glibc)"
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
cargo test --target x86_64-unknown-linux-musl -p certway --test signal_sigterm

echo "== all checks passed =="
