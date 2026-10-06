#!/usr/bin/env bash
# Brings up the Pebble stack, waits for it to answer, runs the ignored
# pebble_e2e tests, tears the stack down regardless of outcome, and exits
# with the test run's own exit code.
#
# Idempotent: `down -v` runs first so a leftover stack from a previous
# (possibly killed) run never blocks a fresh `up`.
set -u

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
compose_file="$script_dir/docker-compose.yml"
ca_bundle="$script_dir/pebble.minica.pem"
dir_url="https://localhost:14000/dir"

cleanup() {
    echo "== tearing down pebble stack =="
    docker compose -f "$compose_file" down -v >/dev/null 2>&1
}
trap cleanup EXIT

echo "== resetting any leftover stack =="
docker compose -f "$compose_file" down -v >/dev/null 2>&1
# A previous run's manual container restarts (pebble_e2e.rs replaces the
# pebble container directly between scenarios) can leave a same-named
# container behind if it was killed mid-test — remove it explicitly so
# `up` below never hits a name conflict.
docker rm -f certway-pebble certway-challtestsrv >/dev/null 2>&1

if [ ! -f "$ca_bundle" ]; then
    echo "MISSING: $ca_bundle — fetch pebble.minica.pem before running (see docs/ref/pebble-v2.10.1.md)." >&2
    exit 1
fi

echo "== starting pebble + challtestsrv =="
if ! docker compose -f "$compose_file" up -d; then
    echo "FAILED: docker compose up — is Docker available? (see stage report, Part 1)" >&2
    exit 1
fi

echo "== waiting for $dir_url =="
ready=0
for _ in $(seq 1 60); do
    if curl -sf --max-time 2 --cacert "$ca_bundle" "$dir_url" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.5
done

if [ "$ready" -ne 1 ]; then
    echo "FAILED: pebble never answered at $dir_url after 30s — not running the suite." >&2
    exit 1
fi
echo "pebble is up."

echo "== running pebble_e2e (serialized: scenarios restart the shared pebble container) =="
(
    cd "$repo_root" && cargo test --test pebble_e2e -- --ignored --test-threads=1
)
test_status=$?

echo "== pebble_e2e exited $test_status =="

echo "== running nginx_edit_pebble_e2e (Stage 4b; needs the musl release binary) =="
(
    cd "$repo_root" && cargo build --release --target x86_64-unknown-linux-musl --bin certway \
        && cargo test --test nginx_edit_pebble_e2e -- --ignored --test-threads=1
)
nginx_edit_status=$?

echo "== nginx_edit_pebble_e2e exited $nginx_edit_status =="

if [ "$test_status" -ne 0 ]; then
    exit "$test_status"
fi
exit "$nginx_edit_status"
