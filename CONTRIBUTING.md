# Contributing

## Building

```
cargo build --release
```

Static musl binary:

```
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Testing

```
cargo test
```

End-to-end tests against a local [Pebble](https://github.com/letsencrypt/pebble)
ACME server need Docker and are `#[ignore]`d by default:

```
tests/pebble/run.sh
```

Never point any test at production Let's Encrypt. Staging only:
`https://acme-staging-v02.api.letsencrypt.org/directory`.

### Testing DNS resolution in containers

`crates/core/src/dns.rs` reads `/etc/resolv.conf` (or `--resolver`/`CERTWAY_RESOLVER`)
itself — certway does not link a DNS resolver from libc. When this was proven
end-to-end in a `FROM scratch` container (no libc, no shell) against a `pebble`
hostname on a Docker user-defined network, resolution worked with no `--resolver`
flag at all: Docker injects `/etc/resolv.conf` into every container at the runtime
level, independent of what the image itself contains. That's an artifact of
running under Docker specifically, not proof the resolver code is unreachable —
don't read the passing test as license to delete or stop testing it. Outside a
container runtime that provides `/etc/resolv.conf` (a bare `chroot`, some minimal
init systems), `--resolver`/`CERTWAY_RESOLVER` is the only way in.

## Code rules

- `#![forbid(unsafe_code)]` in both crates. No exceptions.
- No `unwrap()`/`expect()`/`panic!` outside `#[cfg(test)]`. A panic in a
  tool commonly run as root is not acceptable; every failure path returns
  a `Result`.
- `certway-core` never prints anything (`#![deny(clippy::print_stdout,
  clippy::print_stderr)]`). All user-facing output lives in the `certway`
  binary crate.
- Private keys stay in `Zeroizing<Vec<u8>>`. `Debug` on key types is
  hand-written and never prints key material.
- Files are written atomically (temp sibling, fsync, rename, fsync
  directory). Key files are `0600`, key directories `0700`.
- Adding a dependency is a deliberate decision, not a default — check
  whether the standard library already covers it before reaching for a
  crate, and say why in the PR if not.

## Before opening a PR

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
