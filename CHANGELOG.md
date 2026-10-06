# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-09

### Added

- `certway issue <domain>...` — obtain an ECDSA P-256 certificate from any
  ACME server (Let's Encrypt by default). Supports multiple domains and
  wildcards in a single order.
- HTTP-01 challenge, using a built-in responder on port 80 (configurable).
- DNS-01 challenge via a built-in Cloudflare provider (`--dns cloudflare`)
  or an external command (`--dns-hook`/`--dns-cleanup`), required for
  wildcards.
- `certway renew` — renew one certificate or all due certificates.
  Consults ACME Renewal Information (RFC 9773) when the server advertises
  it, falling back to a 30-day-before-expiry window otherwise.
- `certway install` — detect the platform and wire up automatic renewal:
  a systemd timer where systemd is present, a cron entry otherwise. In a
  container, prints what to schedule instead of installing anything.
- `certway list` — show stored certificates and days remaining.
- `certway export` — write a certificate in `pem`, `combined` (key +
  chain in one file, for HAProxy), or `der` format.
- `certway rollback` — undo an nginx config edit made by `issue`/`renew`.
- Automatic nginx detection and config editing (`--edit-nginx`): adds a
  new `server {}` block rather than rewriting the original, and generates
  HTTP→HTTPS redirects as two separate blocks rather than an `if`
  directive.
- `--json` output for every command, for scripting.
- `certway version` — commit, build date, target triple, and TLS stack,
  for bug reports.
- A single static binary for `x86_64-unknown-linux-musl`, with no runtime
  dependencies: no libc, no shell, no CA bundle beyond the one compiled
  in.

### Known limitations

See the README's "What it does not do yet" section. In short: ECDSA only
(no RSA), Cloudflare is the only built-in DNS provider, PKCS#12 export is
not yet implemented, and six commands (`check`, `doctor`, `import`,
`revoke`, `delete`, `account`) are not yet built.

[0.1.0]: https://github.com/GatewayIRAN/certway/releases/tag/v0.1.0
