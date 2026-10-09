# certway

[![Release](https://img.shields.io/github/v/release/GatewayIRAN/certway?sort=semver&style=flat&label=release)](https://github.com/GatewayIRAN/certway/releases)
[![License](https://img.shields.io/github/license/GatewayIRAN/certway?style=flat&label=license)](LICENSE)
![Platform](https://img.shields.io/badge/platform-linux%20%C2%B7%20macos-6e7781?style=flat)
![Binary](https://img.shields.io/badge/binary-2.1%20MB%20static-1f6feb?style=flat)
![Build](https://github.com/GatewayIRAN/certway/actions/workflows/release.yml/badge.svg)

certway gets a TLS certificate from Let's Encrypt — or any ACME server — onto a Linux or macOS box, and keeps it renewed. One static binary: no runtime, no Python, no OpenSSL, no daemon. `issue` once, `install` once, and the box takes care of the rest.

## Principles

| One command, one outcome | The common case needs no config file. Success is quiet; failure names the identifier and the reason the authority gave. |
| Legible failure | Protocol errors are translated, not forwarded. The DNS record was not visible beats a URN. |
| Nothing phones home | No analytics, no version check, no crash upload. The only host contacted is the CA you named. |
| Keys stay where you put them | Predictable layout, restrictive permissions, no hidden state directory you did not ask for. |

## Install

```bash
curl --proto '=https' --tlsv1.2 -sSfL https://github.com/GatewayIRAN/certway/releases/latest/download/certway-installer.sh | sh
```

Or take a single file off the [releases page](https://github.com/GatewayIRAN/certway/releases) — no installer, no dependencies:

| Platform | Targets | Notes |
| --- | --- | --- |
| Linux | `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` | static — no libc, runs in `FROM scratch` |
| macOS | `x86_64-apple-darwin`, `aarch64-apple-darwin` | |

## Tour

```console
$ certway issue example.com              # get a certificate
$ certway issue "*.example.com" --dns cloudflare   # wildcard over DNS-01
$ certway renew --all                    # renew whatever is due
$ certway list                           # what is installed, what expires when
```

## Commands

| Command | What it does |
| --- | --- |
| `issue <domain>...` | Certificate over HTTP-01, or DNS-01 via Cloudflare / a DNS hook |
| `renew [<domain>]` | Renew what's due — ARI from the CA, 30-day fallback |
| `list` | Stored certificates, expiries and names |
| `install` | Wire up the renewal schedule (systemd timer or cron) |
| `export <name>` | Write `pem`, `combined` or `der` copies |
| `check <name>` | Certificate health: expiry, chain, key match |
| `doctor` | Diagnose paths, permissions, hooks, scheduler |
| `version` | Version, commit, build date, target, TLS backend |

## How it compares

certbot covers more scope (RSA, Apache, its plugin ecosystem); certway covers the ECDSA/nginx/HTTP-01/DNS-01 case in one 2.1 MB static binary with no system deps. If you need RSA certificates, Apache integration, or a DNS-01 provider certway does not build in, certbot remains the broader tool.

## Join the channel

News and how-tos land in the Telegram channel first: https://t.me/GatewayIRAN

## Contribute

- [CONTRIBUTING.md](CONTRIBUTING.md) — how a change gets merged; `git commit -s`, DCO not CLA.
- Found a vulnerability? **Do not open a public issue** — use [private vulnerability reporting](https://github.com/GatewayIRAN/certway/security/advisories/new).
- [Code of conduct](https://github.com/GatewayIRAN/.github/blob/main/CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE) — issues and pull requests welcome at [github.com/GatewayIRAN/certway](https://github.com/GatewayIRAN/certway).

---

certway · GatewayIRAN · MIT · built on ring and rustls