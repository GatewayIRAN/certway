# Real-world nginx fixtures — extraction notes

Captured per Stage 4 plan §8b, before any synthetic fixture was authored.
Four sources, all pulled live from containers on 2026-08-07, not invented.

## Sources

| Directory | Source | nginx version |
|---|---|---|
| `pinned-1.29.3/` | `docker run nginx:1.29.3` (the pinned reference image) — `nginx.conf` + `conf.d/*.conf` | 1.29.3 |
| `debian-apt/` | `debian:bookworm-slim`, `apt-get install nginx` | 1.22.1 |
| `alpine-apk/` | `alpine:3.20`, `apk add nginx` | see `nginx.conf` |
| `rhel-dnf/` | `rockylinux:9`, `dnf install nginx` | see `nginx.conf` |
| `certbot-nginx-plugin/` | Debian + `python3-certbot-nginx`, `certbot install --nginx` against a self-signed cert (no real ACME call) | — |

## Findings that weren't anticipated going in

- **Debian's `sites-enabled` symlink is absolute, not relative.** The `.deb`
  postinst creates `sites-enabled/default -> /etc/nginx/sites-available/default`
  (full path), not the `../sites-available/default` relative form the
  reference's `<layout>` table assumes. Doesn't change matching logic
  (certway resolves symlinks either way) but matters for the "symlink
  outside the config tree" refusal fixture — an absolute in-tree symlink
  target must not be confused with an absolute out-of-tree one.
- **Alpine has a third layout, not just "conf.d" vs "sites-enabled."**
  Alpine's shipped `nginx.conf` includes *both*
  `/etc/nginx/conf.d/*.conf` (directory doesn't exist — silently matches
  zero files, exactly the reference's documented glob trap) *and*
  `/etc/nginx/http.d/*.conf` (Alpine's actual populated convention).
  Neither `ARCH-SPEC.md`'s layout table nor the reference's `<variants>`
  table names `http.d`. Adding this as its own `refuse/`-adjacent test:
  certway must not report a false "no server block" from following the
  dead `conf.d` include while ignoring the live `http.d` one.
- **RHEL nests a second `include` inside the default `server {}` block**
  (`include /etc/nginx/default.d/*.conf;` inside `server { ... }`, not just
  at `http{}` level) — a real instance of the "`include` legal in
  `location`/`server`" case the reference's `<concept name="include-mechanics">`
  describes generically; RHEL's package gives a concrete fixture for it.
- **Certbot's real behavior confirms `ARCH-SPEC.md`'s design choice, not the
  other way around.** Certbot edits the *original* HTTP block in place
  (appends `listen 443 ssl`/`ssl_certificate`/etc. directly into it, `#
  managed by Certbot` per line) rather than appending a separate new block —
  the opposite of what this stage's `edit.rs` does per `ARCH-SPEC.md` §12.5
  (append a new block, never convert the original). More importantly,
  certbot's `--redirect` generates the HTTP→HTTPS redirect using
  `if ($host = ...) { return 301 ...; }` — precisely the "if is evil"
  pattern the reference's `<redirect-pattern>` explicitly says is
  discouraged in favor of the two-separate-`server{}`-blocks form. This is
  real evidence (not just the reference's say-so) that certway's chosen
  redirect shape is the better-engineered one, at the cost of not visually
  matching what a user who has previously run certbot will be used to
  seeing. Worth a one-line note in `edit.rs` when it's written, so the
  divergence from certbot's shape reads as deliberate.

## Extraction note

`certbot-nginx-plugin/` was re-extracted once: the first pass only
captured the single modified vhost file, not the tree it lives in, so it
wasn't actually parseable (its own `nginx.conf` literally-includes
`mime.types` etc., which is a hard error, not a silent skip, when the
literal target is missing). The re-extraction captures the full
`/etc/nginx` and `/etc/letsencrypt` trees from a fresh container, so
`sites-available/example.com`'s real `include /etc/letsencrypt/options-ssl-nginx.conf;`
resolves. This version is also free of the first pass's shell-quoting
accident (`try_files $uri $uri/ =404;` is correct).
