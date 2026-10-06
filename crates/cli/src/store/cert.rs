// SPDX-License-Identifier: MIT

//! Certificate storage layout.
//!
//! ```text
//! <data>/example.com/               0700
//!   ├── fullchain.pem   0644
//!   ├── cert.pem        0644
//!   ├── chain.pem       0644
//!   ├── privkey.pem     0600
//!   └── config.json     0600
//! ```
//!
//! `config.json` holds what the certificate cannot. It never carries
//! `not_after`: expiry is always read from the certificate itself, never
//! trusted from this file (enforced by the
//! `writes_all_five_files_with_correct_modes_and_dir_name` test below).
//!
//! `config.json` is `0600`, not `0644`: `hooks.hook`/`hook_failure`/
//! `hook_url`/`reload` and `dns_hook`/`dns_cleanup` are arbitrary command
//! lines that routinely carry a credential as an argument — the same
//! reason a Cloudflare API token is never accepted on the command line.
//! Treating this file as free of secrets was already wrong once the
//! `hooks` fields existed, and became concretely exploitable once
//! `dns_hook`/`dns_cleanup` were added (anyone who can read the file gets
//! a working `--dns-hook` invocation for the account's own zone).
//!
//! The certificate directory itself is `0700`, not `0755` — `privkey.pem`
//! and `config.json` both live here, and a world-executable directory lets
//! any user on the machine list the filenames it holds even though the
//! files' own modes block reading their contents. A web server still reads
//! `fullchain.pem`/`cert.pem`/`chain.pem` out of it exactly as certbot's
//! own `0700` `/etc/letsencrypt/live/<domain>/` does: the process that
//! opens the file (nginx's master, started as root) does so before
//! dropping privileges, so directory ownership — not world-readability —
//! is what makes that work.

use super::atomic::{atomic_write, create_dir_secure};
use super::link;
use certway_core::json::{write_object, Json, JsonVal};
use certway_core::{self as core};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// One recorded `--link`/`--link-to` entry: which of
/// the four files this certificate writes (`"fullchain"`, `"cert"`,
/// `"chain"`, `"privkey"`), and the exact path it's linked (or copied) to.
/// Recorded in `config.json` so `renew` can re-apply it — without this, the
/// target would point at the previous certificate after the first renewal,
/// the exact failure `--link-to`/`--link` exist to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSpec {
    pub name: String,
    pub target: String,
    pub copy: bool,
}

/// Post-issuance hooks. `reload` is `--reload`'s shorthand and reports
/// under its own `reload` step rather than folding into `hook`. Recorded
/// in `config.json` so `renew` re-applies them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookConfig {
    pub hook: Option<String>,
    pub hook_failure: Option<String>,
    pub hook_url: Option<String>,
    pub reload: Option<String>,
    pub hook_shell: bool,
}

impl HookConfig {
    pub fn is_empty(&self) -> bool {
        self.hook.is_none()
            && self.hook_failure.is_none()
            && self.hook_url.is_none()
            && self.reload.is_none()
    }
}

/// One `certway export <name> --format <f> --out <path>` configuration,
/// recorded so `renew` regenerates it after every successful renewal.
/// Never written by `issue`/`renew` themselves — only the `export` command
/// creates these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSpec {
    pub format: String,
    pub out: String,
}

/// The on-disk directory name for a certificate. Named after the first
/// requested identifier, `first_identifier`; this build has no
/// `--cert-name` override, so it's always the default. A leading `*.`
/// becomes `_.`: `*` is illegal in a Windows path component and awkward to
/// type in a shell.
pub fn cert_dir_name(first_identifier: &str) -> String {
    match first_identifier.strip_prefix("*.") {
        Some(rest) => format!("_.{rest}"),
        None => first_identifier.to_string(),
    }
}

pub struct CertPaths {
    pub dir: PathBuf,
    pub fullchain: PathBuf,
    pub cert: PathBuf,
    pub chain: PathBuf,
    pub privkey: PathBuf,
    pub config: PathBuf,
}

pub fn cert_paths(cert_root: &Path) -> CertPaths {
    CertPaths {
        dir: cert_root.to_path_buf(),
        fullchain: cert_root.join("fullchain.pem"),
        cert: cert_root.join("cert.pem"),
        chain: cert_root.join("chain.pem"),
        privkey: cert_root.join("privkey.pem"),
        config: cert_root.join("config.json"),
    }
}

/// `config.json`'s contents, read back.
#[derive(Debug, Clone)]
pub struct CertConfig {
    pub challenge: String,
    /// `Some("cloudflare")`/`Some("hook")` when `challenge == "dns-01"`,
    /// `None` for `http-01`. `"cloudflare"` alone is enough for `renew` to
    /// rebuild a `CloudflareProvider` (the token comes from the
    /// environment, same as at issuance); `"hook"` additionally needs
    /// `dns_hook`/`dns_cleanup` below, since there is no environment
    /// variable standing in for an arbitrary external command.
    pub dns_provider: Option<String>,
    /// The raw `--dns-hook`/`--dns-cleanup` command strings, recorded only
    /// when `dns_provider == Some("hook")`. `renew` must work from
    /// `config.json` alone, without re-deriving state from the original
    /// `issue` command or repeating its flags — the literal scheduled
    /// command is `certway renew --all --quiet`
    /// (`scheduler/cron.rs`, `scheduler/systemd.rs`), never anything else —
    /// so a hook-based wildcard cannot self-renew unless the commands that
    /// created its records are the same ones read back here. This is the
    /// same class of value `hooks` below already stores (an arbitrary
    /// command line, potentially carrying a credential as an argument);
    /// `hooks` already round-trips through this file the same way, so this
    /// follows existing precedent rather than inventing a new one.
    pub dns_hook: Option<String>,
    pub dns_cleanup: Option<String>,
    pub key_algorithm: String,
    pub reuse_key: bool,
    /// The ACME directory URL this certificate was issued/last renewed
    /// against — what lets `renew` run without `--server` on every call.
    pub ca_directory: String,
    pub links: Vec<LinkSpec>,
    pub hooks: HookConfig,
    pub exports: Vec<ExportSpec>,
}

/// Writes the full set of certificate files atomically, key first: a web
/// server reloading in the microsecond window between renames then reads
/// the new key with the old chain (fails cleanly, retried) rather than the
/// old key with the new chain (a mismatched pair that could be served).
///
/// `links`/`hooks`/`exports` are recorded into `config.json` in the same
/// atomic write as everything else, but **not applied here** — applying a
/// link touches paths outside `cert_root` and belongs to the caller
/// (`link::apply_all`), once this call has returned successfully. Exports
/// are likewise the caller's job (`cmd::export`/the post-renewal sequence),
/// not written by this function.
#[allow(clippy::too_many_arguments)]
pub fn write_certificate(
    cert_root: &Path,
    fullchain_pem: &str,
    key_pem: &str,
    challenge_type: &str,
    dns_provider: Option<&str>,
    dns_hook: Option<&str>,
    dns_cleanup: Option<&str>,
    key_algorithm: &str,
    reuse_key: bool,
    ca_directory: &str,
    links: &[LinkSpec],
    hooks: &HookConfig,
    exports: &[ExportSpec],
) -> Result<CertPaths, core::Error> {
    create_dir_secure(cert_root, 0o700)?;
    let paths = cert_paths(cert_root);

    atomic_write(&paths.privkey, key_pem.as_bytes(), 0o600)?;
    atomic_write(&paths.fullchain, fullchain_pem.as_bytes(), 0o644)?;

    let (leaf, chain) = core::split_leaf_and_chain(fullchain_pem);
    atomic_write(&paths.cert, leaf.as_bytes(), 0o644)?;
    atomic_write(&paths.chain, chain.as_bytes(), 0o644)?;

    write_config(
        &paths,
        &CertConfig {
            challenge: challenge_type.to_string(),
            dns_provider: dns_provider.map(str::to_string),
            dns_hook: dns_hook.map(str::to_string),
            dns_cleanup: dns_cleanup.map(str::to_string),
            key_algorithm: key_algorithm.to_string(),
            reuse_key,
            ca_directory: ca_directory.to_string(),
            links: links.to_vec(),
            hooks: hooks.clone(),
            exports: exports.to_vec(),
        },
    )?;

    Ok(paths)
}

/// Writes `config.json` alone, atomically — shared by `write_certificate`
/// (the full write) and `add_export` (the `export` command's read-modify-
/// write, which touches no certificate file).
fn write_config(paths: &CertPaths, cfg: &CertConfig) -> Result<(), core::Error> {
    // Each link/export entry's JSON object text is built into an owned
    // `String` first and kept alive in these `Vec`s for the duration of the
    // outer `write_object` call below, which only borrows `&str` slices
    // from them (`JsonVal::Raw`) — no allocation is leaked, unlike a
    // `Box::leak` shortcut would require to satisfy the same borrow with a
    // per-element mapping closure.
    let link_jsons: Vec<String> = cfg
        .links
        .iter()
        .map(|l| {
            write_object(&[
                ("name", JsonVal::Str(&l.name)),
                ("target", JsonVal::Str(&l.target)),
                ("copy", JsonVal::Bool(l.copy)),
            ])
        })
        .collect();
    let export_jsons: Vec<String> = cfg
        .exports
        .iter()
        .map(|e| {
            write_object(&[
                ("format", JsonVal::Str(&e.format)),
                ("out", JsonVal::Str(&e.out)),
            ])
        })
        .collect();
    let hooks_json = hooks_to_json(&cfg.hooks);

    let mut fields: Vec<(&str, JsonVal)> = vec![
        ("challenge", JsonVal::Str(&cfg.challenge)),
        ("key_algorithm", JsonVal::Str(&cfg.key_algorithm)),
        ("reuse_key", JsonVal::Bool(cfg.reuse_key)),
        ("ca_directory", JsonVal::Str(&cfg.ca_directory)),
        (
            "links",
            JsonVal::Array(
                link_jsons
                    .iter()
                    .map(|s| JsonVal::Raw(s.as_str()))
                    .collect(),
            ),
        ),
        ("hooks", JsonVal::Raw(&hooks_json)),
        (
            "exports",
            JsonVal::Array(
                export_jsons
                    .iter()
                    .map(|s| JsonVal::Raw(s.as_str()))
                    .collect(),
            ),
        ),
    ];
    if let Some(p) = &cfg.dns_provider {
        fields.push(("dns_provider", JsonVal::Str(p)));
    }
    if let Some(h) = &cfg.dns_hook {
        fields.push(("dns_hook", JsonVal::Str(h)));
    }
    if let Some(h) = &cfg.dns_cleanup {
        fields.push(("dns_cleanup", JsonVal::Str(h)));
    }
    let config = write_object(&fields);
    // 0600, not 0644: `dns_hook`/`dns_cleanup` can carry a credential as a
    // `--dns-hook` argument (same for `hooks.hook`/`hook_failure`/
    // `hook_url`/`reload`, already stored here), so this file is exactly as
    // sensitive as `privkey.pem` and gets the same mode.
    atomic_write(&paths.config, config.as_bytes(), 0o600)
}

/// `certway export`'s recording half: adds `spec` to the certificate's
/// recorded exports so `renew` regenerates it, without touching
/// `fullchain.pem`/`privkey.pem`/etc. Idempotent — exporting the same
/// `(format, out)` twice records it once.
pub fn add_export(cert_root: &Path, spec: ExportSpec) -> Result<(), core::Error> {
    let paths = cert_paths(cert_root);
    let mut cfg = read_config(&paths.config).ok_or_else(|| {
        core::Error::io(
            &paths.config,
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "config.json missing or unreadable",
            ),
        )
    })?;
    if !cfg.exports.contains(&spec) {
        cfg.exports.push(spec);
    }
    write_config(&paths, &cfg)
}

fn hooks_to_json(hooks: &HookConfig) -> String {
    let mut fields: Vec<(&str, JsonVal)> = vec![("hook_shell", JsonVal::Bool(hooks.hook_shell))];
    if let Some(h) = &hooks.hook {
        fields.push(("hook", JsonVal::Str(h)));
    }
    if let Some(h) = &hooks.hook_failure {
        fields.push(("hook_failure", JsonVal::Str(h)));
    }
    if let Some(h) = &hooks.hook_url {
        fields.push(("hook_url", JsonVal::Str(h)));
    }
    if let Some(h) = &hooks.reload {
        fields.push(("reload", JsonVal::Str(h)));
    }
    write_object(&fields)
}

/// Tightens `path`'s mode to `0600` if it is not already: a `config.json`
/// written before `dns_hook`/`dns_cleanup` credentials started living in
/// this file may still be `0644`, sitting there with a `--dns-hook`
/// credential in it for as long as no `renew`/`export` run happens to read
/// it. Best-effort and silent by design: a permission this process cannot
/// change (e.g. it does not own the file) must not turn an otherwise
/// successful renewal into a hard failure — the file was already exposed
/// before this call, and refusing to proceed does not un-expose it. Returns
/// whether anything actually changed, purely so a caller with a terminal
/// can note it (`renew`'s `--verbose`) — never gates the read itself.
pub fn tighten_permissions(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.permissions().mode() & 0o777 == 0o600 {
        return false;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).is_ok()
}

/// Reads `config.json` back for `renew`/`list`. An unparseable `config.json`
/// is not fatal — `None` here, for the caller to treat as "re-derive what
/// can be derived from the certificate," never an error abort.
/// `links`/`hooks`/`exports` are all tolerant of an older
/// `config.json` that predates them: missing arrays/objects become
/// empty/default rather than failing the whole read.
///
/// Tightens the file's mode to `0600` first (`tighten_permissions`) — every
/// caller gets this for free, not just the ones that remember to ask for
/// it explicitly.
pub fn read_config(path: &Path) -> Option<CertConfig> {
    tighten_permissions(path);
    let text = std::fs::read_to_string(path).ok()?;
    let json = Json::parse(text.as_bytes()).ok()?;
    let challenge = json.str("challenge").ok()?.to_string();
    let dns_provider = json.opt_str("dns_provider").map(str::to_string);
    let dns_hook = json.opt_str("dns_hook").map(str::to_string);
    let dns_cleanup = json.opt_str("dns_cleanup").map(str::to_string);
    let key_algorithm = json.str("key_algorithm").ok()?.to_string();
    let reuse_key = if json.has("reuse_key") {
        json.bool("reuse_key").unwrap_or(false)
    } else {
        false
    };
    let ca_directory = json.opt_str("ca_directory").unwrap_or_default().to_string();

    let links = json
        .opt_array("links")
        .unwrap_or_default()
        .iter()
        .filter_map(|l| {
            Some(LinkSpec {
                name: l.str("name").ok()?.to_string(),
                target: l.str("target").ok()?.to_string(),
                copy: l.bool("copy").unwrap_or(false),
            })
        })
        .collect();

    let hooks = json
        .opt_object("hooks")
        .map(|h| HookConfig {
            hook: h.opt_str("hook").map(str::to_string),
            hook_failure: h.opt_str("hook_failure").map(str::to_string),
            hook_url: h.opt_str("hook_url").map(str::to_string),
            reload: h.opt_str("reload").map(str::to_string),
            hook_shell: h.bool("hook_shell").unwrap_or(false),
        })
        .unwrap_or_default();

    let exports = json
        .opt_array("exports")
        .unwrap_or_default()
        .iter()
        .filter_map(|e| {
            Some(ExportSpec {
                format: e.str("format").ok()?.to_string(),
                out: e.str("out").ok()?.to_string(),
            })
        })
        .collect();

    Some(CertConfig {
        challenge,
        dns_provider,
        dns_hook,
        dns_cleanup,
        key_algorithm,
        reuse_key,
        ca_directory,
        links,
        hooks,
        exports,
    })
}

/// Applies every recorded link, stopping at the first failure — a link
/// refusal (a target that isn't ours and `--link-force` wasn't given) is
/// exactly the situation the caller must surface, not paper over by
/// trying the rest. Returns
/// whether any of them fell back to copying because of `link::apply`'s
/// Windows behaviour, for the one-time note.
pub fn apply_links(
    paths: &CertPaths,
    links: &[LinkSpec],
    data_root: &Path,
    force: bool,
) -> Result<bool, core::Error> {
    let mut used_platform_copy = false;
    for spec in links {
        let source = match spec.name.as_str() {
            "fullchain" => &paths.fullchain,
            "cert" => &paths.cert,
            "chain" => &paths.chain,
            "privkey" => &paths.privkey,
            other => {
                return Err(core::Error::io(
                    &paths.dir,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unknown link name {other:?}"),
                    ),
                ))
            }
        };
        let mode = if spec.name == "privkey" { 0o600 } else { 0o644 };
        let target = PathBuf::from(&spec.target);
        let used_copy = link::apply(source, &target, data_root, force, spec.copy, mode)?;
        used_platform_copy = used_platform_copy || (used_copy && !spec.copy);
    }
    Ok(used_platform_copy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certway-cert-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn cert_dir_name_passes_through_a_plain_domain() {
        assert_eq!(cert_dir_name("example.com"), "example.com");
    }

    #[test]
    fn cert_dir_name_sanitizes_a_wildcard() {
        assert_eq!(cert_dir_name("*.example.com"), "_.example.com");
    }

    // `split_leaf_and_chain` itself moved to `certway_core::export` and is
    // tested there (`core::export::tests`) — this module now only calls
    // through it via `write_certificate`, covered below.

    #[test]
    fn writes_all_five_files_with_correct_modes_and_dir_name() {
        let root = tmp_root("full");
        let cert_root = root.join(cert_dir_name("example.com"));
        let fullchain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n";

        let paths = write_certificate(
            &cert_root,
            fullchain,
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            "http-01",
            None,
            None,
            None,
            "ecdsa-p256",
            false,
            "https://acme-staging-v02.api.letsencrypt.org/directory",
            &[],
            &HookConfig::default(),
            &[],
        )
        .unwrap();

        for (path, expected_mode) in [
            (&paths.fullchain, 0o644),
            (&paths.cert, 0o644),
            (&paths.chain, 0o644),
            (&paths.privkey, 0o600),
            // config.json can carry a --dns-hook credential, so it gets
            // privkey.pem's mode, not fullchain.pem's.
            (&paths.config, 0o600),
        ] {
            assert!(path.exists(), "{path:?} must exist");
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, expected_mode, "{path:?} mode");
        }

        // Key directories are 0700. privkey.pem and config.json both live
        // directly in this directory, so listing its filenames must
        // require being the owner.
        let dir_mode = std::fs::metadata(&paths.dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let config_text = std::fs::read_to_string(&paths.config).unwrap();
        assert!(config_text.contains("http-01"));
        assert!(config_text.contains("ecdsa-p256"));
        assert!(
            !config_text.contains("not_after"),
            "config.json must never carry expiry as a source of truth"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_config_round_trips_what_write_certificate_wrote() {
        let root = tmp_root("read-config");
        let cert_root = root.join(cert_dir_name("example.com"));
        let fullchain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";
        let paths = write_certificate(
            &cert_root,
            fullchain,
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            "http-01",
            None,
            None,
            None,
            "ecdsa-p256",
            true,
            "https://acme-v02.api.letsencrypt.org/directory",
            &[],
            &HookConfig::default(),
            &[],
        )
        .unwrap();

        let config = read_config(&paths.config).unwrap();
        assert_eq!(config.challenge, "http-01");
        assert_eq!(config.dns_provider, None);
        assert_eq!(config.key_algorithm, "ecdsa-p256");
        assert!(config.reuse_key);
        assert_eq!(
            config.ca_directory,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert!(config.links.is_empty());
        assert!(config.hooks.is_empty());
        assert!(config.exports.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `dns_provider` round-trips when set, and is omitted from
    /// `config.json` entirely (not written as `null`) when the challenge
    /// was `http-01` — `write_config`'s conditional push, not a fixed
    /// field slot.
    #[test]
    fn dns_provider_round_trips_when_set_and_is_absent_from_json_when_not() {
        let root = tmp_root("dns-provider");
        let cert_root = root.join(cert_dir_name("example.com"));
        let fullchain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";
        let paths = write_certificate(
            &cert_root,
            fullchain,
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            "dns-01",
            Some("cloudflare"),
            None,
            None,
            "ecdsa-p256",
            false,
            "https://a",
            &[],
            &HookConfig::default(),
            &[],
        )
        .unwrap();

        let config_text = std::fs::read_to_string(&paths.config).unwrap();
        assert!(
            config_text.contains("\"dns_provider\":\"cloudflare\""),
            "{config_text}"
        );

        let config = read_config(&paths.config).unwrap();
        assert_eq!(config.challenge, "dns-01");
        assert_eq!(config.dns_provider.as_deref(), Some("cloudflare"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `dns_hook`/`dns_cleanup` round-trip the same way `dns_provider` does
    /// (`CertConfig::dns_hook`'s doc comment) — this is what lets a
    /// hook-based wildcard renew via `renew --all --quiet`, the literal
    /// scheduled command, with no flags of its own.
    #[test]
    fn dns_hook_and_dns_cleanup_round_trip_when_set_and_are_absent_from_json_when_not() {
        let root = tmp_root("dns-hook");
        let cert_root = root.join(cert_dir_name("example.com"));
        let fullchain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";
        let paths = write_certificate(
            &cert_root,
            fullchain,
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            "dns-01",
            Some("hook"),
            Some("/usr/local/bin/my-dns-hook create"),
            Some("/usr/local/bin/my-dns-hook cleanup"),
            "ecdsa-p256",
            false,
            "https://a",
            &[],
            &HookConfig::default(),
            &[],
        )
        .unwrap();

        let config_text = std::fs::read_to_string(&paths.config).unwrap();
        assert!(
            config_text.contains("\"dns_hook\":\"/usr/local/bin/my-dns-hook create\""),
            "{config_text}"
        );
        assert!(
            config_text.contains("\"dns_cleanup\":\"/usr/local/bin/my-dns-hook cleanup\""),
            "{config_text}"
        );

        let config = read_config(&paths.config).unwrap();
        assert_eq!(config.dns_provider.as_deref(), Some("hook"));
        assert_eq!(
            config.dns_hook.as_deref(),
            Some("/usr/local/bin/my-dns-hook create")
        );
        assert_eq!(
            config.dns_cleanup.as_deref(),
            Some("/usr/local/bin/my-dns-hook cleanup")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dns_hook_and_dns_cleanup_are_absent_from_json_for_an_http01_or_cloudflare_certificate() {
        let root = tmp_root("dns-hook-absent");
        let cert_root = root.join(cert_dir_name("example.com"));
        let fullchain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";
        let paths = write_certificate(
            &cert_root,
            fullchain,
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            "http-01",
            None,
            None,
            None,
            "ecdsa-p256",
            false,
            "https://a",
            &[],
            &HookConfig::default(),
            &[],
        )
        .unwrap();

        let config_text = std::fs::read_to_string(&paths.config).unwrap();
        assert!(!config_text.contains("dns_hook"), "{config_text}");
        assert!(!config_text.contains("dns_cleanup"), "{config_text}");

        let config = read_config(&paths.config).unwrap();
        assert!(config.dns_hook.is_none());
        assert!(config.dns_cleanup.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_config_on_missing_file_is_none_not_a_panic() {
        let root = tmp_root("read-config-missing");
        assert!(read_config(&root.join("config.json")).is_none());
    }

    #[test]
    fn read_config_on_corrupt_json_is_none_not_a_panic() {
        let root = tmp_root("read-config-corrupt");
        create_dir_secure(&root, 0o755).unwrap();
        let path = root.join("config.json");
        std::fs::write(&path, b"not json at all").unwrap();
        assert!(read_config(&path).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    // -- links/hooks/exports round-trip through config.json -----------------

    #[test]
    fn links_hooks_exports_round_trip_through_config_json() {
        let root = tmp_root("links-hooks-exports");
        let cert_root = root.join(cert_dir_name("example.com"));
        let fullchain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";

        let links = vec![
            LinkSpec {
                name: "fullchain".to_string(),
                target: "/etc/ssl/example.pem".to_string(),
                copy: false,
            },
            LinkSpec {
                name: "privkey".to_string(),
                target: "/etc/ssl/example.key".to_string(),
                copy: true,
            },
        ];
        let hooks = HookConfig {
            hook: Some("/usr/bin/notify".to_string()),
            hook_failure: Some("/usr/bin/alert".to_string()),
            hook_url: Some("https://sidecar/reload".to_string()),
            reload: Some("systemctl reload nginx".to_string()),
            hook_shell: true,
        };
        let exports = vec![ExportSpec {
            format: "combined".to_string(),
            out: "/etc/haproxy/certs/example.pem".to_string(),
        }];

        let paths = write_certificate(
            &cert_root,
            fullchain,
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            "http-01",
            None,
            None,
            None,
            "ecdsa-p256",
            false,
            "https://acme-v02.api.letsencrypt.org/directory",
            &links,
            &hooks,
            &exports,
        )
        .unwrap();

        let config = read_config(&paths.config).unwrap();
        assert_eq!(config.links, links);
        assert_eq!(config.hooks, hooks);
        assert_eq!(config.exports, exports);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_config_on_a_config_json_written_before_stage_3e_defaults_links_hooks_exports_empty() {
        let root = tmp_root("pre-3e-config");
        create_dir_secure(&root, 0o755).unwrap();
        let path = root.join("config.json");
        std::fs::write(&path, br#"{"challenge":"http-01","key_algorithm":"ecdsa-p256","reuse_key":false,"ca_directory":"https://a"}"#).unwrap();

        let config = read_config(&path).unwrap();
        assert!(config.links.is_empty());
        assert!(config.hooks.is_empty());
        assert!(config.exports.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    fn config_needs_a_terminal_command_to_run(argv: &[&str]) -> bool {
        std::process::Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .is_ok()
    }

    // -- config.json permissions ---------------------------------------------

    /// Confirms `config.json`'s mode survives a hostile umask, mirroring
    /// `store::atomic`'s own `mode_is_exactly_0600_surviving_a_hostile_umask`:
    /// `write_config`'s `atomic_write(..., 0o600)` call must produce exactly
    /// `0600` even under a genuinely hostile process umask of `0o022`, not
    /// whatever `0o600 & ~umask` happens to leave. Re-execs this binary as a
    /// child of `sh -c 'umask 022 && exec ...'` — same technique, same
    /// reason (`std` has no safe way to set the *calling* process's umask).
    #[test]
    fn config_json_is_exactly_0600_surviving_a_hostile_umask() {
        const CHILD_ENV: &str = "CERTWAY_CERT_UMASK_CHILD_ROOT";

        if let Ok(root) = std::env::var(CHILD_ENV) {
            let cert_root = PathBuf::from(&root).join(cert_dir_name("example.com"));
            write_certificate(
                &cert_root,
                "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
                "http-01",
                None,
                None,
                None,
                "ecdsa-p256",
                false,
                "https://a",
                &[],
                &HookConfig::default(),
                &[],
            )
            .unwrap();
            return;
        }

        if !config_needs_a_terminal_command_to_run(&["sh", "-c", "true"]) {
            eprintln!("SKIPPED: no sh on PATH");
            return;
        }

        let root = tmp_root("config-umask");
        std::fs::create_dir_all(&root).unwrap();
        let exe = std::env::current_exe().expect("current_exe");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "umask 022 && exec '{}' --exact store::cert::tests::config_json_is_exactly_0600_surviving_a_hostile_umask",
                exe.to_string_lossy().replace('\'', "'\\''")
            ))
            .env(CHILD_ENV, root.to_string_lossy().to_string())
            .status()
            .expect("spawn sh to run the child under umask 022");
        assert!(status.success(), "child write under umask 0o022 failed");

        let config_path = root.join(cert_dir_name("example.com")).join("config.json");
        let mode = std::fs::metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "config.json's mode must survive a 0o022 umask");

        let _ = std::fs::remove_dir_all(&root);
    }

    // -- certificate directory permissions -----------------------------------

    /// Same technique as `config_json_is_exactly_0600_surviving_a_hostile_umask`:
    /// `create_dir_secure(cert_root, 0o700)` must produce exactly `0700`
    /// under a hostile process umask of `0o022`, not `0o700 & ~0o022`. The
    /// directory holds `privkey.pem` and `config.json` directly, so a mode
    /// wider than requested is a real information leak, not a cosmetic gap.
    #[test]
    fn cert_dir_is_exactly_0700_surviving_a_hostile_umask() {
        const CHILD_ENV: &str = "CERTWAY_CERT_DIR_UMASK_CHILD_ROOT";

        if let Ok(root) = std::env::var(CHILD_ENV) {
            let cert_root = PathBuf::from(&root).join(cert_dir_name("example.com"));
            write_certificate(
                &cert_root,
                "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
                "http-01",
                None,
                None,
                None,
                "ecdsa-p256",
                false,
                "https://a",
                &[],
                &HookConfig::default(),
                &[],
            )
            .unwrap();
            return;
        }

        if !config_needs_a_terminal_command_to_run(&["sh", "-c", "true"]) {
            eprintln!("SKIPPED: no sh on PATH");
            return;
        }

        let root = tmp_root("cert-dir-umask");
        std::fs::create_dir_all(&root).unwrap();
        let exe = std::env::current_exe().expect("current_exe");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "umask 022 && exec '{}' --exact store::cert::tests::cert_dir_is_exactly_0700_surviving_a_hostile_umask",
                exe.to_string_lossy().replace('\'', "'\\''")
            ))
            .env(CHILD_ENV, root.to_string_lossy().to_string())
            .status()
            .expect("spawn sh to run the child under umask 022");
        assert!(status.success(), "child write under umask 0o022 failed");

        let cert_dir = root.join(cert_dir_name("example.com"));
        let mode = std::fs::metadata(&cert_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "cert directory's mode must survive a 0o022 umask");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `config.json` left over from before `dns_hook`/`dns_cleanup`
    /// credentials started living in this file (still `0644`) must be
    /// tightened the first time anything reads it — silently, without
    /// failing the read.
    #[test]
    fn read_config_tightens_a_pre_existing_0644_file_to_0600() {
        let root = tmp_root("config-tighten");
        create_dir_secure(&root, 0o755).unwrap();
        let path = root.join("config.json");
        std::fs::write(&path, br#"{"challenge":"http-01","key_algorithm":"ecdsa-p256","reuse_key":false,"ca_directory":"https://a"}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mode_before = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_before, 0o644, "test setup: file must start out loose");

        let config = read_config(&path);
        assert!(
            config.is_some(),
            "tightening a stale-permission file must not fail the read"
        );

        let mode_after = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode_after, 0o600,
            "read_config must tighten a pre-existing 0644 config.json to 0600"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tighten_permissions_reports_whether_it_changed_anything() {
        let root = tmp_root("tighten-report");
        create_dir_secure(&root, 0o755).unwrap();
        let path = root.join("config.json");
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(tighten_permissions(&path), "0644 -> 0600 is a real change");
        assert!(
            !tighten_permissions(&path),
            "already 0600 -- nothing to report"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // -- apply_links --------------------------------------------------------

    #[test]
    fn apply_links_links_the_named_files_to_their_recorded_targets() {
        let root = tmp_root("apply-links");
        let data_root = root.join("data");
        let cert_root = data_root.join(cert_dir_name("example.com"));
        let fullchain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";
        let paths = write_certificate(
            &cert_root,
            fullchain,
            "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
            "http-01",
            None,
            None,
            None,
            "ecdsa-p256",
            false,
            "https://a",
            &[],
            &HookConfig::default(),
            &[],
        )
        .unwrap();

        let link_target = root.join("out").join("fullchain.pem");
        let links = vec![LinkSpec {
            name: "fullchain".to_string(),
            target: link_target.to_string_lossy().to_string(),
            copy: false,
        }];
        let used_copy = apply_links(&paths, &links, &data_root, false).unwrap();
        assert!(!used_copy);
        assert_eq!(std::fs::read(&link_target).unwrap(), fullchain.as_bytes());

        let _ = std::fs::remove_dir_all(&root);
    }
}
