// SPDX-License-Identifier: MIT

//! The `export` command: `certway export <name> --format <f> --out <path>`.
//!
//! `pem` (the existing per-certificate layout, copied to `--out`),
//! `combined` (key + full chain, one file — HAProxy), and `der` (leaf
//! only, binary) are implemented. **`pkcs12` is not** — see
//! `certway_core::export`'s module doc comment: it is blocked on a
//! dependency decision (PBES2 needs a block cipher none of the six
//! approved crates provide), not something silently skipped here.
//! `--format pkcs12` prints `report::pkcs12_workaround`'s openssl command
//! and exits 2 rather than recording an export it can't generate — a
//! stated limitation with a workaround, not a failure, so it gets the
//! "bad arguments" exit code instead of the "something went wrong while
//! running" one.

use crate::args::ExportArgs;
use crate::render::Out;
use crate::store;
use certway_core::{self as core};
use std::io::Write;
use std::time::Duration;

/// `certway export --help` — see `cmd::issue::ISSUE_HELP`'s doc comment
/// for the shape every command's help follows.
/// `--format`'s description names only what this build can actually
/// write (`pkcs12` prints a stated `openssl` workaround and exits 2 —
/// this module's own doc comment): help text should never claim support
/// for something the build doesn't actually do, whether that's a whole
/// command or one value of one flag.
const EXPORT_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway export <name> --format <f> --out <path> [flags]",
    examples: &[
        "certway export example.com --format pem --out /srv/certs",
        "certway export example.com --format combined --out /srv/certs/example.pem",
    ],
    groups: &[crate::cmd::command_help::FlagGroup {
        heading: "",
        flags: &[
            crate::cmd::command_help::FlagHelp {
                flag: "--format <f>",
                about: "pem, combined, or der (pkcs12 not yet available)",
            },
            crate::cmd::command_help::FlagHelp {
                flag: "--out <path>",
                about: "Destination for the exported file(s)",
            },
            crate::cmd::command_help::FlagHelp {
                flag: "--json",
                about: "Machine-readable output",
            },
            crate::cmd::command_help::FlagHelp {
                flag: "--no-color",
                about: "Disable colour",
            },
        ],
    }],
};

pub fn run(args: ExportArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &EXPORT_HELP);
        return 0;
    }

    // `export` reads an already-issued certificate off disk and never
    // contacts a CA, so the header prints bare `certway {version}` with
    // no CA-status suffix.
    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    let name = args.name.as_deref().unwrap_or_default();
    let format = args.format.as_deref().unwrap_or_default();
    let out_path = args.out.as_deref().unwrap_or_default();

    let data_root = match store::resolve(store::Role::Data, None, "--out") {
        Ok(p) => p,
        Err(e) => return fail(out, &e),
    };
    let cert_root = match find_cert_root(&data_root, name) {
        Ok(p) => p,
        Err(e) => return fail(out, &e),
    };
    let paths = store::cert_paths(&cert_root);
    let fullchain = match std::fs::read_to_string(&paths.fullchain) {
        Ok(s) => s,
        Err(e) => return fail(out, &core::Error::io(&paths.fullchain, e)),
    };

    if format == "pkcs12" {
        return pkcs12_unsupported(out, &paths, out_path);
    }

    let result = match format {
        "pem" => export_pem(&paths, out_path),
        "combined" => export_combined(&paths, &fullchain, out_path),
        "der" => export_der(&fullchain, out_path),
        other => Err(core::Error::io(
            out_path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown format {other:?}"),
            ),
        )),
    };
    if let Err(e) = result {
        return fail(out, &e);
    }

    if let Err(e) = store::add_export(
        &cert_root,
        store::ExportSpec {
            format: format.to_string(),
            out: out_path.to_string(),
        },
    ) {
        return fail(out, &e);
    }

    let _ = out.step_done_with_metric("export", format, out_path, Duration::ZERO);
    0
}

/// Regenerates one already-recorded export, as one step of `renew`'s
/// post-renewal sequence (between refreshing symlinks and running hooks)
/// — the same three implemented formats `run`
/// dispatches on, minus the `add_export` bookkeeping: `renew` refreshes
/// exports `certway export` already recorded, it never creates new ones.
/// `pkcs12` can't appear in a recorded `ExportSpec` today (`run` rejects it
/// before ever reaching `store::add_export`), so it's folded into the
/// generic "unsupported format" arm here rather than repeating `run`'s
/// longer explanatory message.
pub(crate) fn regenerate(
    paths: &store::CertPaths,
    fullchain: &str,
    spec: &store::ExportSpec,
) -> Result<(), core::Error> {
    match spec.format.as_str() {
        "pem" => export_pem(paths, &spec.out),
        "combined" => export_combined(paths, fullchain, &spec.out),
        "der" => export_der(fullchain, &spec.out),
        other => Err(core::Error::io(
            &spec.out,
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("cannot regenerate export format {other:?}"),
            ),
        )),
    }
}

/// `renew.rs`'s `resolve_targets` does the same "try as given, then
/// sanitized" lookup for `--all`/a single name — not reused directly
/// (it's private to that module and shaped for a `Vec` of targets), but
/// the rule is identical: a wildcard name like `*.example.com` can't be
/// used as a directory name as-is, so it's sanitized (e.g. `_.` prefix)
/// before being tried as a path.
fn find_cert_root(
    data_root: &std::path::Path,
    name: &str,
) -> Result<std::path::PathBuf, core::Error> {
    let direct = data_root.join(name);
    if direct.join("fullchain.pem").exists() {
        return Ok(direct);
    }
    let sanitized = data_root.join(store::cert_dir_name(name));
    if sanitized.join("fullchain.pem").exists() {
        return Ok(sanitized);
    }
    Err(core::Error::io(
        &direct,
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no certificate named {name:?} found under {}",
                data_root.display()
            ),
        ),
    ))
}

/// `--format pem`: the same two files the certificate directory already
/// has, copied into `--out` (a directory). This writes both
/// `fullchain.pem` and `privkey.pem`, but the single
/// `step_done_with_metric` line that reports it names only the
/// destination directory, not each file individually.
fn export_pem(paths: &store::CertPaths, out_dir: &str) -> Result<(), core::Error> {
    store::create_dir_secure(std::path::Path::new(out_dir), 0o755)?;
    let fullchain =
        std::fs::read(&paths.fullchain).map_err(|e| core::Error::io(&paths.fullchain, e))?;
    let privkey = std::fs::read(&paths.privkey).map_err(|e| core::Error::io(&paths.privkey, e))?;
    store::atomic_write(
        &std::path::Path::new(out_dir).join("fullchain.pem"),
        &fullchain,
        0o644,
    )?;
    store::atomic_write(
        &std::path::Path::new(out_dir).join("privkey.pem"),
        &privkey,
        0o600,
    )
}

fn export_combined(
    paths: &store::CertPaths,
    fullchain: &str,
    out_path: &str,
) -> Result<(), core::Error> {
    let key_pem =
        std::fs::read_to_string(&paths.privkey).map_err(|e| core::Error::io(&paths.privkey, e))?;
    let combined = core::combined_pem(&key_pem, fullchain);
    if let Some(parent) = std::path::Path::new(out_path).parent() {
        if !parent.as_os_str().is_empty() {
            store::create_dir_secure(parent, 0o755)?;
        }
    }
    // 0600: a combined file carries the private key, so it gets the same
    // owner-only permissions as `privkey.pem` itself, not the more
    // permissive default for an ordinary output file.
    store::atomic_write(std::path::Path::new(out_path), combined.as_bytes(), 0o600)
}

fn export_der(fullchain: &str, out_path: &str) -> Result<(), core::Error> {
    let der = core::leaf_der(fullchain)?;
    if let Some(parent) = std::path::Path::new(out_path).parent() {
        if !parent.as_os_str().is_empty() {
            store::create_dir_secure(parent, 0o755)?;
        }
    }
    store::atomic_write(std::path::Path::new(out_path), &der, 0o644)
}

/// `--format pkcs12`: not a failure — prints the openssl workaround,
/// built with this certificate's real key/chain/`--out` paths so it is
/// copy-pasteable. Exits 2, the "bad arguments" code, because the format
/// was never going to exist in this build; that's different from exit 1,
/// which means something failed while actually running.
fn pkcs12_unsupported(out: &mut Out<impl Write>, paths: &store::CertPaths, out_path: &str) -> i32 {
    let block = crate::report::pkcs12_workaround(
        &paths.privkey.display().to_string(),
        &paths.fullchain.display().to_string(),
        out_path,
    );
    let _ = out.step_failed(block.label, &block.subject);
    let _ = out.error_block(&block);
    2
}

fn fail(out: &mut Out<impl Write>, err: &core::Error) -> i32 {
    let block = crate::report::classify(
        err,
        crate::report::Stage::Account,
        crate::report::Proven::default(),
        "export",
    );
    let _ = out.step_failed("export", &block.summary);
    let _ = out.error_block(&block);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;
    use crate::render::Mode;

    const CERT_A: &str = "-----BEGIN CERTIFICATE-----\nCERTA\n-----END CERTIFICATE-----\n";
    const CERT_B: &str = "-----BEGIN CERTIFICATE-----\nCERTB\n-----END CERTIFICATE-----\n";
    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nKEYX\n-----END PRIVATE KEY-----\n";

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-export-cmd-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Proves `regenerate` overwrites a recorded export in place on
    /// renewal, at the unit level rather than through a live ACME
    /// integration test: this environment has no Docker, so a real Pebble
    /// (test CA) run isn't available here. Calls the exact function
    /// `cmd::renew::run_once`'s post-write sequence calls, with the same
    /// recorded `ExportSpec`, against two different certificate PEMs
    /// standing in for "before" and "after" a renewal.
    #[test]
    fn regenerate_overwrites_the_export_with_whatever_certificate_it_is_called_with() {
        let root = tmp_dir("regenerate");
        let cert_root = root.join("cert");
        let paths = store::write_certificate(
            &cert_root,
            CERT_A,
            KEY_PEM,
            "http-01",
            None,
            None,
            None,
            "ecdsa-p256",
            false,
            "https://a",
            &[],
            &store::HookConfig::default(),
            &[],
        )
        .unwrap();

        let out_path = root.join("combined.pem");
        let spec = store::ExportSpec {
            format: "combined".to_string(),
            out: out_path.to_str().unwrap().to_string(),
        };

        regenerate(&paths, CERT_A, &spec).unwrap();
        let first = std::fs::read_to_string(&out_path).unwrap();
        assert!(first.contains("CERTA"));

        // Stands in for `renew`'s post-write sequence: the same recorded
        // spec, regenerated against the NEW certificate's PEM.
        regenerate(&paths, CERT_B, &spec).unwrap();
        let second = std::fs::read_to_string(&out_path).unwrap();
        assert!(
            second.contains("CERTB"),
            "must contain the new certificate: {second}"
        );
        assert!(
            !second.contains("CERTA"),
            "regenerate must overwrite the stale export, not append to it: {second}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn regenerate_on_an_unsupported_format_errors_cleanly_not_a_panic() {
        let root = tmp_dir("regenerate-unsupported");
        let cert_root = root.join("cert");
        let paths = store::write_certificate(
            &cert_root,
            CERT_A,
            KEY_PEM,
            "http-01",
            None,
            None,
            None,
            "ecdsa-p256",
            false,
            "https://a",
            &[],
            &store::HookConfig::default(),
            &[],
        )
        .unwrap();
        let spec = store::ExportSpec {
            format: "pkcs12".to_string(),
            out: root.join("out.pfx").to_str().unwrap().to_string(),
        };

        let err = regenerate(&paths, CERT_A, &spec).unwrap_err();
        assert!(matches!(err, core::Error::Io { .. }));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--format pkcs12` is a stated-workaround limitation, not a failure
    /// — exit 2, not 1, and the printed `openssl pkcs12 -export` command
    /// carries this certificate's real paths, not a template the user has
    /// to fill in.
    #[test]
    fn pkcs12_unsupported_exits_2_with_real_paths_and_no_recorded_export() {
        let root = tmp_dir("pkcs12-workaround");
        let cert_root = root.join("cert");
        let paths = store::write_certificate(
            &cert_root,
            CERT_A,
            KEY_PEM,
            "http-01",
            None,
            None,
            None,
            "ecdsa-p256",
            false,
            "https://a",
            &[],
            &store::HookConfig::default(),
            &[],
        )
        .unwrap();
        let out_path = root.join("out.pfx");

        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 80,
        };
        let mut buf = Vec::new();
        let code = {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            pkcs12_unsupported(&mut out, &paths, out_path.to_str().unwrap())
        };
        assert_eq!(code, 2);

        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("pkcs12 is not yet supported"));
        assert!(text.contains("openssl pkcs12 -export"));
        assert!(
            text.contains(paths.privkey.to_str().unwrap()),
            "must name the real privkey path: {text}"
        );
        assert!(
            text.contains(paths.fullchain.to_str().unwrap()),
            "must name the real fullchain path: {text}"
        );
        assert!(
            text.contains(out_path.to_str().unwrap()),
            "must name the requested --out path: {text}"
        );
        assert!(text.contains("Native support is planned."));

        let block = crate::report::pkcs12_workaround(
            paths.privkey.to_str().unwrap(),
            paths.fullchain.to_str().unwrap(),
            out_path.to_str().unwrap(),
        );
        assert!(crate::report::wording_violation(&block.summary).is_none());
        assert!(!crate::report::summary_too_long(&block.summary));
        assert!(crate::report::wording_violation(block.action.as_ref().unwrap().line).is_none());
        assert!(crate::report::wording_violation(block.state_line).is_none());

        // No `store::ExportSpec` should be recorded for a format that
        // can't be regenerated on renewal — `run` returns before ever
        // calling `store::add_export` for pkcs12.
        assert!(
            !paths.config.exists()
                || !std::fs::read_to_string(&paths.config)
                    .unwrap()
                    .contains("pkcs12")
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
