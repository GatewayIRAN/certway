// SPDX-License-Identifier: MIT

//! The `revoke` command.
//!
//! Revokes a certificate from the CA:
//! - Requires account access
//! - Supports revocation reasons
//! - Optionally deletes the certificate locally

use crate::args::RevokeArgs;
use crate::render::{Mode, Out};
use crate::store;
use certway_core::{ensure_account, Client, Session};
use std::io::Write;

const REVOKE_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway revoke <name> [flags]",
    examples: &[
        "certway revoke example.com",
        "certway revoke example.com --reason key-compromise",
        "certway revoke example.com --keep-local",
    ],
    groups: &[
        crate::cmd::command_help::FlagGroup {
            heading: "Target",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "<name>",
                    about: "Certificate name to revoke",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Revocation reason",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--reason <reason>",
                    about: "Reason for revocation: unspecified, key-compromise, ca-compromised, affiliation-changed, superseded, cessation-of-operation",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Local cleanup",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--keep-local",
                    about: "Only revoke at CA, don't delete local files",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--out <dir>",
                    about: "Override the data directory",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Output",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--json",
                    about: "Machine-readable output",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--no-color",
                    about: "Disable colour",
                },
            ],
        },
    ],
};

/// `--reason` → RFC 5280 §5.3.1 CRLReason code. `Ok(None)` means omit the
/// field entirely (the CA then records `unspecified`); `Err` is an
/// unrecognized reason, rejected *before* any network traffic so a typo
/// can't silently downgrade to `unspecified`.
fn reason_code(reason: &str) -> Result<Option<u8>, String> {
    match reason {
        "" | "unspecified" => Ok(None),
        "key-compromise" => Ok(Some(1)),
        "ca-compromised" => Ok(Some(2)),
        "affiliation-changed" => Ok(Some(3)),
        "superseded" => Ok(Some(4)),
        "cessation-of-operation" => Ok(Some(5)),
        "privilege-withdrawn" => Ok(Some(6)),
        "certificate-hold" => Ok(Some(7)),
        other => Err(format!(
            "unknown revocation reason '{other}' (expected: unspecified, key-compromise, \
             ca-compromised, affiliation-changed, superseded, cessation-of-operation)"
        )),
    }
}

pub fn run(args: RevokeArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &REVOKE_HELP);
        return 0;
    }

    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    let name = match args.name.as_deref() {
        Some(n) => n,
        None => {
            let _ = out.raw_line("");
            let _ = out.raw_line("  certway: revoke requires a certificate name");
            return 2;
        }
    };

    // Validate the reason before touching the filesystem or network.
    let reason = match args.reason.as_deref().map(reason_code).unwrap_or(Ok(None)) {
        Ok(r) => r,
        Err(msg) => {
            let _ = out.step_failed("input", &msg);
            return 2;
        }
    };

    let data_root =
        match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return 2;
            }
        };

    let cert_root = data_root.join(store::cert_dir_name(name));
    let config_path = cert_root.join("config.json");

    if !config_path.exists() {
        let _ = out.step_failed("certificate", &format!("no certificate named {name} found"));
        return 2;
    }

    // `read_config` returns `Option`, not `Result`: a malformed config
    // reports the same way a missing one does.
    let config = match store::read_config(&config_path) {
        Some(c) => c,
        None => {
            let _ = out.step_failed("config", "cannot read config.json");
            return 2;
        }
    };

    // The certificate's own CA — recorded in config.json at issue time,
    // so revocation never needs `--server` to find the directory.
    let directory_url = config.ca_directory.clone();
    if directory_url.is_empty() {
        let _ = out.step_failed("config", "config.json has no ca_directory recorded");
        return 2;
    }
    let ca_host = store::host_from_url(&directory_url).to_string();
    let account_paths = store::account_paths(&data_root, &ca_host);

    // Refuse to mint a fresh key here: generating one would produce an
    // account that has never registered, and the CA would reject the
    // revocation anyway — but only after the pointless write. A missing
    // key is a clear "not this CA / not registered" signal.
    if !account_paths.key.exists() {
        let _ = out.step_failed(
            "account",
            &format!("no account key for {ca_host}; run `certway account register` first"),
        );
        return 2;
    }

    let account_key = match store::load_or_generate_key(&account_paths, false) {
        Ok((k, _)) => k,
        Err(e) => {
            let _ = out.step_failed("account", &format!("cannot load account key: {e}"));
            return 2;
        }
    };

    // Build HTTP client
    let http = match Client::new() {
        Ok(c) => c,
        Err(e) => {
            let _ = out.step_failed("http", &format!("cannot build client: {e}"));
            return 2;
        }
    };

    // Fetch directory
    let directory = match certway_core::fetch_directory(&http, &directory_url) {
        Ok(d) => d,
        Err(e) => {
            let _ = out.step_failed("directory", &format!("cannot fetch directory: {e}"));
            return 2;
        }
    };

    // Load the certificate — leaf only: the payload is the certificate
    // being revoked, not the chain around it.
    let cert_path = cert_root.join("fullchain.pem");
    let cert_pem = match std::fs::read_to_string(&cert_path) {
        Ok(p) => p,
        Err(e) => {
            let _ = out.step_failed("certificate", &format!("cannot read: {e}"));
            return 2;
        }
    };
    let leaf = match certway_core::leaf_der(&cert_pem) {
        Ok(d) => d,
        Err(e) => {
            let _ = out.step_failed("certificate", &format!("cannot extract certificate: {e}"));
            return 2;
        }
    };

    // Establish `kid` (lookup only — never registers): the revokeCert
    // request must be signed as the account, not with a bare JWK.
    let mut session = Session::new(&directory, &http, &account_key);
    let _ = out.step_running("account");
    if let Err(e) = ensure_account(&mut session, None, false) {
        let _ = out.step_failed("account", &format!("cannot use account: {e}"));
        return 2;
    }

    // Revoke at the CA (RFC 8555 §7.6).
    let _ = out.step_running("revoke");
    match certway_core::revoke_certificate(&mut session, &leaf, reason) {
        Ok(()) => {
            let _ =
                out.step_done("revoke", "certificate revoked at CA", std::time::Duration::ZERO);
        }
        Err(e) => {
            let _ = out.step_failed("revoke", &format!("revocation failed: {e}"));
            return 1;
        }
    }

    // Delete local certificate unless --keep-local
    if !args.keep_local {
        if let Err(e) = std::fs::remove_dir_all(&cert_root) {
            let _ = out.step_warned("cleanup", &format!("cannot delete local cert: {e}"));
        } else {
            let _ = out.step_done("cleanup", "local certificate deleted", std::time::Duration::ZERO);
        }
    }

    if out.mode == Mode::Json {
        let _ = out.json_result_revoked(name);
    } else {
        let _ = out.raw_line("");
        let _ = out.raw_line(&format!("Certificate '{name}' revoked successfully."));
    }

    0
}
