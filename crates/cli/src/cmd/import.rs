// SPDX-License-Identifier: MIT

//! The `import` command.
//!
//! Imports an existing certificate and key into certway's storage:
//! - Accepts PEM or combined formats
//! - Validates the certificate chain
//! - Records challenge metadata for future renewals

use crate::args::ImportArgs;
use crate::render::{Mode, Out};
use crate::store;
use certway_core::{ParsedCert};
use std::io::Write;

const IMPORT_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway import --name <name> --fullchain <path> --privkey <path> [flags]",
    examples: &[
        "certway import --name example.com --fullchain /path/fullchain.pem --privkey /path/privkey.pem",
        "certway import --name example.com --combined /path/combined.pem --out /custom/data",
    ],
    groups: &[
        crate::cmd::command_help::FlagGroup {
            heading: "Input",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--name <name>",
                    about: "Name for the certificate (must be first SAN)",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--fullchain <path>",
                    about: "Certificate chain file (leaf + intermediates)",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--privkey <path>",
                    about: "Private key file (PKCS#8 PEM)",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--combined <path>",
                    about: "Combined certificate and key in one file",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Challenge metadata (for renewal)",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--challenge <type>",
                    about: "Challenge type used (http-01 or dns-01)",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--dns-provider <provider>",
                    about: "DNS provider name (e.g., cloudflare)",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--ca-directory <url>",
                    about: "ACME directory URL for renewal",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Output",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--out <dir>",
                    about: "Override the data directory",
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
        },
    ],
};

pub fn run(args: ImportArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &IMPORT_HELP);
        return 0;
    }

    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    // Validate required arguments
    if args.name.is_none() {
        let _ = out.raw_line("");
        let _ = out.raw_line("  certway: import requires --name");
        return 2;
    }

    let name = args.name.as_deref().unwrap();

    if args.combined.is_none() && (args.fullchain.is_none() || args.privkey.is_none()) {
        let _ = out.raw_line("");
        let _ = out.raw_line("  certway: import requires --combined OR both --fullchain and --privkey");
        return 2;
    }

    let data_root =
        match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return 2;
            }
        };

    let cert_root = data_root.join(store::cert_dir_name(name));
    if let Err(e) = std::fs::create_dir_all(&cert_root) {
        let _ = out.step_failed("storage", &format!("cannot create {cert_root:?}: {e}"));
        return 2;
    }

    // Read certificate
    let cert_pem = if let Some(combined) = &args.combined {
        match std::fs::read_to_string(combined) {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("input", &format!("cannot read --combined: {e}"));
                return 2;
            }
        }
    } else {
        let fullchain = args.fullchain.as_deref().unwrap();
        match std::fs::read_to_string(fullchain) {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("input", &format!("cannot read --fullchain: {e}"));
                return 2;
            }
        }
    };

    // Validate certificate
    let parsed = match ParsedCert::from_leaf_pem(&cert_pem) {
        Ok(p) => p,
        Err(e) => {
            let _ = out.step_failed("certificate", &format!("cannot parse: {e}"));
            return 2;
        }
    };

    // Warn when the storage name isn't covered by the certificate —
    // checked against the SANs, which is what actually decides whether a
    // client accepts the cert; the subject CN is legacy metadata that may
    // not even be present on modern certs.
    let name_covered = parsed.sans.iter().any(|id| match id {
        certway_core::Identifier::Dns(d) => {
            d == name || (d.starts_with("*.") && name.ends_with(&d[1..]))
        }
        certway_core::Identifier::Ip(ip) => ip.to_string() == name,
    });
    if !name_covered {
        let _ = out.step_warned(
            "certificate",
            &format!("name '{name}' is not among the certificate's SANs: {:?}", parsed.sans),
        );
    }

    // Read key
    let key_pem = if args.combined.is_some() {
        // Extract from combined (simple split on -----BEGIN PRIVATE KEY-----)
        cert_pem
            .split("-----BEGIN PRIVATE KEY-----")
            .nth(1)
            .map(|k| format!("-----BEGIN PRIVATE KEY-----{k}"))
    } else {
        let privkey = args.privkey.as_deref().unwrap();
        std::fs::read_to_string(privkey)
            .ok()
            .filter(|k| k.contains("PRIVATE KEY"))
    };

    let key_pem = match key_pem {
        Some(k) => k,
        None => {
            let _ = out.step_failed("key", "no valid private key found");
            return 2;
        }
    };

    // Determine challenge type
    let challenge = args.challenge.as_deref().unwrap_or("http-01");
    if challenge != "http-01" && challenge != "dns-01" {
        let _ = out.step_failed("input", &format!("invalid challenge type: {challenge}"));
        return 2;
    }

    // Write certificate
    let paths = match store::write_certificate(
        &cert_root,
        &cert_pem,
        &key_pem,
        challenge,
        args.dns_provider.as_deref(),
        None,
        None,
        "imported",
        false,
        args.ca_directory.as_deref().unwrap_or(""),
        &[], // links
        &store::HookConfig::default(),
        &[],
    ) {
        Ok(p) => p,
        Err(e) => {
            let _ = out.step_failed("storage", &e.to_string());
            return 2;
        }
    };

    let _ = out.step_done("import", "certificate imported", std::time::Duration::ZERO);

    if out.mode == Mode::Json {
        let _ = out.json_result_imported(name, paths.fullchain.to_str().unwrap_or_default());
    } else {
        let _ = out.raw_line("");
        let _ = out.raw_line(&format!("Certificate '{name}' imported successfully."));
        let _ = out.raw_line(&format!("  fullchain: {}", paths.fullchain.display()));
        let _ = out.raw_line(&format!("  privkey: {}", paths.privkey.display()));
    }

    0
}
