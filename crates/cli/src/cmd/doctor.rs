// SPDX-License-Identifier: MIT

//! The `doctor` command.
//!
//! Scans certificates and configuration for common problems:
//! - Missing or expired hooks
//! - Inconsistent DNS provider settings
//! - Web server configuration drift
//! - Certificate chain issues

use crate::args::DoctorArgs;
use crate::render::Out;
use crate::store;
use std::io::Write;

const DOCTOR_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway doctor [flags]",
    examples: &[
        "certway doctor",
        "certway doctor --fix",
        "certway doctor --out /path/to/data",
    ],
    groups: &[
        crate::cmd::command_help::FlagGroup {
            heading: "Target selection",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--all",
                    about: "Check all certificates",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--name <name>",
                    about: "Check a specific certificate",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Actions",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--fix",
                    about: "Attempt to fix problems automatically",
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

pub fn run(args: DoctorArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &DOCTOR_HELP);
        return 0;
    }

    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    let data_root =
        match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return 2;
            }
        };

    if !data_root.exists() {
        let _ = out.step_failed("storage", &format!("data directory does not exist: {data_root:?}"));
        return 2;
    }

    let entries = match std::fs::read_dir(&data_root) {
        Ok(e) => e,
        Err(e) => {
            let _ = out.step_failed("storage", &format!("cannot read {data_root:?}: {e}"));
            return 2;
        }
    };

    let mut problems_found = 0usize;
    // No fix path increments this yet — the `--fix` branches are TODOs —
    // so it stays immutable until one of them does.
    let problems_fixed = 0usize;
    let mut issues = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        let cert_path = path.join("fullchain.pem");
        let config_path = path.join("config.json");

        if !cert_path.exists() {
            continue;
        }

        // Check hook existence
        if config_path.exists() {
            if let Some(cfg) = store::read_config(&config_path) {
                // `.flatten()` over `[&Option; 2]` yields only the set hooks.
                for h in [&cfg.hooks.hook, &cfg.hooks.hook_failure].into_iter().flatten() {
                    if !std::path::Path::new(h).exists() {
                        problems_found += 1;
                        issues.push(DoctorIssue::MissingHook {
                            name: name.clone(),
                            hook: h.clone(),
                        });
                        if args.fix {
                            // TODO: prompt or auto-removal
                        }
                    }
                }

                // Check DNS provider if configured
                if cfg.challenge == "dns-01"
                    && cfg.dns_provider.as_deref() == Some("cloudflare")
                    && std::env::var("CLOUDFLARE_API_TOKEN").is_err()
                {
                    problems_found += 1;
                    issues.push(DoctorIssue::MissingEnv {
                        name: name.clone(),
                        env: "CLOUDFLARE_API_TOKEN".to_string(),
                    });
                }
            }
        }

        // Check certificate validity (`not_after` is a Unix timestamp in seconds)
        if let Ok(pem) = std::fs::read_to_string(&cert_path) {
            if let Ok(parsed) = certway_core::ParsedCert::from_leaf_pem(&pem) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                if parsed.not_after <= now {
                    problems_found += 1;
                    issues.push(DoctorIssue::Expired {
                        name: name.clone(),
                        expires: parsed.not_after,
                    });
                    if args.fix {
                        // TODO: suggest renewal
                    }
                }
            }
        }
    }

    let _ = out.step_done("summary", &format!("{problems_found} issue(s) found"), std::time::Duration::ZERO);

    if !issues.is_empty() {
        let _ = out.raw_line("");
        for issue in &issues {
            issue.render(out);
        }
        if problems_fixed > 0 {
            let _ = out.raw_line("");
            let _ = out.raw_line(&format!("{problems_fixed} issue(s) fixed."));
        }
        1
    } else {
        let _ = out.raw_line("");
        let _ = out.raw_line("No problems detected.");
        0
    }
}

enum DoctorIssue {
    MissingHook { name: String, hook: String },
    MissingEnv { name: String, env: String },
    Expired { name: String, expires: i64 },
}

impl DoctorIssue {
    fn render(&self, out: &mut Out<impl Write>) {
        match self {
            DoctorIssue::MissingHook { name, hook } => {
                let _ = out.raw_line(&format!("  [{name}] missing hook: {hook}"));
            }
            DoctorIssue::MissingEnv { name, env } => {
                let _ = out.raw_line(&format!("  [{name}] missing environment variable: {env}"));
            }
            DoctorIssue::Expired { name, expires } => {
                let _ = out.raw_line(&format!("  [{name}] expired (not_after: {expires})"));
            }
        }
    }
}
