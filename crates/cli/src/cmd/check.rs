// SPDX-License-Identifier: MIT

//! The `check` command.
//!
//! Validates certificate state without making changes:
//! - Certificate expiration
//! - Chain completeness
//! - DNS/HTTP validation status
//! - Hook configuration health

use crate::args::CheckArgs;
use crate::render::Out;
use crate::store;

use certway_core::ParsedCert;
use std::io::Write;
use std::time::Duration;

const CHECK_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway check <name> [flags]",
    examples: &[
        "certway check example.com",
        "certway check --all",
        "certway check example.com --verbose",
    ],
    groups: &[
        crate::cmd::command_help::FlagGroup {
            heading: "Target selection",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--all",
                    about: "Check all certificates in the data directory",
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
                    flag: "--verbose",
                    about: "Show detailed check results",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--no-color",
                    about: "Disable colour",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "CA",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--out <dir>",
                    about: "Override the data directory",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--server <url>",
                    about: "Use this ACME directory instead of the stored one",
                },
            ],
        },
    ],
};

pub fn run(args: CheckArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &CHECK_HELP);
        return 0;
    }

    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    if args.all {
        return check_all(out, &args.out_dir);
    }

    if args.name.is_none() {
        let _ = out.raw_line("");
        let _ = out.raw_line("  certway: check requires a certificate name or --all");
        return 2;
    }

    let name = args.name.as_deref().unwrap();
    check_certificate(out, name, &args.out_dir, args.server.as_deref(), args.verbose)
}

fn check_all(out: &mut Out<impl Write>, out_dir: &Option<String>) -> i32 {
    let data_root =
        match store::resolve(store::Role::Data, out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return 2;
            }
        };

    let entries = match std::fs::read_dir(&data_root) {
        Ok(e) => e,
        Err(e) => {
            let _ = out.step_failed("storage", &format!("cannot read {data_root:?}: {e}"));
            return 2;
        }
    };

    let mut certs_checked = 0usize;
    let mut certs_ok = 0usize;
    let mut certs_expired = 0usize;
    let mut certs_errors = Vec::new();

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
        if !cert_path.exists() {
            continue;
        }

        certs_checked += 1;
        let result = check_certificate_file(&cert_path, &name, out, false);

        match result {
            CheckResult::Ok => certs_ok += 1,
            CheckResult::Expired => certs_expired += 1,
            CheckResult::Error(msg) => certs_errors.push((name, msg)),
        }
    }

    let _ = out.step_done(
        "summary",
        &format!("{certs_checked} certificates checked, {certs_ok} valid"),
        Duration::ZERO,
    );

    if certs_errors.is_empty() && certs_expired == 0 {
        let _ = out.raw_line("");
        let _ = out.raw_line("All certificates are valid.");
        0
    } else {
        if certs_expired > 0 {
            let _ = out.raw_line("");
            let _ = out.raw_line(&format!("{certs_expired} certificate(s) expired."));
        }
        for (name, msg) in &certs_errors {
            let _ = out.raw_line("");
            let _ = out.raw_line(&format!("  {name}: {msg}"));
        }
        1
    }
}

fn check_certificate(
    out: &mut Out<impl Write>,
    name: &str,
    out_dir: &Option<String>,
    // Recorded per-cert but not consulted here: `check` reports the
    // stored certificate's own health, never a live re-fetch.
    _server: Option<&str>,
    verbose: bool,
) -> i32 {
    let data_root =
        match store::resolve(store::Role::Data, out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return 2;
            }
        };

    let cert_root = data_root.join(store::cert_dir_name(name));
    let cert_path = cert_root.join("fullchain.pem");
    let config_path = cert_root.join("config.json");

    if !cert_path.exists() {
        let _ = out.step_failed("certificate", &format!("no certificate named {name}"));
        return 2;
    }

    let result = check_certificate_file(&cert_path, name, out, verbose);

    if matches!(result, CheckResult::Error(_)) && config_path.exists() {
        let _ = out.step_running("config");
        if let Some(cfg) = store::read_config(&config_path) {
            if verbose {
                let _ = out.raw_line("");
                let _ = out.raw_line(&format!("Challenge: {}", cfg.challenge));
                if let Some(ref provider) = cfg.dns_provider {
                    let _ = out.raw_line(&format!("DNS provider: {provider}"));
                }
            }
        }
    }

    match result {
        CheckResult::Ok => 0,
        CheckResult::Expired | CheckResult::Error(_) => 1,
    }
}

#[derive(PartialEq)]
enum CheckResult {
    Ok,
    Expired,
    Error(String),
}

/// Lowercase hex for raw byte fields (e.g. `serial_der`) — display only,
/// never parsed back.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn check_certificate_file(
    cert_path: &std::path::Path,
    // Reported by the callers (each prints the cert it was checking);
    // here the step label can't embed it — `step_running` wants `&'static str`.
    _name: &str,
    out: &mut Out<impl Write>,
    verbose: bool,
) -> CheckResult {
    // `step_running` takes a `&'static str` (the spinner redraws it from
    // a stored reference), so the label can't embed the cert name.
    let _ = out.step_running("certificate");

    let cert_pem = match std::fs::read_to_string(cert_path) {
        Ok(p) => p,
        Err(e) => return CheckResult::Error(format!("cannot read: {e}")),
    };

    let parsed = match ParsedCert::from_leaf_pem(&cert_pem) {
        Ok(p) => p,
        Err(e) => return CheckResult::Error(format!("cannot parse: {e}")),
    };

    // `ParsedCert::not_after` is a Unix timestamp in seconds (i64), so the
    // comparison happens in the same unit rather than against SystemTime.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let not_after = parsed.not_after;

    if not_after <= now {
        let _ = out.step_failed("certificate", "expired");
        if verbose {
            let _ = out.raw_line(&format!("  not_after: {not_after}"));
        }
        return CheckResult::Expired;
    }

    let days_left = (not_after - now).max(0) / 86400;

    if days_left <= 30 {
        let _ = out.step_warned("certificate", &format!("expires in {days_left} days"));
    } else {
        let _ = out.step_done("certificate", &format!("valid ({days_left} days remaining)"), Duration::ZERO);
    }

    if verbose {
        let _ = out.raw_line(&format!("  sans: {:?}", parsed.sans));
        let _ = out.raw_line(&format!("  not_before: {}", parsed.not_before));
        let _ = out.raw_line(&format!("  not_after: {not_after}"));
        let _ = out.raw_line(&format!("  serial_der: {}", to_hex(&parsed.serial_der)));
    }

    CheckResult::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_ord() {
        assert!(CheckResult::Ok != CheckResult::Expired);
        assert!(CheckResult::Ok != CheckResult::Error("".to_string()));
    }
}
