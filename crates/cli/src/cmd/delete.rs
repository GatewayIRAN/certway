// SPDX-License-Identifier: MIT

//! The `delete` command.
//!
//! Removes a certificate from local storage:
//! - Deletes all files for the certificate
//! - Does NOT revoke at CA (use `revoke` for that)
//! - Useful for cleanup after renewal or migration

use crate::args::DeleteArgs;
use crate::render::{Mode, Out};
use crate::store;
use std::io::Write;

const DELETE_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway delete <name> [flags]",
    examples: &[
        "certway delete example.com",
        "certway delete example.com --force",
    ],
    groups: &[
        crate::cmd::command_help::FlagGroup {
            heading: "Target",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "<name>",
                    about: "Certificate name to delete",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "Options",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--force",
                    about: "Delete without confirmation",
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

pub fn run(args: DeleteArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &DELETE_HELP);
        return 0;
    }

    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    if args.name.is_none() {
        let _ = out.raw_line("");
        let _ = out.raw_line("  certway: delete requires a certificate name");
        return 2;
    }

    let name = args.name.as_deref().unwrap();
    let data_root =
        match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return 2;
            }
        };

    let cert_root = data_root.join(store::cert_dir_name(name));

    if !cert_root.exists() {
        let _ = out.step_failed("certificate", &format!("no certificate named {name} found"));
        return 2;
    }

    // Confirm unless --force
    if !args.force {
        let _ = out.step_running("confirm");
        // Simple confirmation prompt
        // In a real implementation, use stdin reading
        let _ = out.step_warned("confirm", &format!("use --force to delete {name} without prompt"));
        return 2;
    }

    // Delete certificate directory
    let _ = out.step_running("delete");
    match std::fs::remove_dir_all(&cert_root) {
        Ok(()) => {
            let _ = out.step_done("delete", "certificate deleted", std::time::Duration::ZERO);
        }
        Err(e) => {
            let _ = out.step_failed("delete", &format!("cannot delete: {e}"));
            return 2;
        }
    }

    if out.mode == Mode::Json {
        let _ = out.json_result_deleted(name);
    } else {
        let _ = out.raw_line("");
        let _ = out.raw_line(&format!("Certificate '{name}' deleted successfully."));
    }

    0
}
