// SPDX-License-Identifier: MIT

//! The `account` command.
//!
//! Manages ACME account settings:
//! - Register new account
//! - Update contact information
//! - View account status
//! - Change private key

use crate::args::AccountArgs;
use crate::render::{Mode, Out};
use crate::store;
use certway_core::{ensure_account, AccountOutcome, Client, Session};
use std::io::Write;

const ACCOUNT_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway account <subcommand> [flags]",
    examples: &[
        "certway account register --email user@example.com",
        "certway account update --contact mailto:admin@example.com",
        "certway account status",
    ],
    groups: &[
        crate::cmd::command_help::FlagGroup {
            heading: "Subcommands",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "register",
                    about: "Register a new ACME account",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "update",
                    about: "Update account details",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "status",
                    about: "Show account status",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "deactivate",
                    about: "Deactivate account",
                },
            ],
        },
        crate::cmd::command_help::FlagGroup {
            heading: "General",
            flags: &[
                crate::cmd::command_help::FlagHelp {
                    flag: "--out <dir>",
                    about: "Override the data directory",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--server <url>",
                    about: "ACME directory URL",
                },
                crate::cmd::command_help::FlagHelp {
                    flag: "--key <path>",
                    about: "Account private key path",
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

pub fn run(args: AccountArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &ACCOUNT_HELP);
        return 0;
    }

    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    match args.subcommand.as_deref() {
        Some("register") => run_register(&args, out),
        Some("update") => run_update(&args, out),
        Some("status") => run_status(&args, out),
        Some("deactivate") => run_deactivate(&args, out),
        None => {
            let _ = out.raw_line("");
            let _ = out.raw_line("  certway: account requires a subcommand (register/update/status/deactivate)");
            2
        }
        Some(cmd) => {
            let _ = out.raw_line("");
            let _ = out.raw_line(&format!("  certway: unknown account subcommand: {cmd}"));
            2
        }
    }
}

fn run_register(args: &AccountArgs, out: &mut Out<impl Write>) -> i32 {
    let data_root =
        match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return 2;
            }
        };

    let directory_url = args.server.as_deref().unwrap_or("https://acme-v02.api.letsencrypt.org/directory");
    let ca_host = store::host_from_url(directory_url).to_string();
    let account_paths = store::account_paths(&data_root, &ca_host);

    // Load or generate account key
    let account_key = match store::load_or_generate_key(&account_paths, false) {
        Ok((k, _)) => k,
        Err(e) => {
            let _ = out.step_failed("account", &format!("cannot load/generate key: {e}"));
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
    let directory = match certway_core::fetch_directory(&http, directory_url) {
        Ok(d) => d,
        Err(e) => {
            let _ = out.step_failed("directory", &format!("cannot fetch directory: {e}"));
            return 2;
        }
    };

    // Prepare new account - contact list and TOS flag
    let contact = args.email.as_deref().map(|e| format!("mailto:{e}"));
    let agree_tos = args.tos;

    // Register using ensure_account (finds existing or creates new)
    let mut session = Session::new(&directory, &http, &account_key);
    let _ = out.step_running("register");
    match ensure_account(&mut session, contact.as_deref(), agree_tos) {
        Ok((account_url, outcome)) => {
            let what = if outcome == AccountOutcome::New {
                "account created"
            } else {
                "account already exists"
            };
            let _ = out.step_done("register", what, std::time::Duration::ZERO);
            if out.mode == Mode::Json {
                let _ = out.json_result_account(&ca_host, &account_url);
            } else {
                let _ = out.raw_line("");
                let _ = out.raw_line(&format!("Account: {account_url} ({what})"));
            }
        }
        Err(e) => {
            let _ = out.step_failed("register", &format!("account registration failed: {e}"));
            return 2;
        }
    }

    0
}

fn run_update(args: &AccountArgs, out: &mut Out<impl Write>) -> i32 {
    // The new contact list: `--contact` entries verbatim (they already
    // carry their scheme) plus `--email`'s `mailto:` shorthand. With
    // neither flag this is "nothing to change" — deliberately not "clear
    // every contact", since wiping contacts is destructive enough to
    // deserve its own explicit flag.
    let mut contacts: Vec<String> = args.contact.clone();
    if let Some(email) = &args.email {
        contacts.push(format!("mailto:{email}"));
    }
    if contacts.is_empty() {
        let _ = out.raw_line("");
        let _ = out.raw_line("  certway: account update requires --email or --contact");
        return 2;
    }

    let ctx = match ca_context(args, out) {
        Some(c) => c,
        None => return 2,
    };
    let mut session = Session::new(&ctx.directory, &ctx.http, &ctx.account_key);
    let account_url = match lookup_account(&mut session, out) {
        Some(u) => u,
        None => return 2,
    };

    let _ = out.step_running("update");
    match certway_core::update_account(&mut session, &contacts) {
        Ok(()) => {
            let _ = out.step_done("update", "contacts updated", std::time::Duration::ZERO);
            if out.mode == Mode::Json {
                let _ = out.json_result_account(&ctx.ca_host, &account_url);
            } else {
                let _ = out.raw_line("");
                let _ = out.raw_line(&format!("Contacts for {}:", ctx.ca_host));
                for c in &contacts {
                    let _ = out.raw_line(&format!("  {c}"));
                }
            }
            0
        }
        Err(e) => {
            let _ = out.step_failed("update", &format!("account update failed: {e}"));
            2
        }
    }
}

fn run_deactivate(args: &AccountArgs, out: &mut Out<impl Write>) -> i32 {
    let ctx = match ca_context(args, out) {
        Some(c) => c,
        None => return 2,
    };
    let mut session = Session::new(&ctx.directory, &ctx.http, &ctx.account_key);
    let account_url = match lookup_account(&mut session, out) {
        Some(u) => u,
        None => return 2,
    };

    let _ = out.step_running("deactivate");
    match certway_core::deactivate_account(&mut session) {
        Ok(()) => {
            let _ = out.step_done("deactivate", "account deactivated", std::time::Duration::ZERO);
            if out.mode == Mode::Json {
                let _ = out.json_result_account(&ctx.ca_host, &account_url);
            } else {
                let _ = out.raw_line("");
                let _ = out.raw_line(&format!("Account {account_url} deactivated."));
                let _ = out.raw_line("This is irreversible: this key can no longer issue or renew.");
            }
            0
        }
        Err(e) => {
            let _ = out.step_failed("deactivate", &format!("deactivation failed: {e}"));
            2
        }
    }
}

/// Everything a CA-touching subcommand needs before it can sign anything:
/// resolved account key, HTTP client, and fetched directory for the
/// configured CA. Failures are already reported through `out`.
struct CaCtx {
    ca_host: String,
    directory: certway_core::Directory,
    http: Client,
    account_key: certway_core::AccountKey,
}

fn ca_context(args: &AccountArgs, out: &mut Out<impl Write>) -> Option<CaCtx> {
    let data_root =
        match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return None;
            }
        };

    let directory_url = args
        .server
        .as_deref()
        .unwrap_or("https://acme-v02.api.letsencrypt.org/directory");
    let ca_host = store::host_from_url(directory_url).to_string();
    let account_paths = store::account_paths(&data_root, &ca_host);

    let account_key = match store::load_or_generate_key(&account_paths, false) {
        Ok((k, _)) => k,
        Err(e) => {
            let _ = out.step_failed("account", &format!("cannot load key: {e}"));
            return None;
        }
    };

    let http = match Client::new() {
        Ok(c) => c,
        Err(e) => {
            let _ = out.step_failed("http", &format!("cannot build client: {e}"));
            return None;
        }
    };

    let directory = match certway_core::fetch_directory(&http, directory_url) {
        Ok(d) => d,
        Err(e) => {
            let _ = out.step_failed("directory", &format!("cannot fetch directory: {e}"));
            return None;
        }
    };

    Some(CaCtx {
        ca_host,
        directory,
        http,
        account_key,
    })
}

/// Lookup-only `ensure_account`: establishes `kid` so the session can
/// sign account-authenticated requests, without ever creating an
/// account. Returns the account URL, or `None` once the failure has been
/// reported — `update`/`deactivate` act on an existing account, so "not
/// registered" is an error rather than an opportunity to create one.
fn lookup_account(session: &mut Session, out: &mut Out<impl Write>) -> Option<String> {
    let _ = out.step_running("account");
    match ensure_account(session, None, false) {
        Ok((url, _)) => {
            let _ = out.step_done("account", "account found", std::time::Duration::ZERO);
            Some(url)
        }
        Err(certway_core::Error::Acme(p))
            if p.kind == certway_core::ProblemKind::AccountDoesNotExist =>
        {
            let _ = out.step_failed("account", "no account registered for this key");
            let _ = out.raw_line("");
            let _ = out.raw_line("Run `certway account register` first.");
            None
        }
        Err(e) => {
            let _ = out.step_failed("account", &format!("cannot query account: {e}"));
            None
        }
    }
}

fn run_status(args: &AccountArgs, out: &mut Out<impl Write>) -> i32 {
    let data_root =
        match store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out") {
            Ok(p) => p,
            Err(e) => {
                let _ = out.step_failed("storage", &e.to_string());
                return 2;
            }
        };

    let directory_url = args.server.as_deref().unwrap_or("https://acme-v02.api.letsencrypt.org/directory");
    let ca_host = store::host_from_url(directory_url).to_string();
    let account_paths = store::account_paths(&data_root, &ca_host);

    // Load account key
    let (account_key, _) = match store::load_or_generate_key(&account_paths, false) {
        Ok((k, _)) => (k, false),
        Err(e) => {
            let _ = out.step_failed("account", &format!("cannot load key: {e}"));
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
    let directory = match certway_core::fetch_directory(&http, directory_url) {
        Ok(d) => d,
        Err(e) => {
            let _ = out.step_failed("directory", &format!("cannot fetch directory: {e}"));
            return 2;
        }
    };

    // Look the account up under this key (lookup never creates one): an
    // existing account reports its URL; a missing one is a clean
    // "not registered" result rather than a transport error.
    let mut session = Session::new(&directory, &http, &account_key);
    let _ = out.step_running("status");
    match ensure_account(&mut session, None, false) {
        Ok((account_url, _)) => {
            let _ = out.step_done("status", "account exists", std::time::Duration::ZERO);
            if out.mode == Mode::Json {
                let _ = out.json_result_account(&ca_host, &account_url);
            } else {
                let _ = out.raw_line("");
                let _ = out.raw_line(&format!("Account for {ca_host}: {account_url}"));
            }
            0
        }
        Err(certway_core::Error::Acme(p))
            if p.kind == certway_core::ProblemKind::AccountDoesNotExist =>
        {
            let _ = out.step_failed("status", "no account registered for this key");
            if out.mode != Mode::Json {
                let _ = out.raw_line("");
                let _ = out.raw_line(&format!("No ACME account registered with this key at {ca_host}."));
                let _ = out.raw_line("Run `certway account register` to create one.");
            }
            1
        }
        Err(e) => {
            let _ = out.step_failed("status", &format!("cannot query account: {e}"));
            1
        }
    }
}
