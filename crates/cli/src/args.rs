// SPDX-License-Identifier: MIT

//! Argument parsing for the `certway` CLI.
//!
//! Performs **no I/O**: no filesystem access, no environment probing beyond
//! what's handed in. `certway --help` must work on an unreadable
//! filesystem, and argument errors must surface before anything is
//! touched. Capability detection (which does read the environment) happens
//! separately, after parsing, in `caps.rs`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueArgs {
    pub domains: Vec<String>,
    pub staging: bool,
    /// `--out`, unset by default — the storage root resolves via
    /// `store::paths::resolve` when this is `None`. Given, it overrides
    /// that resolution outright (`store::Role::Data`'s explicit-flag
    /// step), the same one flag for both the account directory and the
    /// certificate directory.
    pub out_dir: Option<String>,
    pub email: Option<String>,
    pub no_email: bool,
    pub agree_tos: bool,
    pub http01_port: u16,
    pub json: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub no_color: bool,
    pub server: Option<String>,
    pub ca_bundle: Option<String>,
    pub dry_run: bool,
    /// `--dns <provider>`. `cloudflare` is the only built-in provider —
    /// validated at parse time, not left for the provider construction
    /// step to reject.
    pub dns: Option<String>,
    /// `--dns-hook <cmd>`, paired with `dns_cleanup` — DNS-01 via an
    /// external command instead of a built-in provider.
    pub dns_hook: Option<String>,
    pub dns_cleanup: Option<String>,
    /// `--hook-shell`: runs `dns_hook`/`dns_cleanup` through `sh -c`
    /// instead of `execvp`ing the split argv directly.
    pub hook_shell: bool,
    /// `--resolver <ip>`. Parsed here so a malformed address is an
    /// argument error, not a runtime one.
    pub resolver: Option<std::net::IpAddr>,
    /// Output placement. `link_to` is `--link-to <dir>`: link every file
    /// into that directory. `links` is `--link <name>=<path>` (repeatable):
    /// link exactly one named file (`fullchain`/`cert`/`chain`/`privkey`)
    /// to an exact path.
    pub link_to: Option<String>,
    pub links: Vec<(String, String)>,
    pub link_force: bool,
    pub copy: bool,
    /// After issuance.
    pub hook: Option<String>,
    pub hook_failure: Option<String>,
    pub hook_url: Option<String>,
    pub reload: Option<String>,
    /// Web-server editing. See `cmd::issue::maybe_edit_nginx`'s doc
    /// comment for how detection and editing interact. Opt-in: editing
    /// only happens when this is set, `none` is not, and detection
    /// (possibly forced by `force_nginx`/`force_apache`) resolves to
    /// nginx.
    pub edit_nginx: bool,
    /// `--redirect`: also write an HTTP-to-HTTPS redirect. Default off —
    /// a user may deliberately serve HTTP for a health check, an ACME
    /// path, or a legacy client, so the redirect must stay opt-in, never
    /// default behavior.
    pub redirect: bool,
    /// `--none`: edit nothing, overriding even `edit_nginx`.
    pub none: bool,
    /// `--nginx`: force detection to nginx.
    pub force_nginx: bool,
    /// `--apache`: force detection to Apache. This build never edits
    /// Apache configuration — forcing detection to Apache always falls
    /// through to advice instead of an edit.
    pub force_apache: bool,
    /// `--yes`: accepted, a no-op until the confirmation prompt it's meant
    /// to skip actually exists.
    pub yes: bool,
    /// `--relax-permissions`: downgrades an insecure account key/directory
    /// permissions finding from a hard error to a reported warning, for
    /// containers running as an arbitrary UID that can't control a
    /// mounted volume's ownership. Named to make its cost obvious —
    /// default off.
    pub relax_permissions: bool,
    pub help: bool,
}

impl Default for IssueArgs {
    fn default() -> IssueArgs {
        IssueArgs {
            domains: Vec::new(),
            staging: false,
            out_dir: None,
            email: None,
            no_email: false,
            agree_tos: false,
            http01_port: 80,
            json: false,
            quiet: false,
            verbose: false,
            no_color: false,
            server: None,
            ca_bundle: None,
            dry_run: false,
            dns: None,
            dns_hook: None,
            dns_cleanup: None,
            hook_shell: false,
            resolver: None,
            link_to: None,
            links: Vec::new(),
            link_force: false,
            copy: false,
            hook: None,
            hook_failure: None,
            hook_url: None,
            reload: None,
            edit_nginx: false,
            redirect: false,
            none: false,
            force_nginx: false,
            force_apache: false,
            yes: false,
            relax_permissions: false,
            help: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewArgs {
    /// The certificate's stored directory name, for renewing exactly one.
    /// Mutually exclusive with `all`.
    pub name: Option<String>,
    pub all: bool,
    pub force: bool,
    /// Recorded into `config.json` on a successful renewal, so it need
    /// not be repeated on the next run.
    pub reuse_key: bool,
    pub http01_port: u16,
    pub json: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub no_color: bool,
    /// Overrides the certificate's own stored `ca_directory`
    /// (`config.json`) for this run only — does not rewrite it.
    pub server: Option<String>,
    pub ca_bundle: Option<String>,
    pub out_dir: Option<String>,
    /// `--dns <provider>`/`--dns-hook <cmd>`/`--dns-cleanup <cmd>`: every
    /// challenge-selection flag `issue` accepts is also accepted here.
    /// Given here, these override the certificate's recorded
    /// challenge/provider for *this run only* — the same this-run-only
    /// rule `server` already follows (same precedence: CLI flag →
    /// `config.json` → built-in default). Absent, `renew` reads the
    /// challenge type and provider back from `config.json`, which is what
    /// lets a wildcard certificate keep renewing via dns-01 forever
    /// without repeating the flag.
    pub dns: Option<String>,
    pub dns_hook: Option<String>,
    pub dns_cleanup: Option<String>,
    /// Reports which renewal path each certificate took —
    /// ARI-with-exemption or the 30-day fallback.
    pub explain: bool,
    /// `renew --all --watch`: stay running, waking every ~12h (plus
    /// hostname jitter) to recompute and renew what's due, instead of
    /// exiting after one pass. Only valid with `--all`.
    pub watch: bool,
    /// Output placement / after-issuance flags, shared with `issue`:
    /// given here, these *replace* the certificate's recorded links/hooks
    /// for this and every future renewal; omitted, the previously
    /// recorded set re-applies unchanged — see `store::cert::CertConfig`'s
    /// doc comment.
    pub link_to: Option<String>,
    pub links: Vec<(String, String)>,
    pub link_force: bool,
    pub copy: bool,
    pub hook: Option<String>,
    pub hook_failure: Option<String>,
    pub hook_url: Option<String>,
    pub hook_shell: bool,
    pub reload: Option<String>,
    /// `--relax-permissions` — see `IssueArgs::relax_permissions`'s doc
    /// comment; identical meaning, threaded to the same account-key load.
    pub relax_permissions: bool,
    pub help: bool,
}

impl Default for RenewArgs {
    fn default() -> RenewArgs {
        RenewArgs {
            name: None,
            all: false,
            force: false,
            reuse_key: false,
            http01_port: 80,
            json: false,
            quiet: false,
            verbose: false,
            no_color: false,
            server: None,
            ca_bundle: None,
            out_dir: None,
            dns: None,
            dns_hook: None,
            dns_cleanup: None,
            explain: false,
            watch: false,
            link_to: None,
            links: Vec::new(),
            link_force: false,
            copy: false,
            hook: None,
            hook_failure: None,
            hook_url: None,
            hook_shell: false,
            reload: None,
            relax_permissions: false,
            help: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListArgs {
    pub out_dir: Option<String>,
    pub json: bool,
    pub no_color: bool,
    pub help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallArgs {
    /// Print the environment detected and the reason behind each
    /// automatic choice.
    pub explain: bool,
    pub out_dir: Option<String>,
    pub no_color: bool,
    pub help: bool,
}

/// `certway export <name> --format <f> --out <path>`. `out`'s meaning
/// depends on `format`: for `pem` it's the
/// directory `fullchain.pem`/`privkey.pem` are written into; for
/// `combined`/`der`/`pkcs12` it's the exact single output file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportArgs {
    pub name: Option<String>,
    pub format: Option<String>,
    pub out: Option<String>,
    pub json: bool,
    pub no_color: bool,
    pub help: bool,
}

/// `certway rollback [<file>]`. `file` is the config file to restore from
/// its most recent backup; `None` is the "list available backups" form.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RollbackArgs {
    pub file: Option<String>,
    pub json: bool,
    pub no_color: bool,
    pub help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// No arguments, or `--help` with no subcommand: the top-level screen.
    Help,
    /// `--version` with no subcommand.
    Version,
    Issue(IssueArgs),
    Renew(RenewArgs),
    List(ListArgs),
    Install(InstallArgs),
    Export(ExportArgs),
    Rollback(RollbackArgs),
    Check(CheckArgs),
    Doctor(DoctorArgs),
    Import(ImportArgs),
    Revoke(RevokeArgs),
    Delete(DeleteArgs),
    Account(AccountArgs),
    /// A command name recognized by the CLI but not implemented yet in
    /// this build (`status`).
    NotYetImplemented(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError {
    pub message: String,
    pub suggestion: Option<String>,
}

impl ArgError {
    /// A flag that requires a value was given without one.
    pub fn missing(flag: &str) -> Self {
        ArgError {
            message: format!("missing value for {flag}"),
            suggestion: None,
        }
    }

    /// A positional argument in a position that accepts none.
    pub fn unexpected(arg: String) -> Self {
        ArgError {
            message: format!("unexpected argument `{arg}`"),
            suggestion: None,
        }
    }

    /// An unrecognized flag — suggests the nearest known one.
    pub fn unknown(arg: String) -> Self {
        unknown_flag_error(&arg, ALL_KNOWN_FLAGS)
    }

    /// Two mutually exclusive arguments given together.
    pub fn conflicting(a: &str, b: &str) -> Self {
        ArgError {
            message: format!("{a} and {b} are mutually exclusive"),
            suggestion: None,
        }
    }
}

const KNOWN_COMMANDS: &[&str] = &[
    "issue", "renew", "list", "install", "check", "doctor", "import", "export", "revoke", "delete",
    "account", "rollback", "version", "status",
];

/// Every command with a real `parse_*`/dispatch path — the single source
/// of truth `cmd::help::render`'s screen and `main.rs`'s "not built yet"
/// message both read from, so the two can never drift out of sync again.
/// The bug this exists for: the old message hardcoded "only `issue` is
/// available" while `list`/`install`/`export`/`rollback`/`renew` all
/// worked, and the help screen listed seven commands that didn't.
pub const IMPLEMENTED_COMMANDS: &[&str] =
    &["issue", "renew", "list", "install", "export", "rollback", "check", "doctor", "import", "revoke", "delete", "account"];

/// Recognized by name (so a typo still gets a "did you mean" suggestion,
/// not a bare "unknown command") but with no `parse_*`/dispatch path yet.
pub const NOT_YET_BUILT_COMMANDS: &[&str] =
    &["status"];

const ISSUE_FLAGS: &[&str] = &[
    "--staging",
    "--out",
    "--email",
    "--no-email",
    "--agree-tos",
    "--http-01-port",
    "--json",
    "--quiet",
    "--verbose",
    "--no-color",
    "--server",
    "--ca-bundle",
    "--help",
    "--version",
    "--dry-run",
    "--dns",
    "--dns-hook",
    "--dns-cleanup",
    "--hook-shell",
    "--resolver",
    "--link-to",
    "--link",
    "--link-force",
    "--copy",
    "--hook",
    "--hook-failure",
    "--hook-url",
    "--reload",
    "--edit-nginx",
    "--redirect",
    "--none",
    "--nginx",
    "--apache",
    "--yes",
    "--relax-permissions",
];

const RENEW_FLAGS: &[&str] = &[
    "--all",
    "--force",
    "--reuse-key",
    "--http-01-port",
    "--json",
    "--quiet",
    "--verbose",
    "--no-color",
    "--server",
    "--ca-bundle",
    "--out",
    "--dns",
    "--dns-hook",
    "--dns-cleanup",
    "--explain",
    "--watch",
    "--help",
    "--version",
    "--link-to",
    "--link",
    "--link-force",
    "--copy",
    "--hook",
    "--hook-failure",
    "--hook-url",
    "--hook-shell",
    "--reload",
    "--relax-permissions",
];

const LIST_FLAGS: &[&str] = &["--out", "--json", "--no-color", "--help", "--version"];

const INSTALL_FLAGS: &[&str] = &["--explain", "--out", "--no-color", "--help", "--version"];

const EXPORT_FLAGS: &[&str] = &[
    "--format",
    "--out",
    "--json",
    "--no-color",
    "--help",
    "--version",
];
const ROLLBACK_FLAGS: &[&str] = &["--json", "--no-color", "--help", "--version"];

/// Union of every flag name across every command, for a flag seen *before*
/// the subcommand — at that point which command's flags to diff against
/// isn't known yet, and a suggestion from the wrong command's flag set is
/// still more useful than none. A plain concatenation (with duplicates,
/// harmless for a nearest-match search), not a restructured parser; extend
/// it as later stages give other commands their own flags.
const ALL_KNOWN_FLAGS: &[&str] = &[
    "--staging",
    "--out",
    "--email",
    "--no-email",
    "--agree-tos",
    "--http-01-port",
    "--json",
    "--quiet",
    "--verbose",
    "--no-color",
    "--server",
    "--ca-bundle",
    "--help",
    "--version",
    "--dry-run",
    "--all",
    "--force",
    "--reuse-key",
    "--explain",
    "--watch",
    "--dns",
    "--dns-hook",
    "--dns-cleanup",
    "--hook-shell",
    "--resolver",
    "--link-to",
    "--link",
    "--link-force",
    "--copy",
    "--hook",
    "--hook-failure",
    "--hook-url",
    "--reload",
    "--format",
    "--edit-nginx",
    "--redirect",
    "--none",
    "--nginx",
    "--apache",
    "--yes",
    "--relax-permissions",
];

/// Levenshtein edit distance, hand-written (no crate).
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut prev = row[0];
        row[0] = i;
        for j in 1..=b.len() {
            let temp = row[j];
            row[j] = if a[i - 1] == b[j - 1] {
                prev
            } else {
                1 + prev.min(row[j]).min(row[j - 1])
            };
            prev = temp;
        }
    }
    row[b.len()]
}

fn nearest_flag(unknown: &str, known: &[&'static str]) -> Option<&'static str> {
    known
        .iter()
        .copied()
        .min_by_key(|k| edit_distance(unknown, k))
        .filter(|k| edit_distance(unknown, k) <= 3)
}

fn unknown_flag_error(flag: &str, known: &[&'static str]) -> ArgError {
    let suggestion = nearest_flag(flag, known).map(|k| format!("did you mean {k}?"));
    ArgError {
        message: format!("unknown flag {flag}"),
        suggestion,
    }
}

/// Parses the full argument vector (not including `argv[0]`).
pub fn parse(args: &[String]) -> Result<Command, ArgError> {
    if args.is_empty() {
        return Ok(Command::Help);
    }

    // A bare --help / --version with no subcommand.
    if args[0] == "--help" || args[0] == "-h" {
        return Ok(Command::Help);
    }
    if args[0] == "--version" {
        return Ok(Command::Version);
    }

    let command_word = args[0].as_str();
    if command_word.starts_with('-') {
        return Err(unknown_flag_error(command_word, ALL_KNOWN_FLAGS));
    }

    if command_word == "issue" {
        return parse_issue(&args[1..]).map(Command::Issue);
    }
    if command_word == "renew" {
        return parse_renew(&args[1..]).map(Command::Renew);
    }
    if command_word == "list" {
        return parse_list(&args[1..]).map(Command::List);
    }
    if command_word == "install" {
        return parse_install(&args[1..]).map(Command::Install);
    }
    if command_word == "export" {
        return parse_export(&args[1..]).map(Command::Export);
    }
    if command_word == "rollback" {
        return parse_rollback(&args[1..]).map(Command::Rollback);
    }
    // The `version` *subcommand* — distinct from the bare `--version`
    // flag handled above, but the same `Command::Version`. Before this
    // fix, `version` fell through to `KNOWN_COMMANDS` below and reported
    // itself as not built — while `--version` worked. Same command, two
    // spellings, two different answers.
    if command_word == "version" {
        return Ok(Command::Version);
    }

    if KNOWN_COMMANDS.contains(&command_word) {
        return Ok(Command::NotYetImplemented(command_word.to_string()));
    }

    let suggestion = KNOWN_COMMANDS
        .iter()
        .copied()
        .min_by_key(|k| edit_distance(command_word, k))
        .filter(|k| edit_distance(command_word, k) <= 3)
        .map(|k| format!("did you mean `{k}`?"));
    Err(ArgError {
        message: format!("unknown command `{command_word}`"),
        suggestion,
    })
}

/// Shared by `issue` and `renew` — `renew` accepts every
/// challenge-selection flag `issue` accepts, including how those flags
/// validate — one place for the three DNS-flag rules so the
/// two commands can never drift apart on what counts as a valid
/// `--dns`/`--dns-hook`/`--dns-cleanup` combination:
///
/// 1. `--dns`'s only built-in provider is `cloudflare` —
///    `--dns <other>` names `--dns-hook` as the alternative.
/// 2. `--dns` and `--dns-hook` are mutually exclusive.
/// 3. `--dns-hook` and `--dns-cleanup` must be given together.
fn validate_dns_flags(
    dns: &Option<String>,
    dns_hook: &Option<String>,
    dns_cleanup: &Option<String>,
) -> Result<(), ArgError> {
    if let Some(provider) = dns {
        if provider != "cloudflare" {
            return Err(ArgError {
                message: format!("unknown dns provider `{provider}` — the only built-in provider is `cloudflare`"),
                suggestion: Some("use --dns-hook for any other provider".to_string()),
            });
        }
    }
    if dns.is_some() && dns_hook.is_some() {
        return Err(ArgError {
            message: "--dns and --dns-hook are mutually exclusive".to_string(),
            suggestion: None,
        });
    }
    if dns_hook.is_some() != dns_cleanup.is_some() {
        return Err(ArgError {
            message: "--dns-hook and --dns-cleanup must be given together".to_string(),
            suggestion: None,
        });
    }
    Ok(())
}

fn parse_issue(args: &[String]) -> Result<IssueArgs, ArgError> {
    let mut out = IssueArgs::default();
    let mut end_of_flags = false;
    let mut i = 0;

    // Track which of the mutually-exclusive email flags was seen last, for
    // the exclusivity check below.
    let mut saw_email = false;
    let mut saw_no_email = false;

    while i < args.len() {
        let arg = args[i].as_str();

        if end_of_flags {
            out.domains.push(arg.to_string());
            i += 1;
            continue;
        }
        if arg == "--" {
            end_of_flags = true;
            i += 1;
            continue;
        }
        if !arg.starts_with('-') {
            out.domains.push(arg.to_string());
            i += 1;
            continue;
        }

        match arg {
            "--staging" => out.staging = true,
            "--agree-tos" => out.agree_tos = true,
            "--no-email" => {
                out.no_email = true;
                saw_no_email = true;
            }
            "--json" => out.json = true,
            "--quiet" => out.quiet = true,
            "--verbose" => out.verbose = true,
            "--no-color" => out.no_color = true,
            "--dry-run" => out.dry_run = true,
            "--help" | "-h" => out.help = true,
            "--version" => {
                return Err(ArgError {
                    message: "--version does not take a domain".to_string(),
                    suggestion: None,
                })
            }
            "--out" => {
                let (value, next) = take_value(args, i, "--out")?;
                out.out_dir = Some(value);
                i = next;
                continue;
            }
            "--email" => {
                let (value, next) = take_value(args, i, "--email")?;
                out.email = Some(value);
                saw_email = true;
                i = next;
                continue;
            }
            "--http-01-port" => {
                let (value, next) = take_value(args, i, "--http-01-port")?;
                out.http01_port = value.parse::<u16>().map_err(|_| ArgError {
                    message: format!("--http-01-port expects a port number, got `{value}`"),
                    suggestion: None,
                })?;
                i = next;
                continue;
            }
            "--server" => {
                let (value, next) = take_value(args, i, "--server")?;
                out.server = Some(value);
                i = next;
                continue;
            }
            "--ca-bundle" => {
                let (value, next) = take_value(args, i, "--ca-bundle")?;
                out.ca_bundle = Some(value);
                i = next;
                continue;
            }
            "--hook-shell" => out.hook_shell = true,
            "--dns" => {
                let (value, next) = take_value(args, i, "--dns")?;
                out.dns = Some(value);
                i = next;
                continue;
            }
            "--dns-hook" => {
                let (value, next) = take_value(args, i, "--dns-hook")?;
                out.dns_hook = Some(value);
                i = next;
                continue;
            }
            "--dns-cleanup" => {
                let (value, next) = take_value(args, i, "--dns-cleanup")?;
                out.dns_cleanup = Some(value);
                i = next;
                continue;
            }
            "--resolver" => {
                let (value, next) = take_value(args, i, "--resolver")?;
                out.resolver = Some(value.parse::<std::net::IpAddr>().map_err(|_| ArgError {
                    message: format!("--resolver expects an ip address, got `{value}`"),
                    suggestion: None,
                })?);
                i = next;
                continue;
            }
            "--link-to" => {
                let (value, next) = take_value(args, i, "--link-to")?;
                out.link_to = Some(value);
                i = next;
                continue;
            }
            "--link" => {
                let (value, next) = take_value(args, i, "--link")?;
                let (name, path) = parse_link_value(&value)?;
                out.links.push((name, path));
                i = next;
                continue;
            }
            "--link-force" => out.link_force = true,
            "--copy" => out.copy = true,
            "--hook" => {
                let (value, next) = take_value(args, i, "--hook")?;
                out.hook = Some(value);
                i = next;
                continue;
            }
            "--hook-failure" => {
                let (value, next) = take_value(args, i, "--hook-failure")?;
                out.hook_failure = Some(value);
                i = next;
                continue;
            }
            "--hook-url" => {
                let (value, next) = take_value(args, i, "--hook-url")?;
                out.hook_url = Some(value);
                i = next;
                continue;
            }
            "--reload" => {
                let (value, next) = take_value(args, i, "--reload")?;
                out.reload = Some(value);
                i = next;
                continue;
            }
            "--edit-nginx" => out.edit_nginx = true,
            "--redirect" => out.redirect = true,
            "--none" => out.none = true,
            "--nginx" => out.force_nginx = true,
            "--apache" => out.force_apache = true,
            "--yes" => out.yes = true,
            "--relax-permissions" => out.relax_permissions = true,
            _ => return Err(unknown_flag_error(arg, ISSUE_FLAGS)),
        }
        i += 1;
    }

    if saw_email && saw_no_email {
        return Err(ArgError {
            message: "--email and --no-email are mutually exclusive".to_string(),
            suggestion: None,
        });
    }

    validate_dns_flags(&out.dns, &out.dns_hook, &out.dns_cleanup)?;

    if out.help {
        return Ok(out);
    }

    if out.domains.is_empty() {
        return Err(ArgError {
            message: "issue requires at least one domain".to_string(),
            suggestion: None,
        });
    }

    // A wildcard domain cannot be validated over HTTP-01 — caught here,
    // locally, before any CA contact, rather than surfacing as
    // `ChallengeUnavailable` deep in the challenge step.
    if out.dns.is_none()
        && out.dns_hook.is_none()
        && out.domains.iter().any(|d| d.starts_with("*."))
    {
        return Err(ArgError {
            message: "a wildcard domain requires --dns or --dns-hook".to_string(),
            suggestion: None,
        });
    }

    // Domain given twice: deduplicate silently.
    let mut deduped = Vec::with_capacity(out.domains.len());
    for d in out.domains.drain(..) {
        if !deduped.contains(&d) {
            deduped.push(d);
        }
    }
    out.domains = deduped;

    Ok(out)
}

fn parse_renew(args: &[String]) -> Result<RenewArgs, ArgError> {
    let mut out = RenewArgs::default();
    let mut end_of_flags = false;
    let mut i = 0;
    let mut positional: Vec<String> = Vec::new();

    while i < args.len() {
        let arg = args[i].as_str();

        if end_of_flags {
            positional.push(arg.to_string());
            i += 1;
            continue;
        }
        if arg == "--" {
            end_of_flags = true;
            i += 1;
            continue;
        }
        if !arg.starts_with('-') {
            positional.push(arg.to_string());
            i += 1;
            continue;
        }

        match arg {
            "--all" => out.all = true,
            "--force" => out.force = true,
            "--reuse-key" => out.reuse_key = true,
            "--json" => out.json = true,
            "--quiet" => out.quiet = true,
            "--verbose" => out.verbose = true,
            "--no-color" => out.no_color = true,
            "--explain" => out.explain = true,
            "--watch" => out.watch = true,
            "--help" | "-h" => out.help = true,
            "--version" => {
                return Err(ArgError {
                    message: "--version does not take a certificate name".to_string(),
                    suggestion: None,
                })
            }
            "--out" => {
                let (value, next) = take_value(args, i, "--out")?;
                out.out_dir = Some(value);
                i = next;
                continue;
            }
            "--http-01-port" => {
                let (value, next) = take_value(args, i, "--http-01-port")?;
                out.http01_port = value.parse::<u16>().map_err(|_| ArgError {
                    message: format!("--http-01-port expects a port number, got `{value}`"),
                    suggestion: None,
                })?;
                i = next;
                continue;
            }
            "--server" => {
                let (value, next) = take_value(args, i, "--server")?;
                out.server = Some(value);
                i = next;
                continue;
            }
            "--ca-bundle" => {
                let (value, next) = take_value(args, i, "--ca-bundle")?;
                out.ca_bundle = Some(value);
                i = next;
                continue;
            }
            "--dns" => {
                let (value, next) = take_value(args, i, "--dns")?;
                out.dns = Some(value);
                i = next;
                continue;
            }
            "--dns-hook" => {
                let (value, next) = take_value(args, i, "--dns-hook")?;
                out.dns_hook = Some(value);
                i = next;
                continue;
            }
            "--dns-cleanup" => {
                let (value, next) = take_value(args, i, "--dns-cleanup")?;
                out.dns_cleanup = Some(value);
                i = next;
                continue;
            }
            "--link-to" => {
                let (value, next) = take_value(args, i, "--link-to")?;
                out.link_to = Some(value);
                i = next;
                continue;
            }
            "--link" => {
                let (value, next) = take_value(args, i, "--link")?;
                let (name, path) = parse_link_value(&value)?;
                out.links.push((name, path));
                i = next;
                continue;
            }
            "--link-force" => out.link_force = true,
            "--copy" => out.copy = true,
            "--hook" => {
                let (value, next) = take_value(args, i, "--hook")?;
                out.hook = Some(value);
                i = next;
                continue;
            }
            "--hook-failure" => {
                let (value, next) = take_value(args, i, "--hook-failure")?;
                out.hook_failure = Some(value);
                i = next;
                continue;
            }
            "--hook-url" => {
                let (value, next) = take_value(args, i, "--hook-url")?;
                out.hook_url = Some(value);
                i = next;
                continue;
            }
            "--hook-shell" => out.hook_shell = true,
            "--reload" => {
                let (value, next) = take_value(args, i, "--reload")?;
                out.reload = Some(value);
                i = next;
                continue;
            }
            "--relax-permissions" => out.relax_permissions = true,
            _ => return Err(unknown_flag_error(arg, RENEW_FLAGS)),
        }
        i += 1;
    }

    validate_dns_flags(&out.dns, &out.dns_hook, &out.dns_cleanup)?;

    if out.help {
        return Ok(out);
    }

    if positional.len() > 1 {
        return Err(ArgError {
            message: "renew takes at most one certificate name".to_string(),
            suggestion: None,
        });
    }
    out.name = positional.into_iter().next();

    if out.all && out.name.is_some() {
        return Err(ArgError {
            message: "renew --all does not take a certificate name".to_string(),
            suggestion: None,
        });
    }
    if !out.all && out.name.is_none() {
        return Err(ArgError {
            message: "renew requires a certificate name or --all".to_string(),
            suggestion: None,
        });
    }
    if out.watch && !out.all {
        return Err(ArgError {
            message: "renew --watch requires --all".to_string(),
            suggestion: None,
        });
    }

    Ok(out)
}

fn parse_list(args: &[String]) -> Result<ListArgs, ArgError> {
    let mut out = ListArgs::default();
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();

        if !arg.starts_with('-') {
            return Err(ArgError {
                message: format!("list does not take arguments (got `{arg}`)"),
                suggestion: None,
            });
        }

        match arg {
            "--json" => out.json = true,
            "--no-color" => out.no_color = true,
            "--help" | "-h" => out.help = true,
            "--version" => {
                return Err(ArgError {
                    message: "--version does not take arguments".to_string(),
                    suggestion: None,
                })
            }
            "--out" => {
                let (value, next) = take_value(args, i, "--out")?;
                out.out_dir = Some(value);
                i = next;
                continue;
            }
            _ => return Err(unknown_flag_error(arg, LIST_FLAGS)),
        }
        i += 1;
    }

    Ok(out)
}

fn parse_install(args: &[String]) -> Result<InstallArgs, ArgError> {
    let mut out = InstallArgs::default();
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();

        if !arg.starts_with('-') {
            return Err(ArgError {
                message: format!("install does not take arguments (got `{arg}`)"),
                suggestion: None,
            });
        }

        match arg {
            "--explain" => out.explain = true,
            "--no-color" => out.no_color = true,
            "--help" | "-h" => out.help = true,
            "--version" => {
                return Err(ArgError {
                    message: "--version does not take arguments".to_string(),
                    suggestion: None,
                })
            }
            "--out" => {
                let (value, next) = take_value(args, i, "--out")?;
                out.out_dir = Some(value);
                i = next;
                continue;
            }
            _ => return Err(unknown_flag_error(arg, INSTALL_FLAGS)),
        }
        i += 1;
    }

    Ok(out)
}

/// `--link <name>=<path>` — `name` must be one of the four files
/// `store::cert::write_certificate` writes; anything else is caught here,
/// as an argument error, rather than surfacing later as a confusing
/// "unknown link name" I/O failure mid-issuance.
const LINK_NAMES: &[&str] = &["fullchain", "cert", "chain", "privkey"];

fn parse_link_value(value: &str) -> Result<(String, String), ArgError> {
    let (name, path) = value.split_once('=').ok_or_else(|| ArgError {
        message: format!("--link expects <name>=<path>, got `{value}`"),
        suggestion: None,
    })?;
    if !LINK_NAMES.contains(&name) {
        return Err(ArgError {
            message: format!(
                "--link name must be one of fullchain, cert, chain, privkey — got `{name}`"
            ),
            suggestion: None,
        });
    }
    if path.is_empty() {
        return Err(ArgError {
            message: format!("--link `{value}` has an empty path"),
            suggestion: None,
        });
    }
    Ok((name.to_string(), path.to_string()))
}

const EXPORT_FORMATS: &[&str] = &["pem", "combined", "pkcs12", "der"];

fn parse_export(args: &[String]) -> Result<ExportArgs, ArgError> {
    let mut out = ExportArgs::default();
    let mut i = 0;
    let mut positional: Vec<String> = Vec::new();

    while i < args.len() {
        let arg = args[i].as_str();

        if !arg.starts_with('-') {
            positional.push(arg.to_string());
            i += 1;
            continue;
        }

        match arg {
            "--json" => out.json = true,
            "--no-color" => out.no_color = true,
            "--help" | "-h" => out.help = true,
            "--version" => {
                return Err(ArgError {
                    message: "--version does not take a certificate name".to_string(),
                    suggestion: None,
                })
            }
            "--format" => {
                let (value, next) = take_value(args, i, "--format")?;
                if !EXPORT_FORMATS.contains(&value.as_str()) {
                    return Err(ArgError {
                        message: format!("unknown export format `{value}` — expected one of pem, combined, pkcs12, der"),
                        suggestion: None,
                    });
                }
                out.format = Some(value);
                i = next;
                continue;
            }
            "--out" => {
                let (value, next) = take_value(args, i, "--out")?;
                out.out = Some(value);
                i = next;
                continue;
            }
            _ => return Err(unknown_flag_error(arg, EXPORT_FLAGS)),
        }
        i += 1;
    }

    if out.help {
        return Ok(out);
    }

    if positional.len() > 1 {
        return Err(ArgError {
            message: "export takes at most one certificate name".to_string(),
            suggestion: None,
        });
    }
    out.name = positional.into_iter().next();

    if out.name.is_none() {
        return Err(ArgError {
            message: "export requires a certificate name".to_string(),
            suggestion: None,
        });
    }
    if out.format.is_none() {
        return Err(ArgError {
            message: "export requires --format".to_string(),
            suggestion: None,
        });
    }
    if out.out.is_none() {
        return Err(ArgError {
            message: "export requires --out".to_string(),
            suggestion: None,
        });
    }

    Ok(out)
}

/// `certway rollback [<file>]` — `file` is optional (the no-argument form
/// lists available backups), unlike `export`'s required name.
fn parse_rollback(args: &[String]) -> Result<RollbackArgs, ArgError> {
    let mut out = RollbackArgs::default();
    let mut i = 0;
    let mut positional: Vec<String> = Vec::new();

    while i < args.len() {
        let arg = args[i].as_str();

        if !arg.starts_with('-') {
            positional.push(arg.to_string());
            i += 1;
            continue;
        }

        match arg {
            "--json" => out.json = true,
            "--no-color" => out.no_color = true,
            "--help" | "-h" => out.help = true,
            "--version" => {
                return Err(ArgError {
                    message: "--version does not take a file".to_string(),
                    suggestion: None,
                })
            }
            _ => return Err(unknown_flag_error(arg, ROLLBACK_FLAGS)),
        }
        i += 1;
    }

    if out.help {
        return Ok(out);
    }

    if positional.len() > 1 {
        return Err(ArgError {
            message: "rollback takes at most one file".to_string(),
            suggestion: None,
        });
    }
    out.file = positional.into_iter().next();

    Ok(out)
}

fn take_value(args: &[String], at: usize, flag: &str) -> Result<(String, usize), ArgError> {
    match args.get(at + 1) {
        Some(v) => Ok((v.clone(), at + 2)),
        None => Err(ArgError {
            message: format!("{flag} requires a value"),
            suggestion: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_arguments_is_help() {
        assert_eq!(parse(&[]).unwrap(), Command::Help);
    }

    #[test]
    fn bare_help_flag_is_help() {
        assert_eq!(parse(&v(&["--help"])).unwrap(), Command::Help);
    }

    #[test]
    fn bare_version_flag_is_version() {
        assert_eq!(parse(&v(&["--version"])).unwrap(), Command::Version);
    }

    #[test]
    fn unknown_flag_is_exit_2_worthy_error_with_suggestion() {
        let err = parse(&v(&["issue", "example.com", "--stagng"])).unwrap_err();
        assert_eq!(err.message, "unknown flag --stagng");
        assert_eq!(err.suggestion.as_deref(), Some("did you mean --staging?"));
    }

    #[test]
    fn unknown_flag_is_never_silently_ignored() {
        // A typo'd --staging must not fall through to a normal issue run.
        let result = parse(&v(&["issue", "example.com", "--stagng"]));
        assert!(result.is_err());
    }

    #[test]
    fn double_dash_ends_flag_parsing_domain_starting_with_dash() {
        let cmd = parse(&v(&["issue", "--", "-weird.example.com"])).unwrap();
        match cmd {
            Command::Issue(a) => assert_eq!(a.domains, vec!["-weird.example.com".to_string()]),
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn repeated_out_flag_last_wins_no_warning() {
        let cmd = parse(&v(&[
            "issue",
            "example.com",
            "--out",
            "/tmp/a",
            "--out",
            "/tmp/b",
        ]))
        .unwrap();
        match cmd {
            Command::Issue(a) => assert_eq!(a.out_dir, Some("/tmp/b".to_string())),
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn out_dir_defaults_to_none_letting_storage_resolution_apply() {
        let cmd = parse(&v(&["issue", "example.com"])).unwrap();
        match cmd {
            Command::Issue(a) => assert_eq!(a.out_dir, None),
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn empty_domain_list_is_an_error_not_help() {
        let err = parse(&v(&["issue"])).unwrap_err();
        assert_eq!(err.message, "issue requires at least one domain");
    }

    #[test]
    fn issue_help_flag_still_returns_ok_even_with_no_domains() {
        let cmd = parse(&v(&["issue", "--help"])).unwrap();
        match cmd {
            Command::Issue(a) => assert!(a.help),
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn domain_given_twice_is_deduplicated_silently() {
        let cmd = parse(&v(&["issue", "example.com", "example.com"])).unwrap();
        match cmd {
            Command::Issue(a) => assert_eq!(a.domains, vec!["example.com".to_string()]),
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn email_and_no_email_are_mutually_exclusive() {
        let err = parse(&v(&[
            "issue",
            "example.com",
            "--email",
            "a@b.com",
            "--no-email",
        ]))
        .unwrap_err();
        assert_eq!(err.message, "--email and --no-email are mutually exclusive");
    }

    #[test]
    fn unknown_flag_before_subcommand_still_suggests_nearest() {
        // The subcommand isn't known yet at this point, so there's no
        // per-command flag set to diff against — fall back to the union of
        // every known flag rather than giving up on a suggestion.
        let err = parse(&v(&["--stagng", "issue", "example.com"])).unwrap_err();
        assert_eq!(err.message, "unknown flag --stagng");
        assert_eq!(err.suggestion.as_deref(), Some("did you mean --staging?"));
    }

    #[test]
    fn unknown_top_level_command_suggests_nearest() {
        let err = parse(&v(&["reneww", "example.com"])).unwrap_err();
        assert_eq!(err.suggestion.as_deref(), Some("did you mean `renew`?"));
    }

    #[test]
    fn known_but_unimplemented_command_is_reported_distinctly() {
        assert_eq!(
            parse(&v(&["check"])).unwrap(),
            Command::NotYetImplemented("check".to_string())
        );
    }

    #[test]
    fn install_with_no_arguments_parses() {
        assert_eq!(
            parse(&v(&["install"])).unwrap(),
            Command::Install(InstallArgs::default())
        );
    }

    #[test]
    fn install_explain_flag_parses() {
        let cmd = parse(&v(&["install", "--explain"])).unwrap();
        match cmd {
            Command::Install(a) => assert!(a.explain),
            _ => panic!("expected Install"),
        }
    }

    #[test]
    fn install_rejects_a_positional_argument() {
        let err = parse(&v(&["install", "example.com"])).unwrap_err();
        assert!(err.message.contains("does not take arguments"));
    }

    #[test]
    fn renew_with_a_name_parses() {
        let cmd = parse(&v(&["renew", "example.com"])).unwrap();
        match cmd {
            Command::Renew(a) => {
                assert_eq!(a.name.as_deref(), Some("example.com"));
                assert!(!a.all);
            }
            _ => panic!("expected Renew"),
        }
    }

    #[test]
    fn renew_all_parses() {
        let cmd = parse(&v(&["renew", "--all"])).unwrap();
        match cmd {
            Command::Renew(a) => {
                assert!(a.all);
                assert_eq!(a.name, None);
            }
            _ => panic!("expected Renew"),
        }
    }

    #[test]
    fn renew_with_neither_name_nor_all_is_an_error() {
        let err = parse(&v(&["renew"])).unwrap_err();
        assert_eq!(err.message, "renew requires a certificate name or --all");
    }

    #[test]
    fn renew_with_both_name_and_all_is_an_error() {
        let err = parse(&v(&["renew", "example.com", "--all"])).unwrap_err();
        assert_eq!(err.message, "renew --all does not take a certificate name");
    }

    #[test]
    fn renew_help_flag_returns_ok_even_with_no_name() {
        let cmd = parse(&v(&["renew", "--help"])).unwrap();
        match cmd {
            Command::Renew(a) => assert!(a.help),
            _ => panic!("expected Renew"),
        }
    }

    #[test]
    fn renew_force_and_reuse_key_flags_parse() {
        let cmd = parse(&v(&["renew", "example.com", "--force", "--reuse-key"])).unwrap();
        match cmd {
            Command::Renew(a) => {
                assert!(a.force);
                assert!(a.reuse_key);
            }
            _ => panic!("expected Renew"),
        }
    }

    #[test]
    fn renew_unknown_flag_suggests_nearest() {
        let err = parse(&v(&["renew", "example.com", "--forc"])).unwrap_err();
        assert_eq!(err.suggestion.as_deref(), Some("did you mean --force?"));
    }

    #[test]
    fn renew_watch_requires_all() {
        let err = parse(&v(&["renew", "example.com", "--watch"])).unwrap_err();
        assert_eq!(err.message, "renew --watch requires --all");
    }

    #[test]
    fn renew_dns_hook_and_dns_cleanup_parse() {
        let cmd = parse(&v(&[
            "renew",
            "example.com",
            "--dns-hook",
            "/bin/create",
            "--dns-cleanup",
            "/bin/clean",
        ]))
        .unwrap();
        match cmd {
            Command::Renew(a) => {
                assert_eq!(a.dns_hook.as_deref(), Some("/bin/create"));
                assert_eq!(a.dns_cleanup.as_deref(), Some("/bin/clean"));
            }
            _ => panic!("expected Renew"),
        }
    }

    #[test]
    fn renew_dns_cloudflare_parses() {
        let cmd = parse(&v(&["renew", "example.com", "--dns", "cloudflare"])).unwrap();
        match cmd {
            Command::Renew(a) => assert_eq!(a.dns.as_deref(), Some("cloudflare")),
            _ => panic!("expected Renew"),
        }
    }

    #[test]
    fn renew_dns_unknown_provider_names_dns_hook_as_the_alternative() {
        let err = parse(&v(&["renew", "example.com", "--dns", "route53"])).unwrap_err();
        assert!(err.message.contains("route53"));
        assert_eq!(
            err.suggestion.as_deref(),
            Some("use --dns-hook for any other provider")
        );
    }

    #[test]
    fn renew_dns_hook_without_dns_cleanup_is_an_error() {
        let err = parse(&v(&["renew", "example.com", "--dns-hook", "/bin/create"])).unwrap_err();
        assert_eq!(
            err.message,
            "--dns-hook and --dns-cleanup must be given together"
        );
    }

    #[test]
    fn renew_all_watch_parses() {
        let cmd = parse(&v(&["renew", "--all", "--watch"])).unwrap();
        match cmd {
            Command::Renew(a) => {
                assert!(a.all);
                assert!(a.watch);
            }
            _ => panic!("expected Renew"),
        }
    }

    #[test]
    fn list_with_no_arguments_parses() {
        let cmd = parse(&v(&["list"])).unwrap();
        assert_eq!(cmd, Command::List(ListArgs::default()));
    }

    #[test]
    fn list_rejects_a_positional_argument() {
        let err = parse(&v(&["list", "example.com"])).unwrap_err();
        assert!(err.message.contains("does not take arguments"));
    }

    #[test]
    fn list_json_flag_parses() {
        let cmd = parse(&v(&["list", "--json"])).unwrap();
        match cmd {
            Command::List(a) => assert!(a.json),
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn http01_port_parses_and_rejects_garbage() {
        let cmd = parse(&v(&["issue", "example.com", "--http-01-port", "8080"])).unwrap();
        match cmd {
            Command::Issue(a) => assert_eq!(a.http01_port, 8080),
            _ => panic!("expected Issue"),
        }
        let err = parse(&v(&["issue", "example.com", "--http-01-port", "notaport"])).unwrap_err();
        assert!(err.message.contains("--http-01-port"));
    }

    #[test]
    fn value_flag_missing_value_errors() {
        let err = parse(&v(&["issue", "example.com", "--out"])).unwrap_err();
        assert_eq!(err.message, "--out requires a value");
    }

    #[test]
    fn dns_cloudflare_parses() {
        let cmd = parse(&v(&["issue", "*.example.com", "--dns", "cloudflare"])).unwrap();
        match cmd {
            Command::Issue(a) => assert_eq!(a.dns.as_deref(), Some("cloudflare")),
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn dns_unknown_provider_names_dns_hook_as_the_alternative() {
        let err = parse(&v(&["issue", "example.com", "--dns", "route53"])).unwrap_err();
        assert!(err.message.contains("route53"));
        assert_eq!(
            err.suggestion.as_deref(),
            Some("use --dns-hook for any other provider")
        );
    }

    #[test]
    fn dns_and_dns_hook_are_mutually_exclusive() {
        let err = parse(&v(&[
            "issue",
            "example.com",
            "--dns",
            "cloudflare",
            "--dns-hook",
            "/bin/create",
            "--dns-cleanup",
            "/bin/clean",
        ]))
        .unwrap_err();
        assert_eq!(err.message, "--dns and --dns-hook are mutually exclusive");
    }

    #[test]
    fn dns_hook_without_dns_cleanup_is_an_error() {
        let err = parse(&v(&["issue", "example.com", "--dns-hook", "/bin/create"])).unwrap_err();
        assert_eq!(
            err.message,
            "--dns-hook and --dns-cleanup must be given together"
        );
    }

    #[test]
    fn dns_hook_and_dns_cleanup_together_parse() {
        let cmd = parse(&v(&[
            "issue",
            "*.example.com",
            "--dns-hook",
            "/bin/create",
            "--dns-cleanup",
            "/bin/clean",
            "--hook-shell",
        ]))
        .unwrap();
        match cmd {
            Command::Issue(a) => {
                assert_eq!(a.dns_hook.as_deref(), Some("/bin/create"));
                assert_eq!(a.dns_cleanup.as_deref(), Some("/bin/clean"));
                assert!(a.hook_shell);
            }
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn wildcard_without_any_dns_provider_is_an_error() {
        let err = parse(&v(&["issue", "*.example.com"])).unwrap_err();
        assert_eq!(
            err.message,
            "a wildcard domain requires --dns or --dns-hook"
        );
    }

    #[test]
    fn wildcard_with_dns_hook_is_allowed() {
        let cmd = parse(&v(&[
            "issue",
            "*.example.com",
            "--dns-hook",
            "/bin/create",
            "--dns-cleanup",
            "/bin/clean",
        ]))
        .unwrap();
        assert!(matches!(cmd, Command::Issue(_)));
    }

    #[test]
    fn resolver_parses_ip_and_rejects_garbage() {
        let cmd = parse(&v(&["issue", "example.com", "--resolver", "1.1.1.1"])).unwrap();
        match cmd {
            Command::Issue(a) => assert_eq!(a.resolver, Some("1.1.1.1".parse().unwrap())),
            _ => panic!("expected Issue"),
        }
        let err = parse(&v(&["issue", "example.com", "--resolver", "not-an-ip"])).unwrap_err();
        assert!(err.message.contains("--resolver"));
    }

    // -- web-server editing: --edit-nginx/--none/--nginx/--apache/--yes ------

    // -- command categorization: the drift guard --------------------------

    /// `KNOWN_COMMANDS` (used for "unknown command, did you mean…"
    /// suggestions) must be exactly `IMPLEMENTED_COMMANDS` +
    /// `NOT_YET_BUILT_COMMANDS` + `"version"` — three lists, one of them
    /// derived by hand, that must never silently drift apart the way the
    /// old hardcoded help screen and error message already had.
    #[test]
    fn known_commands_is_exactly_implemented_plus_not_yet_built_plus_version() {
        let mut expected: Vec<&str> = IMPLEMENTED_COMMANDS
            .iter()
            .chain(NOT_YET_BUILT_COMMANDS.iter())
            .chain(["version"].iter())
            .copied()
            .collect();
        expected.sort_unstable();
        let mut actual: Vec<&str> = KNOWN_COMMANDS.to_vec();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn implemented_and_not_yet_built_never_overlap() {
        for cmd in IMPLEMENTED_COMMANDS {
            assert!(
                !NOT_YET_BUILT_COMMANDS.contains(cmd),
                "{cmd} listed as both implemented and not yet built"
            );
        }
    }

    #[test]
    fn the_version_subcommand_and_the_dash_dash_version_flag_agree() {
        assert_eq!(parse(&v(&["version"])).unwrap(), Command::Version);
        assert_eq!(parse(&v(&["--version"])).unwrap(), Command::Version);
    }

    #[test]
    fn edit_nginx_flag_defaults_off() {
        let cmd = parse(&v(&["issue", "example.com"])).unwrap();
        match cmd {
            Command::Issue(a) => {
                assert!(!a.edit_nginx);
                assert!(!a.redirect);
                assert!(!a.none);
                assert!(!a.force_nginx);
                assert!(!a.force_apache);
                assert!(!a.yes);
            }
            _ => panic!("expected Issue"),
        }
    }

    #[test]
    fn edit_nginx_none_nginx_apache_yes_all_parse() {
        let cmd = parse(&v(&[
            "issue",
            "example.com",
            "--edit-nginx",
            "--redirect",
            "--none",
            "--nginx",
            "--apache",
            "--yes",
        ]))
        .unwrap();
        match cmd {
            Command::Issue(a) => {
                assert!(a.edit_nginx);
                assert!(a.redirect);
                assert!(a.none);
                assert!(a.force_nginx);
                assert!(a.force_apache);
                assert!(a.yes);
            }
            _ => panic!("expected Issue"),
        }
    }

    /// `--redirect` alone, without `--edit-nginx`, must still parse — the
    /// gate that makes it a no-op without `--edit-nginx` lives in
    /// `cmd::issue::maybe_edit_nginx`/`classify_redirect`, not here.
    #[test]
    fn redirect_flag_parses_without_edit_nginx() {
        let cmd = parse(&v(&["issue", "example.com", "--redirect"])).unwrap();
        match cmd {
            Command::Issue(a) => {
                assert!(a.redirect);
                assert!(!a.edit_nginx);
            }
            _ => panic!("expected Issue"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckArgs {
    pub name: Option<String>,
    pub all: bool,
    pub verbose: bool,
    pub out_dir: Option<String>,
    pub server: Option<String>,
    pub json: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorArgs {
    pub all: bool,
    pub name: Option<String>,
    pub fix: bool,
    pub out_dir: Option<String>,
    pub json: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportArgs {
    pub name: Option<String>,
    pub fullchain: Option<String>,
    pub privkey: Option<String>,
    pub combined: Option<String>,
    pub challenge: Option<String>,
    pub dns_provider: Option<String>,
    pub ca_directory: Option<String>,
    pub out_dir: Option<String>,
    pub json: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeArgs {
    pub name: Option<String>,
    pub reason: Option<String>,
    pub keep_local: bool,
    pub out_dir: Option<String>,
    pub json: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteArgs {
    pub name: Option<String>,
    pub force: bool,
    pub out_dir: Option<String>,
    pub json: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountArgs {
    pub subcommand: Option<String>,
    pub email: Option<String>,
    pub tos: bool,
    pub contact: Vec<String>,
    pub out_dir: Option<String>,
    pub server: Option<String>,
    pub key: Option<String>,
    pub json: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub help: bool,
}

pub fn parse_check(args: &[&str]) -> Result<Command, ArgError> {
    let mut a = CheckArgs {
        name: None,
        all: false,
        verbose: false,
        out_dir: None,
        server: None,
        json: false,
        quiet: false,
        no_color: false,
        help: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--help" | "-h" => a.help = true,
            "--all" => a.all = true,
            "--verbose" => a.verbose = true,
            "--out" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--out")); }
                a.out_dir = Some(args[i].to_string());
            }
            "--server" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--server")); }
                a.server = Some(args[i].to_string());
            }
            "--json" => a.json = true,
            "--quiet" => a.quiet = true,
            "--no-color" => a.no_color = true,
            arg if !arg.starts_with('-') => {
                if a.name.is_none() {
                    a.name = Some(arg.to_string());
                } else {
                    return Err(ArgError::unexpected(arg.to_string()));
                }
            }
            arg => return Err(ArgError::unknown(arg.to_string())),
        }
        i += 1;
    }
    if !a.all && a.name.is_none() {
        return Err(ArgError::missing("<name>"));
    }
    if a.all && a.name.is_some() {
        return Err(ArgError::conflicting("--all", "<name>"));
    }
    Ok(Command::Check(a))
}

pub fn parse_doctor(args: &[&str]) -> Result<Command, ArgError> {
    let mut a = DoctorArgs {
        all: false,
        name: None,
        fix: false,
        out_dir: None,
        json: false,
        quiet: false,
        no_color: false,
        help: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--help" | "-h" => a.help = true,
            "--all" => a.all = true,
            "--name" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--name")); }
                a.name = Some(args[i].to_string());
            }
            "--fix" => a.fix = true,
            "--out" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--out")); }
                a.out_dir = Some(args[i].to_string());
            }
            "--json" => a.json = true,
            "--quiet" => a.quiet = true,
            "--no-color" => a.no_color = true,
            _ => return Err(ArgError::unexpected(args[i].to_string())),
        }
        i += 1;
    }
    Ok(Command::Doctor(a))
}

pub fn parse_import(args: &[&str]) -> Result<Command, ArgError> {
    let mut a = ImportArgs {
        name: None,
        fullchain: None,
        privkey: None,
        combined: None,
        challenge: None,
        dns_provider: None,
        ca_directory: None,
        out_dir: None,
        json: false,
        quiet: false,
        no_color: false,
        help: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--help" | "-h" => a.help = true,
            "--name" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--name")); }
                a.name = Some(args[i].to_string());
            }
            "--fullchain" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--fullchain")); }
                a.fullchain = Some(args[i].to_string());
            }
            "--privkey" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--privkey")); }
                a.privkey = Some(args[i].to_string());
            }
            "--combined" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--combined")); }
                a.combined = Some(args[i].to_string());
            }
            "--challenge" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--challenge")); }
                a.challenge = Some(args[i].to_string());
            }
            "--dns-provider" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--dns-provider")); }
                a.dns_provider = Some(args[i].to_string());
            }
            "--ca-directory" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--ca-directory")); }
                a.ca_directory = Some(args[i].to_string());
            }
            "--out" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--out")); }
                a.out_dir = Some(args[i].to_string());
            }
            "--json" => a.json = true,
            "--quiet" => a.quiet = true,
            "--no-color" => a.no_color = true,
            _ => return Err(ArgError::unexpected(args[i].to_string())),
        }
        i += 1;
    }
    if a.combined.is_none() && (a.fullchain.is_none() || a.privkey.is_none()) {
        return Err(ArgError::missing("--fullchain and --privkey OR --combined"));
    }
    Ok(Command::Import(a))
}

pub fn parse_revoke(args: &[&str]) -> Result<Command, ArgError> {
    let mut a = RevokeArgs {
        name: None,
        reason: None,
        keep_local: false,
        out_dir: None,
        json: false,
        quiet: false,
        no_color: false,
        help: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--help" | "-h" => a.help = true,
            "--reason" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--reason")); }
                a.reason = Some(args[i].to_string());
            }
            "--keep-local" => a.keep_local = true,
            "--out" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--out")); }
                a.out_dir = Some(args[i].to_string());
            }
            "--json" => a.json = true,
            "--quiet" => a.quiet = true,
            "--no-color" => a.no_color = true,
            arg if !arg.starts_with('-') => {
                if a.name.is_none() {
                    a.name = Some(arg.to_string());
                } else {
                    return Err(ArgError::unexpected(arg.to_string()));
                }
            }
            _ => return Err(ArgError::unexpected(args[i].to_string())),
        }
        i += 1;
    }
    if a.name.is_none() {
        return Err(ArgError::missing("<name>"));
    }
    Ok(Command::Revoke(a))
}

pub fn parse_delete(args: &[&str]) -> Result<Command, ArgError> {
    let mut a = DeleteArgs {
        name: None,
        force: false,
        out_dir: None,
        json: false,
        quiet: false,
        no_color: false,
        help: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--help" | "-h" => a.help = true,
            "--force" => a.force = true,
            "--out" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--out")); }
                a.out_dir = Some(args[i].to_string());
            }
            "--json" => a.json = true,
            "--quiet" => a.quiet = true,
            "--no-color" => a.no_color = true,
            arg if !arg.starts_with('-') => {
                if a.name.is_none() {
                    a.name = Some(arg.to_string());
                } else {
                    return Err(ArgError::unexpected(arg.to_string()));
                }
            }
            _ => return Err(ArgError::unexpected(args[i].to_string())),
        }
        i += 1;
    }
    if a.name.is_none() {
        return Err(ArgError::missing("<name>"));
    }
    Ok(Command::Delete(a))
}

pub fn parse_account(args: &[&str]) -> Result<Command, ArgError> {
    let mut a = AccountArgs {
        subcommand: None,
        email: None,
        tos: false,
        contact: Vec::new(),
        out_dir: None,
        server: None,
        key: None,
        json: false,
        quiet: false,
        no_color: false,
        help: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--help" | "-h" => a.help = true,
            "--email" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--email")); }
                a.email = Some(args[i].to_string());
            }
            "--tos" => a.tos = true,
            "--contact" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--contact")); }
                a.contact.push(args[i].to_string());
            }
            "--out" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--out")); }
                a.out_dir = Some(args[i].to_string());
            }
            "--server" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--server")); }
                a.server = Some(args[i].to_string());
            }
            "--key" => {
                i += 1;
                if i >= args.len() { return Err(ArgError::missing("--key")); }
                a.key = Some(args[i].to_string());
            }
            "--json" => a.json = true,
            "--quiet" => a.quiet = true,
            "--no-color" => a.no_color = true,
            arg if !arg.starts_with('-') => {
                if a.subcommand.is_none() {
                    a.subcommand = Some(arg.to_string());
                } else {
                    return Err(ArgError::unexpected(arg.to_string()));
                }
            }
            _ => return Err(ArgError::unexpected(args[i].to_string())),
        }
        i += 1;
    }
    if a.subcommand.is_none() {
        return Err(ArgError::missing("<subcommand>"));
    }
    Ok(Command::Account(a))
}
