// SPDX-License-Identifier: MIT

//! Error classification: turning a raw `core::Error` into the four-part
//! error block the CLI prints.
//!
//! `classify` is a pure function: no terminal, no I/O, no network. It takes
//! a `core::Error` plus what earlier stages proved and returns a struct the
//! renderer turns into bytes. This is what makes the error surface testable
//! without a CA.

use certway_core::{self as core, ProblemKind};

/// Which step of the `issue` sequence was running when the error occurred.
/// Only the steps this build implements — `preflight` and `rehearsal` are
/// not wired into `cmd::issue` yet, which is why `Proven` below can
/// currently only ever be "nothing proven".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Account,
    Order,
    Challenge,
    Validate,
    Certificate,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::Account => "account",
            Stage::Order => "order",
            Stage::Challenge => "challenge",
            Stage::Validate => "validate",
            Stage::Certificate => "certificate",
        }
    }
}

/// What earlier stages established. `preflight` and `rehearsal` are not
/// implemented in this build, so both fields are always `false` here — but
/// the struct and `classify`'s branches on it are written and tested as if
/// they could be true, so wiring up those stages later needs no changes
/// here, even though only the `Neither` branch is reachable from
/// `cmd::issue` today.
#[derive(Debug, Clone, Copy, Default)]
pub struct Proven {
    pub preflight_passed: bool,
    pub rehearsal_passed: bool,
}

#[derive(Debug, Clone)]
pub struct Action {
    pub line: &'static str,
    pub command: String,
}

#[derive(Debug, Clone)]
pub struct ErrorBlock {
    pub label: &'static str,
    pub subject: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub narrowing: &'static str,
    pub causes: Vec<&'static str>,
    pub action: Option<Action>,
    pub state_line: &'static str,
}

/// Emits the narrowing line's causes only when there are 2+ of them — a
/// single bullet would just restate the summary the user already read one
/// line up, so it is suppressed rather than printed as a redundant list of
/// one.
fn narrowing_causes(causes: Vec<&'static str>) -> Vec<&'static str> {
    if causes.len() >= 2 {
        causes
    } else {
        vec![]
    }
}

fn narrowing_line(proven: Proven) -> &'static str {
    if proven.rehearsal_passed {
        "The staging run succeeded moments ago, so this is most likely:"
    } else if proven.preflight_passed {
        "Your DNS is correct, so this is most likely:"
    } else {
        "Most likely one of:"
    }
}

/// The state line is always present and, in this stage, always the same:
/// nothing implemented here creates DNS records, and every reachable
/// failure stops during issuance — the other state lines that exist for
/// preflight, rehearsal, and dns-01 outcomes don't apply, since none of
/// those stages exist yet.
const STATE_LINE_ISSUANCE: &str = "No certificate was issued. Nothing was changed.";

/// The "stopped before an order was attempted" state line — distinct from
/// `STATE_LINE_ISSUANCE`, which already implies an order was attempted.
const STATE_LINE_PREFLIGHT: &str = "Stopped before contacting Let's Encrypt. No rate limit used.";

/// A wildcard identifier can only ever be validated via dns-01 — the CA
/// offers no http-01 challenge for one. Built directly rather than through
/// `classify`: this never reaches a `core::Error` at all, since it is
/// caught before any request would have produced one — for `renew`
/// specifically, this is what turns "every automatic attempt on a wildcard
/// fails until the certificate expires" (the CA would otherwise report a
/// confusing `ChallengeUnavailable` on every retry, since dns-01 is never
/// offered) into one local, actionable line instead.
///
/// `identifier` is the wildcard name itself (the block's subject, e.g.
/// `*.example.com`); `example_command` is the caller-built fix — `renew`
/// names the certificate by its stored directory name, not the wildcard
/// identifier, since that is what `renew <name>` actually takes.
pub fn wildcard_needs_dns01(identifier: &str, example_command: String) -> ErrorBlock {
    ErrorBlock {
        label: "preflight",
        subject: identifier.to_string(),
        summary: "A wildcard certificate can only be validated over DNS.".to_string(),
        evidence: vec!["Let's Encrypt offers no HTTP challenge for a wildcard name.".to_string()],
        narrowing: "Most likely one of:",
        causes: vec![],
        action: Some(Action {
            line: "Pass a DNS provider:",
            command: example_command,
        }),
        state_line: STATE_LINE_PREFLIGHT,
    }
}

/// A limitation with a stated workaround is not a failure — this never
/// reaches `classify`, exactly like `wildcard_needs_dns01`. `--format
/// pkcs12` has no native encoder (no crate provides PBES2's block cipher
/// under this build's approved dependency set; see `certway_core::export`'s
/// module doc), so the fix is the
/// `openssl pkcs12 -export` command that already does today what
/// certway itself does not yet — built with this certificate's real
/// paths, not a template the user fills in.
const STATE_LINE_PKCS12_PLANNED: &str = "Native support is planned.";

pub fn pkcs12_workaround(privkey_path: &str, fullchain_path: &str, out_path: &str) -> ErrorBlock {
    let command = format!(
        "openssl pkcs12 -export \\\n      -inkey  {privkey_path} \\\n      -in     {fullchain_path} \\\n      -out    {out_path}"
    );
    ErrorBlock {
        label: "export",
        subject: "pkcs12 is not yet supported".to_string(),
        summary: "certway does not build PKCS#12 files yet.".to_string(),
        evidence: vec![],
        narrowing: "Most likely one of:",
        causes: vec![],
        action: Some(Action {
            line: "Convert the PEM files with openssl:",
            command,
        }),
        state_line: STATE_LINE_PKCS12_PLANNED,
    }
}

/// `cmd::rollback`, not `classify`: `Stage`'s variants and its state lines
/// are all issuance-specific ("No certificate was issued..."), and rollback
/// is not an issuance stage, so none of them fit — same reasoning as
/// `pkcs12_workaround` above, built by hand instead.
pub fn rollback_no_backup_found(file: &str) -> ErrorBlock {
    ErrorBlock {
        label: "rollback",
        subject: file.to_string(),
        summary: "No backup was found for this file.".to_string(),
        evidence: vec![],
        narrowing: "Most likely one of:",
        causes: vec![],
        action: None,
        state_line: "The file was not touched.",
    }
}

/// The restore itself wrote successfully but the restored bytes still fail
/// validation — `transaction.rs`'s own `RestoreFailed` treats this as
/// maximum severity, requiring the user to intervene by hand, so this is
/// the one rollback outcome with a concrete recovery command rather than
/// just a state line.
pub fn rollback_restore_failed(file: &str, backup_path: &str, stderr: &str) -> ErrorBlock {
    ErrorBlock {
        label: "rollback",
        subject: file.to_string(),
        summary: "The restored file still fails validation.".to_string(),
        evidence: vec![stderr.to_string()],
        narrowing: "Most likely one of:",
        causes: vec![],
        action: Some(Action {
            line: "Restore this backup by hand:",
            command: format!("cp {backup_path} {file}"),
        }),
        state_line: "The file may be left in a broken state. Restore the backup by hand.",
    }
}

/// A filesystem-layer failure reading the file, listing its backups, or
/// writing the restore — never a validation outcome (those are the two
/// constructors above). `atomic_write`'s temp-file-then-rename design means
/// a write failure here never leaves the target partially modified: either
/// the rename never happened (old content intact) or the failure was in
/// reading a backup, which never touches the target at all.
pub fn rollback_io_failed(file: &str, err: &core::Error) -> ErrorBlock {
    ErrorBlock {
        label: "rollback",
        subject: file.to_string(),
        summary: "Could not read or write the file or its backup.".to_string(),
        evidence: vec![err.to_string()],
        narrowing: "Most likely one of:",
        causes: vec![],
        action: None,
        state_line: "The file was not modified.",
    }
}

/// The 25 ACME problem types with a fixed summary sentence. `badNonce` is
/// retried transparently and never reaches here; `compound` is unwrapped
/// by the caller into its subproblems before classification — see
/// `classify_problem`.
fn problem_summary(kind: &ProblemKind) -> String {
    match kind {
        ProblemKind::AccountDoesNotExist => {
            "The stored account is not known to this server.".to_string()
        }
        ProblemKind::AlreadyRevoked => "That certificate was already revoked.".to_string(),
        ProblemKind::BadCsr => "Let's Encrypt rejected the certificate request.".to_string(),
        ProblemKind::BadNonce => {
            "certway could not complete this request; retrying did not help.".to_string()
        }
        ProblemKind::BadPublicKey => "Let's Encrypt does not accept this key type.".to_string(),
        ProblemKind::BadRevocationReason => "That revocation reason is not accepted.".to_string(),
        ProblemKind::BadSignatureAlgorithm => {
            "Let's Encrypt does not accept this signature type.".to_string()
        }
        ProblemKind::Caa => {
            "A CAA record on this domain forbids Let's Encrypt from issuing.".to_string()
        }
        ProblemKind::Compound => "Let's Encrypt reported more than one problem.".to_string(),
        ProblemKind::Connection => "Let's Encrypt could not reach your server.".to_string(),
        ProblemKind::Dns => "Let's Encrypt could not resolve this domain.".to_string(),
        ProblemKind::ExternalAccountRequired => {
            "This CA requires an account key from its operator.".to_string()
        }
        ProblemKind::IncorrectResponse => {
            "Your server answered, but with the wrong content.".to_string()
        }
        ProblemKind::InvalidContact => "That contact address was rejected.".to_string(),
        ProblemKind::Malformed => "certway sent a request this server could not parse.".to_string(),
        ProblemKind::OrderNotReady => "The order is not ready yet.".to_string(),
        ProblemKind::RateLimited => "You have reached a Let's Encrypt rate limit.".to_string(),
        ProblemKind::RejectedIdentifier => {
            "Let's Encrypt will not issue certificates for this domain.".to_string()
        }
        ProblemKind::ServerInternal => "Let's Encrypt had an internal error.".to_string(),
        ProblemKind::Tls => "The TLS connection to your server failed.".to_string(),
        ProblemKind::Unauthorized => {
            "Let's Encrypt could not confirm you control this domain.".to_string()
        }
        ProblemKind::UnsupportedContact => {
            "That kind of contact address is not supported.".to_string()
        }
        ProblemKind::UnsupportedIdentifier => {
            "That is not a kind of name Let's Encrypt can certify.".to_string()
        }
        ProblemKind::UserActionRequired => {
            "Let's Encrypt needs you to take an action first.".to_string()
        }
        ProblemKind::AlreadyReplaced => "That certificate has already been replaced.".to_string(),
        ProblemKind::Conflict => "This request conflicts with one already in progress.".to_string(),
        ProblemKind::InvalidProfile => "That certificate profile is not available.".to_string(),
        ProblemKind::Unknown(_) => {
            "Let's Encrypt reported a problem certway does not recognise.".to_string()
        }
    }
}

fn problem_causes(kind: &ProblemKind) -> Vec<&'static str> {
    match kind {
        ProblemKind::Unauthorized => vec![
            "the http-01 response was not reachable from the internet",
            "the token file was removed before Let's Encrypt checked it",
        ],
        ProblemKind::Connection => {
            vec![
                "port 80 blocked by a firewall or security group",
                "your server only accepts connections from certain addresses",
            ]
        }
        ProblemKind::Dns => vec!["the domain does not resolve", "a typo in the domain name"],
        ProblemKind::Tls => vec![
            "the wrong certificate is served on this port",
            "a firewall is intercepting the connection",
        ],
        _ => vec![],
    }
}

fn problem_action(kind: &ProblemKind, subject: &str) -> Option<Action> {
    match kind {
        ProblemKind::Connection | ProblemKind::Unauthorized => Some(Action {
            line: "Check from outside your network:",
            command: format!("curl -sI http://{subject}/.well-known/acme-challenge/test"),
        }),
        ProblemKind::Caa => Some(Action {
            line: "Allow Let's Encrypt in your CAA record, then retry:",
            command: format!("dig CAA {subject}"),
        }),
        _ => None,
    }
}

/// A more specific cause than `problem_summary`'s type-based sentence can
/// give, recognised from the server's own `detail` text. The ACME `type`
/// only says the request was rejected; `detail` often says *why*, and when
/// it does, that is what the user should be told — not a generic sentence
/// that happens to be technically true but points them at the wrong fix.
/// (Case in point: `malformed` covers both "certway sent a malformed
/// request" and "you did not agree to the terms of service" — very
/// different problems, very different fixes.)
///
/// A table, not a chain of `if`s, so a new row is one line, not a new
/// branch. `needle` is matched case-insensitively as a substring of
/// `detail`. Matched in order; first match wins.
struct DetailOverride {
    needle: &'static str,
    summary: &'static str,
    action_line: Option<&'static str>,
}

const DETAIL_OVERRIDES: &[DetailOverride] = &[
    DetailOverride {
        needle: "agree to terms",
        summary: "You must accept the Let's Encrypt Terms of Service.",
        action_line: Some("Pass --agree-tos, or run without --quiet to be asked."),
    },
    DetailOverride {
        needle: "terms of service",
        summary: "You must accept the Let's Encrypt Terms of Service.",
        action_line: Some("Pass --agree-tos, or run without --quiet to be asked."),
    },
    DetailOverride {
        needle: "does not end in a public suffix",
        summary: "Let's Encrypt will not issue certificates for this domain.",
        action_line: Some(
            "Use a domain you control. Reserved names like example.com cannot be issued.",
        ),
    },
    DetailOverride {
        needle: "reserved",
        summary: "Let's Encrypt will not issue certificates for this domain.",
        action_line: Some(
            "Use a domain you control. Reserved names like example.com cannot be issued.",
        ),
    },
    DetailOverride {
        needle: "deny list",
        summary: "Let's Encrypt will not issue certificates for this domain.",
        action_line: Some(
            "Use a domain you control. Reserved names like example.com cannot be issued.",
        ),
    },
    // Deliberately absent: "too many certificates" / "rate limit" and "CAA"
    // are NOT overridden here — the rateLimited and caa type-based
    // sentences are already the specific, correct summary for those, and
    // problem_action already gives caa its own command. A detail override
    // exists only to add specificity beyond the type; it must never take
    // it away.
];

fn detail_override(detail: &Option<String>) -> Option<&'static DetailOverride> {
    let detail = detail.as_deref()?;
    let lower = detail.to_ascii_lowercase();
    DETAIL_OVERRIDES.iter().find(|o| lower.contains(o.needle))
}

/// Maps a `ProblemKind` to the short slug used in `--json` error output.
/// Deliberately mirrors the ACME wire name, lower camel-cased, since that
/// is what a machine consumer already keys off of in every other ACME
/// client.
pub fn problem_slug(kind: &ProblemKind) -> String {
    match kind {
        ProblemKind::Unknown(s) => s.clone(),
        other => {
            let debug = format!("{other:?}");
            let mut out = String::new();
            for (i, c) in debug.chars().enumerate() {
                if i == 0 {
                    out.push(c.to_ascii_lowercase());
                } else {
                    out.push(c);
                }
            }
            out
        }
    }
}

/// Slug for non-ACME `core::Error` variants, used in `--json` output.
pub fn error_slug(err: &core::Error) -> String {
    match err {
        core::Error::Connect { .. } => "connect".to_string(),
        core::Error::Tls { .. } => "tls".to_string(),
        core::Error::Timeout { .. } => "timeout".to_string(),
        core::Error::HttpMalformed { .. } => "http_malformed".to_string(),
        core::Error::HttpStatus { .. } => "http_status".to_string(),
        core::Error::BodyTooLarge { .. } => "body_too_large".to_string(),
        core::Error::JsonParse { .. } => "json_parse".to_string(),
        core::Error::JsonMissing { .. } => "json_missing".to_string(),
        core::Error::JsonType { .. } => "json_type".to_string(),
        core::Error::Io { .. } => "io".to_string(),
        core::Error::CaBundle { .. } => "ca_bundle".to_string(),
        core::Error::KeyGeneration => "key_generation".to_string(),
        core::Error::KeyFormat { .. } => "key_format".to_string(),
        core::Error::Signing => "signing".to_string(),
        core::Error::Base64 { .. } => "base64".to_string(),
        core::Error::Acme(problem) => problem_slug(&problem.kind),
        core::Error::UnknownStatus { .. } => "unknown_status".to_string(),
        core::Error::NoNonce => "no_nonce".to_string(),
        core::Error::NonceExhausted { .. } => "nonce_exhausted".to_string(),
        core::Error::ChallengeUnavailable { .. } => "challenge_unavailable".to_string(),
        core::Error::OrderNotReady { .. } => "order_not_ready".to_string(),
        core::Error::PollExhausted { .. } => "poll_exhausted".to_string(),
        core::Error::CertChainEmpty => "cert_chain_empty".to_string(),
        core::Error::Csr { .. } => "csr".to_string(),
        core::Error::PrivilegedPort { .. } => "privileged_port".to_string(),
        core::Error::CertParse { .. } => "cert_parse".to_string(),
        core::Error::AriWindowInvalid => "ari_window_invalid".to_string(),
        core::Error::AriUnavailable { .. } => "ari_unavailable".to_string(),
        core::Error::NoResolver => "no_resolver".to_string(),
        core::Error::DnsTimeout { .. } => "dns_timeout".to_string(),
        core::Error::DnsMalformed { .. } => "dns_malformed".to_string(),
        core::Error::DnsNoRecord { .. } => "dns_no_record".to_string(),
        core::Error::DnsNameTooLong { .. } => "dns_name_too_long".to_string(),
        core::Error::DnsCompressionLoop => "dns_compression_loop".to_string(),
        core::Error::DnsHookFailed { .. } => "dns_hook_failed".to_string(),
        core::Error::DnsHookTimeout { .. } => "dns_hook_timeout".to_string(),
        core::Error::DnsProviderConfig { .. } => "dns_provider_config".to_string(),
        _ => "unexpected".to_string(),
    }
}

/// `true` when the failure happened while contacting the ACME server itself
/// (as opposed to a local problem such as failing to bind port 80). Used
/// both for the narrowing/causes selection and for the process exit code.
fn is_ca_unreachable(err: &core::Error) -> bool {
    match err {
        core::Error::Connect { host, .. } | core::Error::Tls { host, .. } => {
            host != "0.0.0.0" && host != "::"
        }
        core::Error::Timeout { .. } => true,
        _ => false,
    }
}

/// Process exit code for this failure. Codes 3 and 4 (preflight/rehearsal)
/// do not apply — this build starts at `account`.
pub fn exit_code(err: &core::Error, _stage: Stage) -> i32 {
    if let core::Error::Acme(problem) = err {
        if problem.kind == ProblemKind::RateLimited {
            return 6;
        }
    }
    if is_ca_unreachable(err) {
        return 7;
    }
    5
}

fn format_retry_after(problem: &core::Problem) -> Option<String> {
    // The raw Retry-After value is not threaded through core::Problem
    // today; when it is, this is where the "You can try again after
    // HH:MM (in N minutes)." line is built.
    let _ = problem;
    None
}

/// The pure classification function. Builds everything the renderer needs
/// to print the four-part error block, without touching a terminal.
///
/// `subject` is the identifier this `issue` run concerns (the requested
/// domain(s)) — used as the `<subject>` slot next to the step label for
/// ACME problems, since the problem's own `detail` is prose meant for the
/// evidence line, not a label fragment.
pub fn classify(err: &core::Error, stage: Stage, proven: Proven, subject: &str) -> ErrorBlock {
    let label = stage.label();

    if let core::Error::PrivilegedPort { port } = err {
        return ErrorBlock {
            label,
            subject: format!("port {port}"),
            summary: "certway needs permission to use port 80.".to_string(),
            evidence: vec![format!("bind 0.0.0.0:{port} → permission denied")],
            narrowing: narrowing_line(proven),
            causes: narrowing_causes(vec![
                "certway does not have permission to bind privileged ports",
            ]),
            action: Some(Action {
                line: "Run with sudo, or grant the capability once:",
                command: "sudo setcap CAP_NET_BIND_SERVICE=+eip $(which certway)".to_string(),
            }),
            state_line: STATE_LINE_ISSUANCE,
        };
    }

    if let core::Error::Acme(problem) = err {
        if problem.kind == ProblemKind::Compound && !problem.subproblems.is_empty() {
            // Render the first subproblem; the others are the same shape.
            // A multi-block render is a rendering-layer decision outside
            // this pure function's scope for this stage.
            return classify_problem(&problem.subproblems[0], label, proven, subject);
        }
        return classify_problem(problem, label, proven, subject);
    }

    let subject = default_subject(err, stage);
    let summary = default_summary(err);
    let evidence = vec![err.to_string()];

    ErrorBlock {
        label,
        subject,
        summary,
        evidence,
        narrowing: narrowing_line(proven),
        causes: narrowing_causes(default_causes(err)),
        action: None,
        state_line: STATE_LINE_ISSUANCE,
    }
}

fn classify_problem(
    problem: &core::Problem,
    label: &'static str,
    proven: Proven,
    subject: &str,
) -> ErrorBlock {
    let subject = subject.to_string();
    let mut evidence = Vec::new();
    if let Some(detail) = &problem.detail {
        evidence.push(detail.clone());
    }

    let overridden = detail_override(&problem.detail);
    let (mut summary, mut action) = match overridden {
        Some(o) => (
            o.summary.to_string(),
            o.action_line.map(|line| Action {
                line,
                command: String::new(),
            }),
        ),
        None => (
            problem_summary(&problem.kind),
            problem_action(&problem.kind, &subject),
        ),
    };

    if problem.kind == ProblemKind::RateLimited {
        if let Some(line) = format_retry_after(problem) {
            evidence.push(line);
        }
    }
    if problem.kind == ProblemKind::Malformed && overridden.is_none() {
        // A generic `malformed` error means certway sent a request the
        // server couldn't parse — that's certway's bug, not the user's, so
        // the summary deliberately names certway rather than the user, and
        // no action line implicates the user's setup. Does not apply once
        // a detail override has already given a more specific,
        // user-actionable cause (e.g. "you did not agree to the terms of
        // service" — that action is real).
        action = None;
    }

    // Never leak the raw urn:ietf:params:acme:error:* string outside
    // --verbose, and keep summaries to a single short sentence. Truncate a
    // summary that somehow grew past 12 words defensively (should not
    // happen given the fixed table and override table above).
    if summary.split_whitespace().count() > 12 {
        summary = problem_summary(&ProblemKind::Unknown(String::new()));
    }

    let causes = narrowing_causes(problem_causes(&problem.kind));

    ErrorBlock {
        label,
        subject,
        summary,
        evidence,
        narrowing: narrowing_line(proven),
        causes,
        action,
        state_line: STATE_LINE_ISSUANCE,
    }
}

/// The `<subject>` slot in the error block's leading line, for errors that
/// don't come from `classify_problem`'s ACME path. Prefers whatever the
/// error itself names (a host, an operation) over repeating the step
/// label, which would otherwise read as `label subject` with the same
/// word twice — e.g. `✗ account        account`.
fn default_subject(err: &core::Error, stage: Stage) -> String {
    match err {
        core::Error::Connect { host, .. } | core::Error::Tls { host, .. } => host.clone(),
        core::Error::Timeout { operation, .. } => operation.to_string(),
        _ => stage.label().to_string(),
    }
}

fn default_summary(err: &core::Error) -> String {
    match err {
        core::Error::Connect { .. } => "Let's Encrypt could not reach your server.".to_string(),
        core::Error::Tls { .. } => "The TLS connection to your server failed.".to_string(),
        core::Error::Timeout { .. } => "The connection to Let's Encrypt timed out.".to_string(),
        core::Error::ChallengeUnavailable { wanted } => {
            format!("Let's Encrypt did not offer a {wanted} challenge.")
        }
        core::Error::PollExhausted { .. } => "Let's Encrypt did not finish in time.".to_string(),
        core::Error::CertChainEmpty => {
            "Let's Encrypt returned an empty certificate chain.".to_string()
        }
        core::Error::KeyGeneration => "certway could not generate a certificate key.".to_string(),
        core::Error::Csr { .. } => "certway could not build the certificate request.".to_string(),
        core::Error::Io { .. } => {
            "certway could not read or write a required local file.".to_string()
        }
        // `NoResolver` deserves a bespoke full-screen layout, but that is
        // keyed to a `preflight` stage this build doesn't have yet
        // (preflight/rehearsal are not implemented). This is the plain
        // one-line summary through the existing error block as a stand-in
        // until that stage exists.
        core::Error::NoResolver => {
            "certway could not find a DNS resolver on this system.".to_string()
        }
        core::Error::DnsTimeout { .. } => "A DNS query timed out.".to_string(),
        core::Error::DnsNoRecord { .. } => {
            "certway could not find the DNS record it needed.".to_string()
        }
        core::Error::DnsHookFailed { .. } => "The DNS hook command failed.".to_string(),
        core::Error::DnsHookTimeout { .. } => "The DNS hook command timed out.".to_string(),
        core::Error::DnsProviderConfig { .. } => {
            "The DNS provider is not configured correctly.".to_string()
        }
        _ => "certway hit an unexpected error.".to_string(),
    }
}

fn default_causes(err: &core::Error) -> Vec<&'static str> {
    match err {
        core::Error::Connect { .. } | core::Error::Timeout { .. } => {
            vec![
                "Let's Encrypt's API is temporarily unreachable from this network",
                "a firewall is blocking outbound HTTPS",
            ]
        }
        _ => vec![],
    }
}

// ---------------------------------------------------------------------
// Wording lint — the mechanical check every emittable string is run
// through by the test suite.
// ---------------------------------------------------------------------

pub fn wording_violation(s: &str) -> Option<&'static str> {
    if s.contains('!') {
        return Some("contains an exclamation mark");
    }
    let lower = s.to_ascii_lowercase();
    for banned in ["sorry", "oops", "whoops", "uh oh"] {
        if lower.contains(banned) {
            return Some("contains an apology");
        }
    }
    if s.chars().any(|c| {
        let cp = c as u32;
        (0x1F300..=0x1FAFF).contains(&cp) || (0x2600..=0x27BF).contains(&cp)
    }) {
        return Some("contains an emoji");
    }
    if s.contains("urn:ietf:params:acme:error:") {
        return Some("leaks a raw acme error urn");
    }
    None
}

/// Word-count cap for summary lines specifically: longer than 12 words and
/// it reads as an explanation, not a summary.
pub fn summary_too_long(s: &str) -> bool {
    s.split_whitespace().count() > 12
}

#[cfg(test)]
mod tests {
    use super::*;
    use certway_core::Problem;

    fn problem(kind: ProblemKind) -> core::Error {
        core::Error::Acme(Problem {
            kind,
            detail: None,
            subproblems: vec![],
        })
    }

    // One test per ACME problem type. badNonce and compound are
    // behaviours, not summary sentences, which is why there are 25 cases
    // below, not 27.
    #[test]
    fn all_25_summary_sentences_match_ui_spec_exactly() {
        let cases: &[(ProblemKind, &str)] = &[
            (
                ProblemKind::AccountDoesNotExist,
                "The stored account is not known to this server.",
            ),
            (
                ProblemKind::AlreadyRevoked,
                "That certificate was already revoked.",
            ),
            (
                ProblemKind::BadCsr,
                "Let's Encrypt rejected the certificate request.",
            ),
            (
                ProblemKind::BadPublicKey,
                "Let's Encrypt does not accept this key type.",
            ),
            (
                ProblemKind::BadRevocationReason,
                "That revocation reason is not accepted.",
            ),
            (
                ProblemKind::BadSignatureAlgorithm,
                "Let's Encrypt does not accept this signature type.",
            ),
            (
                ProblemKind::Caa,
                "A CAA record on this domain forbids Let's Encrypt from issuing.",
            ),
            (
                ProblemKind::Connection,
                "Let's Encrypt could not reach your server.",
            ),
            (
                ProblemKind::Dns,
                "Let's Encrypt could not resolve this domain.",
            ),
            (
                ProblemKind::ExternalAccountRequired,
                "This CA requires an account key from its operator.",
            ),
            (
                ProblemKind::IncorrectResponse,
                "Your server answered, but with the wrong content.",
            ),
            (
                ProblemKind::InvalidContact,
                "That contact address was rejected.",
            ),
            (
                ProblemKind::Malformed,
                "certway sent a request this server could not parse.",
            ),
            (ProblemKind::OrderNotReady, "The order is not ready yet."),
            (
                ProblemKind::RateLimited,
                "You have reached a Let's Encrypt rate limit.",
            ),
            (
                ProblemKind::RejectedIdentifier,
                "Let's Encrypt will not issue certificates for this domain.",
            ),
            (
                ProblemKind::ServerInternal,
                "Let's Encrypt had an internal error.",
            ),
            (
                ProblemKind::Tls,
                "The TLS connection to your server failed.",
            ),
            (
                ProblemKind::Unauthorized,
                "Let's Encrypt could not confirm you control this domain.",
            ),
            (
                ProblemKind::UnsupportedContact,
                "That kind of contact address is not supported.",
            ),
            (
                ProblemKind::UnsupportedIdentifier,
                "That is not a kind of name Let's Encrypt can certify.",
            ),
            (
                ProblemKind::UserActionRequired,
                "Let's Encrypt needs you to take an action first.",
            ),
            (
                ProblemKind::AlreadyReplaced,
                "That certificate has already been replaced.",
            ),
            (
                ProblemKind::Conflict,
                "This request conflicts with one already in progress.",
            ),
            (
                ProblemKind::InvalidProfile,
                "That certificate profile is not available.",
            ),
        ];
        assert_eq!(cases.len(), 25);
        for (kind, expected) in cases {
            let block = classify(
                &problem(kind.clone()),
                Stage::Validate,
                Proven::default(),
                "example.com",
            );
            assert_eq!(&block.summary, expected, "mismatch for {kind:?}");
        }
    }

    #[test]
    fn bad_nonce_is_a_behaviour_not_a_summary() {
        // Never reaches classify in practice — core::acme retries it
        // transparently up to 5 times. Documented here, not asserted as a
        // summary sentence, since it has none.
        let block = classify(
            &problem(ProblemKind::BadNonce),
            Stage::Order,
            Proven::default(),
            "example.com",
        );
        assert!(!block.summary.is_empty());
    }

    #[test]
    fn compound_unwraps_to_first_subproblem() {
        let compound = core::Error::Acme(Problem {
            kind: ProblemKind::Compound,
            detail: None,
            subproblems: vec![
                Problem {
                    kind: ProblemKind::Malformed,
                    detail: None,
                    subproblems: vec![],
                },
                Problem {
                    kind: ProblemKind::RateLimited,
                    detail: None,
                    subproblems: vec![],
                },
            ],
        });
        let block = classify(&compound, Stage::Order, Proven::default(), "example.com");
        assert_eq!(
            block.summary,
            "certway sent a request this server could not parse."
        );
    }

    #[test]
    fn raw_urn_never_appears_in_a_summary() {
        for kind in [
            ProblemKind::Malformed,
            ProblemKind::Unauthorized,
            ProblemKind::Unknown("newThing".to_string()),
        ] {
            let block = classify(
                &problem(kind),
                Stage::Validate,
                Proven::default(),
                "example.com",
            );
            assert!(!block.summary.contains("urn:ietf"));
        }
    }

    #[test]
    fn privileged_port_maps_to_challenge_stage_block() {
        let err = core::Error::PrivilegedPort { port: 80 };
        let block = classify(&err, Stage::Challenge, Proven::default(), "example.com");
        assert_eq!(block.label, "challenge");
        assert_eq!(block.subject, "port 80");
        assert!(block.summary.contains("permission"));
        assert_eq!(
            block.state_line,
            "No certificate was issued. Nothing was changed."
        );
        assert!(block.action.is_some());
    }

    // -- Detail-based recognition beats the type-based fallback -----------

    #[test]
    fn malformed_missing_agree_tos_is_recognised_from_detail_not_generic() {
        let err = core::Error::Acme(Problem {
            kind: ProblemKind::Malformed,
            detail: Some("must agree to terms of service".to_string()),
            subproblems: vec![],
        });
        let block = classify(&err, Stage::Account, Proven::default(), "example.com");
        assert_eq!(
            block.summary,
            "You must accept the Let's Encrypt Terms of Service."
        );
        // The subject is the requested identifier, never a fragment of detail.
        assert_eq!(block.subject, "example.com");
        assert_eq!(
            block.evidence,
            vec!["must agree to terms of service".to_string()]
        );
        let action = block
            .action
            .expect("agree-tos detail should carry an action");
        assert_eq!(
            action.line,
            "Pass --agree-tos, or run without --quiet to be asked."
        );
    }

    #[test]
    fn rejected_identifier_reserved_domain_is_recognised_from_detail() {
        let err = core::Error::Acme(Problem {
            kind: ProblemKind::RejectedIdentifier,
            detail: Some(
                "Invalid identifiers requested :: \"example.com\" does not end in a public suffix (reserved TLD)"
                    .to_string(),
            ),
            subproblems: vec![],
        });
        let block = classify(&err, Stage::Order, Proven::default(), "example.com");
        assert_eq!(
            block.summary,
            "Let's Encrypt will not issue certificates for this domain."
        );
        let action = block
            .action
            .expect("reserved-domain detail should carry an action");
        assert_eq!(
            action.line,
            "Use a domain you control. Reserved names like example.com cannot be issued."
        );
    }

    #[test]
    fn rate_limited_and_caa_keep_the_type_sentence_even_when_detail_could_confuse_the_matcher() {
        // These details would look domain- or terms-related to a careless
        // needle, but rateLimited/caa already have the specific, correct
        // §17 sentence — a detail override must never take that away.
        let rate_limited = core::Error::Acme(Problem {
            kind: ProblemKind::RateLimited,
            detail: Some(
                "too many certificates already issued for this exact set of domains".to_string(),
            ),
            subproblems: vec![],
        });
        let block = classify(
            &rate_limited,
            Stage::Order,
            Proven::default(),
            "example.com",
        );
        assert_eq!(
            block.summary,
            "You have reached a Let's Encrypt rate limit."
        );

        let caa = core::Error::Acme(Problem {
            kind: ProblemKind::Caa,
            detail: Some("CAA record for example.com prevents issuance".to_string()),
            subproblems: vec![],
        });
        let block = classify(&caa, Stage::Validate, Proven::default(), "example.com");
        assert_eq!(
            block.summary,
            "A CAA record on this domain forbids Let's Encrypt from issuing."
        );
    }

    // -- No narrowing line/bullet for a single cause -----------------------

    #[test]
    fn narrowing_causes_suppresses_a_single_cause() {
        assert!(narrowing_causes(vec!["only one"]).is_empty());
        assert_eq!(narrowing_causes(vec!["a", "b"]), vec!["a", "b"]);
        assert!(narrowing_causes(vec![]).is_empty());
    }

    #[test]
    fn privileged_port_has_no_narrowing_causes() {
        let err = core::Error::PrivilegedPort { port: 80 };
        let block = classify(&err, Stage::Challenge, Proven::default(), "example.com");
        assert!(
            block.causes.is_empty(),
            "single cause must not appear as a narrowing bullet"
        );
    }

    #[test]
    fn narrowing_line_selects_by_proven() {
        assert_eq!(
            narrowing_line(Proven {
                preflight_passed: false,
                rehearsal_passed: false
            }),
            "Most likely one of:"
        );
        assert_eq!(
            narrowing_line(Proven {
                preflight_passed: true,
                rehearsal_passed: false
            }),
            "Your DNS is correct, so this is most likely:"
        );
        assert_eq!(
            narrowing_line(Proven {
                preflight_passed: true,
                rehearsal_passed: true
            }),
            "The staging run succeeded moments ago, so this is most likely:"
        );
    }

    #[test]
    fn exit_code_rate_limited_is_6() {
        let err = problem(ProblemKind::RateLimited);
        assert_eq!(exit_code(&err, Stage::Order), 6);
    }

    #[test]
    fn exit_code_ca_connect_is_7() {
        let err = core::Error::Connect {
            host: "acme-staging-v02.api.letsencrypt.org".to_string(),
            port: 443,
            source: std::io::Error::other("x"),
        };
        assert_eq!(exit_code(&err, Stage::Account), 7);
    }

    #[test]
    fn exit_code_local_bind_connect_is_5_not_7() {
        let err = core::Error::Connect {
            host: "0.0.0.0".to_string(),
            port: 80,
            source: std::io::Error::other("x"),
        };
        assert_eq!(exit_code(&err, Stage::Challenge), 5);
    }

    #[test]
    fn exit_code_privileged_port_is_5() {
        let err = core::Error::PrivilegedPort { port: 80 };
        assert_eq!(exit_code(&err, Stage::Challenge), 5);
    }

    #[test]
    fn exit_code_generic_acme_problem_is_5() {
        let err = problem(ProblemKind::Unauthorized);
        assert_eq!(exit_code(&err, Stage::Validate), 5);
    }

    #[test]
    fn wildcard_needs_dns01_matches_the_ui_spec_example_shape() {
        let block = wildcard_needs_dns01(
            "*.example.com",
            "certway renew example.com --dns cloudflare".to_string(),
        );
        assert_eq!(block.label, "preflight");
        assert_eq!(block.subject, "*.example.com");
        assert_eq!(
            block.summary,
            "A wildcard certificate can only be validated over DNS."
        );
        assert_eq!(
            block.evidence,
            vec!["Let's Encrypt offers no HTTP challenge for a wildcard name.".to_string()]
        );
        assert!(
            block.causes.is_empty(),
            "single cause must not appear as a narrowing bullet"
        );
        let action = block.action.expect("must name the fix");
        assert_eq!(action.line, "Pass a DNS provider:");
        assert_eq!(action.command, "certway renew example.com --dns cloudflare");
        assert_eq!(
            block.state_line,
            "Stopped before contacting Let's Encrypt. No rate limit used."
        );
    }

    #[test]
    fn wildcard_needs_dns01_passes_the_wording_lint() {
        let block = wildcard_needs_dns01(
            "*.example.com",
            "certway renew example.com --dns cloudflare".to_string(),
        );
        assert!(wording_violation(&block.summary).is_none());
        assert!(!summary_too_long(&block.summary));
        for line in &block.evidence {
            assert!(wording_violation(line).is_none());
        }
        assert!(wording_violation(block.action.as_ref().unwrap().line).is_none());
        assert!(wording_violation(block.state_line).is_none());
    }

    #[test]
    fn wording_lint_catches_exclamation_apology_emoji_urn() {
        assert!(wording_violation("Oops, something went wrong!").is_some());
        assert!(wording_violation("Sorry about that.").is_some());
        assert!(wording_violation("Great \u{1F389} success").is_some());
        assert!(wording_violation("saw urn:ietf:params:acme:error:malformed").is_some());
        assert!(wording_violation("Let's Encrypt could not reach your server.").is_none());
    }

    fn all_problem_kinds() -> Vec<ProblemKind> {
        vec![
            ProblemKind::AccountDoesNotExist,
            ProblemKind::AlreadyRevoked,
            ProblemKind::BadCsr,
            ProblemKind::BadNonce,
            ProblemKind::BadPublicKey,
            ProblemKind::BadRevocationReason,
            ProblemKind::BadSignatureAlgorithm,
            ProblemKind::Caa,
            ProblemKind::Compound,
            ProblemKind::Connection,
            ProblemKind::Dns,
            ProblemKind::ExternalAccountRequired,
            ProblemKind::IncorrectResponse,
            ProblemKind::InvalidContact,
            ProblemKind::Malformed,
            ProblemKind::OrderNotReady,
            ProblemKind::RateLimited,
            ProblemKind::RejectedIdentifier,
            ProblemKind::ServerInternal,
            ProblemKind::Tls,
            ProblemKind::Unauthorized,
            ProblemKind::UnsupportedContact,
            ProblemKind::UnsupportedIdentifier,
            ProblemKind::UserActionRequired,
            ProblemKind::AlreadyReplaced,
            ProblemKind::Conflict,
            ProblemKind::InvalidProfile,
        ]
    }

    /// The mechanical wording lint run over every summary sentence the
    /// program can emit — all 27 problem kinds, not just a sample.
    #[test]
    fn every_summary_sentence_passes_the_wording_lint() {
        for kind in all_problem_kinds() {
            let s = problem_summary(&kind);
            assert!(
                wording_violation(&s).is_none(),
                "violation in {s:?} for {kind:?}"
            );
            assert!(!summary_too_long(&s), "too long: {s:?} for {kind:?}");
        }
    }

    /// Same lint, run over the causes, narrowing lines, action lines, and
    /// state lines every `classify` branch can produce — the other three
    /// quarters of the error block template.
    #[test]
    fn every_static_error_block_string_passes_the_wording_lint() {
        let mut strings: Vec<String> = Vec::new();
        strings.push(STATE_LINE_ISSUANCE.to_string());
        for proven in [
            Proven {
                preflight_passed: false,
                rehearsal_passed: false,
            },
            Proven {
                preflight_passed: true,
                rehearsal_passed: false,
            },
            Proven {
                preflight_passed: true,
                rehearsal_passed: true,
            },
        ] {
            strings.push(narrowing_line(proven).to_string());
        }
        for kind in all_problem_kinds() {
            strings.extend(problem_causes(&kind).iter().map(|s| s.to_string()));
            if let Some(action) = problem_action(&kind, "example.com") {
                strings.push(action.line.to_string());
                strings.push(action.command.clone());
            }
        }
        let privileged_port = classify(
            &core::Error::PrivilegedPort { port: 80 },
            Stage::Challenge,
            Proven::default(),
            "example.com",
        );
        strings.push(privileged_port.summary.clone());
        if let Some(a) = &privileged_port.action {
            strings.push(a.line.to_string());
        }
        strings.extend(privileged_port.causes.iter().map(|s| s.to_string()));

        for s in strings {
            // Commands (setcap, curl, dig) legitimately contain characters
            // this lint doesn't police; it only checks the wording rules
            // that apply to prose (no exclamation marks, no apologies, no
            // emoji, no raw acme urn).
            assert!(wording_violation(&s).is_none(), "violation in {s:?}");
        }
    }
}
