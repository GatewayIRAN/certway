use std::fmt;

#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    Connect {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    Tls {
        host: String,
        source: rustls::Error,
    },
    Timeout {
        operation: &'static str,
        secs: u64,
    },
    HttpMalformed {
        detail: &'static str,
    },
    HttpStatus {
        code: u16,
        body_excerpt: String,
    },
    BodyTooLarge {
        limit: usize,
    },
    /// `--resolver`/`CERTWAY_RESOLVER`/`/etc/resolv.conf` all absent, and
    /// deliberately no further fallback: resolving names against a
    /// hardcoded public resolver would disclose the user's domain names to
    /// a third party without consent.
    NoResolver,
    DnsTimeout {
        name: String,
        resolver: std::net::IpAddr,
    },
    DnsMalformed {
        detail: &'static str,
    },
    DnsNoRecord {
        name: String,
        kind: &'static str,
    },
    DnsNameTooLong {
        name: String,
    },
    /// Total pointer jumps while expanding one compressed name exceeded the
    /// cap. Exceeding it is always an error, never a hang.
    DnsCompressionLoop,
    JsonParse {
        detail: String,
    },
    JsonMissing {
        field: &'static str,
    },
    JsonType {
        field: &'static str,
        expected: &'static str,
    },
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    CaBundle {
        detail: &'static str,
    },
    KeyGeneration,
    KeyFormat {
        detail: String,
    },
    Signing,
    Base64 {
        detail: &'static str,
    },
    Acme(crate::acme::Problem),
    UnknownStatus {
        field: &'static str,
        value: String,
    },
    NoNonce,
    NonceExhausted {
        attempts: u8,
    },
    ChallengeUnavailable {
        wanted: crate::acme::ChallengeType,
    },
    OrderNotReady {
        status: crate::acme::OrderStatus,
    },
    PollExhausted {
        resource: &'static str,
        elapsed_secs: u64,
    },
    CertChainEmpty,
    Csr {
        detail: String,
    },
    PrivilegedPort {
        port: u16,
    },
    /// Any structural failure while parsing an X.509 certificate's DER
    /// encoding — truncated input, a tag that isn't where the profile says
    /// it must be, or a field whose content doesn't fit its declared
    /// length. Never raised for a well-formed certificate this parser
    /// simply chooses not to read every field of.
    CertParse {
        detail: &'static str,
    },
    /// RFC 9773 §4.2: `suggestedWindow.end` at or before `.start` is an
    /// invalid RenewalInfo object, not an "all in the past" signal — it
    /// must be treated the same as a failed fetch.
    AriWindowInvalid,
    /// A certID cannot be built from this certificate — today, only because
    /// it carries no Authority Key Identifier extension (RFC 9773's certID
    /// requires one). Absent AKI means ARI is unavailable for this
    /// certificate, not that the certificate itself failed to parse.
    AriUnavailable {
        detail: &'static str,
    },
    /// A configured DNS provider is missing something it needs to run at
    /// all — today, only "no `CLOUDFLARE_API_TOKEN` /
    /// `CLOUDFLARE_API_TOKEN_FILE`".
    DnsProviderConfig {
        detail: String,
    },
    /// Same gap as above, for the external hook: a non-zero exit's
    /// captured stderr needs somewhere to go. Deliberately carries no
    /// `command`/argv field — a `--dns-hook` command line routinely embeds
    /// a credential as an argument (`docs/ref/cloudflare-dns-api-2026-07-31.md`'s
    /// own `--dns-hook` example shows exactly this shape), and this is a
    /// `core::Error`: every field on it is a candidate for ending up in
    /// user-facing output somewhere (`err.to_string()`/`{e}` is used
    /// throughout the CLI as a shortcut around `report::classify`). Keeping
    /// the field only "not printed by convention" would leave the leak one
    /// careless `{e:?}` away — never storing it here is what makes that
    /// leak structurally impossible rather than merely unlikely.
    DnsHookFailed {
        stderr: String,
    },
    DnsHookTimeout {
        secs: u64,
    },
    /// Post-issuance `--hook`/`--hook-failure`. Distinct from
    /// `DnsHookFailed` because a post-issuance hook's failure is only ever
    /// a warning, never propagated to `fail()`; this variant exists only so
    /// `hook::run_local` has somewhere to put the detail for the caller to
    /// render as a `step_warned` line. No `command` field, same reasoning
    /// as `DnsHookFailed`.
    HookFailed {
        stderr: String,
    },
    HookTimeout {
        secs: u64,
    },
    /// `--link`/`--link-to` target inspection: the target exists and is
    /// neither absent nor a symlink certway itself owns (one pointing into
    /// the resolved data directory). Refused unless `--link-force`.
    LinkTargetNotOwned {
        path: std::path::PathBuf,
    },
}

impl Error {
    /// Builds an HttpStatus error, capping the body excerpt at 200 bytes so a
    /// malicious or malformed response body cannot flood logs. Cutting mid
    /// character is safe: from_utf8_lossy replaces any truncated sequence at
    /// the boundary with U+FFFD rather than panicking.
    pub fn http_status(code: u16, body: &[u8]) -> Error {
        let cap = body.len().min(200);
        let body_excerpt = String::from_utf8_lossy(&body[..cap]).into_owned();
        Error::HttpStatus { code, body_excerpt }
    }

    /// Builds an `Io` error. `Error` is `#[non_exhaustive]`, so a
    /// downstream crate (the `certway` binary) cannot otherwise construct
    /// any variant directly — only match on one already produced here.
    /// This is the one constructor the CLI needs, for local file-write
    /// failures when writing the issued certificate to disk.
    pub fn io(path: impl Into<std::path::PathBuf>, source: std::io::Error) -> Error {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Connect { host, port, source } => {
                write!(f, "connect to {host}:{port} failed: {source}")
            }
            Error::Tls { host, source } => write!(f, "tls handshake with {host} failed: {source}"),
            Error::Timeout { operation, secs } => {
                write!(f, "operation \"{operation}\" timed out after {secs}s")
            }
            Error::HttpMalformed { detail } => write!(f, "malformed http response: {detail}"),
            Error::HttpStatus { code, body_excerpt } => {
                write!(f, "http status {code}: {body_excerpt}")
            }
            Error::BodyTooLarge { limit } => write!(f, "body exceeds limit of {limit} bytes"),
            Error::NoResolver => write!(f, "no dns resolver configured"),
            Error::DnsTimeout { name, resolver } => {
                write!(
                    f,
                    "dns query for {name} timed out against resolver {resolver}"
                )
            }
            Error::DnsMalformed { detail } => write!(f, "malformed dns message: {detail}"),
            Error::DnsNoRecord { name, kind } => write!(f, "no {kind} record found for {name}"),
            Error::DnsNameTooLong { name } => write!(f, "dns name too long: {name}"),
            Error::DnsCompressionLoop => write!(f, "dns message compression pointer loop"),
            Error::JsonParse { detail } => write!(f, "json parse error: {detail}"),
            Error::JsonMissing { field } => write!(f, "json field \"{field}\" missing"),
            Error::JsonType { field, expected } => {
                write!(f, "json field \"{field}\" expected type {expected}")
            }
            Error::Io { path, source } => write!(f, "io error on {}: {source}", path.display()),
            Error::CaBundle { detail } => write!(f, "ca bundle error: {detail}"),
            Error::KeyGeneration => write!(f, "key generation failed"),
            Error::KeyFormat { detail } => write!(f, "key format error: {detail}"),
            Error::Signing => write!(f, "signing failed"),
            Error::Base64 { detail } => write!(f, "base64 error: {detail}"),
            Error::Acme(problem) => write!(f, "acme error: {problem}"),
            Error::UnknownStatus { field, value } => {
                write!(f, "unknown value \"{value}\" for field \"{field}\"")
            }
            Error::NoNonce => write!(f, "no replay-nonce available"),
            Error::NonceExhausted { attempts } => {
                write!(f, "nonce retry exhausted after {attempts} attempts")
            }
            Error::ChallengeUnavailable { wanted } => {
                write!(f, "no {wanted} challenge offered by the server")
            }
            Error::OrderNotReady { status } => {
                write!(f, "order is not in the expected state: {status:?}")
            }
            Error::PollExhausted {
                resource,
                elapsed_secs,
            } => {
                write!(f, "polling {resource} exhausted after {elapsed_secs}s")
            }
            Error::CertChainEmpty => write!(f, "certificate chain response was empty"),
            Error::Csr { detail } => write!(f, "csr error: {detail}"),
            Error::PrivilegedPort { port } => {
                write!(f, "binding port {port} requires elevated privileges")
            }
            Error::CertParse { detail } => write!(f, "certificate parse error: {detail}"),
            Error::AriWindowInvalid => {
                write!(f, "renewal info window is invalid (end at or before start)")
            }
            Error::AriUnavailable { detail } => write!(f, "renewal info unavailable: {detail}"),
            Error::DnsProviderConfig { detail } => {
                write!(f, "dns provider configuration error: {detail}")
            }
            // Never the command/argv (`DnsHookFailed`'s own doc comment) —
            // only what the hook itself printed and how it failed.
            Error::DnsHookFailed { stderr } => write!(f, "the dns hook failed: {stderr}"),
            Error::DnsHookTimeout { secs } => write!(f, "the dns hook timed out after {secs}s"),
            Error::HookFailed { stderr } => write!(f, "the hook failed: {stderr}"),
            Error::HookTimeout { secs } => write!(f, "the hook timed out after {secs}s"),
            Error::LinkTargetNotOwned { path } => {
                write!(
                    f,
                    "{} exists and is not a link certway owns",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Connect { source, .. } => Some(source),
            Error::Tls { source, .. } => Some(source),
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
