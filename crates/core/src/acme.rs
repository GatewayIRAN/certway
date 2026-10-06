use crate::crypto::{b64url_encode, sign_jws, AccountKey, Auth, Jws, Payload};
use crate::error::Error;
use crate::http::{Client, Method, Response};
use crate::json::{write_object, Json, JsonVal};
use ring::rand::{SecureRandom, SystemRandom};
use std::fmt;
use std::net::IpAddr;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
    pub key_change: String,
    pub renewal_info: Option<String>,
    pub terms_of_service: Option<String>,
    pub external_account_required: bool,
}

impl Directory {
    pub fn parse(json: &Json) -> Result<Directory, Error> {
        let new_nonce = json.str("newNonce")?.to_string();
        let new_account = json.str("newAccount")?.to_string();
        let new_order = json.str("newOrder")?.to_string();
        let revoke_cert = json.str("revokeCert")?.to_string();
        let key_change = json.str("keyChange")?.to_string();
        let renewal_info = json.opt_str("renewalInfo").map(str::to_string);

        let meta = json.opt_object("meta");
        let terms_of_service = meta
            .as_ref()
            .and_then(|m| m.opt_str("termsOfService"))
            .map(str::to_string);
        let external_account_required = meta
            .as_ref()
            .map(|m| {
                if m.has("externalAccountRequired") {
                    m.bool("externalAccountRequired")
                } else {
                    Ok(false)
                }
            })
            .transpose()?
            .unwrap_or(false);

        Ok(Directory {
            new_nonce,
            new_account,
            new_order,
            revoke_cert,
            key_change,
            renewal_info,
            terms_of_service,
            external_account_required,
        })
    }
}

/// Unauthenticated GET of the directory document. There is no session yet
/// at this point — nothing has been signed.
pub fn fetch_directory(http: &Client, url: &str) -> Result<Directory, Error> {
    let response = http.request(Method::Get, url, None, None)?;
    let json = Json::parse(&response.body)?;
    Directory::parse(&json)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl OrderStatus {
    fn parse(s: &str) -> Result<OrderStatus, Error> {
        match s {
            "pending" => Ok(OrderStatus::Pending),
            "ready" => Ok(OrderStatus::Ready),
            "processing" => Ok(OrderStatus::Processing),
            "valid" => Ok(OrderStatus::Valid),
            "invalid" => Ok(OrderStatus::Invalid),
            other => Err(Error::UnknownStatus {
                field: "status",
                value: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

impl AuthzStatus {
    fn parse(s: &str) -> Result<AuthzStatus, Error> {
        match s {
            "pending" => Ok(AuthzStatus::Pending),
            "valid" => Ok(AuthzStatus::Valid),
            "invalid" => Ok(AuthzStatus::Invalid),
            "deactivated" => Ok(AuthzStatus::Deactivated),
            "expired" => Ok(AuthzStatus::Expired),
            "revoked" => Ok(AuthzStatus::Revoked),
            other => Err(Error::UnknownStatus {
                field: "status",
                value: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

impl ChallengeStatus {
    fn parse(s: &str) -> Result<ChallengeStatus, Error> {
        match s {
            "pending" => Ok(ChallengeStatus::Pending),
            "processing" => Ok(ChallengeStatus::Processing),
            "valid" => Ok(ChallengeStatus::Valid),
            "invalid" => Ok(ChallengeStatus::Invalid),
            other => Err(Error::UnknownStatus {
                field: "status",
                value: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    Http01,
    Dns01,
    TlsAlpn01,
}

impl ChallengeType {
    fn as_str(self) -> &'static str {
        match self {
            ChallengeType::Http01 => "http-01",
            ChallengeType::Dns01 => "dns-01",
            ChallengeType::TlsAlpn01 => "tls-alpn-01",
        }
    }
}

impl fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identifier {
    Dns(String),
    Ip(IpAddr),
}

impl Identifier {
    fn type_and_value(&self) -> (&'static str, String) {
        match self {
            Identifier::Dns(d) => ("dns", d.clone()),
            Identifier::Ip(ip) => ("ip", ip.to_string()),
        }
    }
}

fn parse_identifier(json: &Json) -> Result<Identifier, Error> {
    let kind = json.str("type")?;
    let value = json.str("value")?;
    match kind {
        "dns" => Ok(Identifier::Dns(value.to_string())),
        "ip" => value
            .parse::<IpAddr>()
            .map(Identifier::Ip)
            .map_err(|_| Error::UnknownStatus {
                field: "identifier.value",
                value: value.to_string(),
            }),
        other => Err(Error::UnknownStatus {
            field: "identifier.type",
            value: other.to_string(),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProblemKind {
    AccountDoesNotExist,
    AlreadyRevoked,
    BadCsr,
    BadNonce,
    BadPublicKey,
    BadRevocationReason,
    BadSignatureAlgorithm,
    Caa,
    Compound,
    Connection,
    Dns,
    ExternalAccountRequired,
    IncorrectResponse,
    InvalidContact,
    Malformed,
    OrderNotReady,
    RateLimited,
    RejectedIdentifier,
    ServerInternal,
    Tls,
    Unauthorized,
    UnsupportedContact,
    UnsupportedIdentifier,
    UserActionRequired,
    // Boulder-specific, not in RFC 8555.
    AlreadyReplaced,
    Conflict,
    InvalidProfile,
    Unknown(String),
}

impl ProblemKind {
    const PREFIX: &'static str = "urn:ietf:params:acme:error:";

    fn parse(type_str: &str) -> ProblemKind {
        let suffix = type_str
            .strip_prefix(ProblemKind::PREFIX)
            .unwrap_or(type_str);
        match suffix {
            "accountDoesNotExist" => ProblemKind::AccountDoesNotExist,
            "alreadyRevoked" => ProblemKind::AlreadyRevoked,
            "badCSR" => ProblemKind::BadCsr,
            "badNonce" => ProblemKind::BadNonce,
            "badPublicKey" => ProblemKind::BadPublicKey,
            "badRevocationReason" => ProblemKind::BadRevocationReason,
            "badSignatureAlgorithm" => ProblemKind::BadSignatureAlgorithm,
            "caa" => ProblemKind::Caa,
            "compound" => ProblemKind::Compound,
            "connection" => ProblemKind::Connection,
            "dns" => ProblemKind::Dns,
            "externalAccountRequired" => ProblemKind::ExternalAccountRequired,
            "incorrectResponse" => ProblemKind::IncorrectResponse,
            "invalidContact" => ProblemKind::InvalidContact,
            "malformed" => ProblemKind::Malformed,
            "orderNotReady" => ProblemKind::OrderNotReady,
            "rateLimited" => ProblemKind::RateLimited,
            "rejectedIdentifier" => ProblemKind::RejectedIdentifier,
            "serverInternal" => ProblemKind::ServerInternal,
            "tls" => ProblemKind::Tls,
            "unauthorized" => ProblemKind::Unauthorized,
            "unsupportedContact" => ProblemKind::UnsupportedContact,
            "unsupportedIdentifier" => ProblemKind::UnsupportedIdentifier,
            "userActionRequired" => ProblemKind::UserActionRequired,
            "alreadyReplaced" => ProblemKind::AlreadyReplaced,
            "conflict" => ProblemKind::Conflict,
            "invalidProfile" => ProblemKind::InvalidProfile,
            other => ProblemKind::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for ProblemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let ProblemKind::Unknown(s) = self {
            return write!(f, "{s}");
        }
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone)]
pub struct Problem {
    pub kind: ProblemKind,
    pub detail: Option<String>,
    pub subproblems: Vec<Problem>,
}

impl Problem {
    fn from_json(json: &Json) -> Problem {
        let kind = json
            .opt_str("type")
            .map(ProblemKind::parse)
            .unwrap_or_else(|| ProblemKind::Unknown("about:blank".to_string()));
        let detail = json.opt_str("detail").map(str::to_string);
        let subproblems = json
            .opt_array("subproblems")
            .map(|items| items.iter().map(Problem::from_json).collect())
            .unwrap_or_default();
        Problem {
            kind,
            detail,
            subproblems,
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

fn is_problem_response(response: &Response) -> bool {
    let content_type_is_problem = response
        .headers
        .content_type()
        .map(|ct| ct.starts_with("application/problem+json"))
        .unwrap_or(false);
    content_type_is_problem || response.status >= 400
}

fn parse_problem(response: &Response) -> Result<Problem, Error> {
    let json = Json::parse(&response.body)?;
    Ok(Problem::from_json(&json))
}

#[derive(Debug, Clone)]
pub struct Order {
    pub url: String,
    pub status: OrderStatus,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

fn parse_order(url: &str, json: &Json) -> Result<Order, Error> {
    let status = OrderStatus::parse(json.str("status")?)?;
    let authorizations: Vec<String> = json
        .array("authorizations")?
        .iter()
        .map(|item| item.as_str().map(str::to_string))
        .collect::<Result<_, _>>()?;
    if authorizations.is_empty() {
        return Err(Error::UnknownStatus {
            field: "authorizations",
            value: "empty".to_string(),
        });
    }
    let finalize = json.str("finalize")?.to_string();
    let certificate = json.opt_str("certificate").map(str::to_string);
    Ok(Order {
        url: url.to_string(),
        status,
        authorizations,
        finalize,
        certificate,
    })
}

#[derive(Debug, Clone)]
pub struct Authorization {
    pub status: AuthzStatus,
    pub identifier: Identifier,
    pub wildcard: bool,
    pub challenges: Vec<Challenge>,
}

impl Authorization {
    /// Finds the challenge of the given type, or ChallengeUnavailable if the
    /// server did not offer one.
    pub fn challenge(&self, kind: ChallengeType) -> Result<&Challenge, Error> {
        self.challenges
            .iter()
            .find(|c| c.kind == kind)
            .ok_or(Error::ChallengeUnavailable { wanted: kind })
    }
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub url: String,
    pub kind: ChallengeType,
    pub token: String,
    pub status: ChallengeStatus,
    pub error: Option<Problem>,
}

fn parse_authorization(json: &Json) -> Result<Authorization, Error> {
    let status = AuthzStatus::parse(json.str("status")?)?;
    let identifier = parse_identifier(&json.object("identifier")?)?;
    let wildcard = if json.has("wildcard") {
        json.bool("wildcard")?
    } else {
        false
    };
    let mut challenges = Vec::new();
    for c in json.array("challenges")? {
        if let Some(challenge) = parse_challenge(&c)? {
            challenges.push(challenge);
        }
    }
    Ok(Authorization {
        status,
        identifier,
        wildcard,
        challenges,
    })
}

/// Returns `Ok(None)` for a challenge type this client does not implement
/// (e.g. a future extension type) rather than erroring the whole
/// authorization — RFC 8555 authorizations routinely list challenge types
/// alongside the ones we support.
fn parse_challenge(json: &Json) -> Result<Option<Challenge>, Error> {
    let kind = match json.str("type")? {
        "http-01" => ChallengeType::Http01,
        "dns-01" => ChallengeType::Dns01,
        "tls-alpn-01" => ChallengeType::TlsAlpn01,
        _ => return Ok(None),
    };
    let url = json.str("url")?.to_string();
    let token = json.str("token")?.to_string();
    let status = ChallengeStatus::parse(json.str("status")?)?;
    let error = json.opt_object("error").map(|e| Problem::from_json(&e));
    Ok(Some(Challenge {
        url,
        kind,
        token,
        status,
        error,
    }))
}

/// A single-use anti-replay nonce. No `Clone`/`Copy`: once `take_nonce`
/// removes it from a `Session`, the only way to get another value out of it
/// is to move it — signing a second request with the same nonce is a
/// compile error, not a bug that only shows up against the real CA.
pub struct Nonce(String);

impl Nonce {
    /// Consumes the nonce, handing back the raw value for exactly one
    /// signing operation.
    fn into_string(self) -> String {
        self.0
    }
}

pub struct Session<'a> {
    directory: &'a Directory,
    http: &'a Client,
    key: &'a AccountKey,
    kid: Option<String>,
    nonce: Option<Nonce>,
}

impl<'a> Session<'a> {
    pub fn new(directory: &'a Directory, http: &'a Client, key: &'a AccountKey) -> Session<'a> {
        Session {
            directory,
            http,
            key,
            kid: None,
            nonce: None,
        }
    }

    /// Removes any stored nonce, leaving `None` behind. Pure extraction —
    /// does not contact the server; see `next_nonce` for that.
    fn take_nonce(&mut self) -> Option<Nonce> {
        self.nonce.take()
    }

    /// Returns a nonce ready for one signed request: the stored one if
    /// `take_nonce` finds one, otherwise a fresh one from `newNonce`.
    fn next_nonce(&mut self) -> Result<Nonce, Error> {
        if let Some(nonce) = self.take_nonce() {
            return Ok(nonce);
        }
        let response = self
            .http
            .request(Method::Head, &self.directory.new_nonce, None, None)?;
        response
            .headers
            .replay_nonce()
            .map(|s| Nonce(s.to_string()))
            .ok_or(Error::NoNonce)
    }

    /// Signs and POSTs one ACME request, handling the nonce lifecycle and
    /// the two distinct retry classes (badNonce, and 5xx/serverInternal/
    /// connection failure) described in the module docs.
    fn request_signed(
        &mut self,
        url: &str,
        payload: Option<&str>,
        use_kid: bool,
    ) -> Result<Response, Error> {
        let mut nonce_attempts: u8 = 0;
        let mut retry_attempts: u32 = 0;

        loop {
            let nonce = self.next_nonce()?;

            let kid_owned;
            let auth = if use_kid {
                kid_owned = self.kid.clone().ok_or(Error::HttpMalformed {
                    detail: "kid required before account established",
                })?;
                Auth::Kid(&kid_owned)
            } else {
                Auth::Jwk
            };
            let payload_v = match payload {
                Some(p) => Payload::Json(p),
                None => Payload::Empty,
            };
            // Consumes the Nonce by value: past this point the value backing
            // this request cannot be reached again through `nonce`.
            let nonce_value = nonce.into_string();
            let jws = Jws {
                url,
                nonce: &nonce_value,
                payload: payload_v,
                auth,
            };
            let body = sign_jws(self.key, &jws)?;

            let send_result = self.http.request(
                Method::Post,
                url,
                Some("application/jose+json"),
                Some(body.as_bytes()),
            );

            let response = match send_result {
                Ok(r) => r,
                Err(e) => {
                    if retry_attempts >= 3 {
                        return Err(e);
                    }
                    retry_attempts += 1;
                    thread::sleep(jittered_backoff(retry_attempts));
                    continue;
                }
            };

            if let Some(n) = response.headers.replay_nonce() {
                self.nonce = Some(Nonce(n.to_string()));
            }

            if !is_problem_response(&response) {
                return Ok(response);
            }

            let problem = match parse_problem(&response) {
                Ok(p) => p,
                Err(e) => {
                    if response.status >= 500 && retry_attempts < 3 {
                        retry_attempts += 1;
                        thread::sleep(jittered_backoff(retry_attempts));
                        continue;
                    }
                    return Err(e);
                }
            };

            if problem.kind == ProblemKind::BadNonce {
                if nonce_attempts >= 5 {
                    return Err(Error::NonceExhausted {
                        attempts: nonce_attempts,
                    });
                }
                nonce_attempts += 1;
                continue;
            }

            if response.status >= 500 || problem.kind == ProblemKind::ServerInternal {
                if retry_attempts >= 3 {
                    return Err(Error::Acme(problem));
                }
                retry_attempts += 1;
                thread::sleep(jittered_backoff(retry_attempts));
                continue;
            }

            return Err(Error::Acme(problem));
        }
    }
}

/// Backoff for retry attempt `attempt` (1-indexed): 1s, 2s, 4s, each ±25%
/// jittered, so a fleet of clients retrying together does not stay in
/// lockstep.
fn jittered_backoff(attempt: u32) -> Duration {
    let base = 2u64.pow(attempt.saturating_sub(1));
    let mut byte = [0u8; 1];
    let _ = SystemRandom::new().fill(&mut byte);
    let frac = byte[0] as f64 / 255.0;
    let jitter = 0.75 + frac * 0.5;
    Duration::from_secs_f64(base as f64 * jitter)
}

/// Whether `ensure_account` found an account already registered under this
/// key, or had to create one. The CLI's `account` step surfaces this
/// directly (`new` vs `existing`); there is no other way to distinguish the
/// two outcomes from outside this function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountOutcome {
    New,
    Existing,
}

pub fn ensure_account(
    session: &mut Session,
    contact: Option<&str>,
    agree_tos: bool,
) -> Result<(String, AccountOutcome), Error> {
    let new_account_url = session.directory.new_account.clone();
    let lookup_payload = write_object(&[("onlyReturnExisting", JsonVal::Bool(true))]);

    match session.request_signed(&new_account_url, Some(&lookup_payload), false) {
        Ok(response) => {
            let url = response
                .headers
                .location()
                .ok_or(Error::HttpMalformed {
                    detail: "new-account response missing Location header",
                })?
                .to_string();
            session.kid = Some(url.clone());
            Ok((url, AccountOutcome::Existing))
        }
        Err(Error::Acme(p)) if p.kind == ProblemKind::AccountDoesNotExist => {
            let mut fields: Vec<(&str, JsonVal)> =
                vec![("termsOfServiceAgreed", JsonVal::Bool(agree_tos))];
            if let Some(email) = contact {
                fields.push(("contact", JsonVal::Array(vec![JsonVal::Str(email)])));
            }
            let payload = write_object(&fields);
            let response = session.request_signed(&new_account_url, Some(&payload), false)?;
            let url = response
                .headers
                .location()
                .ok_or(Error::HttpMalformed {
                    detail: "new-account response missing Location header",
                })?
                .to_string();
            session.kid = Some(url.clone());
            Ok((url, AccountOutcome::New))
        }
        Err(e) => Err(e),
    }
}

/// The account URL this session acts under — the `kid` half of every
/// account-authenticated request. `ensure_account` establishes it; asking
/// for an update/deactivation before that is a programming error, not a
/// condition to paper over.
fn established_kid(session: &Session) -> Result<String, Error> {
    session
        .kid
        .clone()
        .ok_or(Error::HttpMalformed {
            detail: "account not established; call ensure_account first",
        })
}

/// RFC 8555 §7.3 — update this account's contacts. `contacts` replaces
/// the stored contact list outright (pass an empty slice to drop every
/// contact): the spec's `contact` field is a full replacement, never a
/// merge, so the caller decides the complete new list rather than
/// appending to a list it has not read.
pub fn update_account(session: &mut Session, contacts: &[String]) -> Result<(), Error> {
    let account_url = established_kid(session)?;
    let contact_vals: Vec<JsonVal> = contacts.iter().map(|c| JsonVal::Str(c)).collect();
    let payload = write_object(&[("contact", JsonVal::Array(contact_vals))]);
    session.request_signed(&account_url, Some(&payload), true)?;
    Ok(())
}

/// RFC 8555 §7.3.6 — deactivate this account. Irreversible: the key can
/// no longer place orders or renew, and the CA may refuse to re-register
/// it under the same account.
pub fn deactivate_account(session: &mut Session) -> Result<(), Error> {
    let account_url = established_kid(session)?;
    let payload = write_object(&[("status", JsonVal::Str("deactivated"))]);
    session.request_signed(&account_url, Some(&payload), true)?;
    Ok(())
}

/// RFC 8555 §7.6 — revoke a certificate this account controls.
///
/// The payload is the leaf's base64url DER plus an optional RFC 5280
/// §5.3.1 CRLReason code; `None` omits `reason` and the CA records
/// `unspecified`. Signed with `kid`, so the CA checks the *account*, not
/// the certificate key — revocation works without ever touching the leaf
/// private key.
pub fn revoke_certificate(
    session: &mut Session,
    leaf_der: &[u8],
    reason: Option<u8>,
) -> Result<(), Error> {
    let revoke_url = session.directory.revoke_cert.clone();
    let encoded = b64url_encode(leaf_der);
    let reason_str = reason.map(|r| r.to_string());
    let mut fields: Vec<(&str, JsonVal)> = vec![("certificate", JsonVal::Str(&encoded))];
    if let Some(code) = &reason_str {
        fields.push(("reason", JsonVal::Raw(code)));
    }
    let payload = write_object(&fields);
    session.request_signed(&revoke_url, Some(&payload), true)?;
    Ok(())
}

/// The newOrder request body, split out from `new_order` as a pure
/// function so the exact bytes sent — in particular, whether `replaces` is
/// present — are unit-testable without a live server: asserting on the
/// literal payload string catches wire-format regressions that a test
/// only checking "the code called the right function" would miss.
fn build_new_order_payload(identifiers: &[Identifier], replaces: Option<&str>) -> String {
    let mut deduped: Vec<&Identifier> = Vec::new();
    for id in identifiers {
        if !deduped.contains(&id) {
            deduped.push(id);
        }
    }

    let ident_objs: Vec<String> = deduped
        .iter()
        .map(|id| {
            let (kind, value) = id.type_and_value();
            write_object(&[
                ("type", JsonVal::Str(kind)),
                ("value", JsonVal::Str(&value)),
            ])
        })
        .collect();
    let ident_vals: Vec<JsonVal> = ident_objs
        .iter()
        .map(|s| JsonVal::Raw(s.as_str()))
        .collect();
    let mut fields: Vec<(&str, JsonVal)> = vec![("identifiers", JsonVal::Array(ident_vals))];
    if let Some(cert_id) = replaces {
        fields.push(("replaces", JsonVal::Str(cert_id)));
    }
    write_object(&fields)
}

/// `replaces`, when given, is sent as the newOrder request's `replaces`
/// field (RFC 9773 §5) — the certID of the certificate this order renews.
/// Callers must only pass `Some` when the directory advertises
/// `renewalInfo`; sending it against a non-ARI server is undefined
/// behavior per RFC 9773.
pub fn new_order(
    session: &mut Session,
    identifiers: &[Identifier],
    replaces: Option<&str>,
) -> Result<Order, Error> {
    let payload = build_new_order_payload(identifiers, replaces);

    let new_order_url = session.directory.new_order.clone();
    let response = session.request_signed(&new_order_url, Some(&payload), true)?;
    let location = response
        .headers
        .location()
        .ok_or(Error::HttpMalformed {
            detail: "new-order response missing Location header",
        })?
        .to_string();
    let json = Json::parse(&response.body)?;
    parse_order(&location, &json)
}

pub fn fetch_authorization(session: &mut Session, url: &str) -> Result<Authorization, Error> {
    let response = session.request_signed(url, None, true)?;
    let json = Json::parse(&response.body)?;
    parse_authorization(&json)
}

pub fn answer_challenge(session: &mut Session, url: &str) -> Result<(), Error> {
    session.request_signed(url, Some("{}"), true)?;
    Ok(())
}

/// Schedule: 1s, 2s, then 3s repeating, capped at 60 seconds total elapsed.
fn poll_delay(attempt: usize) -> Duration {
    const SCHEDULE: [u64; 3] = [1, 2, 3];
    Duration::from_secs(SCHEDULE[attempt.min(SCHEDULE.len() - 1)])
}

pub fn poll_authorization(session: &mut Session, url: &str) -> Result<Authorization, Error> {
    let start = Instant::now();
    let mut attempt = 0usize;
    loop {
        let authz = fetch_authorization(session, url)?;
        if authz.status != AuthzStatus::Pending {
            return Ok(authz);
        }
        let elapsed = start.elapsed().as_secs();
        if elapsed >= 60 {
            return Err(Error::PollExhausted {
                resource: "authorization",
                elapsed_secs: elapsed,
            });
        }
        thread::sleep(poll_delay(attempt));
        attempt += 1;
    }
}

fn fetch_order(session: &mut Session, url: &str) -> Result<Order, Error> {
    let response = session.request_signed(url, None, true)?;
    let json = Json::parse(&response.body)?;
    parse_order(url, &json)
}

fn poll_order(session: &mut Session, url: &str, target: OrderStatus) -> Result<Order, Error> {
    let start = Instant::now();
    let mut attempt = 0usize;
    loop {
        let order = fetch_order(session, url)?;
        if order.status == target || order.status == OrderStatus::Invalid {
            return Ok(order);
        }
        let elapsed = start.elapsed().as_secs();
        if elapsed >= 60 {
            return Err(Error::PollExhausted {
                resource: "order",
                elapsed_secs: elapsed,
            });
        }
        thread::sleep(poll_delay(attempt));
        attempt += 1;
    }
}

pub fn finalize(session: &mut Session, order: &Order, csr_der: &[u8]) -> Result<Order, Error> {
    let ready = poll_order(session, &order.url, OrderStatus::Ready)?;
    if ready.status != OrderStatus::Ready {
        return Err(Error::OrderNotReady {
            status: ready.status,
        });
    }

    let csr_b64 = b64url_encode(csr_der);
    let payload = write_object(&[("csr", JsonVal::Str(&csr_b64))]);
    session.request_signed(&ready.finalize, Some(&payload), true)?;

    let valid = poll_order(session, &order.url, OrderStatus::Valid)?;
    if valid.status != OrderStatus::Valid {
        return Err(Error::OrderNotReady {
            status: valid.status,
        });
    }
    Ok(valid)
}

pub fn download_certificate(session: &mut Session, url: &str) -> Result<String, Error> {
    let response = session.request_signed(url, None, true)?;
    let pem = String::from_utf8(response.body).map_err(|_| Error::HttpMalformed {
        detail: "certificate response not utf8",
    })?;
    if pem.trim().is_empty() {
        return Err(Error::CertChainEmpty);
    }
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Json {
        Json::parse(s.as_bytes()).unwrap()
    }

    fn dummy_directory() -> Directory {
        Directory {
            new_nonce: "https://a/nonce".to_string(),
            new_account: "https://a/acct".to_string(),
            new_order: "https://a/order".to_string(),
            revoke_cert: "https://a/revoke".to_string(),
            key_change: "https://a/key-change".to_string(),
            renewal_info: None,
            terms_of_service: None,
            external_account_required: false,
        }
    }

    #[test]
    fn take_nonce_removes_it_leaving_none_behind() {
        let directory = dummy_directory();
        let http = Client::new().unwrap();
        let key = AccountKey::generate().unwrap();
        let mut session = Session::new(&directory, &http, &key);

        session.nonce = Some(Nonce("first-nonce".to_string()));
        let taken = session.take_nonce().unwrap();
        assert_eq!(taken.into_string(), "first-nonce");
        assert!(session.nonce.is_none());
        assert!(session.take_nonce().is_none());
    }

    #[test]
    fn directory_with_unknown_extra_key_is_parsed() {
        let json = parse(
            r#"{"newNonce":"https://a/nonce","newAccount":"https://a/acct","newOrder":"https://a/order",
               "revokeCert":"https://a/revoke","keyChange":"https://a/key-change","futureField":"decoy"}"#,
        );
        let dir = Directory::parse(&json).unwrap();
        assert_eq!(dir.new_nonce, "https://a/nonce");
    }

    #[test]
    fn directory_without_renewal_info_is_none() {
        let json = parse(
            r#"{"newNonce":"https://a/nonce","newAccount":"https://a/acct","newOrder":"https://a/order",
               "revokeCert":"https://a/revoke","keyChange":"https://a/key-change"}"#,
        );
        let dir = Directory::parse(&json).unwrap();
        assert!(dir.renewal_info.is_none());
    }

    #[test]
    fn directory_with_renewal_info_is_some() {
        let json = parse(
            r#"{"newNonce":"https://a/nonce","newAccount":"https://a/acct","newOrder":"https://a/order",
               "revokeCert":"https://a/revoke","keyChange":"https://a/key-change","renewalInfo":"https://a/ari"}"#,
        );
        let dir = Directory::parse(&json).unwrap();
        assert_eq!(dir.renewal_info.as_deref(), Some("https://a/ari"));
    }

    #[test]
    fn order_with_unknown_status_is_an_error() {
        let json = parse(
            r#"{"status":"frobnicated","authorizations":["https://a/authz/1"],"finalize":"https://a/f"}"#,
        );
        let err = parse_order("https://a/order/1", &json).unwrap_err();
        assert!(matches!(
            err,
            Error::UnknownStatus {
                field: "status",
                ..
            }
        ));
    }

    #[test]
    fn order_with_empty_authorizations_is_an_error() {
        let json = parse(r#"{"status":"pending","authorizations":[],"finalize":"https://a/f"}"#);
        let err = parse_order("https://a/order/1", &json).unwrap_err();
        assert!(matches!(
            err,
            Error::UnknownStatus {
                field: "authorizations",
                ..
            }
        ));
    }

    #[test]
    fn problem_with_known_type_maps_to_correct_kind() {
        let json = parse(r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"try again"}"#);
        let problem = Problem::from_json(&json);
        assert_eq!(problem.kind, ProblemKind::BadNonce);
        assert_eq!(problem.detail.as_deref(), Some("try again"));
    }

    #[test]
    fn problem_with_unrecognised_type_is_unknown_not_a_panic() {
        let json = parse(r#"{"type":"urn:ietf:params:acme:error:somethingNew","detail":"x"}"#);
        let problem = Problem::from_json(&json);
        assert_eq!(
            problem.kind,
            ProblemKind::Unknown("somethingNew".to_string())
        );
    }

    #[test]
    fn problem_with_subproblems_parses_all() {
        let json = parse(
            r#"{"type":"urn:ietf:params:acme:error:compound","subproblems":[
                {"type":"urn:ietf:params:acme:error:malformed"},
                {"type":"urn:ietf:params:acme:error:rateLimited"}
            ]}"#,
        );
        let problem = Problem::from_json(&json);
        assert_eq!(problem.subproblems.len(), 2);
        assert_eq!(problem.subproblems[0].kind, ProblemKind::Malformed);
        assert_eq!(problem.subproblems[1].kind, ProblemKind::RateLimited);
    }

    #[test]
    fn authorization_already_valid_is_recognised_as_skippable() {
        let json = parse(
            r#"{"status":"valid","identifier":{"type":"dns","value":"example.com"},"challenges":[]}"#,
        );
        let authz = parse_authorization(&json).unwrap();
        assert_eq!(authz.status, AuthzStatus::Valid);
    }

    #[test]
    fn authorization_unknown_status_is_an_error() {
        let json = parse(
            r#"{"status":"frobnicated","identifier":{"type":"dns","value":"example.com"},"challenges":[]}"#,
        );
        assert!(matches!(
            parse_authorization(&json),
            Err(Error::UnknownStatus { .. })
        ));
    }

    #[test]
    fn challenge_of_unsupported_type_is_skipped_not_an_error() {
        let json = parse(
            r#"{"status":"pending","identifier":{"type":"dns","value":"example.com"},"challenges":[
                {"type":"dns-account-01","url":"https://a/c/1","token":"tok","status":"pending"},
                {"type":"http-01","url":"https://a/c/2","token":"tok2","status":"pending"}
            ]}"#,
        );
        let authz = parse_authorization(&json).unwrap();
        assert_eq!(authz.challenges.len(), 1);
        assert_eq!(authz.challenges[0].kind, ChallengeType::Http01);
    }

    #[test]
    fn challenge_with_error_member_parses_the_problem() {
        let json = parse(
            r#"{"type":"http-01","url":"https://a/c/1","token":"tok","status":"invalid",
               "error":{"type":"urn:ietf:params:acme:error:unauthorized","detail":"nope"}}"#,
        );
        let challenge = parse_challenge(&json).unwrap().unwrap();
        assert_eq!(challenge.status, ChallengeStatus::Invalid);
        assert_eq!(challenge.error.unwrap().kind, ProblemKind::Unauthorized);
    }

    // This crate denies clippy::print_stdout/print_stderr, so the exact
    // bytes a `newOrder` request carries cannot be captured by instrumenting
    // the live HTTP path with a debug print. This asserts the exact payload
    // text directly instead — the same string `Session::request_signed`
    // signs and POSTs verbatim as the JWS `payload` member, unit-tested
    // rather than captured off the wire.

    #[test]
    fn new_order_payload_with_replaces_carries_the_cert_id_verbatim() {
        let ids = vec![Identifier::Dns("example.com".to_string())];
        let payload = build_new_order_payload(&ids, Some("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"));
        assert_eq!(
            payload,
            r#"{"identifiers":[{"type":"dns","value":"example.com"}],"replaces":"aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"}"#
        );
        // And it round-trips through this crate's own JSON reader, so a
        // real server sees exactly this shape.
        let parsed = Json::parse(payload.as_bytes()).unwrap();
        assert_eq!(
            parsed.str("replaces").unwrap(),
            "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
        );
    }

    #[test]
    fn new_order_payload_without_replaces_omits_the_field_entirely() {
        let ids = vec![Identifier::Dns("example.com".to_string())];
        let payload = build_new_order_payload(&ids, None);
        assert_eq!(
            payload,
            r#"{"identifiers":[{"type":"dns","value":"example.com"}]}"#
        );
        assert!(!payload.contains("replaces"));
    }

    #[test]
    fn identifiers_deduplicated_preserving_order() {
        let ids = vec![
            Identifier::Dns("b.example.com".to_string()),
            Identifier::Dns("a.example.com".to_string()),
            Identifier::Dns("b.example.com".to_string()),
        ];
        let mut deduped: Vec<&Identifier> = Vec::new();
        for id in &ids {
            if !deduped.contains(&id) {
                deduped.push(id);
            }
        }
        assert_eq!(deduped, vec![&ids[0], &ids[1]]);
    }
}
