//! ACME Renewal Information — certID construction and the renewal window
//! (RFC 9773).
//!
//! Two things this module deliberately does not do:
//!
//! - It never signs the RenewalInfo GET. RFC 9773 §4.1 is explicit this is
//!   the one ACME endpoint that is a plain, unauthenticated GET — wrapping
//!   it in `acme::Session`'s POST-as-GET convention is simply wrong here,
//!   not "more correct."
//! - It never touches disk. `Retry-After` caching to `ari.json` is the
//!   CLI's job, per this crate's one rule: `certway-core` returns values,
//!   `certway` decides what touches a file.

use crate::acme::Directory;
use crate::cert::{epoch_seconds, ParsedCert};
use crate::crypto::b64url_encode;
use crate::error::Error;
use crate::http::{Client, Method};
use crate::json::Json;
use ring::digest;

/// RFC 9773 §4.3.2's mandatory clamp: a client MUST clamp the effective
/// re-check interval to [1 minute, 1 day] regardless of what the server's
/// `Retry-After` header says.
const RETRY_AFTER_MIN_SECS: i64 = 60;
const RETRY_AFTER_MAX_SECS: i64 = 86_400;
/// §4.3.3's long-term default: used whenever `Retry-After` is missing or
/// unparseable, not only when the server errors outright.
const RETRY_AFTER_DEFAULT_SECS: i64 = 21_600;

/// `base64url(AKI keyIdentifier) "." base64url(DER serial number)` — RFC
/// 9773 §4.2. Constructible only from a `ParsedCert`: building this from a
/// serial number alone (or any other shortcut) produces a well-formed,
/// wrong identifier, per the RFC's own warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertId(String);

impl CertId {
    pub fn from_certificate(cert: &ParsedCert) -> Result<CertId, Error> {
        let aki = cert.aki_key_id.as_ref().ok_or(Error::AriUnavailable {
            detail: "certificate has no Authority Key Identifier",
        })?;
        let aki_b64 = b64url_encode(aki);
        let serial_b64 = b64url_encode(&cert.serial_der);
        Ok(CertId(format!("{aki_b64}.{serial_b64}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct RenewalWindow {
    pub start: i64,
    pub end: i64,
    pub explanation_url: Option<String>,
    /// Absolute Unix time after which a re-fetch is due. Already clamped to
    /// RFC 9773 §4.3.2's [1 minute, 1 day] bound and already carrying
    /// §4.3.3's six-hour default when the header was missing or invalid —
    /// the caller stores this verbatim, it does not redo the clamp.
    pub retry_after_deadline: i64,
}

/// `GET {renewalInfo}/{certID}` — RFC 9773 §4.1. Built directly on
/// `Client::request`, never on `acme::Session::request_signed`: no JWS
/// envelope, no nonce, exactly the plain, unauthenticated GET the RFC
/// mandates. `now` is the caller's current Unix time, threaded in rather
/// than read from `SystemTime::now()` here so this function stays a pure
/// mapping from (inputs) to (result) under test.
pub fn fetch_renewal_info(
    http: &Client,
    directory: &Directory,
    cert_id: &CertId,
    now: i64,
) -> Result<RenewalWindow, Error> {
    let base = directory
        .renewal_info
        .as_deref()
        .ok_or(Error::AriUnavailable {
            detail: "directory does not advertise renewalInfo",
        })?;
    let url = format!("{}/{}", base.trim_end_matches('/'), cert_id.as_str());

    let response = http.request(Method::Get, &url, None, None)?;
    if response.status != 200 {
        return Err(Error::http_status(response.status, &response.body));
    }

    let json = Json::parse(&response.body)?;
    let window = json.object("suggestedWindow")?;
    let start = parse_rfc3339(window.str("start")?)?;
    let end = parse_rfc3339(window.str("end")?)?;
    if end <= start {
        // RFC 9773 §4.2: an all-past window is valid — it means "renew
        // now." Only end <= start is a malformed RenewalInfo object, and
        // that must be treated the same as a failed fetch, not acted on.
        return Err(Error::AriWindowInvalid);
    }
    let explanation_url = json.opt_str("explanationURL").map(str::to_string);

    let delta = response
        .headers
        .retry_after()
        .and_then(parse_retry_after_delta)
        .map(|d| d.clamp(RETRY_AFTER_MIN_SECS, RETRY_AFTER_MAX_SECS))
        .unwrap_or(RETRY_AFTER_DEFAULT_SECS);

    Ok(RenewalWindow {
        start,
        end,
        explanation_url,
        retry_after_deadline: now + delta,
    })
}

/// The moment inside `window` this certificate renews at — seeded by a
/// hash of the certificate name, never drawn randomly: the same
/// certificate picks the same moment on every wake, and two different
/// certificates pick different moments. A fresh random draw per wake
/// would make the decision flap across the window boundary depending on
/// exactly when a timer fired.
///
/// Precondition: `window.end > window.start` — true of every `RenewalWindow`
/// `fetch_renewal_info` returns, since it rejects `end <= start` itself.
pub fn renewal_moment(cert_name: &str, window: &RenewalWindow) -> i64 {
    let hash = digest::digest(&digest::SHA256, cert_name.as_bytes());
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&hash.as_ref()[..8]);
    let seed = u64::from_be_bytes(seed_bytes);
    let span = (window.end - window.start).max(0) as u64;
    let offset = if span == 0 { 0 } else { seed % span };
    window.start + offset as i64
}

/// RFC 9773 §6's clock-skew check: the CA's `Date` header against local
/// time, on the first response of every run. `None` when the header is
/// absent or unparseable — never a failure, since a wrong clock must not
/// stop a renewal that is genuinely due. The CLI renders the `! time`
/// warning line when the magnitude exceeds 5 minutes; this function only
/// computes the difference.
pub fn skew_seconds(ca_date_header: &str, local_now: i64) -> Option<i64> {
    let ca_epoch = parse_http_date(ca_date_header)?;
    Some(local_now - ca_epoch)
}

/// Delta-seconds form only (`Retry-After: 21600`) — the only form any ACME
/// deployment this project targets (Let's Encrypt, Pebble; both Go
/// `net/http`) has been observed to send for `renewalInfo`, and the form
/// RFC 9773 §4.1's own worked example uses. The HTTP-date form RFC 7231
/// also permits for `Retry-After` is not implemented; an unparseable
/// header already falls back to §4.3.3's six-hour default, which is the
/// same outcome a correct HTTP-date parse of a header nothing sends would
/// produce.
fn parse_retry_after_delta(s: &str) -> Option<i64> {
    s.trim().parse::<i64>().ok().filter(|n| *n >= 0)
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)` — RFC 3339, the timestamp form
/// `suggestedWindow.start`/`.end` use. A numeric offset is applied to
/// compute the UTC instant, then discarded — fractional seconds are parsed
/// past but not retained (this crate works in whole Unix seconds
/// throughout).
fn parse_rfc3339(s: &str) -> Result<i64, Error> {
    let malformed = || Error::JsonType {
        field: "suggestedWindow",
        expected: "RFC 3339 timestamp",
    };

    if s.len() < 20 {
        return Err(malformed());
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(malformed());
    }
    match bytes[10] {
        b'T' | b't' | b' ' => {}
        _ => return Err(malformed()),
    }
    let year: i64 = s
        .get(0..4)
        .ok_or_else(malformed)?
        .parse()
        .map_err(|_| malformed())?;
    let month: u32 = s
        .get(5..7)
        .ok_or_else(malformed)?
        .parse()
        .map_err(|_| malformed())?;
    let day: u32 = s
        .get(8..10)
        .ok_or_else(malformed)?
        .parse()
        .map_err(|_| malformed())?;

    let rest = s.get(11..).ok_or_else(malformed)?;
    let rest_bytes = rest.as_bytes();
    if rest_bytes.len() < 8 || rest_bytes[2] != b':' || rest_bytes[5] != b':' {
        return Err(malformed());
    }
    let hour: u32 = rest
        .get(0..2)
        .ok_or_else(malformed)?
        .parse()
        .map_err(|_| malformed())?;
    let minute: u32 = rest
        .get(3..5)
        .ok_or_else(malformed)?
        .parse()
        .map_err(|_| malformed())?;
    let second: u32 = rest
        .get(6..8)
        .ok_or_else(malformed)?
        .parse()
        .map_err(|_| malformed())?;

    let after_seconds = rest.get(8..).ok_or_else(malformed)?;
    let marker_pos = after_seconds
        .find(['+', '-', 'Z', 'z'])
        .ok_or_else(malformed)?;
    let offset_part = &after_seconds[marker_pos..];

    let offset_seconds: i64 = if offset_part.eq_ignore_ascii_case("z") {
        0
    } else {
        let sign: i64 = match offset_part.as_bytes().first() {
            Some(b'+') => 1,
            Some(b'-') => -1,
            _ => return Err(malformed()),
        };
        let hhmm = &offset_part[1..];
        if hhmm.len() < 5 || hhmm.as_bytes()[2] != b':' {
            return Err(malformed());
        }
        let oh: i64 = hhmm
            .get(0..2)
            .ok_or_else(malformed)?
            .parse()
            .map_err(|_| malformed())?;
        let om: i64 = hhmm
            .get(3..5)
            .ok_or_else(malformed)?
            .parse()
            .map_err(|_| malformed())?;
        sign * (oh * 3600 + om * 60)
    };

    let utc = epoch_seconds(year, month, day, hour, minute, second)?;
    Ok(utc - offset_seconds)
}

/// RFC 7231 IMF-fixdate only: `"Sun, 06 Nov 1994 08:49:37 GMT"`. The other
/// two obsolete forms RFC 7231 also grandfathers in (RFC 850, asctime) are
/// not implemented — no server this project targets has ever been
/// observed to send them, since Go's `net/http` (Let's Encrypt, Pebble)
/// only emits IMF-fixdate. Returns `None` on any other shape, exactly like
/// an absent header — never an error; see `skew_seconds`'s doc comment.
fn parse_http_date(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() != 29 || !s.ends_with(" GMT") {
        return None;
    }
    let b = s.as_bytes();
    if b[3] != b','
        || b[4] != b' '
        || b[7] != b' '
        || b[11] != b' '
        || b[16] != b' '
        || b[19] != b':'
        || b[22] != b':'
    {
        return None;
    }
    let day: u32 = s.get(5..7)?.parse().ok()?;
    let month = month_from_abbrev(s.get(8..11)?)?;
    let year: i64 = s.get(12..16)?.parse().ok()?;
    let hour: u32 = s.get(17..19)?.parse().ok()?;
    let minute: u32 = s.get(20..22)?.parse().ok()?;
    let second: u32 = s.get(23..25)?.parse().ok()?;
    epoch_seconds(year, month, day, hour, minute, second).ok()
}

fn month_from_abbrev(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Identifier;

    fn cert_with(aki: Option<Vec<u8>>, serial: Vec<u8>) -> ParsedCert {
        ParsedCert {
            not_before: 0,
            not_after: 0,
            serial_der: serial,
            aki_key_id: aki,
            sans: vec![Identifier::Dns("example.com".to_string())],
            public_key: vec![],
        }
    }

    // RFC 9773 §4.1's own worked example — the certID
    // "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" decoded by hand from its two
    // base64url halves (verified independently with Python's
    // base64.urlsafe_b64decode before writing this test): a 20-byte AKI
    // keyIdentifier and a 5-byte serial whose content starts 0x00.
    #[test]
    fn cert_id_matches_rfc9773_worked_example() {
        let aki = vec![
            0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3, 0x7b, 0x84, 0x7b, 0xa0,
            0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4,
        ];
        let serial = vec![0x00, 0x87, 0x65, 0x43, 0x21];
        let cert = cert_with(Some(aki), serial);
        let cert_id = CertId::from_certificate(&cert).unwrap();
        assert_eq!(cert_id.as_str(), "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE");
    }

    #[test]
    fn cert_id_without_aki_is_unavailable_not_a_panic() {
        let cert = cert_with(None, vec![0x01]);
        assert!(matches!(
            CertId::from_certificate(&cert),
            Err(Error::AriUnavailable { .. })
        ));
    }

    #[test]
    fn cert_id_has_no_public_string_constructor() {
        // Compile-time property, exercised as a comment rather than an
        // assertion: CertId's only field is private, so the only way to
        // build one outside this crate is `from_certificate`. Building it
        // from a serial alone is not merely undesirable, it is not
        // possible to express.
        let cert = cert_with(Some(vec![0xaa; 20]), vec![0x00, 0x01]);
        let a = CertId::from_certificate(&cert).unwrap();
        let b = CertId::from_certificate(&cert).unwrap();
        assert_eq!(a, b);
    }

    fn window(start: i64, end: i64) -> RenewalWindow {
        RenewalWindow {
            start,
            end,
            explanation_url: None,
            retry_after_deadline: 0,
        }
    }

    #[test]
    fn renewal_moment_is_stable_across_calls() {
        let w = window(1_000_000, 1_086_400);
        let a = renewal_moment("example.com", &w);
        let b = renewal_moment("example.com", &w);
        assert_eq!(a, b);
        assert!(a >= w.start && a < w.end);
    }

    #[test]
    fn renewal_moment_differs_across_certificate_names() {
        let w = window(1_000_000, 1_086_400);
        let a = renewal_moment("example.com", &w);
        let b = renewal_moment("other.example.com", &w);
        assert_ne!(a, b, "two different certificate names landing on the exact same second is astronomically unlikely and would indicate a seeding bug");
    }

    #[test]
    fn renewal_moment_within_window_for_many_names() {
        let w = window(2_000_000_000, 2_000_086_400);
        for i in 0..200 {
            let name = format!("cert-{i}.example.com");
            let m = renewal_moment(&name, &w);
            assert!(
                m >= w.start && m < w.end,
                "{name} produced {m}, outside [{}, {})",
                w.start,
                w.end
            );
        }
    }

    #[test]
    fn rfc3339_z_form_parses() {
        assert_eq!(
            parse_rfc3339("2025-01-02T04:00:00Z").unwrap(),
            parse_rfc3339("2025-01-02T04:00:00+00:00").unwrap()
        );
    }

    #[test]
    fn rfc3339_positive_offset_shifts_earlier_in_utc() {
        let z = parse_rfc3339("2025-01-02T04:00:00Z").unwrap();
        let plus_two = parse_rfc3339("2025-01-02T06:00:00+02:00").unwrap();
        assert_eq!(z, plus_two);
    }

    #[test]
    fn rfc3339_negative_offset_shifts_later_in_utc() {
        let z = parse_rfc3339("2025-01-02T04:00:00Z").unwrap();
        let minus_five = parse_rfc3339("2025-01-01T23:00:00-05:00").unwrap();
        assert_eq!(z, minus_five);
    }

    #[test]
    fn rfc3339_fractional_seconds_are_ignored_not_an_error() {
        let a = parse_rfc3339("2025-01-02T04:00:00.987Z").unwrap();
        let b = parse_rfc3339("2025-01-02T04:00:00Z").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rfc3339_rejects_garbage() {
        for s in [
            "not a timestamp",
            "2025-01-02",
            "2025-01-02T04:00:00",
            "2025/01/02T04:00:00Z",
            "",
        ] {
            assert!(parse_rfc3339(s).is_err(), "expected {s:?} to be rejected");
        }
    }

    #[test]
    fn end_at_or_before_start_window_is_never_constructed_as_valid_by_the_seed_math() {
        // renewal_moment's own defensiveness (span.max(0)) — this does not
        // exercise fetch_renewal_info's own end<=start rejection (that
        // needs a live/mock server), but proves the seed arithmetic itself
        // never panics or divides by zero on a degenerate window.
        let degenerate = window(1000, 1000);
        let m = renewal_moment("example.com", &degenerate);
        assert_eq!(m, 1000);
    }

    #[test]
    fn http_date_parses_imf_fixdate() {
        let epoch = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        // Independently known Unix timestamp for this exact instant.
        assert_eq!(epoch, 784111777);
    }

    #[test]
    fn http_date_rejects_other_shapes() {
        assert!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").is_none());
        assert!(parse_http_date("Sun Nov  6 08:49:37 1994").is_none());
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("").is_none());
    }

    #[test]
    fn skew_seconds_none_on_unparseable_header() {
        assert!(skew_seconds("garbage", 1_000_000).is_none());
    }

    #[test]
    fn skew_seconds_computes_local_minus_ca() {
        let ca = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(
            skew_seconds("Sun, 06 Nov 1994 08:49:37 GMT", ca + 300).unwrap(),
            300
        );
    }

    #[test]
    fn retry_after_delta_parses_plain_integer_only() {
        assert_eq!(parse_retry_after_delta("21600"), Some(21600));
        assert_eq!(parse_retry_after_delta(" 300 "), Some(300));
        assert_eq!(parse_retry_after_delta("-5"), None);
        assert_eq!(
            parse_retry_after_delta("Sun, 06 Nov 1994 08:49:37 GMT"),
            None
        );
    }
}
