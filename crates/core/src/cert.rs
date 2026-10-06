//! X.509 certificate parsing, by hand (RFC 5280).
//!
//! Reads exactly the fields the rest of this crate needs from a leaf
//! certificate's DER encoding: `notBefore`/`notAfter`, the raw serial
//! number, the Authority Key Identifier's `keyIdentifier` octets (if
//! present), the subject alternative names, and the raw `subjectPublicKey`
//! bytes. Nothing else is read — no signature verification, no issuer or
//! subject distinguished name, no extension other than AKI and SAN. This is
//! a reader, not a validator: an unrecognized or malformed extension this
//! module doesn't care about is skipped, never rejected.
//!
//! `serial_der` and `aki_key_id` hold DER *content* octets — the bytes
//! inside the INTEGER/OCTET STRING, not the tag+length+value that encodes
//! them. Verified against RFC 9773 §4.1's own worked example: the certID
//! `aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE` decodes to a 20-byte left half (a
//! SHA-1-length keyIdentifier) and a 5-byte right half starting `0x00` (an
//! INTEGER's content octets, including its sign-avoidance byte) — not a
//! 22-byte OCTET STRING TLV or a 7-byte INTEGER TLV. Parsing the serial to
//! a number and re-encoding it would drop that leading byte and produce a
//! different, wrong certID.

use crate::error::Error;

pub use crate::acme::Identifier;

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const BOOLEAN: u8 = 0x01;
const CTX0_EXPLICIT_VERSION: u8 = 0xA0;
const CTX1_ISSUER_UID: u8 = 0x81;
const CTX2_SUBJECT_UID: u8 = 0x82;
const CTX3_EXPLICIT_EXTENSIONS: u8 = 0xA3;
const AKI_KEY_ID: u8 = 0x80;
const SAN_DNS_NAME: u8 = 0x82;
const SAN_IP_ADDRESS: u8 = 0x87;

/// `id-ce-authorityKeyIdentifier`, 2.5.29.35, DER content octets.
const OID_AKI: [u8; 3] = [0x55, 0x1D, 0x23];
/// `id-ce-subjectAltName`, 2.5.29.17, DER content octets.
const OID_SAN: [u8; 3] = [0x55, 0x1D, 0x11];

fn err(detail: &'static str) -> Error {
    Error::CertParse { detail }
}

/// A bounds-checked cursor over a DER byte slice. Every read either
/// advances past a fully-present TLV or returns an error — there is no
/// state from which a caller can read past the end of `data`.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Reads one TLV: tag, DER length (short or long form, 1-4 length
    /// octets), and exactly that many content bytes. Rejects the BER
    /// indefinite-length form (`0x80` alone) — never valid in DER — and any
    /// length that would read past the end of `data`.
    fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let tag = *self
            .data
            .get(self.pos)
            .ok_or(err("truncated: expected a tag byte"))?;
        self.pos += 1;
        let len_byte = *self
            .data
            .get(self.pos)
            .ok_or(err("truncated: expected a length byte"))?;
        self.pos += 1;

        let len = if len_byte & 0x80 == 0 {
            len_byte as usize
        } else {
            let n = (len_byte & 0x7f) as usize;
            if n == 0 {
                return Err(err("indefinite-length DER encoding is not permitted"));
            }
            if n > 4 {
                return Err(err("length encoding longer than 4 octets"));
            }
            if self.remaining() < n {
                return Err(err("truncated: length octets"));
            }
            let mut len: usize = 0;
            for _ in 0..n {
                len = (len << 8) | self.data[self.pos] as usize;
                self.pos += 1;
            }
            len
        };

        if self.remaining() < len {
            return Err(err("truncated: content shorter than declared length"));
        }
        let content = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, content))
    }

    fn expect_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], Error> {
        let (tag, content) = self.read_tlv()?;
        if tag != expected_tag {
            return Err(err("unexpected tag"));
        }
        Ok(content)
    }
}

/// The four fields `renew`/`list`/`ari` need from a leaf certificate, plus
/// its subject alternative names and raw public key.
#[derive(Debug, Clone)]
pub struct ParsedCert {
    pub not_before: i64,
    pub not_after: i64,
    /// Raw DER content octets of the `serialNumber` INTEGER — not an
    /// integer this crate ever parses or re-encodes. See the module doc.
    pub serial_der: Vec<u8>,
    /// `None` when the certificate carries no Authority Key Identifier
    /// extension at all (legal per RFC 5280 §4.2.1.1, though rare outside
    /// self-signed roots). Absent AKI means ARI is unavailable for this
    /// certificate — a fallback the caller handles, never a parse error.
    pub aki_key_id: Option<Vec<u8>>,
    pub sans: Vec<Identifier>,
    /// The raw `subjectPublicKey` BIT STRING content (unused-bits octet
    /// stripped). Required so callers can implement a post-renewal "key
    /// matches" check — comparing the renewed certificate's public key
    /// against the key it was issued for — which is otherwise
    /// unimplementable from a `ParsedCert` alone.
    pub public_key: Vec<u8>,
}

impl ParsedCert {
    /// Parses a single DER-encoded `Certificate`. Every read is
    /// bounds-checked (see `Reader`); malformed or truncated input always
    /// produces `Err(Error::CertParse { .. })`, never a panic or a hang.
    pub fn from_der(der: &[u8]) -> Result<ParsedCert, Error> {
        let mut outer = Reader::new(der);
        let cert_content = outer.expect_tlv(SEQUENCE)?;

        let mut cert = Reader::new(cert_content);
        let tbs_content = cert.expect_tlv(SEQUENCE)?;
        // signatureAlgorithm and signatureValue, the other two top-level
        // Certificate fields, are never read — this module verifies
        // nothing cryptographic.

        let mut tbs = Reader::new(tbs_content);

        if tbs.peek_tag() == Some(CTX0_EXPLICIT_VERSION) {
            tbs.read_tlv()?; // version — DEFAULT v1, absent entirely in a v1 cert
        }

        let serial_der = tbs.expect_tlv(INTEGER)?.to_vec();
        if serial_der.is_empty() {
            return Err(err("serial number has zero-length content"));
        }

        tbs.expect_tlv(SEQUENCE)?; // signature AlgorithmIdentifier — must equal the
                                   // outer one per RFC 5280 §4.1.1.2; not re-verified here
        tbs.expect_tlv(SEQUENCE)?; // issuer Name — not read

        let validity_content = tbs.expect_tlv(SEQUENCE)?;
        let mut validity = Reader::new(validity_content);
        let not_before = parse_time(&mut validity)?;
        let not_after = parse_time(&mut validity)?;

        tbs.expect_tlv(SEQUENCE)?; // subject Name — not read

        let spki_content = tbs.expect_tlv(SEQUENCE)?;
        let public_key = parse_subject_public_key(spki_content)?;

        if tbs.peek_tag() == Some(CTX1_ISSUER_UID) {
            tbs.read_tlv()?; // issuerUniqueID — deprecated, not read
        }
        if tbs.peek_tag() == Some(CTX2_SUBJECT_UID) {
            tbs.read_tlv()?; // subjectUniqueID — deprecated, not read
        }

        let mut aki_key_id = None;
        let mut sans = Vec::new();
        if tbs.peek_tag() == Some(CTX3_EXPLICIT_EXTENSIONS) {
            let wrapper_content = tbs.expect_tlv(CTX3_EXPLICIT_EXTENSIONS)?;
            let mut wrapper = Reader::new(wrapper_content);
            let list_content = wrapper.expect_tlv(SEQUENCE)?;
            let mut list = Reader::new(list_content);

            while !list.is_empty() {
                let ext_content = list.expect_tlv(SEQUENCE)?;
                let mut ext = Reader::new(ext_content);
                let oid = ext.expect_tlv(OID)?;
                if ext.peek_tag() == Some(BOOLEAN) {
                    ext.read_tlv()?; // critical flag — this module reads fields
                                     // regardless of criticality, it does not
                                     // validate the certificate
                }
                let value = ext.expect_tlv(OCTET_STRING)?;

                if oid == OID_AKI {
                    aki_key_id = parse_aki(value)?;
                } else if oid == OID_SAN {
                    sans = parse_sans(value)?;
                }
                // Any other extension — recognized or not — is skipped.
            }
        }

        Ok(ParsedCert {
            not_before,
            not_after,
            serial_der,
            aki_key_id,
            sans,
            public_key,
        })
    }

    /// Parses the first certificate found in `pem` — the leaf, per RFC
    /// 8555's `application/pem-certificate-chain` ordering. Everything
    /// from the first `-----END CERTIFICATE-----` onward — intermediates,
    /// trailing whitespace — is ignored.
    pub fn from_leaf_pem(pem: &str) -> Result<ParsedCert, Error> {
        let der = extract_first_pem_block(pem)?;
        ParsedCert::from_der(&der)
    }
}

fn parse_time(r: &mut Reader) -> Result<i64, Error> {
    let (tag, content) = r.read_tlv()?;
    match tag {
        UTC_TIME => parse_utc_time(content),
        GENERALIZED_TIME => parse_generalized_time(content),
        _ => Err(err("expected a UTCTime or GeneralizedTime")),
    }
}

fn ascii_digit_pair(b: &[u8], at: usize) -> Result<u32, Error> {
    let hi = *b.get(at).ok_or(err("time value truncated"))?;
    let lo = *b.get(at + 1).ok_or(err("time value truncated"))?;
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        return Err(err("time value contains a non-digit"));
    }
    Ok((hi - b'0') as u32 * 10 + (lo - b'0') as u32)
}

/// RFC 5280 §4.1.2.5.1: exactly `YYMMDDHHMMSSZ`, seconds and `Z` both
/// required, no fractional seconds, no numeric offset — the looser general
/// UTCTime grammar is not this profile. Two-digit year: 50-99 -> 19xx,
/// 00-49 -> 20xx.
fn parse_utc_time(content: &[u8]) -> Result<i64, Error> {
    if content.len() != 13 || content[12] != b'Z' {
        return Err(err("UTCTime must be exactly YYMMDDHHMMSSZ"));
    }
    let yy = ascii_digit_pair(content, 0)? as i64;
    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
    let month = ascii_digit_pair(content, 2)?;
    let day = ascii_digit_pair(content, 4)?;
    let hour = ascii_digit_pair(content, 6)?;
    let minute = ascii_digit_pair(content, 8)?;
    let second = ascii_digit_pair(content, 10)?;
    epoch_seconds(year, month, day, hour, minute, second)
}

/// Exactly `YYYYMMDDHHMMSSZ` — the same seconds+`Z`-required rule as
/// UTCTime, four-digit year.
fn parse_generalized_time(content: &[u8]) -> Result<i64, Error> {
    if content.len() != 15 || content[14] != b'Z' {
        return Err(err("GeneralizedTime must be exactly YYYYMMDDHHMMSSZ"));
    }
    let century = ascii_digit_pair(content, 0)? as i64;
    let yy = ascii_digit_pair(content, 2)? as i64;
    let year = century * 100 + yy;
    let month = ascii_digit_pair(content, 4)?;
    let day = ascii_digit_pair(content, 6)?;
    let hour = ascii_digit_pair(content, 8)?;
    let minute = ascii_digit_pair(content, 10)?;
    let second = ascii_digit_pair(content, 12)?;
    epoch_seconds(year, month, day, hour, minute, second)
}

/// Calendar fields to Unix seconds. No calendar/time crate is a dependency
/// of this crate, so this hand-writes Howard Hinnant's well-known
/// `days_from_civil` algorithm rather than reaching for one.
pub(crate) fn epoch_seconds(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<i64, Error> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(err("time field out of range"));
    }
    let days = days_from_civil(year, month, day);
    Ok(days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64)
}

/// Days since 1970-01-01 (proleptic Gregorian) for `(year, month, day)`.
/// Howard Hinnant's `days_from_civil`, verified correct for the whole
/// `i64` domain this crate ever feeds it (X.509 UTCTime/GeneralizedTime
/// years, and small deltas from `SystemTime::now()` for the HTTP `Date`
/// header) — not re-derived here, just transcribed.
pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(month) + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

fn parse_subject_public_key(spki_content: &[u8]) -> Result<Vec<u8>, Error> {
    let mut spki = Reader::new(spki_content);
    spki.expect_tlv(SEQUENCE)?; // algorithm AlgorithmIdentifier — not read
    let bits = spki.expect_tlv(BIT_STRING)?;
    let (unused_bits, key) = bits
        .split_first()
        .ok_or(err("subjectPublicKey BIT STRING is empty"))?;
    if *unused_bits != 0 {
        return Err(err(
            "subjectPublicKey BIT STRING has a non-zero unused-bits count",
        ));
    }
    Ok(key.to_vec())
}

/// `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET
/// STRING OPTIONAL, ... }` (RFC 5280 §4.2.1.1). Only the first field is
/// read; `authorityCertIssuer`/`authorityCertSerialNumber`, when present
/// instead, leave this `None` — RFC 9773's certID needs the keyIdentifier
/// form specifically.
fn parse_aki(extn_value: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let mut outer = Reader::new(extn_value);
    let seq_content = outer.expect_tlv(SEQUENCE)?;
    let mut seq = Reader::new(seq_content);
    if seq.peek_tag() == Some(AKI_KEY_ID) {
        let (_, content) = seq.read_tlv()?;
        return Ok(Some(content.to_vec()));
    }
    Ok(None)
}

/// `SubjectAltName ::= SEQUENCE OF GeneralName`. Only `dNSName` and
/// `iPAddress` are collected, matching the two `Identifier` variants this
/// crate models (`acme::Identifier`) — every other `GeneralName` choice
/// (`otherName`, `rfc822Name`, `directoryName`, ...) is skipped, the same
/// "recognized subset, others ignored" rule `acme::parse_challenge` already
/// applies to challenge types.
fn parse_sans(extn_value: &[u8]) -> Result<Vec<Identifier>, Error> {
    let mut outer = Reader::new(extn_value);
    let seq_content = outer.expect_tlv(SEQUENCE)?;
    let mut list = Reader::new(seq_content);
    let mut out = Vec::new();

    while !list.is_empty() {
        let (tag, content) = list.read_tlv()?;
        match tag {
            SAN_DNS_NAME => {
                if !content.is_ascii() {
                    return Err(err("dNSName is not valid IA5String"));
                }
                let name = std::str::from_utf8(content)
                    .map_err(|_| err("dNSName is not valid IA5String"))?;
                out.push(Identifier::Dns(name.to_string()));
            }
            SAN_IP_ADDRESS => {
                let ip = match content.len() {
                    4 => {
                        let mut b = [0u8; 4];
                        b.copy_from_slice(content);
                        std::net::IpAddr::from(b)
                    }
                    16 => {
                        let mut b = [0u8; 16];
                        b.copy_from_slice(content);
                        std::net::IpAddr::from(b)
                    }
                    _ => return Err(err("iPAddress GeneralName is neither 4 nor 16 bytes")),
                };
                out.push(Identifier::Ip(ip));
            }
            _ => {} // any other GeneralName choice — not an Identifier we track
        }
    }
    Ok(out)
}

fn extract_first_pem_block(pem: &str) -> Result<Vec<u8>, Error> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem
        .find(BEGIN)
        .ok_or(err("no PEM certificate block found"))?;
    let after_begin = start + BEGIN.len();
    let end_rel = pem[after_begin..]
        .find(END)
        .ok_or(err("unterminated PEM certificate block"))?;
    let b64: String = pem[after_begin..after_begin + end_rel]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    standard_base64_decode(&b64)
}

/// Standard (padded, `+`/`/`) base64 — PEM's alphabet, distinct from
/// `crypto::b64url_*`'s unpadded base64url used everywhere else in this
/// crate. `http.rs` has its own private copy of the same decoder for the
/// embedded CA bundle; duplicated here rather than shared across a
/// `cert -> http` dependency this crate's module boundaries don't allow.
fn standard_base64_decode(s: &str) -> Result<Vec<u8>, Error> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in s.bytes().filter(|&b| b != b'=') {
        let v = val(b).ok_or(err("invalid base64 in certificate"))? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    fn openssl(args: &[&str]) -> std::process::Output {
        Command::new("openssl")
            .args(args)
            .output()
            .expect("openssl must be on PATH for this test")
    }

    /// Generates a self-signed EC (P-256) certificate with a `subjectAltName`
    /// (two DNS names + one IP), an `authorityKeyIdentifier` (self-signed,
    /// so it equals its own `subjectKeyIdentifier` per RFC 5280 §4.2.1.1),
    /// and a serial number whose top byte is >= 0x80 — forcing openssl to
    /// prepend a `0x00` sign-avoidance byte, so this fixture exercises the
    /// leading-zero serial case.
    fn generate_fixture_cert(tmp_tag: &str) -> (Vec<u8>, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "certway-cert-fixture-{tmp_tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("key.pem");
        let cert_path = dir.join("cert.pem");

        let status = Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key_path)
            .status()
            .expect("openssl ecparam");
        assert!(status.success());

        // 0x80000000... forces a leading 0x00 sign-avoidance byte in the
        // DER INTEGER encoding of the serial. `-addext`, not `-extfile`:
        // `openssl req` (unlike `openssl x509 -req` / `openssl ca`) has no
        // `-extfile` option at all — verified live, `req: Extra (unknown)
        // options: "extfile" ...` — one-liner `-addext` is the form `req`
        // actually supports.
        let status = Command::new("openssl")
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key_path)
            .args([
                "-days",
                "30",
                "-subj",
                "/CN=fixture.example",
                "-set_serial",
                "0x8000000000000001",
                "-addext",
                "subjectAltName=DNS:example.com,DNS:www.example.com,IP:203.0.113.7",
                "-addext",
                "authorityKeyIdentifier=keyid:always",
                "-addext",
                "subjectKeyIdentifier=hash",
                "-out",
            ])
            .arg(&cert_path)
            .status()
            .expect("openssl req -x509");
        assert!(status.success());

        let pem = std::fs::read_to_string(&cert_path).unwrap();
        (extract_first_pem_block(&pem).unwrap(), cert_path)
    }

    #[test]
    fn parses_notbefore_notafter_serial_aki_sans_matching_openssl() {
        let (der, cert_path) = generate_fixture_cert("full");
        let parsed = ParsedCert::from_der(&der).unwrap();

        let text = String::from_utf8(
            openssl(&[
                "x509",
                "-in",
                cert_path.to_str().unwrap(),
                "-noout",
                "-text",
            ])
            .stdout,
        )
        .unwrap();
        assert!(text.contains("DNS:example.com"), "{text}");
        assert!(text.contains("DNS:www.example.com"), "{text}");
        assert!(text.contains("IP Address:203.0.113.7"), "{text}");

        assert_eq!(parsed.sans.len(), 3);
        assert!(parsed
            .sans
            .contains(&Identifier::Dns("example.com".to_string())));
        assert!(parsed
            .sans
            .contains(&Identifier::Dns("www.example.com".to_string())));
        assert!(parsed
            .sans
            .contains(&Identifier::Ip("203.0.113.7".parse().unwrap())));

        // Self-signed: AKI keyIdentifier must equal SKI, per RFC 5280 §4.2.1.1.
        let ski_text = String::from_utf8(
            openssl(&[
                "x509",
                "-in",
                cert_path.to_str().unwrap(),
                "-noout",
                "-ext",
                "subjectKeyIdentifier",
            ])
            .stdout,
        )
        .unwrap();
        let ski_hex: String = ski_text
            .lines()
            .nth(1)
            .unwrap()
            .trim()
            .replace(':', "")
            .to_ascii_lowercase();
        let aki = parsed.aki_key_id.clone().unwrap();
        let aki_hex: String = aki.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(aki_hex, ski_hex);

        // openssl -checkend proves notAfter is in the future by more than a
        // day; cross-check the actual parsed value against asn1parse below
        // instead of trusting -checkend's boolean alone.
        let asn1 =
            String::from_utf8(openssl(&["asn1parse", "-in", cert_path.to_str().unwrap()]).stdout)
                .unwrap();
        // The validity SEQUENCE's two UTCTime/GeneralizedTime lines
        // (openssl's asn1parse prints them as e.g. "UTCTIME :250101000000Z").
        let times: Vec<&str> = asn1
            .lines()
            .filter(|l| l.contains("UTCTIME") || l.contains("GENERALIZEDTIME"))
            .map(|l| l.rsplit(':').next().unwrap().trim())
            .collect();
        assert_eq!(
            times.len(),
            2,
            "expected exactly notBefore and notAfter:\n{asn1}"
        );
        assert!(parsed.not_before < parsed.not_after);
        assert!(
            parsed.not_after > parsed.not_before + 29 * 86400,
            "expected roughly a 30-day validity window"
        );

        let _ = std::fs::remove_dir_all(cert_path.parent().unwrap());
    }

    /// Finds the number immediately after `marker` in an `openssl
    /// asn1parse` structural line (e.g. `"hl=2"` -> 2), skipping the
    /// padding spaces that line's fixed-width columns use.
    fn number_after(line: &str, marker: &str) -> usize {
        let idx = line.find(marker).unwrap() + marker.len();
        let digits: String = line[idx..]
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().unwrap()
    }

    #[test]
    fn serial_with_leading_zero_byte_is_preserved_content_octets_not_reencoded() {
        let (der, cert_path) = generate_fixture_cert("leadingzero");
        let parsed = ParsedCert::from_der(&der).unwrap();

        // openssl -outform der: a byte-identical, independently-produced
        // copy of the DER this test's own `der` variable already holds
        // (via `extract_first_pem_block`'s base64 decode) — used here so
        // the cross-check below never touches this crate's own PEM
        // decoding, only openssl's.
        let der_path = cert_path.with_extension("der");
        let status = Command::new("openssl")
            .args([
                "x509",
                "-in",
                cert_path.to_str().unwrap(),
                "-outform",
                "der",
                "-out",
            ])
            .arg(&der_path)
            .status()
            .unwrap();
        assert!(status.success());
        let openssl_der = std::fs::read(&der_path).unwrap();

        // `openssl asn1parse`'s structural columns (offset, header length,
        // content length) are trustworthy — they are what lets it correctly
        // find every *subsequent* sibling element. Its abbreviated value
        // column is NOT: openssl prints an INTEGER's value as a minimal
        // big-number hex string, which drops exactly the DER
        // sign-avoidance 0x00 byte this test exists to verify — confirmed
        // live: `l=   9` (9 content bytes) alongside a displayed value of
        // only 8 hex bytes. So this test reads the raw content bytes
        // directly out of the independently-produced DER file at the
        // offset/length asn1parse reports, never from that abbreviated
        // text column.
        let asn1 =
            String::from_utf8(openssl(&["asn1parse", "-in", cert_path.to_str().unwrap()]).stdout)
                .unwrap();
        // Depth 2 plus "prim: INTEGER" is unambiguous for this fixture:
        // tbsCertificate is depth 1, version's `cont [ 0 ]` wrapper is
        // depth 2, but version's own INTEGER content is depth 3 inside it,
        // and serialNumber — version's sibling — is the only depth-2
        // INTEGER:
        //    8:d=2  hl=2 l=   3 cons: cont [ 0 ]
        //   10:d=3  hl=2 l=   1 prim: INTEGER   :02        <- version
        //   13:d=2  hl=2 l=   9 prim: INTEGER   :8000...   <- serialNumber
        let serial_line = asn1
            .lines()
            .find(|l| l.contains(":d=2") && l.contains("prim: INTEGER"))
            .unwrap();
        let offset = serial_line
            .split(':')
            .next()
            .unwrap()
            .trim()
            .parse::<usize>()
            .unwrap();
        let hl = number_after(serial_line, "hl=");
        let l = number_after(serial_line, " l=");
        let expected = &openssl_der[offset + hl..offset + hl + l];

        assert_eq!(
            parsed.serial_der, expected,
            "serial content octets must match the raw DER bytes exactly, leading 0x00 included"
        );
        assert_eq!(
            parsed.serial_der[0], 0x00,
            "top bit set in the value requires a DER sign-avoidance 0x00 byte"
        );
        assert_eq!(parsed.serial_der.len(), 9);

        let _ = std::fs::remove_dir_all(cert_path.parent().unwrap());
    }

    #[test]
    fn certificate_with_no_aki_extension_parses_with_none() {
        let dir =
            std::env::temp_dir().join(format!("certway-cert-fixture-noaki-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("key.pem");
        let cert_path = dir.join("cert.pem");
        let config_path = dir.join("minimal.cnf");

        let status = Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key_path)
            .status()
            .unwrap();
        assert!(status.success());

        // The system default openssl.cnf's own `x509_extensions` section
        // (used automatically by `req -x509`) adds subjectKeyIdentifier
        // *and* authorityKeyIdentifier on most distros — verified live,
        // plain `-subj` with no extension flags at all still produced an
        // AKI. A minimal `-config` with no `x509_extensions` directive at
        // all is what actually suppresses it.
        std::fs::write(
            &config_path,
            "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = noext.example\n",
        )
        .unwrap();
        let status = Command::new("openssl")
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key_path)
            .args(["-days", "30", "-config"])
            .arg(&config_path)
            .args(["-out"])
            .arg(&cert_path)
            .status()
            .unwrap();
        assert!(status.success());

        let pem = std::fs::read_to_string(&cert_path).unwrap();
        let der = extract_first_pem_block(&pem).unwrap();
        let parsed = ParsedCert::from_der(&der).unwrap();
        assert!(parsed.aki_key_id.is_none());
        assert!(parsed.sans.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_der_never_panics_and_always_errors() {
        let (der, cert_path) = generate_fixture_cert("truncate");
        for cut in [0usize, 1, 2, 5, 10, der.len() / 2, der.len() - 1] {
            let truncated = &der[..cut.min(der.len())];
            let result = ParsedCert::from_der(truncated);
            assert!(
                result.is_err(),
                "truncated to {cut} bytes must error, not succeed"
            );
        }
        let _ = std::fs::remove_dir_all(cert_path.parent().unwrap());
    }

    #[test]
    fn garbage_bytes_never_panic() {
        let cases: &[&[u8]] = &[
            b"",
            &[0x30],
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
            &[0x00; 16],
            &[0xff; 32],
        ];
        for case in cases {
            let _ = ParsedCert::from_der(case);
        }
    }

    #[test]
    fn deeply_nested_length_octets_do_not_allocate_unbounded_memory() {
        // A length byte claiming a 4-octet length of 0xFFFFFFFF must error
        // (declared length exceeds remaining input) rather than attempt to
        // read/allocate 4GB.
        let malformed = [0x30u8, 0x84, 0xff, 0xff, 0xff, 0xff];
        let result = ParsedCert::from_der(&malformed);
        assert!(result.is_err());
    }

    #[test]
    fn from_leaf_pem_reads_only_the_first_certificate_in_a_chain() {
        let (leaf_der, cert_path) = generate_fixture_cert("chain");
        let leaf_pem = std::fs::read_to_string(&cert_path).unwrap();
        // Simulate a fullchain.pem: leaf followed by a second (identical
        // for this test's purposes — only the *count* and *order* matter)
        // certificate block.
        let fullchain = format!("{leaf_pem}{leaf_pem}");
        let parsed = ParsedCert::from_leaf_pem(&fullchain).unwrap();
        let direct = ParsedCert::from_der(&leaf_der).unwrap();
        assert_eq!(parsed.serial_der, direct.serial_der);
        let _ = std::fs::remove_dir_all(cert_path.parent().unwrap());
    }

    #[test]
    fn days_from_civil_matches_known_epoch_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(2025, 1, 1), 20089);
    }

    #[test]
    fn epoch_seconds_rejects_out_of_range_fields() {
        assert!(epoch_seconds(2025, 13, 1, 0, 0, 0).is_err());
        assert!(epoch_seconds(2025, 1, 32, 0, 0, 0).is_err());
        assert!(epoch_seconds(2025, 1, 1, 24, 0, 0).is_err());
        assert!(epoch_seconds(2025, 1, 1, 0, 60, 0).is_err());
        assert!(epoch_seconds(2025, 1, 1, 0, 0, 60).is_err());
        assert!(epoch_seconds(2025, 1, 1, 0, 0, 59).is_ok());
    }
}
