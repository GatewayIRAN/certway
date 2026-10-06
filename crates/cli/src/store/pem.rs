// SPDX-License-Identifier: MIT

//! Minimal PKCS#8 PEM encode/decode for the account key. `certway-core`'s
//! `AccountKey` only speaks raw PKCS#8 DER
//! (`to_pkcs8`/`from_pkcs8`) — rcgen's `KeyPair` PEM helpers (used for the
//! certificate key in `csr.rs`) aren't available for the `ring`-backed
//! account key, so this crate carries its own small standard-base64 PEM
//! wrapper rather than reaching for a crate.

use zeroize::Zeroizing;

const LABEL: &str = "PRIVATE KEY";
const LINE_WIDTH: usize = 64;
const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn std_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(STD_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(STD_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            STD_ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            STD_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn std_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn std_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in s.bytes().filter(|&b| b != b'=') {
        let v = std_val(b).ok_or("account key PEM contains invalid base64")? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

/// Encodes raw PKCS#8 DER as a `-----BEGIN PRIVATE KEY-----` PEM block,
/// wrapped at 64 columns. The returned string is `Zeroizing`, matching
/// `csr::CertKey::to_pkcs8_pem`'s convention for the certificate key — this
/// is the account key's private material in text form.
pub fn encode_pkcs8_pem(der: &[u8]) -> Zeroizing<String> {
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(LABEL);
    out.push_str("-----\n");
    let b64 = std_encode(der);
    for chunk in b64.as_bytes().chunks(LINE_WIDTH) {
        // `std_encode`'s alphabet plus '=' is pure ASCII, so this is always
        // valid UTF-8 to re-slice as str.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(LABEL);
    out.push_str("-----\n");
    Zeroizing::new(out)
}

/// Decodes a `-----BEGIN PRIVATE KEY-----` PEM block back to raw PKCS#8 DER.
/// Returns `Err` with a short reason (never panics) on anything that isn't a
/// well-formed PEM block — the caller (`store::account`) turns that into
/// the hard error required for a corrupt `account.key` (never a silent
/// regeneration, since that would orphan the existing ACME account).
pub fn decode_pkcs8_pem(pem: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let begin = format!("-----BEGIN {LABEL}-----");
    let end = format!("-----END {LABEL}-----");
    let start = pem.find(&begin).ok_or("missing PEM begin marker")?;
    let rest = &pem[start + begin.len()..];
    let stop = rest.find(&end).ok_or("missing PEM end marker")?;
    let b64: String = rest[..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if b64.is_empty() {
        return Err("PEM block is empty");
    }
    std_decode(&b64).map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_bytes() {
        let der: Vec<u8> = (0u8..=255).cycle().take(300).collect();
        let pem = encode_pkcs8_pem(&der);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
        let decoded = decode_pkcs8_pem(&pem).unwrap();
        assert_eq!(&decoded[..], der.as_slice());
    }

    #[test]
    fn lines_wrap_at_64_columns() {
        let der = vec![0xABu8; 100];
        let pem = encode_pkcs8_pem(&der);
        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(
                line.len() <= LINE_WIDTH,
                "line too long: {} chars",
                line.len()
            );
        }
    }

    #[test]
    fn missing_markers_error_not_panic() {
        assert!(decode_pkcs8_pem("not a pem at all").is_err());
        assert!(decode_pkcs8_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n").is_err());
        assert!(decode_pkcs8_pem("").is_err());
    }

    #[test]
    fn invalid_base64_character_errors() {
        let pem = "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n";
        assert!(decode_pkcs8_pem(pem).is_err());
    }

    #[test]
    fn empty_body_errors() {
        let pem = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n";
        assert!(decode_pkcs8_pem(pem).is_err());
    }
}
