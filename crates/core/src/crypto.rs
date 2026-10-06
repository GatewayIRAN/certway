use crate::error::Error;
use crate::json::{write_object, JsonVal};
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use zeroize::Zeroizing;

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

fn b64url_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Rejects any character outside the unpadded base64url alphabet (including
/// `=`) and a final group of exactly one leftover byte, which cannot encode
/// even one full output byte.
pub fn b64url_decode(input: &str) -> Result<Vec<u8>, Error> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Error::Base64 {
            detail: "final group has one leftover byte",
        });
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let v = b64url_val(b).ok_or(Error::Base64 {
            detail: "character outside base64url alphabet",
        })? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

/// A P-256 ECDSA account key, as used for ACME account authentication.
pub struct AccountKey {
    keypair: EcdsaKeyPair,
    pkcs8: Zeroizing<Vec<u8>>,
    jwk: String,
    thumbprint: [u8; 32],
}

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKey { .. }")
    }
}

impl AccountKey {
    pub fn generate() -> Result<AccountKey, Error> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| Error::KeyGeneration)?;
        AccountKey::from_pkcs8_bytes(Zeroizing::new(doc.as_ref().to_vec()))
    }

    pub fn from_pkcs8(bytes: &[u8]) -> Result<AccountKey, Error> {
        AccountKey::from_pkcs8_bytes(Zeroizing::new(bytes.to_vec()))
    }

    fn from_pkcs8_bytes(pkcs8: Zeroizing<Vec<u8>>) -> Result<AccountKey, Error> {
        let rng = SystemRandom::new();
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|e| Error::KeyFormat {
                detail: e.to_string(),
            })?;

        let point = keypair.public_key().as_ref();
        if point.len() != 65 || point[0] != 0x04 {
            return Err(Error::KeyFormat {
                detail: "unexpected public key point encoding".to_string(),
            });
        }
        let x = &point[1..33];
        let y = &point[33..65];

        let jwk = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            b64url_encode(x),
            b64url_encode(y)
        );
        let hash = digest::digest(&digest::SHA256, jwk.as_bytes());
        let mut thumbprint = [0u8; 32];
        thumbprint.copy_from_slice(hash.as_ref());

        Ok(AccountKey {
            keypair,
            pkcs8,
            jwk,
            thumbprint,
        })
    }

    pub fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        self.pkcs8.clone()
    }

    pub fn thumbprint(&self) -> &[u8; 32] {
        &self.thumbprint
    }

    pub fn jwk(&self) -> &str {
        &self.jwk
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let rng = SystemRandom::new();
        let sig = self
            .keypair
            .sign(&rng, message)
            .map_err(|_| Error::Signing)?;
        Ok(sig.as_ref().to_vec())
    }
}

pub struct Jws<'a> {
    pub url: &'a str,
    pub nonce: &'a str,
    pub payload: Payload<'a>,
    pub auth: Auth<'a>,
}

pub enum Payload<'a> {
    /// POST-as-GET: the payload member is the empty string.
    Empty,
    /// Already-serialised JSON.
    Json(&'a str),
}

pub enum Auth<'a> {
    /// newAccount and key rollover only.
    Jwk,
    /// Everything else — the account URL.
    Kid(&'a str),
}

pub fn sign_jws(key: &AccountKey, jws: &Jws) -> Result<String, Error> {
    let mut header: Vec<(&str, JsonVal)> = vec![
        ("alg", JsonVal::Str("ES256")),
        ("nonce", JsonVal::Str(jws.nonce)),
        ("url", JsonVal::Str(jws.url)),
    ];
    match jws.auth {
        Auth::Jwk => header.push(("jwk", JsonVal::Raw(key.jwk()))),
        Auth::Kid(kid) => header.push(("kid", JsonVal::Str(kid))),
    }
    let protected = write_object(&header);

    let payload = match jws.payload {
        Payload::Empty => String::new(),
        Payload::Json(s) => s.to_string(),
    };

    let protected_b64 = b64url_encode(protected.as_bytes());
    let payload_b64 = b64url_encode(payload.as_bytes());
    let signing_input = format!("{protected_b64}.{payload_b64}");

    let signature = key.sign(signing_input.as_bytes())?;
    let signature_b64 = b64url_encode(&signature);

    Ok(write_object(&[
        ("protected", JsonVal::Str(&protected_b64)),
        ("payload", JsonVal::Str(&payload_b64)),
        ("signature", JsonVal::Str(&signature_b64)),
    ]))
}

/// HTTP-01 publishes this value as-is.
pub fn key_authorization(token: &str, key: &AccountKey) -> String {
    format!("{token}.{}", b64url_encode(key.thumbprint()))
}

/// DNS-01 publishes the SHA-256 hash of the key authorization, not the
/// key authorization itself.
pub fn dns_challenge_value(token: &str, key: &AccountKey) -> String {
    hash_key_authorization(&key_authorization(token, key))
}

/// The SHA-256 + base64url hash of an already-built key authorization
/// string. `dns_challenge_value` above is this applied to a
/// freshly-computed one; `challenge::Dns01Solver` calls it directly since
/// its `Task` already carries the key authorization.
pub fn hash_key_authorization(key_authorization: &str) -> String {
    let hash = digest::digest(&digest::SHA256, key_authorization.as_bytes());
    b64url_encode(hash.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7638 §3.1 worked example (RSA), used to verify the SHA-256 and
    // base64url path independently of this module's P-256-only JWK builder.
    const RFC7638_CANONICAL: &str = concat!(
        r#"{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_"#,
        r#"BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}"#
    );
    const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    #[test]
    fn rfc7638_sha256_and_base64url_path() {
        let hash = digest::digest(&digest::SHA256, RFC7638_CANONICAL.as_bytes());
        assert_eq!(b64url_encode(hash.as_ref()), RFC7638_THUMBPRINT);
    }

    #[test]
    fn b64url_round_trip_all_byte_values() {
        let input: Vec<u8> = (0..=255).collect();
        let encoded = b64url_encode(&input);
        assert!(!encoded.contains('='));
        let decoded = b64url_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn b64url_decode_rejects_padding() {
        assert!(matches!(b64url_decode("QQ=="), Err(Error::Base64 { .. })));
    }

    #[test]
    fn b64url_decode_rejects_one_leftover_byte() {
        assert!(matches!(b64url_decode("A"), Err(Error::Base64 { .. })));
    }

    #[test]
    fn b64url_decode_rejects_non_alphabet_character() {
        assert!(matches!(b64url_decode("abc!"), Err(Error::Base64 { .. })));
    }

    #[test]
    fn generate_serialize_load_same_thumbprint() {
        let key = AccountKey::generate().unwrap();
        let pkcs8 = key.to_pkcs8();
        let loaded = AccountKey::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(key.thumbprint(), loaded.thumbprint());
    }

    #[test]
    fn from_pkcs8_random_bytes_errors_no_panic() {
        let bytes = [0x42u8; 64];
        assert!(AccountKey::from_pkcs8(&bytes).is_err());
    }

    #[test]
    fn from_pkcs8_empty_slice_errors_no_panic() {
        assert!(AccountKey::from_pkcs8(&[]).is_err());
    }

    /// Empty input fails ring's ASN.1 parse ("InvalidEncoding"), while a
    /// syntactically valid PKCS#8 document with a corrupted private-key
    /// octet fails ring's public/private key consistency check
    /// ("InconsistentComponents"). Different failure modes must not
    /// collapse into one message.
    #[test]
    fn from_pkcs8_empty_and_inconsistent_bytes_report_different_reasons() {
        let empty_err = AccountKey::from_pkcs8(&[]).unwrap_err();

        let key = AccountKey::generate().unwrap();
        let mut mutated = key.to_pkcs8().to_vec();
        let idx = mutated.len() - 20;
        mutated[idx] ^= 0xFF;
        let inconsistent_err = AccountKey::from_pkcs8(&mutated).unwrap_err();

        let (
            Error::KeyFormat {
                detail: empty_detail,
            },
            Error::KeyFormat {
                detail: inconsistent_detail,
            },
        ) = (empty_err, inconsistent_err)
        else {
            panic!("expected KeyFormat errors");
        };
        assert_ne!(empty_detail, inconsistent_detail);
    }

    #[test]
    fn signature_is_exactly_64_bytes() {
        let key = AccountKey::generate().unwrap();
        let sig = key.sign(b"message").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn two_signatures_over_same_message_differ() {
        let key = AccountKey::generate().unwrap();
        let sig1 = key.sign(b"message").unwrap();
        let sig2 = key.sign(b"message").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn canonical_jwk_json_is_byte_exact() {
        let key = AccountKey::generate().unwrap();
        let jwk = key.jwk();
        assert!(jwk.starts_with(r#"{"crv":"P-256","kty":"EC","x":""#));
        assert!(!jwk.contains(' '));
        let x_start = jwk.find("\"x\":\"").unwrap() + 5;
        let x_end = jwk[x_start..].find('"').unwrap() + x_start;
        let y_start = jwk.find("\"y\":\"").unwrap() + 5;
        let y_end = jwk[y_start..].find('"').unwrap() + y_start;
        assert!(jwk.find("\"crv\"").unwrap() < jwk.find("\"kty\"").unwrap());
        assert!(jwk.find("\"kty\"").unwrap() < jwk.find("\"x\"").unwrap());
        assert!(jwk.find("\"x\"").unwrap() < jwk.find("\"y\"").unwrap());
        let x = b64url_decode(&jwk[x_start..x_end]).unwrap();
        let y = b64url_decode(&jwk[y_start..y_end]).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
    }

    /// A naive implementation that strips leading zero bytes from the
    /// coordinate before encoding passes every other test and fails only
    /// this one. Coordinates beginning with a zero byte occur roughly once
    /// in 256 keys, so generate until one appears.
    #[test]
    fn coordinate_with_leading_zero_byte_stays_32_bytes() {
        let mut generated = 0u32;
        loop {
            generated += 1;
            let key = AccountKey::generate().unwrap();
            let jwk = key.jwk();
            let x_start = jwk.find("\"x\":\"").unwrap() + 5;
            let x_end = jwk[x_start..].find('"').unwrap() + x_start;
            let y_start = jwk.find("\"y\":\"").unwrap() + 5;
            let y_end = jwk[y_start..].find('"').unwrap() + y_start;
            let x = b64url_decode(&jwk[x_start..x_end]).unwrap();
            let y = b64url_decode(&jwk[y_start..y_end]).unwrap();
            if x[0] == 0 || y[0] == 0 {
                assert_eq!(x.len(), 32);
                assert_eq!(y.len(), 32);
                break;
            }
            if generated > 100_000 {
                panic!("no leading-zero coordinate found after 100000 keys");
            }
        }
    }

    #[test]
    fn auth_jwk_header_contains_jwk_never_kid() {
        let key = AccountKey::generate().unwrap();
        let jws = Jws {
            url: "https://example.com/acme/new-account",
            nonce: "n0nce",
            payload: Payload::Empty,
            auth: Auth::Jwk,
        };
        let out = sign_jws(&key, &jws).unwrap();
        let parsed = crate::json::Json::parse(out.as_bytes()).unwrap();
        let protected_b64 = parsed.str("protected").unwrap();
        let protected = String::from_utf8(b64url_decode(protected_b64).unwrap()).unwrap();
        assert!(protected.contains("\"jwk\""));
        assert!(!protected.contains("\"kid\""));
    }

    #[test]
    fn auth_kid_header_contains_kid_never_jwk() {
        let key = AccountKey::generate().unwrap();
        let jws = Jws {
            url: "https://example.com/acme/order/1",
            nonce: "n0nce",
            payload: Payload::Empty,
            auth: Auth::Kid("https://example.com/acme/acct/1"),
        };
        let out = sign_jws(&key, &jws).unwrap();
        let parsed = crate::json::Json::parse(out.as_bytes()).unwrap();
        let protected_b64 = parsed.str("protected").unwrap();
        let protected = String::from_utf8(b64url_decode(protected_b64).unwrap()).unwrap();
        assert!(protected.contains("\"kid\""));
        assert!(!protected.contains("\"jwk\""));
    }

    #[test]
    fn empty_payload_produces_empty_string_payload_member() {
        let key = AccountKey::generate().unwrap();
        let jws = Jws {
            url: "https://example.com/acme/order/1",
            nonce: "n0nce",
            payload: Payload::Empty,
            auth: Auth::Kid("https://example.com/acme/acct/1"),
        };
        let out = sign_jws(&key, &jws).unwrap();
        assert!(out.contains("\"payload\":\"\""));
    }

    #[test]
    fn signing_input_contains_exactly_one_dot() {
        let key = AccountKey::generate().unwrap();
        let jws = Jws {
            url: "https://example.com/acme/order/1",
            nonce: "n0nce",
            payload: Payload::Json(r#"{"status":"ready"}"#),
            auth: Auth::Kid("https://example.com/acme/acct/1"),
        };
        let out = sign_jws(&key, &jws).unwrap();
        let parsed = crate::json::Json::parse(out.as_bytes()).unwrap();
        let protected_b64 = parsed.str("protected").unwrap();
        let payload_b64 = parsed.str("payload").unwrap();
        let signing_input = format!("{protected_b64}.{payload_b64}");
        assert_eq!(signing_input.matches('.').count(), 1);
    }

    #[test]
    fn debug_output_has_no_key_material() {
        let key = AccountKey::generate().unwrap();
        let debug = format!("{key:?}");
        assert_eq!(debug, "AccountKey { .. }");
        assert!(!debug.contains(&b64url_encode(key.thumbprint())));
    }

    #[test]
    fn key_authorization_and_dns_challenge_value_differ() {
        let key = AccountKey::generate().unwrap();
        let ka = key_authorization("token123", &key);
        let dns = dns_challenge_value("token123", &key);
        assert_ne!(ka, dns);
    }
}
