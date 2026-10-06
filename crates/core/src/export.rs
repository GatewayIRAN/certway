//! Export format builders: `pem` (the existing per-file layout
//! `store::cert::write_certificate` already writes, unchanged), `combined`
//! (private key, then the full chain, one file — HAProxy), and `der` (leaf
//! only, binary).
//!
//! **PKCS#12 is not implemented in this build.** RFC 7292's `PKCS#12` is
//! built from a `PKCS8ShroudedKeyBag` — a PBES2-encrypted PKCS#8 key — and
//! PBES2 needs a block cipher. `ring` 0.17.14's only symmetric cipher
//! surface is AEAD (`AES_128_GCM`/`AES_256_GCM`/`CHACHA20_POLY1305`); it has
//! no CBC mode, and none of the other five approved crates carry symmetric
//! crypto at all. AES-256-GCM under PBES2 was prototyped and rejected by
//! OpenSSL's own encoder (`openssl pkcs8 -topk8 -v2 aes-256-gcm` →
//! `pkcs8: AEAD ciphers not supported`) and, symmetrically, a hand-built
//! `EncryptedPrivateKeyInfo` using it fails to decrypt under `openssl
//! pkcs8` — not an encoding bug on either side, AEAD is simply not wired
//! into that code path in this OpenSSL. This is a deliberate stop pending a
//! dependency decision, not a silent workaround.

use crate::error::Error;
use crate::http::parse_pem_certificates;

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// Splits a `fullchain.pem`-shaped PEM string (leaf first, per RFC 8555's
/// `application/pem-certificate-chain` ordering) into each certificate's
/// own block — `-----BEGIN CERTIFICATE-----` through the newline after the
/// matching `-----END CERTIFICATE-----`, byte-identical to the source.
/// Every export format that needs individual certificates shares this one
/// splitter rather than a separate ad-hoc string search each.
pub fn split_pem_certs(pem: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut consumed = 0usize;
    while let Some(begin_rel) = pem[consumed..].find(BEGIN) {
        let begin = consumed + begin_rel;
        let Some(end_rel) = pem[begin..].find(END) else {
            break;
        };
        let after_end = begin + end_rel + END.len();
        // Include the newline right after END, if there is one, so the
        // blocks concatenate back into exactly the original text.
        let block_end = match pem[after_end..].find('\n') {
            Some(nl) => after_end + nl + 1,
            None => pem.len(),
        };
        blocks.push(&pem[begin..block_end]);
        consumed = block_end;
    }
    blocks
}

/// The leaf certificate's block, and everything after it joined —
/// `cert.pem`/`chain.pem`'s contents (`store::cert::write_certificate`). A
/// chain with only one certificate yields an empty second string.
pub fn split_leaf_and_chain(pem: &str) -> (String, String) {
    let blocks = split_pem_certs(pem);
    match blocks.split_first() {
        Some((leaf, chain)) => (leaf.to_string(), chain.concat()),
        None => (pem.to_string(), String::new()),
    }
}

/// `combined` format: the private key PEM first, then the full certificate
/// chain, leaf first — HAProxy's `bind ... crt <pem>` ordering.
/// `docs/ref/haproxy-ssl-3.0.8.md`'s own worked fixture is built the
/// identical way (`cat k.pem c.pem > certs/test.pem`, key before cert),
/// independently confirming that ordering.
///
/// Reversing this order is not a load-time error: HAProxy accepts the
/// file and only fails on the first TLS handshake, hours later — see this
/// module's ordering test (`combined_pem_puts_key_before_the_chain`),
/// confirmed live by temporarily swapping this function's two arguments and
/// watching that test fail with the expected message, then reverting.
pub fn combined_pem(key_pem: &str, fullchain_pem: &str) -> String {
    let mut out = String::with_capacity(key_pem.len() + fullchain_pem.len() + 1);
    out.push_str(key_pem);
    if !key_pem.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(fullchain_pem);
    out
}

/// `der` format: the leaf certificate only, binary DER. Reuses
/// `http::parse_pem_certificates` — the crate's one existing
/// PEM-to-DER path (already exercised against real Let's Encrypt/Pebble
/// chains for CA-bundle loading) — rather than a second base64 decoder.
pub fn leaf_der(fullchain_pem: &str) -> Result<Vec<u8>, Error> {
    let certs = parse_pem_certificates(fullchain_pem)?;
    certs
        .into_iter()
        .next()
        .map(|c| c.as_ref().to_vec())
        .ok_or(Error::CertChainEmpty)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAF: &str = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";
    const INTER: &str = "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nKEYBYTES\n-----END PRIVATE KEY-----\n";

    #[test]
    fn split_pem_certs_multi_cert() {
        let pem = format!("{LEAF}{INTER}");
        let blocks = split_pem_certs(&pem);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], LEAF);
        assert_eq!(blocks[1], INTER);
        assert_eq!(
            blocks.concat(),
            pem,
            "blocks must concatenate back to the exact source"
        );
    }

    #[test]
    fn split_leaf_and_chain_single_cert_yields_empty_chain() {
        let (leaf, chain) = split_leaf_and_chain(LEAF);
        assert_eq!(leaf, LEAF);
        assert!(chain.is_empty());
    }

    /// Asserts `combined_pem` puts the key first — a byte-order assertion,
    /// not a substring check.
    #[test]
    fn combined_pem_puts_key_before_the_chain() {
        let fullchain = format!("{LEAF}{INTER}");
        let combined = combined_pem(KEY, &fullchain);
        let key_pos = combined.find("PRIVATE KEY").unwrap();
        let leaf_pos = combined.find("LEAF").unwrap();
        assert!(
            key_pos < leaf_pos,
            "key must precede the leaf certificate in combined-PEM output"
        );
        assert!(combined.starts_with(KEY));
        assert_eq!(combined, format!("{KEY}{LEAF}{INTER}"));
    }

    #[test]
    fn leaf_der_first_byte_is_der_sequence_tag() {
        // base64("\x30\x03\x02\x01\x01") — SEQUENCE { INTEGER 1 } — a
        // minimal but genuinely valid DER encoding, not a placeholder.
        let pem = "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";
        let der = leaf_der(pem).unwrap();
        assert_eq!(der, vec![0x30, 0x03, 0x02, 0x01, 0x01]);
        assert_eq!(der[0], 0x30, "DER SEQUENCE tag");
    }

    #[test]
    fn leaf_der_on_empty_chain_is_cert_chain_empty_error() {
        assert!(matches!(leaf_der(""), Err(Error::CertChainEmpty)));
    }
}
