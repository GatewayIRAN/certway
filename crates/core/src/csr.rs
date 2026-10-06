use crate::acme::Identifier;
use crate::error::Error;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use zeroize::Zeroizing;

/// A certificate key pair (distinct from the ACME account key), used to
/// generate a CSR and later paired with the issued certificate.
pub struct CertKey {
    inner: KeyPair,
}

impl CertKey {
    pub fn generate() -> Result<CertKey, Error> {
        let inner = KeyPair::generate().map_err(|_| Error::KeyGeneration)?;
        Ok(CertKey { inner })
    }

    /// Only PKCS#8 is accepted, matching rcgen's `KeyPair::from_pem`.
    pub fn from_pkcs8_pem(pem: &str) -> Result<CertKey, Error> {
        let inner = KeyPair::from_pem(pem).map_err(|e| Error::KeyFormat {
            detail: e.to_string(),
        })?;
        Ok(CertKey { inner })
    }

    pub fn to_pkcs8_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(self.inner.serialize_pem())
    }

    /// Raw PKCS#8 DER — what a PKCS#12 `KeyBag`/`PKCS8ShroudedKeyBag` needs
    /// to wrap. Not used by this build's `export` command today (PKCS#12
    /// itself is blocked — see `export.rs`'s doc comment); added now so the
    /// crypto decision, once made, does not also require touching this
    /// file.
    pub fn to_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.inner.serialize_der())
    }

    /// The raw public key point — for P-256, the same uncompressed
    /// `0x04 || X || Y` format a certificate's `subjectPublicKey` BIT
    /// STRING content holds (`cert::ParsedCert::public_key`). Comparing the
    /// two directly implements the post-renewal "key matches" check — not
    /// implemented as a method on `ParsedCert` itself, since a
    /// key/certificate match is a relationship between the two, not a
    /// property of either alone.
    pub fn public_key_raw(&self) -> &[u8] {
        self.inner.public_key_raw()
    }
}

fn identifier_to_san(id: &Identifier) -> String {
    match id {
        Identifier::Dns(d) => d.clone(),
        Identifier::Ip(ip) => ip.to_string(),
    }
}

/// Returns the raw DER of a PKCS#10 CSR — not PEM. `not_before`, `not_after`
/// and `serial_number` are never set here: they cannot travel in a CSR and
/// some rcgen configurations reject them outright.
pub fn build_csr(key: &CertKey, identifiers: &[Identifier]) -> Result<Vec<u8>, Error> {
    if identifiers.is_empty() {
        return Err(Error::Csr {
            detail: "at least one identifier is required".to_string(),
        });
    }
    let sans: Vec<String> = identifiers.iter().map(identifier_to_san).collect();
    let mut params = CertificateParams::new(sans).map_err(|e| Error::Csr {
        detail: e.to_string(),
    })?;
    // `CertificateParams::new` defaults `distinguished_name` to
    // `CN=rcgen self signed cert` — meant for rcgen's self-signed-cert use
    // case, not a CSR. Left as-is, that
    // placeholder CN travels into the CSR's Subject field and real Let's
    // Encrypt rejects the order outright: "Cannot issue for \"rcgen self
    // signed cert\": Domain name contains an invalid character" (the
    // space) — confirmed live against production Let's Encrypt staging,
    // never caught by this crate's own tests or by Pebble, which is
    // lenient enough to not enforce Subject CN validity. SAN carries every
    // identifier already; an empty Subject is the modern, correct shape
    // for a Let's Encrypt cert (CA/Browser Forum baseline requirements
    // deprecate CN in favor of SAN) and is what a stock `certbot`/`acme.sh`
    // CSR also carries.
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&key.inner)
        .map_err(|e| Error::Csr {
            detail: e.to_string(),
        })?;
    Ok(csr.der().as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn openssl_verify(der: &[u8]) -> String {
        let mut child = Command::new("openssl")
            .args(["req", "-inform", "der", "-noout", "-text", "-verify"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("openssl must be on PATH for this test");
        child.stdin.take().unwrap().write_all(der).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "openssl verify failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    #[test]
    fn csr_output_is_der_not_pem() {
        let key = CertKey::generate().unwrap();
        let der = build_csr(&key, &[Identifier::Dns("example.com".to_string())]).unwrap();
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn csr_for_one_domain_verifies_with_openssl() {
        let key = CertKey::generate().unwrap();
        let der = build_csr(&key, &[Identifier::Dns("example.com".to_string())]).unwrap();
        let out = openssl_verify(&der);
        assert!(out.contains("Signature Verified OK") || out.contains("verify OK"));
        assert!(out.contains("example.com"));
    }

    /// The bug found live against real Let's Encrypt staging (never caught
    /// by this crate's own tests or by Pebble): rcgen's default
    /// `distinguished_name` — `CN=rcgen self signed cert` — traveled into
    /// the CSR's Subject unless explicitly cleared, and the real CA
    /// rejected the order outright over the space in that placeholder.
    #[test]
    fn csr_subject_never_carries_rcgens_self_signed_placeholder() {
        let key = CertKey::generate().unwrap();
        let der = build_csr(&key, &[Identifier::Dns("example.com".to_string())]).unwrap();
        let out = openssl_verify(&der);
        assert!(
            !out.contains("rcgen self signed cert"),
            "rcgen's default CSR subject placeholder must never reach the CA: {out}"
        );
        assert!(
            out.contains("Subject: \n") || out.contains("Subject:\n") || out.contains("Subject: []"),
            "the CSR's subject should be empty (SAN carries every identifier): {out}"
        );
    }

    #[test]
    fn csr_for_three_domains_including_wildcard_has_all_sans() {
        let key = CertKey::generate().unwrap();
        let ids = vec![
            Identifier::Dns("example.com".to_string()),
            Identifier::Dns("www.example.com".to_string()),
            Identifier::Dns("*.example.com".to_string()),
        ];
        let der = build_csr(&key, &ids).unwrap();
        let out = openssl_verify(&der);
        assert!(out.contains("Signature Verified OK") || out.contains("verify OK"));
        assert!(out.contains("DNS:example.com"));
        assert!(out.contains("DNS:www.example.com"));
        assert!(out.contains("DNS:*.example.com"));
    }

    #[test]
    fn certkey_round_trip_through_pem_keeps_same_public_key() {
        let key = CertKey::generate().unwrap();
        let pem = key.to_pkcs8_pem();
        let loaded = CertKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(key.inner.public_key_raw(), loaded.inner.public_key_raw());
    }

    #[test]
    fn build_csr_rejects_empty_identifiers() {
        let key = CertKey::generate().unwrap();
        assert!(matches!(build_csr(&key, &[]), Err(Error::Csr { .. })));
    }
}
