//! The Cloudflare DNS-01 provider.
//!
//! `/user/tokens/verify` and the zone-listing `/zones?name=` endpoint are
//! outside the DNS surface `docs/ref/cloudflare-dns-api-2026-07-31.md`
//! deliberately scopes itself to (that reference's own `<protocol>` block
//! excludes non-DNS Cloudflare products) — not a contradiction, just a
//! different part of the same v4 API.

use super::{DnsTxtProvider, TxtRecord};
use crate::dns::suffix_candidates;
use crate::error::Error;
use crate::http::{Client, Method};
use crate::json::{write_object, Json, JsonVal};
use std::collections::HashMap;
use zeroize::Zeroizing;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// DNS-01 TXT records always carry this TTL. `ttl:1` in Cloudflare's own
/// API means "automatic," not "one second" — 60 is a literal, deliberate
/// value, never `1`.
const TTL_SECS: &str = "60";

pub struct CloudflareProvider<'a> {
    http: &'a Client,
    token: Zeroizing<String>,
    /// Registrable domain -> zone ID, filled in as `find_zone` discovers
    /// them — an order can name domains in more than one zone.
    zone_cache: HashMap<String, String>,
    /// Zone ID -> record IDs this run created, for `remove`. Not persisted:
    /// a crash before cleanup leaves orphans by design, for `certway doctor`
    /// to find later.
    created: HashMap<String, Vec<String>>,
}

impl<'a> CloudflareProvider<'a> {
    pub fn from_env(http: &'a Client) -> Result<CloudflareProvider<'a>, Error> {
        Ok(CloudflareProvider {
            http,
            token: read_token()?,
            zone_cache: HashMap::new(),
            created: HashMap::new(),
        })
    }

    pub fn verify_token(&self) -> Result<(), Error> {
        let resp = self.http.request_authenticated(
            Method::Get,
            &format!("{API_BASE}/user/tokens/verify"),
            &self.token,
            None,
            None,
        )?;
        parse_envelope(resp.status, &resp.body)?;
        Ok(())
    }

    /// Walks candidate registrable domains, longest first, querying
    /// `GET /zones?name=` at each and stopping at the first match — the
    /// same shape as `dns::discover_authoritative`'s NS walk, for the same
    /// reason: a delegation this program cannot know about in advance.
    fn find_zone(&mut self, domain: &str) -> Result<String, Error> {
        if let Some(id) = self.zone_cache.get(domain) {
            return Ok(id.clone());
        }
        for candidate in suffix_candidates(domain) {
            let url = format!("{API_BASE}/zones?name={candidate}");
            let resp =
                self.http
                    .request_authenticated(Method::Get, &url, &self.token, None, None)?;
            let parsed = parse_envelope(resp.status, &resp.body)?;
            let results = parsed.array("result")?;
            if let Some(first) = results.first() {
                let id = first.str("id")?.to_string();
                self.zone_cache.insert(domain.to_string(), id.clone());
                return Ok(id);
            }
        }
        Err(Error::DnsNoRecord {
            name: domain.to_string(),
            kind: "cloudflare zone",
        })
    }
}

impl<'a> DnsTxtProvider for CloudflareProvider<'a> {
    /// Groups records by zone and issues exactly one
    /// `dns_records/batch` call per zone — the two-record wildcard case
    /// (both records sharing a zone) lands in a single `posts` array, so
    /// both exist from the same atomic-ish batch rather than one being
    /// created while the other is still in flight.
    fn create(&mut self, records: &[TxtRecord]) -> Result<(), Error> {
        let mut by_zone: HashMap<String, Vec<&TxtRecord>> = HashMap::new();
        for r in records {
            let zone_id = self.find_zone(&r.domain)?;
            by_zone.entry(zone_id).or_default().push(r);
        }

        for (zone_id, recs) in &by_zone {
            let post_strings: Vec<String> = recs
                .iter()
                .map(|r| {
                    write_object(&[
                        ("type", JsonVal::Str("TXT")),
                        ("name", JsonVal::Str(&r.name)),
                        ("content", JsonVal::Str(&r.value)),
                        ("ttl", JsonVal::Raw(TTL_SECS)),
                    ])
                })
                .collect();
            let posts: Vec<JsonVal> = post_strings
                .iter()
                .map(|s| JsonVal::Raw(s.as_str()))
                .collect();
            let body = write_object(&[("posts", JsonVal::Array(posts))]);
            let url = format!("{API_BASE}/zones/{zone_id}/dns_records/batch");
            let resp = self.http.request_authenticated(
                Method::Post,
                &url,
                &self.token,
                Some("application/json"),
                Some(body.as_bytes()),
            )?;
            let parsed = parse_envelope(resp.status, &resp.body)?;
            let result = parsed.object("result")?;
            let posted = result.array("posts")?;
            // Batch is not fully transactional across its four operation
            // arrays (the API's own documented trap) — check the per-item
            // result count, not just the envelope's top-level `success`.
            if posted.len() != recs.len() {
                return Err(Error::HttpMalformed {
                    detail: "cloudflare batch create returned an unexpected record count",
                });
            }
            let mut ids = Vec::with_capacity(posted.len());
            for p in &posted {
                ids.push(p.str("id")?.to_string());
            }
            self.created.entry(zone_id.clone()).or_default().extend(ids);
        }
        Ok(())
    }

    /// Ignores `_records` in favor of the IDs this run itself created and
    /// tracked — idempotent (a zone with nothing tracked is simply
    /// skipped) and never returns on the first failure: every zone with
    /// tracked records gets its own delete attempt, and the first error
    /// (if any) is what's returned once every zone has been tried.
    fn remove(&mut self, _records: &[TxtRecord]) -> Result<(), Error> {
        let mut first_err: Option<Error> = None;
        for (zone_id, ids) in &self.created {
            if ids.is_empty() {
                continue;
            }
            let delete_strings: Vec<String> = ids
                .iter()
                .map(|id| write_object(&[("id", JsonVal::Str(id))]))
                .collect();
            let deletes: Vec<JsonVal> = delete_strings
                .iter()
                .map(|s| JsonVal::Raw(s.as_str()))
                .collect();
            let body = write_object(&[("deletes", JsonVal::Array(deletes))]);
            let url = format!("{API_BASE}/zones/{zone_id}/dns_records/batch");
            let outcome = self
                .http
                .request_authenticated(
                    Method::Post,
                    &url,
                    &self.token,
                    Some("application/json"),
                    Some(body.as_bytes()),
                )
                .and_then(|resp| parse_envelope(resp.status, &resp.body));
            if let Err(e) = outcome {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        self.created.clear();
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn read_token() -> Result<Zeroizing<String>, Error> {
    if let Ok(token) = std::env::var("CLOUDFLARE_API_TOKEN") {
        return Ok(Zeroizing::new(token));
    }
    if let Ok(path) = std::env::var("CLOUDFLARE_API_TOKEN_FILE") {
        let contents = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
        return Ok(Zeroizing::new(contents.trim().to_string()));
    }
    Err(Error::DnsProviderConfig {
        detail: "neither CLOUDFLARE_API_TOKEN nor CLOUDFLARE_API_TOKEN_FILE is set".to_string(),
    })
}

/// Parses the `{success, errors, result}` envelope every Cloudflare v4
/// response uses, treating a non-2xx status or `success:false` alike as a
/// failure — `Error::http_status` caps the body at 200 bytes, which is
/// also what keeps a redacted-looking error rather than an unbounded
/// Cloudflare error blob (the token itself never appears in a response
/// body, so there is nothing of the token's to redact here, only to never
/// log elsewhere).
fn parse_envelope(status: u16, body: &[u8]) -> Result<Json, Error> {
    if status >= 400 {
        return Err(Error::http_status(status, body));
    }
    let json = Json::parse(body)?;
    if !json.bool("success").unwrap_or(false) {
        return Err(Error::http_status(status, body));
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `read_token` reads process-wide env vars that `cargo test`'s default
    // parallelism would otherwise race across these three tests — a plain
    // `Mutex` (no new dependency) serializes just this group rather than
    // forcing the whole binary to `--test-threads=1`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn read_token_prefers_direct_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("CLOUDFLARE_API_TOKEN", "direct-token-value");
        std::env::remove_var("CLOUDFLARE_API_TOKEN_FILE");
        let token = read_token().unwrap();
        assert_eq!(token.as_str(), "direct-token-value");
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
    }

    #[test]
    fn read_token_falls_back_to_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
        let path =
            std::env::temp_dir().join(format!("certway-cf-token-test-{}.txt", std::process::id()));
        std::fs::write(&path, "file-token-value\n").unwrap();
        std::env::set_var("CLOUDFLARE_API_TOKEN_FILE", path.to_str().unwrap());
        let token = read_token().unwrap();
        assert_eq!(token.as_str(), "file-token-value");
        std::env::remove_var("CLOUDFLARE_API_TOKEN_FILE");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_token_missing_both_is_a_clean_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
        std::env::remove_var("CLOUDFLARE_API_TOKEN_FILE");
        assert!(matches!(read_token(), Err(Error::DnsProviderConfig { .. })));
    }

    #[test]
    fn parse_envelope_rejects_success_false_even_on_200() {
        let body = br#"{"success":false,"errors":[{"code":9109,"message":"nope"}],"result":null}"#;
        assert!(parse_envelope(200, body).is_err());
    }

    #[test]
    fn parse_envelope_accepts_success_true() {
        let body = br#"{"success":true,"errors":[],"result":{"status":"active"}}"#;
        assert!(parse_envelope(200, body).is_ok());
    }

    #[test]
    fn parse_envelope_rejects_4xx_status_even_with_success_true_body() {
        // Shouldn't happen in practice, but the status check must not be
        // skippable by a malformed/unexpected body.
        let body = br#"{"success":true,"errors":[],"result":null}"#;
        assert!(parse_envelope(403, body).is_err());
    }
}
