//! DNS-01 record providers: Cloudflare, and the external hook that removes
//! the single-provider limitation.

pub mod cloudflare;
pub mod hook;

use crate::error::Error;

/// One TXT record to create or remove. `domain` and `name` are kept
/// separate rather than derived from each other: `domain` is the
/// identifier with any wildcard prefix already stripped (what a hook's
/// `CERTWAY_DOMAIN` gets), `name` is the full `_acme-challenge.<domain>`
/// record name — for a wildcard pair, several `TxtRecord`s share the same
/// `name` with different `value`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    pub domain: String,
    pub name: String,
    pub value: String,
}

/// A place DNS-01 TXT records can be created and removed. `create` always
/// receives every record for the whole order at once — never one at a
/// time — which is what makes the two-record wildcard case correct rather
/// than accidental.
pub trait DnsTxtProvider {
    fn create(&mut self, records: &[TxtRecord]) -> Result<(), Error>;

    /// Idempotent: safe to call on records that were never created, or
    /// were already removed. Callers (`challenge::Dns01Solver::cleanup`)
    /// rely on this to attempt every removal rather than stopping at the
    /// first failure.
    fn remove(&mut self, records: &[TxtRecord]) -> Result<(), Error>;
}
