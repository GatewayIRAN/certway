#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod acme;
pub mod ari;
pub mod cert;
pub mod challenge;
pub mod crypto;
pub mod csr;
pub mod dns;
pub mod dns_provider;
pub mod error;
pub mod export;
pub mod hook;
pub mod http;
pub mod json;

pub use acme::{
    answer_challenge, deactivate_account, download_certificate, ensure_account,
    fetch_authorization, fetch_directory, finalize, new_order, poll_authorization,
    revoke_certificate, update_account, AccountOutcome, Authorization, AuthzStatus, Challenge,
    ChallengeStatus, ChallengeType, Directory, Identifier, Order, OrderStatus, Problem,
    ProblemKind, Session,
};
pub use ari::{fetch_renewal_info, renewal_moment, CertId, RenewalWindow};
pub use cert::ParsedCert;
pub use challenge::{Dns01Solver, Http01Server, Solver, Task};
pub use crypto::{b64url_decode, b64url_encode, AccountKey, Auth, Jws, Payload};
pub use csr::{build_csr, CertKey};
pub use dns::{Propagated, RecordType, Resolver};
pub use dns_provider::cloudflare::CloudflareProvider;
pub use dns_provider::hook::HookProvider;
pub use dns_provider::{DnsTxtProvider, TxtRecord};
pub use error::Error;
pub use export::{combined_pem, leaf_der, split_leaf_and_chain, split_pem_certs};
pub use hook::{post_hook_url, run_local as run_hook};
pub use http::{Client, Headers, Method, Response};
pub use json::{Json, JsonVal};
