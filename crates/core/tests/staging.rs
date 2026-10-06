use certway_core::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// End-to-end against Let's Encrypt STAGING only — never point this at
/// production. Cannot fully succeed without a real domain pointing at this
/// machine with port 80 reachable from the internet; it reports exactly how
/// far the protocol engine gets.
#[test]
#[ignore]
fn issues_from_staging() {
    let directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory";
    let http = Client::new().expect("client construction with embedded root");

    let directory = fetch_directory(&http, directory_url).expect("directory fetch");
    println!("directory fetched");

    let key = AccountKey::generate().expect("account key generation");
    let mut session = Session::new(&directory, &http, &key);

    let (account_url, outcome) =
        ensure_account(&mut session, None, true).expect("account creation");
    println!("account created — {account_url} ({outcome:?})");

    // Not example.com/.org/.net: Let's Encrypt staging rejects all three
    // with rejectedIdentifier ("... does not end with a valid public
    // suffix (TLD)" / reserved-name policy), even with --agree-tos and a
    // syntactically valid request. Confirmed live against the staging API.
    //
    // No default: this test needs a domain that actually points at the
    // machine running it, and a domain baked in here would be someone's
    // real DNS record sitting in a public repository. Required, not
    // best-effort, so a bare `cargo test -- --ignored` fails loudly
    // instead of silently ordering against a domain nobody controls
    // anymore.
    let domain = std::env::var("CERTWAY_TEST_DOMAIN").expect(
        "CERTWAY_TEST_DOMAIN must be set to a domain that resolves to this machine \
         on port 80 — e.g. CERTWAY_TEST_DOMAIN=test.example.org cargo test --test staging -- --ignored",
    );
    let identifiers = vec![Identifier::Dns(domain.clone())];

    let order = new_order(&mut session, &identifiers, None).expect("order creation");
    println!("order created — {}", order.url);

    let authz_url = order.authorizations[0].clone();
    let authz = fetch_authorization(&mut session, &authz_url).expect("authorization fetch");
    let challenge = authz
        .challenge(ChallengeType::Http01)
        .expect("http-01 challenge offered")
        .clone();
    println!(
        "authorization fetched, http-01 challenge found, token {}",
        challenge.token
    );

    let key_auth = certway_core::crypto::key_authorization(&challenge.token, &key);

    let mut server = match Http01Server::bind(80) {
        Ok(s) => s,
        Err(e) => {
            println!("HTTP-01 server bind to port 80 — FAILED: {e}");
            println!("stopped at: binding the standalone HTTP-01 server to port 80");
            return;
        }
    };
    println!("HTTP-01 server bound to port 80");
    server.add(&challenge.token, &key_auth);

    let done = Arc::new(AtomicBool::new(false));
    let done_clone = Arc::clone(&done);
    let server_thread = std::thread::spawn(move || {
        let _ = server.serve_until(&|| done_clone.load(Ordering::Relaxed));
    });

    if let Err(e) = answer_challenge(&mut session, &challenge.url) {
        println!("answer_challenge — FAILED: {e}");
    }

    let poll_result = poll_authorization(&mut session, &authz_url);
    done.store(true, Ordering::Relaxed);
    let _ = server_thread.join();

    match poll_result {
        Ok(final_authz) => {
            println!(
                "authorization finished with status: {:?}",
                final_authz.status
            );
            for c in &final_authz.challenges {
                if let Some(err) = &c.error {
                    println!("challenge error: {err}");
                }
            }
        }
        Err(e) => println!("poll_authorization — FAILED: {e}"),
    }
}
