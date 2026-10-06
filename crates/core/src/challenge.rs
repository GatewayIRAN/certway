use crate::acme::Identifier;
use crate::dns::{self, Propagated, Resolver};
use crate::dns_provider::{DnsTxtProvider, TxtRecord};
use crate::error::Error;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const MAX_REQUEST: usize = 8 * 1024;
const READ_TIMEOUT_SECS: u64 = 5;
const PREFIX: &str = "/.well-known/acme-challenge/";
const ACCEPT_POLL_INTERVAL_MS: u64 = 50;

/// A minimal standalone HTTP-01 challenge responder. Answers exactly one
/// path shape and nothing else — it is a target for anything that can reach
/// the port, so it is deliberately dumb.
pub struct Http01Server {
    listeners: Vec<TcpListener>,
    tokens: HashMap<String, String>,
}

impl Http01Server {
    pub fn bind(port: u16) -> Result<Http01Server, Error> {
        let v4 = TcpListener::bind(("0.0.0.0", port)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                Error::PrivilegedPort { port }
            } else {
                Error::Connect {
                    host: "0.0.0.0".to_string(),
                    port,
                    source: e,
                }
            }
        })?;
        v4.set_nonblocking(true).map_err(|e| Error::Connect {
            host: "0.0.0.0".to_string(),
            port,
            source: e,
        })?;

        let mut listeners = vec![v4];
        if let Ok(v6) = TcpListener::bind(("::", port)) {
            if v6.set_nonblocking(true).is_ok() {
                listeners.push(v6);
            }
        }

        Ok(Http01Server {
            listeners,
            tokens: HashMap::new(),
        })
    }

    pub fn add(&mut self, token: &str, key_authorization: &str) {
        self.tokens
            .insert(token.to_string(), key_authorization.to_string());
    }

    /// Serves connections, sequentially, on this one thread, until `done`
    /// returns true. The caller drives the lifecycle from another thread:
    /// answer the challenge, then serve while polling, then stop.
    pub fn serve_until(&mut self, done: &dyn Fn() -> bool) -> Result<(), Error> {
        while !done() {
            let mut accepted = false;
            for listener in &self.listeners {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handle_connection(stream, &self.tokens);
                        accepted = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            if !accepted {
                std::thread::sleep(Duration::from_millis(ACCEPT_POLL_INTERVAL_MS));
            }
        }
        Ok(())
    }

    pub fn shutdown(self) {
        drop(self);
    }
}

fn handle_connection(mut stream: TcpStream, tokens: &HashMap<String, String>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
    let _ = stream.set_nodelay(true);

    let response = match read_request_head(&mut stream) {
        Some(head) => match parse_get_path(&head).and_then(token_from_path) {
            Some(token) => match tokens.get(token) {
                Some(key_auth) => {
                    build_response(200, Some("application/octet-stream"), key_auth.as_bytes())
                }
                None => build_response(404, None, b""),
            },
            None => build_response(404, None, b""),
        },
        None => build_response(400, None, b""),
    };

    let _ = stream.write_all(&response);
}

/// Reads until the request-line/header terminator or MAX_REQUEST is hit.
/// The body, if any, is never read.
fn read_request_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        if let Some(pos) = find_terminator(&buf) {
            buf.truncate(pos);
            return Some(buf);
        }
        if buf.len() > MAX_REQUEST {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
}

fn find_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_get_path(head: &[u8]) -> Option<&str> {
    let line_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    if method != "GET" {
        return None;
    }
    Some(path)
}

fn token_from_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix(PREFIX)?;
    let token = rest.split(['?', '#']).next().unwrap_or("");
    if token.is_empty() || token.contains('/') {
        return None;
    }
    Some(token)
}

fn build_response(status: u16, content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let mut head = format!("HTTP/1.1 {status} {status_text}\r\n");
    if let Some(ct) = content_type {
        head.push_str("Content-Type: ");
        head.push_str(ct);
        head.push_str("\r\n");
    }
    head.push_str("Content-Length: ");
    head.push_str(&body.len().to_string());
    head.push_str("\r\nConnection: close\r\n\r\n");

    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------
// The common validation-method shape, and DNS-01. `Http01Server` above
// predates this trait and is deliberately not retrofitted onto it: it has
// no separate ready()/cleanup() phases to map onto — bind/add/
// serve_until/shutdown already cover its full lifecycle.
// ---------------------------------------------------------------------

/// One authorization's challenge, ready to be provisioned.
pub struct Task {
    pub identifier: Identifier,
    pub token: String,
    pub key_authorization: String,
}

/// Every validation method implements this. `prepare` always receives
/// *every* task for the order at once, never one at a time — the
/// structural reason the two-record wildcard case is correct rather than
/// accidental. `cleanup` is idempotent and safe to call on every exit
/// path: success, failure, and signal.
pub trait Solver {
    fn prepare(&mut self, tasks: &[Task]) -> Result<(), Error>;
    fn ready(&self) -> Result<(), Error>;
    fn cleanup(&mut self) -> Result<(), Error>;
}

fn strip_wildcard_prefix(domain: &str) -> String {
    domain.strip_prefix("*.").unwrap_or(domain).to_string()
}

/// DNS-01. Delegates record creation/removal to a `DnsTxtProvider`
/// (Cloudflare or the external hook) and propagation confirmation to
/// `dns::check_propagation` — this struct's own job is just building the
/// `_acme-challenge.<domain>` records from `Task`s and grouping them back
/// up by name for the propagation check, since several tasks can share
/// one record name with different values.
pub struct Dns01Solver<'a> {
    provider: &'a mut (dyn DnsTxtProvider + Send),
    resolver: &'a Resolver,
    /// Checked by `dns::check_propagation` at ~100ms granularity so a
    /// signal-driven shutdown reaches the caller promptly instead of
    /// waiting out the full 300s cap — the same `&dyn Fn() -> bool` shape
    /// `Http01Server::serve_until` already uses. `+ Sync` (so `&interrupt`
    /// is `Send`) is needed because this whole struct crosses onto
    /// `steps::animate`'s scoped spinner thread — a plain `fn() -> bool`
    /// like `signal::requested` satisfies it trivially.
    interrupt: &'a (dyn Fn() -> bool + Sync),
    records: Vec<TxtRecord>,
    /// How many authoritative nameservers `ready()`'s most recent
    /// discovery found, for the CLI's "visible on N nameservers" detail —
    /// `AtomicUsize` rather than `Cell` specifically so `&Dns01Solver`
    /// stays `Sync`, since `ready(&self)` runs on `steps::animate`'s
    /// scoped spinner thread while the CLI reads this back on the main
    /// one afterward.
    last_server_count: std::sync::atomic::AtomicUsize,
}

impl<'a> Dns01Solver<'a> {
    pub fn new(
        provider: &'a mut (dyn DnsTxtProvider + Send),
        resolver: &'a Resolver,
        interrupt: &'a (dyn Fn() -> bool + Sync),
    ) -> Dns01Solver<'a> {
        Dns01Solver {
            provider,
            resolver,
            interrupt,
            records: Vec::new(),
            last_server_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Records actually created by `prepare` — 0 before it runs, or if it
    /// failed before creating any. What the CLI's "dns" step detail
    /// ("N records created") and the "cleanup is only shown when records
    /// were created" rule both key off.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// The authoritative nameserver count from `ready()`'s most recent
    /// discovery — 0 before `ready()` has run.
    pub fn last_authoritative_server_count(&self) -> usize {
        self.last_server_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl<'a> Solver for Dns01Solver<'a> {
    fn prepare(&mut self, tasks: &[Task]) -> Result<(), Error> {
        let mut records = Vec::with_capacity(tasks.len());
        for task in tasks {
            let domain = match &task.identifier {
                Identifier::Dns(d) => strip_wildcard_prefix(d),
                // dns-01 cannot prove control of an IP identifier —
                // reachable only if a caller builds a DNS-01 task for one
                // by mistake.
                Identifier::Ip(_) => {
                    return Err(Error::ChallengeUnavailable {
                        wanted: crate::acme::ChallengeType::Dns01,
                    })
                }
            };
            let name = format!("_acme-challenge.{domain}");
            let value = crate::crypto::hash_key_authorization(&task.key_authorization);
            records.push(TxtRecord {
                domain,
                name,
                value,
            });
        }
        // Recorded *before* `create` runs, not after — a provider that
        // creates some records and then fails partway through (a hook
        // whose second invocation errors, say) must still have every
        // attempted record available to `cleanup`. `DnsTxtProvider::remove`
        // is documented idempotent specifically so this is safe even for
        // the ones that were never actually created.
        self.records = records;
        self.provider.create(&self.records)?;
        Ok(())
    }

    /// Groups the created records by name (the two-record case shares one
    /// name across two values) and confirms each group's full expected set
    /// is visible at every authoritative nameserver before returning.
    fn ready(&self) -> Result<(), Error> {
        let mut groups: HashMap<&str, (&str, HashSet<String>)> = HashMap::new();
        for r in &self.records {
            let entry = groups
                .entry(r.name.as_str())
                .or_insert_with(|| (r.domain.as_str(), HashSet::new()));
            entry.1.insert(r.value.clone());
        }
        for (name, (domain, expected)) in &groups {
            let servers = dns::discover_authoritative(self.resolver, domain);
            self.last_server_count
                .store(servers.len(), std::sync::atomic::Ordering::Relaxed);
            match dns::check_propagation(&servers, name, expected, self.interrupt)? {
                Propagated::Yes => {}
                // A signal-driven shutdown, not a genuine timeout — but
                // `Solver::ready`'s signature carries no separate
                // "interrupted" outcome, and the effect is the same
                // either way: stop waiting, let the caller run cleanup
                // and unwind. Reusing `PollExhausted` here means no new
                // error variant for what is, from this trait's
                // perspective, the same "did not finish waiting" case.
                Propagated::Interrupted => {
                    return Err(Error::PollExhausted {
                        resource: "dns propagation",
                        elapsed_secs: 0,
                    })
                }
            }
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Error> {
        if self.records.is_empty() {
            return Ok(());
        }
        self.provider.remove(&self.records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Fixed high port for these localhost-only tests; no public API exposes
    // the bound port for an ephemeral (port 0) bind.
    const TEST_PORT: u16 = 18765;

    /// Binding port 80 needs CAP_NET_BIND_SERVICE / root on Linux. This
    /// tolerates running as root (where the bind can succeed) but demands
    /// the specific variant, not the generic `Connect`, when it can't.
    #[test]
    fn binding_privileged_port_without_permission_reports_specific_error() {
        match Http01Server::bind(80) {
            Err(Error::PrivilegedPort { port }) => assert_eq!(port, 80),
            Ok(_) => {}
            Err(other) => panic!("expected PrivilegedPort (or success as root), got: {other}"),
        }
    }

    fn get(port: u16, path: &str) -> (u16, Vec<u8>) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut reader = std::io::BufReader::new(&stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).unwrap();
        (status, body)
    }

    #[test]
    fn known_token_returns_key_authorization() {
        let mut server = Http01Server::bind(TEST_PORT).unwrap();
        server.add("tok123", "tok123.thumbprint");
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        let handle = std::thread::spawn(move || {
            server
                .serve_until(&|| done_clone.load(Ordering::Relaxed))
                .unwrap();
        });

        std::thread::sleep(Duration::from_millis(100));
        let (status, body) = get(TEST_PORT, "/.well-known/acme-challenge/tok123");
        assert_eq!(status, 200);
        assert_eq!(body, b"tok123.thumbprint");

        let (status, _) = get(TEST_PORT, "/.well-known/acme-challenge/unknown-token");
        assert_eq!(status, 404);

        done.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    // -- Dns01Solver ----------------------------------------------------

    #[derive(Default)]
    struct MockProvider {
        created: Vec<TxtRecord>,
        removed: Vec<TxtRecord>,
        fail_create: bool,
    }

    impl DnsTxtProvider for MockProvider {
        fn create(&mut self, records: &[TxtRecord]) -> Result<(), Error> {
            if self.fail_create {
                return Err(Error::DnsMalformed {
                    detail: "forced failure",
                });
            }
            self.created.extend_from_slice(records);
            Ok(())
        }
        fn remove(&mut self, records: &[TxtRecord]) -> Result<(), Error> {
            self.removed.extend_from_slice(records);
            Ok(())
        }
    }

    fn task(domain: &str, token: &str, key_auth: &str) -> Task {
        Task {
            identifier: Identifier::Dns(domain.to_string()),
            token: token.to_string(),
            key_authorization: key_auth.to_string(),
        }
    }

    fn never_interrupt() -> bool {
        false
    }

    #[test]
    fn prepare_strips_wildcard_prefix_from_the_record_name() {
        let mut provider = MockProvider::default();
        let resolver = Resolver::discover(Some("127.0.0.1".parse().unwrap())).unwrap();
        let mut solver = Dns01Solver::new(&mut provider, &resolver, &never_interrupt);
        let tasks = vec![task("*.example.com", "tok1", "tok1.thumb")];
        solver.prepare(&tasks).unwrap();
        assert_eq!(provider.created.len(), 1);
        assert_eq!(provider.created[0].domain, "example.com");
        assert_eq!(provider.created[0].name, "_acme-challenge.example.com");
    }

    /// The load-bearing case: a bare domain and its wildcard produce two
    /// records sharing one name with different values, both passed to
    /// `provider.create` in the same call.
    #[test]
    fn prepare_builds_two_records_sharing_a_name_for_the_wildcard_pair() {
        let mut provider = MockProvider::default();
        let resolver = Resolver::discover(Some("127.0.0.1".parse().unwrap())).unwrap();
        let mut solver = Dns01Solver::new(&mut provider, &resolver, &never_interrupt);
        let tasks = vec![
            task("example.com", "tok1", "tok1.thumb"),
            task("*.example.com", "tok2", "tok2.thumb"),
        ];
        solver.prepare(&tasks).unwrap();

        assert_eq!(
            provider.created.len(),
            2,
            "both tasks must reach create() in one call"
        );
        assert!(provider
            .created
            .iter()
            .all(|r| r.name == "_acme-challenge.example.com"));
        let values: HashSet<&str> = provider.created.iter().map(|r| r.value.as_str()).collect();
        assert_eq!(
            values.len(),
            2,
            "the two records must carry different values"
        );
    }

    #[test]
    fn prepare_rejects_an_ip_identifier() {
        let mut provider = MockProvider::default();
        let resolver = Resolver::discover(Some("127.0.0.1".parse().unwrap())).unwrap();
        let mut solver = Dns01Solver::new(&mut provider, &resolver, &never_interrupt);
        let tasks = vec![Task {
            identifier: Identifier::Ip("203.0.113.9".parse().unwrap()),
            token: "t".to_string(),
            key_authorization: "t.thumb".to_string(),
        }];
        assert!(matches!(
            solver.prepare(&tasks),
            Err(Error::ChallengeUnavailable { .. })
        ));
    }

    #[test]
    fn cleanup_is_a_no_op_before_prepare_ever_ran() {
        let mut provider = MockProvider::default();
        let resolver = Resolver::discover(Some("127.0.0.1".parse().unwrap())).unwrap();
        let mut solver = Dns01Solver::new(&mut provider, &resolver, &never_interrupt);
        solver.cleanup().unwrap();
        assert!(provider.removed.is_empty());
    }

    #[test]
    fn cleanup_passes_every_created_record_to_remove() {
        let mut provider = MockProvider::default();
        let resolver = Resolver::discover(Some("127.0.0.1".parse().unwrap())).unwrap();
        let mut solver = Dns01Solver::new(&mut provider, &resolver, &never_interrupt);
        let tasks = vec![
            task("example.com", "tok1", "tok1.thumb"),
            task("*.example.com", "tok2", "tok2.thumb"),
        ];
        solver.prepare(&tasks).unwrap();
        solver.cleanup().unwrap();
        assert_eq!(provider.removed.len(), 2);
    }

    /// The regression this fix exists for: a provider whose `create` fails
    /// partway (a hook whose second invocation errors, having already
    /// created the first record for real) must still have every attempted
    /// record reach `cleanup` — `self.records` is set *before* `create`
    /// runs specifically so a partial failure isn't silently un-cleanable.
    #[test]
    fn prepare_failure_still_attempts_cleanup_of_every_task() {
        let mut provider = MockProvider {
            fail_create: true,
            ..Default::default()
        };
        let resolver = Resolver::discover(Some("127.0.0.1".parse().unwrap())).unwrap();
        let mut solver = Dns01Solver::new(&mut provider, &resolver, &never_interrupt);
        let tasks = vec![
            task("example.com", "tok1", "tok1.thumb"),
            task("*.example.com", "tok2", "tok2.thumb"),
        ];
        assert!(solver.prepare(&tasks).is_err());
        solver.cleanup().unwrap();
        assert_eq!(
            provider.removed.len(),
            2,
            "cleanup must attempt every task that was going to be created, not just none"
        );
    }
}
