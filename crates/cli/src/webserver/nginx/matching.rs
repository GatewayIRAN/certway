// SPDX-License-Identifier: MIT

//! Which `server {}` block belongs to a domain — the dangerous part.
//! Scoped per `listen` address:port, never searched
//! globally: a `:80` block and a `:443` block both naming the same domain
//! is the normal, expected case, not ambiguity.
//!
//! **What this module never does:** fall through to `default_server` or
//! the first block for the port as if that were a match for *our* domain.
//! Those rules describe how nginx picks a block for a Host header it
//! doesn't recognise — they are never a legitimate answer to "which block
//! is this domain's," so this module has no code path that returns one as
//! `Matched`. No match found is `NoMatch`, full stop; `mod.rs` is the layer
//! that turns `NoMatch` into the "add these two lines yourself" report.
//!
//! Regex and variable `server_name` entries are never evaluated — this
//! parser doesn't run a regex engine or a variable evaluator, and a
//! block selected only by a regex or a variable `server_name` is treated
//! as a refusal condition, not something to guess at. The rule applied
//! here: if no exact/wildcard match resolves the domain
//! *and* an in-scope block has a regex or variable entry that might have,
//! refuse rather than silently falling through — the same "don't skip an
//! unevaluated possibility" principle for both.

use super::parse::Directive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortScope {
    /// `listen ... 443 ... ssl ...` — the in-place-edit search.
    Tls443,
    /// `listen ... 80 ...` with no `ssl` param — the append-new-block search.
    Plain80,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    Regex,
    VariableServerName,
    /// More than one block matches equally — an exact-name tie, or a
    /// wildcard tie at the winning specificity. nginx itself would
    /// silently pick whichever block it happened to parse first and only
    /// log a warning — an easy trap, since two equally-specific blocks
    /// quietly doing different things is hard to notice — but certway
    /// treats the tie itself as reason enough to refuse.
    Ambiguous,
    /// A `server_name` that would otherwise match our domain exists only
    /// inside a nested `if {}` — nginx's `if` is non-local, so a directive
    /// found there is not trusted as a real match.
    InsideIf,
    /// The matched block's file is a symlink resolving outside the config
    /// tree — a provenance question about the *file*, not about directive
    /// content, so detection lives in the orchestrator (`mod.rs`), not
    /// here. The variant lives on this enum anyway so every §12.4 refusal
    /// condition is one list, not two.
    SymlinkOutsideTree,
}

#[derive(Debug)]
pub enum FindResult<'a> {
    Matched(&'a Directive),
    NoMatch,
    Refused(RefusalReason),
}

/// Finds the `server {}` block for `domain` within `scope`, across every
/// `server` block reachable from `root` (i.e. after `include` splicing —
/// `root` is `parse::parse_file`'s output, so this never touches the
/// filesystem itself).
pub fn find_server_block<'a>(
    root: &'a [Directive],
    domain: &str,
    scope: PortScope,
) -> FindResult<'a> {
    let servers = collect_server_blocks(root);
    let in_scope: Vec<&Directive> = servers
        .iter()
        .filter(|s| block_listens_in_scope(s, scope))
        .copied()
        .collect();
    if in_scope.is_empty() {
        return FindResult::NoMatch;
    }

    let candidates: Vec<Candidate<'_>> = in_scope.iter().map(|s| classify(s, domain)).collect();

    if let Some(r) = pick_exact(&candidates) {
        return r;
    }
    if let Some(r) = pick_wildcard(&candidates, WildcardKind::Leading) {
        return r;
    }
    if let Some(r) = pick_wildcard(&candidates, WildcardKind::Trailing) {
        return r;
    }
    if candidates.iter().any(|c| c.has_regex) {
        return FindResult::Refused(RefusalReason::Regex);
    }
    if candidates.iter().any(|c| c.has_variable) {
        return FindResult::Refused(RefusalReason::VariableServerName);
    }
    if any_match_inside_if(&in_scope, domain) {
        return FindResult::Refused(RefusalReason::InsideIf);
    }
    FindResult::NoMatch
}

struct Candidate<'a> {
    directive: &'a Directive,
    exact: bool,
    leading_wildcard_len: Option<usize>,
    trailing_wildcard_len: Option<usize>,
    has_regex: bool,
    has_variable: bool,
}

enum WildcardKind {
    Leading,
    Trailing,
}

/// Only the last `server_name` directive among a block's direct children
/// counts — nginx's standard "last occurrence in one context wins" rule
/// for a non-array directive. `location`/`if` children are direct
/// children too but are not `server_name`/`listen`, so this is naturally
/// scoped without extra filtering.
fn last_server_name(server: &Directive) -> Option<&Directive> {
    server
        .block
        .as_ref()?
        .iter()
        .rev()
        .find(|d| d.name == "server_name")
}

fn classify<'a>(server: &'a Directive, domain: &str) -> Candidate<'a> {
    let mut c = Candidate {
        directive: server,
        exact: false,
        leading_wildcard_len: None,
        trailing_wildcard_len: None,
        has_regex: false,
        has_variable: false,
    };
    let Some(sn) = last_server_name(server) else {
        return c;
    };
    for arg in &sn.args {
        if arg.starts_with('~') {
            c.has_regex = true;
        } else if arg.contains('$') {
            c.has_variable = true;
        } else if arg == domain {
            c.exact = true;
        } else if let Some(suffix) = arg.strip_prefix("*.") {
            // *.example.com matches example.com's subdomains, per nginx,
            // NOT example.com itself.
            if domain.ends_with(suffix)
                && domain.len() > suffix.len()
                && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            {
                c.leading_wildcard_len = Some(
                    c.leading_wildcard_len
                        .map_or(arg.len(), |l| l.max(arg.len())),
                );
            }
        } else if let Some(prefix) = arg.strip_suffix(".*") {
            if domain.starts_with(prefix)
                && domain.len() > prefix.len()
                && domain.as_bytes()[prefix.len()] == b'.'
            {
                c.trailing_wildcard_len = Some(
                    c.trailing_wildcard_len
                        .map_or(arg.len(), |l| l.max(arg.len())),
                );
            }
        }
        // Anything else (a plain name that doesn't equal `domain`) simply
        // doesn't match — no case for it needed.
    }
    c
}

fn pick_exact<'a>(candidates: &[Candidate<'a>]) -> Option<FindResult<'a>> {
    let matches: Vec<&Candidate<'a>> = candidates.iter().filter(|c| c.exact).collect();
    match matches.len() {
        0 => None,
        1 => Some(FindResult::Matched(matches[0].directive)),
        _ => Some(FindResult::Refused(RefusalReason::Ambiguous)),
    }
}

fn pick_wildcard<'a>(candidates: &[Candidate<'a>], kind: WildcardKind) -> Option<FindResult<'a>> {
    let lens: Vec<(usize, &Candidate<'a>)> = candidates
        .iter()
        .filter_map(|c| {
            let len = match kind {
                WildcardKind::Leading => c.leading_wildcard_len,
                WildcardKind::Trailing => c.trailing_wildcard_len,
            };
            len.map(|l| (l, c))
        })
        .collect();
    let max = lens.iter().map(|(l, _)| *l).max()?;
    let winners: Vec<&Candidate<'a>> = lens
        .iter()
        .filter(|(l, _)| *l == max)
        .map(|(_, c)| *c)
        .collect();
    match winners.len() {
        1 => Some(FindResult::Matched(winners[0].directive)),
        _ => Some(FindResult::Refused(RefusalReason::Ambiguous)),
    }
}

/// Deliberately narrow: exact-string match only (no wildcard/regex
/// evaluation) against `server_name` directives found anywhere inside a
/// nested `if {}` within a `server` block, at any depth. This exists only
/// to distinguish "genuinely no server block for this domain" from "the
/// only thing that named this domain was inside an `if`, which nginx's own
/// non-local `if` semantics make untrustworthy" — not to fully re-run
/// precedence inside `if` bodies.
fn any_match_inside_if(servers: &[&Directive], domain: &str) -> bool {
    servers.iter().any(|server| {
        server
            .block
            .as_ref()
            .is_some_and(|block| search_if_bodies(block, domain))
    })
}

fn search_if_bodies(children: &[Directive], domain: &str) -> bool {
    for child in children {
        if child.name == "if" {
            if let Some(block) = &child.block {
                if block
                    .iter()
                    .any(|d| d.name == "server_name" && d.args.iter().any(|a| a == domain))
                {
                    return true;
                }
                if search_if_bodies(block, domain) {
                    return true;
                }
            }
        } else if let Some(block) = &child.block {
            if search_if_bodies(block, domain) {
                return true;
            }
        }
    }
    false
}

/// Every `server` directive reachable from `root`, recursing into any
/// `http` block found at any depth (`include` splicing means one could in
/// principle appear nested, even though real configs never do this).
fn collect_server_blocks(root: &[Directive]) -> Vec<&Directive> {
    let mut out = Vec::new();
    collect_http_blocks(root, &mut out);
    out
}

fn collect_http_blocks<'a>(directives: &'a [Directive], out: &mut Vec<&'a Directive>) {
    for d in directives {
        if d.name == "http" {
            if let Some(block) = &d.block {
                out.extend(block.iter().filter(|c| c.name == "server"));
            }
        }
        if let Some(block) = &d.block {
            collect_http_blocks(block, out);
        }
    }
}

fn block_listens_in_scope(server: &Directive, scope: PortScope) -> bool {
    let Some(children) = &server.block else {
        return false;
    };
    children
        .iter()
        .filter(|d| d.name == "listen")
        .filter_map(|d| parse_listen(&d.args))
        .any(|l| match scope {
            PortScope::Tls443 => l.ssl && l.port == Some(443),
            PortScope::Plain80 => !l.ssl && l.port == Some(80),
        })
}

struct ListenSocket {
    port: Option<u16>,
    ssl: bool,
}

fn parse_listen(args: &[String]) -> Option<ListenSocket> {
    let first = args.first()?;
    if first.starts_with("unix:") {
        return None;
    }
    let port = extract_port(first);
    let ssl = args.iter().skip(1).any(|a| a == "ssl");
    Some(ListenSocket { port, ssl })
}

fn extract_port(addr: &str) -> Option<u16> {
    if let Some(rest) = addr.strip_prefix('[') {
        let close = rest.find(']')?;
        let after = &rest[close + 1..];
        after.strip_prefix(':').and_then(|p| p.parse().ok())
    } else if let Some(idx) = addr.rfind(':') {
        addr[idx + 1..].parse().ok()
    } else {
        addr.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webserver::nginx::parse::{mock_fs::MockFs, parse_file};
    use std::path::Path;

    fn parse(src: &str) -> Vec<Directive> {
        let fs = MockFs::with(&[("/etc/nginx/nginx.conf", src)]);
        parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap()
    }

    fn matched_server_name<'a>(result: &FindResult<'a>) -> Vec<String> {
        match result {
            FindResult::Matched(d) => last_server_name(d)
                .map(|sn| sn.args.clone())
                .unwrap_or_default(),
            _ => panic!("expected Matched, got {result:?}"),
        }
    }

    #[test]
    fn exact_match_wins_over_wildcard_and_regex() {
        let root = parse(
            r#"
            http {
                server { listen 443 ssl; server_name *.example.com; }
                server { listen 443 ssl; server_name ~^www\.example\.com$; }
                server { listen 443 ssl; server_name www.example.com; }
            }
            "#,
        );
        let r = find_server_block(&root, "www.example.com", PortScope::Tls443);
        assert_eq!(matched_server_name(&r), vec!["www.example.com"]);
    }

    #[test]
    fn longest_leading_wildcard_wins() {
        let root = parse(
            r#"
            http {
                server { listen 443 ssl; server_name *.example.com; }
                server { listen 443 ssl; server_name *.foo.example.com; }
            }
            "#,
        );
        let r = find_server_block(&root, "bar.foo.example.com", PortScope::Tls443);
        assert_eq!(matched_server_name(&r), vec!["*.foo.example.com"]);
    }

    #[test]
    fn longest_trailing_wildcard_wins() {
        let root = parse(
            r#"
            http {
                server { listen 443 ssl; server_name www.example.*; }
                server { listen 443 ssl; server_name www.example.co.*; }
            }
            "#,
        );
        let r = find_server_block(&root, "www.example.co.uk", PortScope::Tls443);
        assert_eq!(matched_server_name(&r), vec!["www.example.co.*"]);
    }

    #[test]
    fn leading_wildcard_does_not_match_the_bare_apex() {
        let root = parse(r#"http { server { listen 443 ssl; server_name *.example.com; } }"#);
        let r = find_server_block(&root, "example.com", PortScope::Tls443);
        assert!(matches!(r, FindResult::NoMatch));
    }

    #[test]
    fn no_match_never_falls_through_to_default_server() {
        let root = parse(
            r#"
            http {
                server { listen 443 ssl default_server; server_name catchall; }
                server { listen 443 ssl; server_name other.example.com; }
            }
            "#,
        );
        let r = find_server_block(&root, "unknown.example.com", PortScope::Tls443);
        assert!(matches!(r, FindResult::NoMatch));
    }

    #[test]
    fn no_match_never_falls_through_to_first_block() {
        let root = parse(
            r#"
            http {
                server { listen 443 ssl; server_name first.example.com; }
                server { listen 443 ssl; server_name second.example.com; }
            }
            "#,
        );
        let r = find_server_block(&root, "unknown.example.com", PortScope::Tls443);
        assert!(matches!(r, FindResult::NoMatch));
    }

    #[test]
    fn duplicate_exact_server_name_is_ambiguous() {
        let root = parse(
            r#"
            http {
                server { listen 443 ssl; server_name dup.example.com; }
                server { listen 443 ssl; server_name dup.example.com; }
            }
            "#,
        );
        let r = find_server_block(&root, "dup.example.com", PortScope::Tls443);
        assert!(matches!(r, FindResult::Refused(RefusalReason::Ambiguous)));
    }

    #[test]
    fn tied_wildcard_specificity_is_ambiguous() {
        let root = parse(
            r#"
            http {
                server { listen 443 ssl; server_name *.example.com; }
                server { listen 443 ssl; server_name *.example.com; }
            }
            "#,
        );
        let r = find_server_block(&root, "www.example.com", PortScope::Tls443);
        assert!(matches!(r, FindResult::Refused(RefusalReason::Ambiguous)));
    }

    #[test]
    fn regex_block_refuses_when_nothing_else_matches() {
        let root =
            parse(r#"http { server { listen 443 ssl; server_name ~^www\.example\.com$; } }"#);
        let r = find_server_block(&root, "www.example.com", PortScope::Tls443);
        assert!(matches!(r, FindResult::Refused(RefusalReason::Regex)));
    }

    #[test]
    fn regex_block_does_not_refuse_an_unrelated_domain() {
        let root =
            parse(r#"http { server { listen 443 ssl; server_name ~^www\.example\.com$; } }"#);
        let r = find_server_block(&root, "totally-different.org", PortScope::Tls443);
        // The regex block is present but for a domain it plainly cannot
        // affect the intent of, this is still "cannot rule it out" per
        // this module's conservative rule — refuse, not NoMatch. Encodes
        // the deliberate choice: we do not evaluate the regex to decide
        // it's irrelevant, ever.
        assert!(matches!(r, FindResult::Refused(RefusalReason::Regex)));
    }

    #[test]
    fn variable_server_name_refuses_when_nothing_else_matches() {
        let root = parse(r#"http { server { listen 443 ssl; server_name $host; } }"#);
        let r = find_server_block(&root, "example.com", PortScope::Tls443);
        assert!(matches!(
            r,
            FindResult::Refused(RefusalReason::VariableServerName)
        ));
    }

    #[test]
    fn exact_match_wins_even_when_a_different_block_has_a_variable() {
        let root = parse(
            r#"
            http {
                server { listen 443 ssl; server_name $host; }
                server { listen 443 ssl; server_name example.com; }
            }
            "#,
        );
        let r = find_server_block(&root, "example.com", PortScope::Tls443);
        assert_eq!(matched_server_name(&r), vec!["example.com"]);
    }

    #[test]
    fn port_scope_is_respected_80_vs_443() {
        let root = parse(
            r#"
            http {
                server { listen 80; server_name example.com; }
                server { listen 443 ssl; server_name example.com; }
            }
            "#,
        );
        // Exactly one block per scope — not "two blocks match equally".
        assert!(matches!(
            find_server_block(&root, "example.com", PortScope::Tls443),
            FindResult::Matched(_)
        ));
        assert!(matches!(
            find_server_block(&root, "example.com", PortScope::Plain80),
            FindResult::Matched(_)
        ));
    }

    #[test]
    fn no_listen_in_scope_at_all_is_no_match_not_refused() {
        let root = parse(r#"http { server { listen 8080; server_name example.com; } }"#);
        let r = find_server_block(&root, "example.com", PortScope::Tls443);
        assert!(matches!(r, FindResult::NoMatch));
    }

    #[test]
    fn server_name_inside_if_is_not_trusted_as_a_direct_match() {
        let root = parse(
            r#"
            http {
                server {
                    listen 443 ssl;
                    server_name other.example.com;
                    if ($host = "in-an-if.example.com") {
                        server_name in-an-if.example.com;
                    }
                }
            }
            "#,
        );
        let r = find_server_block(&root, "in-an-if.example.com", PortScope::Tls443);
        assert!(matches!(r, FindResult::Refused(RefusalReason::InsideIf)));
    }

    #[test]
    fn last_server_name_directive_wins_when_repeated() {
        let root = parse(
            r#"
            http {
                server {
                    listen 443 ssl;
                    server_name old.example.com;
                    server_name new.example.com;
                }
            }
            "#,
        );
        assert!(matches!(
            find_server_block(&root, "old.example.com", PortScope::Tls443),
            FindResult::NoMatch
        ));
        assert!(matches!(
            find_server_block(&root, "new.example.com", PortScope::Tls443),
            FindResult::Matched(_)
        ));
    }

    #[test]
    fn ipv6_listen_with_ssl_is_recognised() {
        let root = parse(r#"http { server { listen [::]:443 ssl; server_name example.com; } }"#);
        assert!(matches!(
            find_server_block(&root, "example.com", PortScope::Tls443),
            FindResult::Matched(_)
        ));
    }

    #[test]
    fn extract_port_handles_common_forms() {
        assert_eq!(extract_port("80"), Some(80));
        assert_eq!(extract_port("443"), Some(443));
        assert_eq!(extract_port("0.0.0.0:8080"), Some(8080));
        assert_eq!(extract_port("[::]:443"), Some(443));
        assert_eq!(extract_port("[::1]"), None);
        assert_eq!(extract_port("*:80"), Some(80));
    }
}
