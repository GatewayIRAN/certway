// SPDX-License-Identifier: MIT

//! Computes the new file content for a matched `server {}` block. Pure
//! string/span manipulation — no filesystem access, no validation, no
//! decision about *which* block to edit (that's `matching.rs`'s job).
//! `transaction.rs` takes whatever this module produces and is the only
//! thing that ever writes it to disk.
//!
//! Two edits, no more:
//! - a `:443 ssl` block already exists for the domain: replace
//!   `ssl_certificate`/`ssl_certificate_key` in place if present, insert
//!   them after the last `listen` line if absent.
//! - only a `:80` block exists: append a brand-new minimal `server {}`
//!   block after it, never converting/rewriting the existing one — the
//!   original's `location`/`proxy_pass`/anything else is deliberately
//!   never copied into the new block: a subtly-wrong copy would break the
//!   site in a way that looks like certway's fault, not the site owner's
//!   own config.

use super::parse::Directive;
use super::tokenize::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditRefusal {
    /// The matched block's `ssl_certificate`/`ssl_certificate_key` are in a
    /// shape this writer won't guess at: more than one of either (the
    /// legal RSA+ECDSA dual-certificate shape) or one present without its
    /// pair. Refusing and reporting the two lines by hand is safer than
    /// picking one of several existing directives to overwrite.
    AmbiguousCertificateDirectives,
    /// The matched block has no `listen` directive in scope at all — should
    /// be unreachable in practice, since `matching.rs` only ever returns a
    /// block that already passed `block_listens_in_scope`, but the writer
    /// checks for itself rather than trusting that invariant silently.
    MalformedBlock,
}

/// Replaces (or inserts) `ssl_certificate`/`ssl_certificate_key` in
/// `tls_block`, which must be the `server {}` `Directive` `matching.rs`
/// returned for `PortScope::Tls443`. Returns the complete new content for
/// `tls_block.file`'s source text (`source` — the caller reads this from
/// the same file `tls_block.file` names, via the same `ConfigFs` used to
/// parse it).
pub fn build_in_place_edit(
    source: &str,
    tls_block: &Directive,
    fullchain_path: &str,
    key_path: &str,
) -> Result<String, EditRefusal> {
    let children = tls_block.block.as_deref().unwrap_or(&[]);
    let certs: Vec<&Directive> = children
        .iter()
        .filter(|d| d.name == "ssl_certificate")
        .collect();
    let keys: Vec<&Directive> = children
        .iter()
        .filter(|d| d.name == "ssl_certificate_key")
        .collect();

    match (certs.len(), keys.len()) {
        (1, 1) => {
            let (cert, key) = (certs[0], keys[0]);
            if cert.arg_spans.is_empty() || key.arg_spans.is_empty() {
                return Err(EditRefusal::MalformedBlock);
            }
            let edits = vec![
                (cert.arg_spans[0], fullchain_path.to_string()),
                (key.arg_spans[0], key_path.to_string()),
            ];
            Ok(apply_edits(source, edits))
        }
        (0, 0) => {
            let listens: Vec<&Directive> = children.iter().filter(|d| d.name == "listen").collect();
            let Some(last_listen) = listens.last() else {
                return Err(EditRefusal::MalformedBlock);
            };
            let indent = leading_whitespace(source, last_listen.span.start);
            let insert_text = format!("\n{indent}ssl_certificate     {fullchain_path};\n{indent}ssl_certificate_key {key_path};");
            let pos = last_listen.span.end;
            Ok(apply_edits(source, vec![(zero_width(pos), insert_text)]))
        }
        _ => Err(EditRefusal::AmbiguousCertificateDirectives),
    }
}

/// Appends the minimal new `:443` block after `plain_block` (the `server
/// {}` `Directive` `matching.rs` returned for `PortScope::Plain80`),
/// including the explanatory comment on the last line — a real constraint
/// on the reader's expectations, not just a note, since the original
/// block's `location`/`proxy_pass` directives are deliberately never
/// copied in. `http2_supported` selects between `http2 on;` (nginx >=
/// 1.25.1) and the deprecated combined `listen ... http2` form (earlier
/// versions), per `version::supports_http2_directive`.
pub fn build_appended_block(
    source: &str,
    plain_block: &Directive,
    domain: &str,
    fullchain_path: &str,
    key_path: &str,
    http2_supported: bool,
) -> String {
    let indent = leading_whitespace(source, plain_block.span.start);
    let inner = format!("{indent}    ");

    let listen_lines = if http2_supported {
        format!("{inner}listen 443 ssl;\n{inner}listen [::]:443 ssl;\n{inner}http2 on;")
    } else {
        format!("{inner}listen 443 ssl http2;\n{inner}listen [::]:443 ssl http2;")
    };

    let block = format!(
        "\n\n{indent}# managed by certway — {domain}\n\
         {indent}server {{\n\
         {listen_lines}\n\
         \n\
         {inner}server_name {domain};\n\
         \n\
         {inner}ssl_certificate     {fullchain_path};\n\
         {inner}ssl_certificate_key {key_path};\n\
         \n\
         {inner}# (the original block's location directives are NOT copied)\n\
         {indent}}}"
    );

    let pos = plain_block.span.end;
    apply_edits(source, vec![(zero_width(pos), block)])
}

/// Appends the standalone HTTP-to-HTTPS redirect block after `after` —
/// only ever called by the orchestrator when it has independently
/// confirmed no existing `:80` block already names this domain (appending
/// this next to one that does would create the very shadowing duplicate
/// `server_name` `transaction.rs`'s strict post-edit check exists to
/// catch).
pub fn build_redirect_block(source: &str, after: &Directive, domain: &str) -> String {
    let indent = leading_whitespace(source, after.span.start);
    let inner = format!("{indent}    ");

    let block = format!(
        "\n\n{indent}server {{\n\
         {inner}listen 80;\n\
         {inner}server_name {domain};\n\
         {inner}return 301 https://$host$request_uri;\n\
         {indent}}}"
    );

    let pos = after.span.end;
    apply_edits(source, vec![(zero_width(pos), block)])
}

fn zero_width(pos: usize) -> Span {
    Span {
        start: pos,
        end: pos,
        line: 0,
    }
}

/// Splices `edits` into `source`. Applied in descending `span.start` order
/// so an earlier edit's byte offsets stay valid while later (in document
/// order) edits are made first — the standard trick for applying multiple
/// non-overlapping replacements against the same original offsets without
/// re-parsing between them.
fn apply_edits(source: &str, mut edits: Vec<(Span, String)>) -> String {
    edits.sort_by_key(|e| std::cmp::Reverse(e.0.start));
    for pair in edits.windows(2) {
        debug_assert!(
            pair[1].0.end <= pair[0].0.start,
            "edit spans must not overlap: {:?} vs {:?}",
            pair[1].0,
            pair[0].0
        );
    }
    let mut out = source.to_string();
    for (span, replacement) in edits {
        out.replace_range(span.start..span.end, &replacement);
    }
    out
}

/// The whitespace-only run immediately preceding byte offset `pos` on its
/// own line — used to match a new line's indentation to its neighbour's.
/// Stops at the first non-space/tab byte or line start, so it never grabs
/// unrelated content from earlier on the same line.
fn leading_whitespace(source: &str, pos: usize) -> &str {
    let bytes = source.as_bytes();
    let mut start = pos;
    while start > 0 && (bytes[start - 1] == b' ' || bytes[start - 1] == b'\t') {
        start -= 1;
    }
    &source[start..pos]
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

    fn only_server(root: &[Directive]) -> &Directive {
        &root[0].block.as_ref().unwrap()[0]
    }

    #[test]
    fn replaces_existing_cert_paths_in_place_preserving_everything_else() {
        let src = "http {\n    server {\n        listen 443 ssl;\n        server_name example.com;\n        ssl_certificate /old/fullchain.pem;\n        ssl_certificate_key /old/privkey.pem;\n        location / { root /var/www; }\n    }\n}";
        let root = parse(src);
        let server = only_server(&root);

        let out =
            build_in_place_edit(src, server, "/new/fullchain.pem", "/new/privkey.pem").unwrap();

        assert!(out.contains("ssl_certificate /new/fullchain.pem;"));
        assert!(out.contains("ssl_certificate_key /new/privkey.pem;"));
        assert!(
            out.contains("location / { root /var/www; }"),
            "unrelated content must survive untouched"
        );
        assert!(!out.contains("/old/"));
    }

    #[test]
    fn inserts_cert_directives_after_the_last_listen_when_absent() {
        let src = "http {\n    server {\n        listen 443 ssl;\n        listen [::]:443 ssl;\n        server_name example.com;\n    }\n}";
        let root = parse(src);
        let server = only_server(&root);

        let out =
            build_in_place_edit(src, server, "/new/fullchain.pem", "/new/privkey.pem").unwrap();

        let listen_pos = out.find("listen [::]:443 ssl;").unwrap();
        let cert_pos = out.find("ssl_certificate     /new/fullchain.pem;").unwrap();
        let name_pos = out.find("server_name example.com;").unwrap();
        assert!(
            listen_pos < cert_pos,
            "cert lines must come after the last listen"
        );
        assert!(
            cert_pos < name_pos,
            "cert lines must come before server_name (inserted immediately after listen)"
        );
        assert!(out.contains("ssl_certificate_key /new/privkey.pem;"));
    }

    #[test]
    fn inserted_lines_match_the_blocks_own_indentation() {
        let src = "http {\n  server {\n    listen 443 ssl;\n  }\n}";
        let root = parse(src);
        let server = only_server(&root);

        let out = build_in_place_edit(src, server, "/f", "/k").unwrap();
        assert!(out.contains("\n    ssl_certificate     /f;"));
        assert!(out.contains("\n    ssl_certificate_key /k;"));
    }

    #[test]
    fn mismatched_cert_and_key_presence_is_refused() {
        let src = "http { server { listen 443 ssl; ssl_certificate /only/cert.pem; } }";
        let root = parse(src);
        let server = only_server(&root);

        let result = build_in_place_edit(src, server, "/new/fullchain.pem", "/new/privkey.pem");
        assert_eq!(result, Err(EditRefusal::AmbiguousCertificateDirectives));
    }

    #[test]
    fn dual_certificate_shape_is_refused_not_guessed_at() {
        // RSA + ECDSA — legal nginx (>= 1.11.0) but not something this
        // writer picks between.
        let src = "http { server { listen 443 ssl; ssl_certificate /a/rsa.pem; ssl_certificate_key /a/rsa.key; ssl_certificate /a/ecdsa.pem; ssl_certificate_key /a/ecdsa.key; } }";
        let root = parse(src);
        let server = only_server(&root);

        let result = build_in_place_edit(src, server, "/new/fullchain.pem", "/new/privkey.pem");
        assert_eq!(result, Err(EditRefusal::AmbiguousCertificateDirectives));
    }

    #[test]
    fn appended_block_matches_the_arch_spec_template_shape() {
        // Top-level (unindented) server block, so the new block's own
        // indentation (matched to this one) is unambiguous to assert on.
        let src = "server {\n    listen 80;\n    server_name example.com;\n}";
        let root = parse(src);
        let server = &root[0];

        let out = build_appended_block(
            src,
            server,
            "example.com",
            "/var/lib/certway/example.com/fullchain.pem",
            "/var/lib/certway/example.com/privkey.pem",
            true,
        );

        assert!(out.contains("# managed by certway — example.com"));
        assert!(out.contains("    listen 443 ssl;\n    listen [::]:443 ssl;\n    http2 on;"));
        assert!(out.contains("server_name example.com;"));
        assert!(out.contains("ssl_certificate     /var/lib/certway/example.com/fullchain.pem;"));
        assert!(out.contains("ssl_certificate_key /var/lib/certway/example.com/privkey.pem;"));
        assert!(out.contains("# (the original block's location directives are NOT copied)"));
        // The original block is untouched, not converted.
        assert!(out.contains("server {\n    listen 80;\n    server_name example.com;\n}"));
    }

    #[test]
    fn appended_block_uses_legacy_http2_form_when_unsupported() {
        let src = "server { listen 80; server_name example.com; }";
        let root = parse(src);
        let server = &root[0];

        let out = build_appended_block(src, server, "example.com", "/f", "/k", false);
        assert!(out.contains("listen 443 ssl http2;"));
        assert!(out.contains("listen [::]:443 ssl http2;"));
        assert!(!out.contains("http2 on;"));
    }

    #[test]
    fn appended_block_is_inserted_immediately_after_the_plain_blocks_close_brace() {
        let src = "server { listen 80; server_name example.com; }\nserver { listen 80; server_name other.com; }";
        let root = parse(src);
        let plain = &root[0];

        let out = build_appended_block(src, plain, "example.com", "/f", "/k", true);
        let new_block_pos = out.find("# managed by certway").unwrap();
        let other_pos = out.find("other.com").unwrap();
        assert!(
            new_block_pos < other_pos,
            "new block must land right after the matched block, before its sibling"
        );
    }

    #[test]
    fn redirect_block_matches_the_arch_spec_template_shape() {
        let src = "server {\n    listen 443 ssl;\n    server_name example.com;\n}";
        let root = parse(src);
        let server = &root[0];

        let out = build_redirect_block(src, server, "example.com");
        assert!(out.contains("server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}"));
    }

    #[test]
    fn empty_block_with_no_listen_at_all_is_malformed() {
        let src = "http { server { server_name example.com; } }";
        let root = parse(src);
        let server = only_server(&root);

        let result = build_in_place_edit(src, server, "/f", "/k");
        assert_eq!(result, Err(EditRefusal::MalformedBlock));
    }
}
