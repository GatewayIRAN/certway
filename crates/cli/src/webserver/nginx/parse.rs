// SPDX-License-Identifier: MIT

//! Builds a directive tree from tokens. `include`
//! directives are expanded and spliced in at the point they occur — glob
//! patterns sorted lexicographically (proven against the pinned container:
//! `nginx -T` resolves three deliberately out-of-creation-order files
//! `a-first`/`b-second`/`c-third` in that alphabetical order regardless of
//! which was written to disk first), relative paths resolved against the
//! `nginx -V` compiled prefix, and include cycles a hard error. A glob that
//! matches zero files is not an error — Alpine's real shipped `nginx.conf`
//! includes both a populated `http.d/*.conf` and an unpopulated
//! `conf.d/*.conf`; treating the empty one as a failure would make certway
//! unable to find any block on a real Alpine box.
//!
//! Every error here is recoverable by the caller, never a panic: a config
//! this parser can't make sense of is defence #4 ("refuse to edit anything
//! not understood"), not a crash.

use super::tokenize::{tokenize, Span, Token, TokenKind, TokenizeError};
use std::iter::Peekable;
use std::path::{Path, PathBuf};
use std::slice;

#[derive(Debug, Clone)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    /// One span per `args` entry, in order — exact byte range of just that
    /// argument's token (not including surrounding whitespace/quotes'
    /// delimiters), so `edit.rs` can replace a single value (e.g.
    /// `ssl_certificate`'s path) without disturbing anything else on the
    /// line.
    pub arg_spans: Vec<Span>,
    pub block: Option<Vec<Directive>>,
    /// The logical (virtual) path this directive's tokens came from — the
    /// path as it exists on the real box, independent of any test-only
    /// `root` a `ConfigFs` impl reads from underneath.
    pub file: PathBuf,
    /// The whole directive's exact byte range in `file`'s source text:
    /// name-token-start through the terminating `;` for a simple
    /// directive, or through the matching `}` for a block directive.
    /// Precise both ways — `edit.rs` needs the exact close-brace position
    /// to insert a new sibling block right after this one.
    pub span: Span,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Tokenize { file: PathBuf, inner: TokenizeError },
    Read { path: PathBuf, detail: String },
    IncludeCycle { path: PathBuf },
    IncludeArgCount { file: PathBuf, line: u32 },
    UnexpectedToken { file: PathBuf, line: u32 },
    DirectiveWithoutTerminator { file: PathBuf },
    UnterminatedBlock { file: PathBuf },
    UnexpectedCloseBrace { file: PathBuf, line: u32 },
}

/// The filesystem seam. Production always uses `RealFs { root: None }`;
/// tests substitute either `RealFs { root: Some(fixture_dir) }` (real
/// captured configs, absolute `include` paths transparently rebased under
/// `fixture_dir`) or `MockFs` (in-memory, for exercising include/glob/cycle
/// logic without touching disk at all).
pub trait ConfigFs {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
    /// Lists `dir`'s entries matching the single-component glob `pattern`
    /// (e.g. `"*.conf"`), sorted lexicographically by file name. A missing
    /// `dir` is zero matches, not an error — nginx's own glob does the
    /// same, confirmed live: Alpine's shipped `nginx.conf` includes both a
    /// populated `http.d/*.conf` and a `conf.d/*.conf` that doesn't exist
    /// on disk at all.
    fn glob_dir(&self, dir: &Path, pattern: &str) -> std::io::Result<Vec<PathBuf>>;
}

pub struct RealFs {
    pub root: Option<PathBuf>,
}

impl RealFs {
    /// Rebases an absolute path under `root` when set — the seam that lets
    /// tests point at a captured fixture tree instead of the real
    /// filesystem. Also walks symlinks manually (bounded to 40 hops,
    /// matching common OS limits — never an infinite loop on a cyclic
    /// link) rather than letting the OS auto-follow them: an *absolute*
    /// symlink target (confirmed real on Debian's `sites-enabled`, per
    /// `tests/fixtures/nginx/real/NOTES.md`) would otherwise resolve
    /// against the real filesystem root, escaping `root` entirely, since
    /// the OS has no idea a virtual root is in play. In production
    /// (`root: None`) this is a no-op past the first `return` — real
    /// symlinks resolve exactly as the OS would do it anyway.
    fn resolve(&self, path: &Path) -> PathBuf {
        let Some(root) = &self.root else {
            return path.to_path_buf();
        };
        if !path.is_absolute() {
            return path.to_path_buf();
        }
        let mut current = root.join(path.strip_prefix("/").unwrap_or(path));
        for _ in 0..40 {
            match std::fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => match std::fs::read_link(&current) {
                    Ok(target) if target.is_absolute() => {
                        current = root.join(target.strip_prefix("/").unwrap_or(&target));
                    }
                    Ok(target) => {
                        current = current.parent().unwrap_or(Path::new("/")).join(target);
                    }
                    Err(_) => break,
                },
                _ => break,
            }
        }
        current
    }
}

impl ConfigFs for RealFs {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(self.resolve(path))
    }

    fn glob_dir(&self, dir: &Path, pattern: &str) -> std::io::Result<Vec<PathBuf>> {
        let resolved = self.resolve(dir);
        let mut names: Vec<String> = match std::fs::read_dir(&resolved) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| glob_match(pattern, n))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        names.sort();
        Ok(names.into_iter().map(|n| dir.join(n)).collect())
    }
}

/// Two-pointer wildcard match (`*` = zero or more of any char; no other
/// metacharacters — every real `include` pattern seen is exactly this
/// shape: `*.conf`, `*`, never `?`/`[...]`/`**`). Iterative, not
/// recursive backtracking, so it terminates in bounded time regardless of
/// input.
fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    let (mut star_p, mut star_n) = (None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '*' || p[pi] == n[ni]) {
            if p[pi] == '*' {
                star_p = Some(pi);
                star_n = ni;
                pi += 1;
            } else {
                pi += 1;
                ni += 1;
            }
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_n += 1;
            ni = star_n;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Lexical normalisation only — no filesystem access. Used for cycle
/// detection against the *logical* include graph, not real symlink loops
/// on disk (that's a separate, higher-level refusal condition).
fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Parses `entry_path` and every file it (transitively) `include`s,
/// against `prefix` (the `nginx -V` compiled prefix, for resolving
/// relative `include` paths) and `fs` (the filesystem seam).
pub fn parse_file(
    entry_path: &Path,
    prefix: &Path,
    fs: &dyn ConfigFs,
) -> Result<Vec<Directive>, ParseError> {
    let mut stack = Vec::new();
    parse_file_inner(entry_path, prefix, fs, &mut stack)
}

fn parse_file_inner(
    path: &Path,
    prefix: &Path,
    fs: &dyn ConfigFs,
    stack: &mut Vec<PathBuf>,
) -> Result<Vec<Directive>, ParseError> {
    let canon = normalize(path);
    if stack.contains(&canon) {
        return Err(ParseError::IncludeCycle { path: canon });
    }
    let content = fs.read_to_string(path).map_err(|e| ParseError::Read {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let tokens = tokenize(&content).map_err(|inner| ParseError::Tokenize {
        file: path.to_path_buf(),
        inner,
    })?;

    stack.push(canon);
    let mut iter = tokens.iter().peekable();
    let result = parse_block(&mut iter, path, prefix, fs, stack, false)
        .map(|(directives, _close_span)| directives);
    stack.pop();
    result
}

enum ParsedDirective {
    Plain(Directive),
    Spliced(Vec<Directive>),
}

/// Returns the parsed children plus, when `in_block`, the `}` token's own
/// span (`edit.rs` needs the exact close-brace position to know where a
/// block ends — e.g. to insert a new sibling `server {}` right after this
/// one). `None` at top level, where there is no closing brace to report.
fn parse_block<'a>(
    iter: &mut Peekable<slice::Iter<'a, Token>>,
    file: &Path,
    prefix: &Path,
    fs: &dyn ConfigFs,
    stack: &mut Vec<PathBuf>,
    in_block: bool,
) -> Result<(Vec<Directive>, Option<Span>), ParseError> {
    let mut out = Vec::new();
    loop {
        match iter.peek() {
            None => {
                if in_block {
                    return Err(ParseError::UnterminatedBlock {
                        file: file.to_path_buf(),
                    });
                }
                return Ok((out, None));
            }
            Some(tok) if tok.kind == TokenKind::CloseBrace => {
                if !in_block {
                    return Err(ParseError::UnexpectedCloseBrace {
                        file: file.to_path_buf(),
                        line: tok.span.line,
                    });
                }
                let close_span = tok.span;
                iter.next();
                return Ok((out, Some(close_span)));
            }
            _ => match parse_one_directive(iter, file, prefix, fs, stack)? {
                ParsedDirective::Plain(d) => out.push(d),
                ParsedDirective::Spliced(mut ds) => out.append(&mut ds),
            },
        }
    }
}

fn parse_one_directive<'a>(
    iter: &mut Peekable<slice::Iter<'a, Token>>,
    file: &Path,
    prefix: &Path,
    fs: &dyn ConfigFs,
    stack: &mut Vec<PathBuf>,
) -> Result<ParsedDirective, ParseError> {
    let name_tok = iter.next().expect("caller peeked Some and not CloseBrace");
    let name = match &name_tok.kind {
        TokenKind::Word(w) => w.clone(),
        _ => {
            return Err(ParseError::UnexpectedToken {
                file: file.to_path_buf(),
                line: name_tok.span.line,
            })
        }
    };
    let start_span = name_tok.span;
    let mut args: Vec<String> = Vec::new();
    let mut arg_spans: Vec<Span> = Vec::new();

    loop {
        match iter.peek() {
            None => {
                return Err(ParseError::DirectiveWithoutTerminator {
                    file: file.to_path_buf(),
                })
            }
            Some(tok) => match &tok.kind {
                TokenKind::Word(w) => {
                    args.push(w.clone());
                    arg_spans.push(tok.span);
                    iter.next();
                }
                TokenKind::Semicolon => {
                    let end = tok.span.end;
                    iter.next();
                    let span = Span {
                        start: start_span.start,
                        end,
                        line: start_span.line,
                    };
                    if name == "include" {
                        if args.len() != 1 {
                            return Err(ParseError::IncludeArgCount {
                                file: file.to_path_buf(),
                                line: start_span.line,
                            });
                        }
                        let matched = resolve_include(&args[0], prefix, fs)?;
                        let mut spliced = Vec::new();
                        for m in matched {
                            spliced.append(&mut parse_file_inner(&m, prefix, fs, stack)?);
                        }
                        return Ok(ParsedDirective::Spliced(spliced));
                    }
                    return Ok(ParsedDirective::Plain(Directive {
                        name,
                        args,
                        arg_spans,
                        block: None,
                        file: file.to_path_buf(),
                        span,
                    }));
                }
                TokenKind::OpenBrace => {
                    iter.next();
                    let (nested, close_span) = parse_block(iter, file, prefix, fs, stack, true)?;
                    let end = close_span
                        .expect("parse_block(in_block: true) always returns Some on success")
                        .end;
                    let span = Span {
                        start: start_span.start,
                        end,
                        line: start_span.line,
                    };
                    return Ok(ParsedDirective::Plain(Directive {
                        name,
                        args,
                        arg_spans,
                        block: Some(nested),
                        file: file.to_path_buf(),
                        span,
                    }));
                }
                TokenKind::CloseBrace => {
                    return Err(ParseError::DirectiveWithoutTerminator {
                        file: file.to_path_buf(),
                    })
                }
            },
        }
    }
}

/// `arg` is the `include` directive's single argument: an absolute path
/// used as-is, or a relative one resolved against `prefix` — always
/// against the compiled prefix, never relative to the including file's
/// own directory, matching nginx's real behavior. A glob (contains `*`)
/// expands via `fs.glob_dir`, sorted; a literal path must exist (nginx
/// errors on a missing literal include).
fn resolve_include(
    arg: &str,
    prefix: &Path,
    fs: &dyn ConfigFs,
) -> Result<Vec<PathBuf>, ParseError> {
    let pattern_path = if Path::new(arg).is_absolute() {
        PathBuf::from(arg)
    } else {
        prefix.join(arg)
    };

    if pattern_path.to_string_lossy().contains('*') {
        let dir = pattern_path
            .parent()
            .unwrap_or(Path::new("/"))
            .to_path_buf();
        let pattern = pattern_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        fs.glob_dir(&dir, &pattern).map_err(|e| ParseError::Read {
            path: pattern_path.clone(),
            detail: e.to_string(),
        })
    } else {
        Ok(vec![pattern_path])
    }
}

#[cfg(test)]
pub(crate) mod mock_fs {
    use super::ConfigFs;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// In-memory filesystem double: exact byte-for-byte control over what
    /// `include` sees, with no real disk I/O — the right tool for proving
    /// glob/sort/cycle/prefix logic in isolation from real containers.
    #[derive(Default)]
    pub struct MockFs {
        pub files: BTreeMap<PathBuf, String>,
    }

    impl MockFs {
        pub fn with(pairs: &[(&str, &str)]) -> Self {
            let mut files = BTreeMap::new();
            for (path, content) in pairs {
                files.insert(PathBuf::from(path), content.to_string());
            }
            MockFs { files }
        }
    }

    impl ConfigFs for MockFs {
        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            self.files.get(path).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "mock file not found")
            })
        }

        fn glob_dir(&self, dir: &Path, pattern: &str) -> std::io::Result<Vec<PathBuf>> {
            let mut names: Vec<String> = self
                .files
                .keys()
                .filter_map(|p| {
                    let parent = p.parent()?;
                    if parent != dir {
                        return None;
                    }
                    p.file_name().and_then(|n| n.to_str()).map(str::to_string)
                })
                .filter(|n| super::glob_match(pattern, n))
                .collect();
            names.sort();
            Ok(names.into_iter().map(|n| dir.join(n)).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock_fs::MockFs;
    use super::*;

    #[test]
    fn simple_server_block() {
        let fs = MockFs::with(&[(
            "/etc/nginx/nginx.conf",
            "http { server { listen 80; server_name x; } }",
        )]);
        let d = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "http");
        let server = &d[0].block.as_ref().unwrap()[0];
        assert_eq!(server.name, "server");
        assert_eq!(server.block.as_ref().unwrap()[0].args, vec!["80"]);
    }

    #[test]
    fn include_is_spliced_at_the_same_level() {
        let fs = MockFs::with(&[
            (
                "/etc/nginx/nginx.conf",
                "http { include /etc/nginx/conf.d/a.conf; }",
            ),
            ("/etc/nginx/conf.d/a.conf", "server { listen 80; }"),
        ]);
        let d = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap();
        let http_children = d[0].block.as_ref().unwrap();
        assert_eq!(http_children.len(), 1);
        assert_eq!(http_children[0].name, "server");
    }

    #[test]
    fn glob_include_is_sorted_regardless_of_map_order() {
        // BTreeMap already sorts keys, so prove sorting a different way:
        // three names whose creation/insertion order (b, a, c) differs
        // from lexicographic order, same as the live container proof.
        let fs = MockFs::with(&[
            (
                "/etc/nginx/nginx.conf",
                "http { include /etc/nginx/conf.d/*.conf; }",
            ),
            (
                "/etc/nginx/conf.d/b-second.conf",
                "server { server_name from_b; }",
            ),
            (
                "/etc/nginx/conf.d/a-first.conf",
                "server { server_name from_a; }",
            ),
            (
                "/etc/nginx/conf.d/c-third.conf",
                "server { server_name from_c; }",
            ),
        ]);
        let d = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap();
        let names: Vec<&str> = d[0]
            .block
            .as_ref()
            .unwrap()
            .iter()
            .map(|server| server.block.as_ref().unwrap()[0].args[0].as_str())
            .collect();
        assert_eq!(names, vec!["from_a", "from_b", "from_c"]);
    }

    #[test]
    fn glob_matching_zero_files_is_not_an_error() {
        // The Alpine case: nginx.conf includes a conf.d that doesn't exist
        // on disk at all, alongside a populated http.d.
        let fs = MockFs::with(&[
            (
                "/etc/nginx/nginx.conf",
                "http { include /etc/nginx/conf.d/*.conf; include /etc/nginx/http.d/*.conf; }",
            ),
            ("/etc/nginx/http.d/default.conf", "server { listen 80; }"),
        ]);
        let d = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap();
        let http_children = d[0].block.as_ref().unwrap();
        assert_eq!(http_children.len(), 1);
        assert_eq!(http_children[0].name, "server");
    }

    #[test]
    fn relative_include_resolves_against_prefix_not_including_files_directory() {
        let fs = MockFs::with(&[
            ("/etc/nginx/nginx.conf", "http { include conf.d/a.conf; }"),
            ("/etc/nginx/conf.d/a.conf", "server { listen 80; }"),
        ]);
        let d = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap();
        assert_eq!(d[0].block.as_ref().unwrap()[0].name, "server");
    }

    #[test]
    fn include_cycle_is_a_hard_error() {
        let fs = MockFs::with(&[("/etc/nginx/nginx.conf", "include /etc/nginx/nginx.conf;")]);
        let err = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::IncludeCycle { .. }));
    }

    #[test]
    fn indirect_include_cycle_is_a_hard_error() {
        let fs = MockFs::with(&[
            ("/etc/nginx/a.conf", "include /etc/nginx/b.conf;"),
            ("/etc/nginx/b.conf", "include /etc/nginx/a.conf;"),
        ]);
        let err =
            parse_file(Path::new("/etc/nginx/a.conf"), Path::new("/etc/nginx"), &fs).unwrap_err();
        assert!(matches!(err, ParseError::IncludeCycle { .. }));
    }

    #[test]
    fn missing_literal_include_is_an_error() {
        let fs = MockFs::with(&[("/etc/nginx/nginx.conf", "include /etc/nginx/missing.conf;")]);
        let err = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::Read { .. }));
    }

    #[test]
    fn unterminated_block_errors_not_panics() {
        let fs = MockFs::with(&[("/etc/nginx/nginx.conf", "http { server { listen 80; ")]);
        let err = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::UnterminatedBlock { .. }));
    }

    #[test]
    fn stray_close_brace_errors_not_panics() {
        let fs = MockFs::with(&[("/etc/nginx/nginx.conf", "http { } }")]);
        let err = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::UnexpectedCloseBrace { .. }));
    }

    #[test]
    fn directive_without_terminator_at_eof_errors_not_panics() {
        let fs = MockFs::with(&[("/etc/nginx/nginx.conf", "http { server_name x")]);
        let err = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::DirectiveWithoutTerminator { .. }));
    }

    #[test]
    fn glob_match_basic_cases() {
        assert!(glob_match("*.conf", "default.conf"));
        assert!(!glob_match("*.conf", "default.txt"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("*.conf", ""));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("a*b*c", "aXbYd"));
    }

    #[test]
    fn real_world_shape_nested_include_inside_server_block() {
        // The RHEL/dnf case: `include /etc/nginx/default.d/*.conf;` sits
        // inside the server{} block itself, not just at http{} level.
        let fs = MockFs::with(&[
            (
                "/etc/nginx/nginx.conf",
                "http { server { listen 80; server_name _; include /etc/nginx/default.d/*.conf; } }",
            ),
            ("/etc/nginx/default.d/ssl.conf", "add_header X-Test on;"),
        ]);
        let d = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap();
        let server = &d[0].block.as_ref().unwrap()[0];
        let names: Vec<&str> = server
            .block
            .as_ref()
            .unwrap()
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, vec!["listen", "server_name", "add_header"]);
    }

    #[test]
    fn block_span_end_lands_exactly_on_the_close_brace_byte() {
        // edit.rs inserts a new sibling block right after this position —
        // if it drifted even one byte, the insertion would land inside the
        // existing block's body or eat part of the brace itself.
        let src = "server { listen 80; }";
        let fs = MockFs::with(&[("/etc/nginx/nginx.conf", src)]);
        let d = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap();
        let close_brace_byte = src.rfind('}').unwrap();
        assert_eq!(d[0].span.end, close_brace_byte + 1);
        assert_eq!(&src[d[0].span.end - 1..d[0].span.end], "}");
    }

    #[test]
    fn arg_span_covers_exactly_the_argument_token() {
        let src = r#"ssl_certificate /etc/nginx/old.pem;"#;
        let fs = MockFs::with(&[("/etc/nginx/nginx.conf", src)]);
        let d = parse_file(
            Path::new("/etc/nginx/nginx.conf"),
            Path::new("/etc/nginx"),
            &fs,
        )
        .unwrap();
        let span = d[0].arg_spans[0];
        assert_eq!(&src[span.start..span.end], "/etc/nginx/old.pem");
    }
}
