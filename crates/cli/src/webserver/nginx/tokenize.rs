// SPDX-License-Identifier: MIT

//! nginx config tokeniser. Handles `{` `}` `;` nesting/terminators, `#`
//! comments, and single/double quoted strings with `\`-escapes — nothing
//! else. It does not know what a directive means; it only turns bytes
//! into tokens, bounds-checked throughout so a malformed or truncated file
//! errors instead of panicking or hanging (never indexes past the input,
//! never loops without consuming a byte).
//!
//! Escape handling inside quotes is this tokeniser's own choice, not a
//! rule imposed by nginx's own config grammar (this program only needs to
//! *safely edit* an existing config, not fully author one): `\` followed
//! by any character consumes both and emits the character literally. This
//! is a conservative superset of nginx's real behavior, chosen so quoted
//! content we don't need to interpret (e.g. an `add_header` value) is
//! skipped over correctly rather than misparsed.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Word(String),
    OpenBrace,
    CloseBrace,
    Semicolon,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenizeError {
    pub message: &'static str,
    pub line: u32,
}

impl fmt::Display for TokenizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at line {}", self.message, self.line)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: u32,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a str) -> Self {
        Cursor {
            bytes: input.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
        }
        Some(b)
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }
}

/// Tokenises a whole config file's text. Bounds-checked and total: every
/// branch either consumes at least one byte or returns, so this always
/// terminates on finite input.
pub fn tokenize(input: &str) -> Result<Vec<Token>, TokenizeError> {
    let mut cur = Cursor::new(input);
    let mut tokens = Vec::new();

    loop {
        skip_whitespace_and_comments(&mut cur);
        if cur.at_end() {
            return Ok(tokens);
        }
        let start = cur.pos;
        let start_line = cur.line;
        let b = cur.peek().expect("checked at_end above");

        match b {
            b'{' => {
                cur.bump();
                tokens.push(Token {
                    kind: TokenKind::OpenBrace,
                    span: Span {
                        start,
                        end: cur.pos,
                        line: start_line,
                    },
                });
            }
            b'}' => {
                cur.bump();
                tokens.push(Token {
                    kind: TokenKind::CloseBrace,
                    span: Span {
                        start,
                        end: cur.pos,
                        line: start_line,
                    },
                });
            }
            b';' => {
                cur.bump();
                tokens.push(Token {
                    kind: TokenKind::Semicolon,
                    span: Span {
                        start,
                        end: cur.pos,
                        line: start_line,
                    },
                });
            }
            b'"' | b'\'' => {
                let word = read_quoted(&mut cur, b)?;
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    span: Span {
                        start,
                        end: cur.pos,
                        line: start_line,
                    },
                });
            }
            _ => {
                let word = read_bareword(&mut cur);
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    span: Span {
                        start,
                        end: cur.pos,
                        line: start_line,
                    },
                });
            }
        }
    }
}

fn skip_whitespace_and_comments(cur: &mut Cursor) {
    loop {
        match cur.peek() {
            Some(b) if b.is_ascii_whitespace() => {
                cur.bump();
            }
            Some(b'#') => {
                while let Some(b) = cur.peek() {
                    if b == b'\n' {
                        break;
                    }
                    cur.bump();
                }
            }
            _ => return,
        }
    }
}

/// Reads a bareword: everything up to the next whitespace, `{`, `}`, `;`,
/// `#`, or quote char — those are always token boundaries in nginx config
/// syntax, even without surrounding whitespace (`listen 80;server_name` is
/// two directives, not a malformed one).
fn read_bareword(cur: &mut Cursor) -> String {
    let mut out = String::new();
    while let Some(b) = cur.peek() {
        if b.is_ascii_whitespace() || matches!(b, b'{' | b'}' | b';' | b'#') {
            break;
        }
        // A quote that starts mid-bareword (e.g. `foo"bar"`) is rare but
        // real; nginx concatenates the quoted segment into the same word.
        // Bounds-checked: read_quoted itself never runs off the end.
        if b == b'"' || b == b'\'' {
            cur.bump();
            match read_quoted_body(cur, b) {
                Ok(s) => out.push_str(&s),
                Err(_) => break,
            }
            continue;
        }
        out.push(b as char);
        cur.bump();
    }
    out
}

fn read_quoted(cur: &mut Cursor, quote: u8) -> Result<String, TokenizeError> {
    let line = cur.line;
    cur.bump(); // consume opening quote
    read_quoted_body(cur, quote).map_err(|_| TokenizeError {
        message: "unterminated quoted string",
        line,
    })
}

/// The shared body-reader for both a standalone quoted word and a quote
/// segment embedded in a bareword. Assumes the opening quote has already
/// been consumed by the caller.
fn read_quoted_body(cur: &mut Cursor, quote: u8) -> Result<String, ()> {
    let mut out = String::new();
    loop {
        match cur.bump() {
            None => return Err(()),
            Some(b) if b == quote => return Ok(out),
            Some(b'\\') => match cur.bump() {
                None => return Err(()),
                Some(escaped) => out.push(escaped as char),
            },
            Some(b) => out.push(b as char),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(tokens: &[Token]) -> Vec<&str> {
        tokens
            .iter()
            .filter_map(|t| match &t.kind {
                TokenKind::Word(w) => Some(w.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn simple_directive() {
        let tokens = tokenize("listen 443 ssl;").unwrap();
        assert_eq!(words(&tokens), vec!["listen", "443", "ssl"]);
        assert_eq!(tokens.last().unwrap().kind, TokenKind::Semicolon);
    }

    #[test]
    fn nested_block() {
        let tokens = tokenize("http { server { listen 80; } }").unwrap();
        let kinds: Vec<&TokenKind> = tokens.iter().map(|t| &t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                &TokenKind::Word("http".into()),
                &TokenKind::OpenBrace,
                &TokenKind::Word("server".into()),
                &TokenKind::OpenBrace,
                &TokenKind::Word("listen".into()),
                &TokenKind::Word("80".into()),
                &TokenKind::Semicolon,
                &TokenKind::CloseBrace,
                &TokenKind::CloseBrace,
            ]
        );
    }

    #[test]
    fn comments_are_skipped() {
        let tokens = tokenize("# a comment\nlisten 80; # trailing\nserver_name x;").unwrap();
        assert_eq!(words(&tokens), vec!["listen", "80", "server_name", "x"]);
    }

    #[test]
    fn hash_inside_quotes_is_not_a_comment() {
        let tokens = tokenize(r#"add_header X-Test "value # not a comment";"#).unwrap();
        assert_eq!(
            words(&tokens),
            vec!["add_header", "X-Test", "value # not a comment"]
        );
    }

    #[test]
    fn quoted_escape_sequences() {
        let tokens = tokenize(r#"add_header X "a\"b\\c";"#).unwrap();
        assert_eq!(words(&tokens), vec!["add_header", "X", "a\"b\\c"]);
    }

    #[test]
    fn semicolon_boundary_without_whitespace() {
        let tokens = tokenize("listen 80;server_name x;").unwrap();
        assert_eq!(words(&tokens), vec!["listen", "80", "server_name", "x"]);
    }

    #[test]
    fn brace_boundary_without_whitespace() {
        let tokens = tokenize("server{listen 80;}").unwrap();
        let kinds: Vec<&TokenKind> = tokens.iter().map(|t| &t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                &TokenKind::Word("server".into()),
                &TokenKind::OpenBrace,
                &TokenKind::Word("listen".into()),
                &TokenKind::Word("80".into()),
                &TokenKind::Semicolon,
                &TokenKind::CloseBrace,
            ]
        );
    }

    #[test]
    fn unterminated_quote_errors_not_panics() {
        let err = tokenize(r#"server_name "unterminated;"#).unwrap_err();
        assert_eq!(err.message, "unterminated quoted string");
    }

    #[test]
    fn trailing_backslash_at_eof_errors_not_panics() {
        let err = tokenize("server_name \"a\\").unwrap_err();
        assert_eq!(err.message, "unterminated quoted string");
    }

    #[test]
    fn empty_input_is_no_tokens() {
        assert_eq!(tokenize("").unwrap(), vec![]);
    }

    #[test]
    fn only_whitespace_and_comments_is_no_tokens() {
        assert_eq!(tokenize("   \n\t # just a comment\n  ").unwrap(), vec![]);
    }

    #[test]
    fn line_numbers_track_newlines() {
        let tokens = tokenize("listen 80;\nserver_name x;").unwrap();
        let server_name_tok = tokens
            .iter()
            .find(|t| t.kind == TokenKind::Word("server_name".into()))
            .unwrap();
        assert_eq!(server_name_tok.span.line, 2);
    }

    #[test]
    fn variable_in_bareword_is_captured_raw() {
        let tokens = tokenize("server_name $host;").unwrap();
        assert_eq!(words(&tokens), vec!["server_name", "$host"]);
    }
}
