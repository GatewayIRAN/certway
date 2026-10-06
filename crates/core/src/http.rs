use crate::dns::{self, Resolver};
use crate::error::Error;
use rustls_pki_types::{CertificateDer, ServerName};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const CONNECT_TIMEOUT_SECS: u64 = 10;
const RW_TIMEOUT_SECS: u64 = 30;
const MAX_HEADER_BLOCK: usize = 64 * 1024;
const DEFAULT_MAX_BODY: usize = 1_000_000;
const MAX_CHUNK_LINE: usize = 32;

const EMBEDDED_ROOT_PEM: &str = include_str!("../../../assets/isrgrootx1.pem");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
        }
    }
}

/// Response headers. Names are stored lowercased for lookup; duplicates are
/// kept in arrival order since the Link header can legitimately repeat.
pub struct Headers(Vec<(String, String)>);

impl Headers {
    fn new() -> Headers {
        Headers(Vec::new())
    }

    fn push(&mut self, name: &str, value: String) {
        self.0.push((name.to_ascii_lowercase(), value));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.0
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let name = name.to_ascii_lowercase();
        self.0
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn replay_nonce(&self) -> Option<&str> {
        self.get("replay-nonce")
    }

    pub fn location(&self) -> Option<&str> {
        self.get("location")
    }

    pub fn retry_after(&self) -> Option<&str> {
        self.get("retry-after")
    }

    /// The `Date` header, raw and unparsed — RFC 9773 §6's clock-skew check
    /// (`ari::skew_seconds`) is the one caller.
    pub fn date(&self) -> Option<&str> {
        self.get("date")
    }

    pub fn content_type(&self) -> Option<&str> {
        self.get("content-type")
    }

    /// All Link header entries across every Link header line, as (url, rel).
    pub fn link(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for header_value in self.get_all("link") {
            for entry in split_link_entries(header_value) {
                if let Some(pair) = parse_link_entry(entry) {
                    out.push(pair);
                }
            }
        }
        out
    }
}

fn split_link_entries(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].trim());
    out
}

fn parse_link_entry(entry: &str) -> Option<(String, String)> {
    let entry = entry.trim();
    if !entry.starts_with('<') {
        return None;
    }
    let url_end = entry.find('>')?;
    let url = entry[1..url_end].to_string();
    let mut rel = String::new();
    for part in entry[url_end + 1..].split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("rel=") {
            rel = rest.trim().trim_matches('"').to_string();
        }
    }
    Some((url, rel))
}

pub struct Response {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

pub struct Client {
    tls: Arc<rustls::ClientConfig>,
    timeout_secs: u64,
    max_body: usize,
    /// Set via `with_resolver` — normally the CLI's own `--resolver`-aware
    /// `dns::Resolver::discover` call, threaded through explicitly. `None`
    /// means "not yet configured by a caller that cares," in which case
    /// `tcp_connect` falls back to a bare `Resolver::discover(None)` per
    /// connection: enough for `Client::new()` to stay infallible and for
    /// existing tests (and any real host with a usable
    /// `/etc/resolv.conf`) to keep working unmodified.
    resolver: Option<Resolver>,
}

impl Client {
    /// Uses the embedded ISRG Root X1.
    pub fn new() -> Result<Client, Error> {
        Client::from_pem(EMBEDDED_ROOT_PEM)
    }

    /// Uses the given PEM bundle INSTEAD of the embedded root.
    pub fn with_ca_bundle(pem: &str) -> Result<Client, Error> {
        Client::from_pem(pem)
    }

    /// Attaches an explicitly-resolved `Resolver` (`--resolver` /
    /// `CERTWAY_RESOLVER` / `/etc/resolv.conf`, in that order) so every
    /// connection this client makes uses it instead of re-discovering one
    /// per request.
    pub fn with_resolver(mut self, resolver: Resolver) -> Client {
        self.resolver = Some(resolver);
        self
    }

    fn from_pem(pem: &str) -> Result<Client, Error> {
        let der_certs = parse_pem_certificates(pem)?;

        // Install once per process. A second call returns Err; that is not a failure.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut roots = rustls::RootCertStore::empty();
        let (added, _ignored) = roots.add_parsable_certificates(der_certs);
        if added == 0 {
            return Err(pem_error("ca bundle contains no parsable certificates"));
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Client {
            tls: Arc::new(config),
            timeout_secs: RW_TIMEOUT_SECS,
            max_body: DEFAULT_MAX_BODY,
            resolver: None,
        })
    }

    pub fn request(
        &self,
        method: Method,
        url: &str,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Response, Error> {
        self.request_inner(method, url, None, content_type, body)
    }

    /// `request`, with a bearer token added as an `Authorization` header —
    /// additive rather than a signature change to `request`, since ACME
    /// itself never needs one (auth travels inside the signed JWS body).
    /// `dns_provider::cloudflare` is the one caller today.
    pub fn request_authenticated(
        &self,
        method: Method,
        url: &str,
        bearer_token: &str,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Response, Error> {
        let auth = format!("Bearer {bearer_token}");
        self.request_inner(method, url, Some(auth.as_str()), content_type, body)
    }

    fn request_inner(
        &self,
        method: Method,
        url: &str,
        authorization: Option<&str>,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Response, Error> {
        let parsed = ParsedUrl::parse(url)?;
        let sock = tcp_connect(
            &parsed.host,
            parsed.port,
            self.timeout_secs,
            self.resolver.as_ref(),
        )?;
        let mut tls = self.tls_connect(&parsed.host, sock)?;

        let request_bytes = build_request(method, &parsed, authorization, content_type, body)?;
        tls.write_all(&request_bytes).map_err(map_io_err)?;
        tls.flush().map_err(map_io_err)?;

        parse_response(&mut tls, method, self.max_body)
    }

    fn tls_connect(
        &self,
        host: &str,
        sock: TcpStream,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Error> {
        let server_name = ServerName::try_from(host.to_string()).map_err(|_| Error::Tls {
            host: host.to_string(),
            source: rustls::Error::General("invalid server name".to_string()),
        })?;
        let conn =
            rustls::ClientConnection::new(Arc::clone(&self.tls), server_name).map_err(|e| {
                Error::Tls {
                    host: host.to_string(),
                    source: e,
                }
            })?;
        Ok(rustls::StreamOwned::new(conn, sock))
    }
}

/// Resolves `host` without ever calling the system resolver: an IP literal
/// needs no lookup; `/etc/hosts` is a static file this module parses
/// itself (same category as `/etc/resolv.conf`'s `nameserver` lines, not
/// the NSS/getaddrinfo path that fallback is about) and is what keeps a
/// plain `https://localhost/...` URL working without forcing `--resolver`
/// just to reach it; anything else goes through `dns::Resolver` — the
/// caller's explicit one if set via `with_resolver`, else a fresh
/// `Resolver::discover(None)` per connection.
fn resolve_host(host: &str, resolver: Option<&Resolver>) -> Result<Vec<IpAddr>, Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let hosts_hit = dns::hosts_file_lookup(host);
    if !hosts_hit.is_empty() {
        return Ok(hosts_hit);
    }
    match resolver {
        Some(r) => r.resolve_addrs(host),
        None => Resolver::discover(None)?.resolve_addrs(host),
    }
}

fn tcp_connect(
    host: &str,
    port: u16,
    rw_timeout_secs: u64,
    resolver: Option<&Resolver>,
) -> Result<TcpStream, Error> {
    let ips = resolve_host(host, resolver)?;
    let addrs = ips.into_iter().map(|ip| SocketAddr::new(ip, port));

    let mut last_err: Option<std::io::Error> = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(CONNECT_TIMEOUT_SECS)) {
            Ok(sock) => {
                let configure = || -> std::io::Result<()> {
                    sock.set_read_timeout(Some(Duration::from_secs(rw_timeout_secs)))?;
                    sock.set_write_timeout(Some(Duration::from_secs(rw_timeout_secs)))?;
                    sock.set_nodelay(true)?;
                    Ok(())
                };
                match configure() {
                    Ok(()) => return Ok(sock),
                    Err(e) => last_err = Some(e),
                }
            }
            Err(e) => last_err = Some(e),
        }
    }

    Err(Error::Connect {
        host: host.to_string(),
        port,
        source: last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "host resolved to no addresses",
            )
        }),
    })
}

struct ParsedUrl {
    host: String,
    port: u16,
    path_and_query: String,
}

impl ParsedUrl {
    fn parse(url: &str) -> Result<ParsedUrl, Error> {
        let rest = url.strip_prefix("https://").ok_or(Error::HttpMalformed {
            detail: "url must use https",
        })?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rfind(':') {
            Some(i) => {
                let port: u16 = authority[i + 1..]
                    .parse()
                    .map_err(|_| Error::HttpMalformed {
                        detail: "invalid port in url",
                    })?;
                (authority[..i].to_string(), port)
            }
            None => (authority.to_string(), 443u16),
        };
        if host.is_empty() {
            return Err(Error::HttpMalformed {
                detail: "url missing host",
            });
        }
        let path_and_query = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        Ok(ParsedUrl {
            host,
            port,
            path_and_query,
        })
    }
}

fn check_header_value(v: &str) -> Result<(), Error> {
    if v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(Error::HttpMalformed {
            detail: "header value contains forbidden byte",
        });
    }
    Ok(())
}

fn build_request(
    method: Method,
    url: &ParsedUrl,
    authorization: Option<&str>,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    check_header_value(&url.host)?;
    if let Some(ct) = content_type {
        check_header_value(ct)?;
    }
    if let Some(auth) = authorization {
        check_header_value(auth)?;
    }

    let mut req = String::new();
    req.push_str(method.as_str());
    req.push(' ');
    req.push_str(&url.path_and_query);
    req.push_str(" HTTP/1.1\r\n");
    req.push_str("Host: ");
    req.push_str(&url.host);
    if url.port != 443 {
        req.push(':');
        req.push_str(&url.port.to_string());
    }
    req.push_str("\r\n");
    req.push_str("User-Agent: certway/");
    req.push_str(env!("CARGO_PKG_VERSION"));
    req.push_str("\r\n");
    req.push_str("Accept: */*\r\n");
    req.push_str("Connection: close\r\n");
    if let Some(auth) = authorization {
        req.push_str("Authorization: ");
        req.push_str(auth);
        req.push_str("\r\n");
    }

    if method == Method::Post {
        if let Some(ct) = content_type {
            req.push_str("Content-Type: ");
            req.push_str(ct);
            req.push_str("\r\n");
        }
        let len = body.map(<[u8]>::len).unwrap_or(0);
        req.push_str("Content-Length: ");
        req.push_str(&len.to_string());
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    let mut out = req.into_bytes();
    if method == Method::Post {
        if let Some(b) = body {
            out.extend_from_slice(b);
        }
    }
    Ok(out)
}

fn map_io_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Error::Timeout {
            operation: "http io",
            secs: RW_TIMEOUT_SECS,
        },
        std::io::ErrorKind::UnexpectedEof => Error::HttpMalformed {
            detail: "connection closed unexpectedly",
        },
        _ => Error::HttpMalformed {
            detail: "connection error",
        },
    }
}

/// Wraps a stream so bytes already consumed while scanning for the header
/// terminator (but belonging to the body) are replayed before further reads
/// hit the underlying stream.
struct BodyReader<'a, R: Read> {
    prefix: Vec<u8>,
    pos: usize,
    inner: &'a mut R,
}

impl<'a, R: Read> Read for BodyReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = buf.len().min(self.prefix.len() - self.pos);
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        } else {
            self.inner.read(buf)
        }
    }
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn read_header_block<R: Read>(stream: &mut R) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        if let Some(pos) = find_header_terminator(&raw) {
            let header_bytes = raw[..pos].to_vec();
            let leftover = raw[pos + 4..].to_vec();
            return Ok((header_bytes, leftover));
        }
        if raw.len() > MAX_HEADER_BLOCK {
            return Err(Error::HttpMalformed {
                detail: "header block exceeds 64KB limit",
            });
        }
        let n = stream.read(&mut chunk).map_err(map_io_err)?;
        if n == 0 {
            return Err(Error::HttpMalformed {
                detail: "connection closed before headers completed",
            });
        }
        raw.extend_from_slice(&chunk[..n]);
    }
}

fn split_crlf(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            out.push(&buf[start..i]);
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(&buf[start..]);
    out
}

fn parse_status_line(line: &[u8]) -> Result<u16, Error> {
    let s = std::str::from_utf8(line).map_err(|_| Error::HttpMalformed {
        detail: "status line not utf8",
    })?;
    let mut parts = s.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(Error::HttpMalformed {
            detail: "unsupported http version",
        });
    }
    let code = parts.next().ok_or(Error::HttpMalformed {
        detail: "missing status code",
    })?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::HttpMalformed {
            detail: "status code is not three ascii digits",
        });
    }
    code.parse::<u16>().map_err(|_| Error::HttpMalformed {
        detail: "status code not numeric",
    })
}

fn parse_headers(lines: &[&[u8]]) -> Result<Headers, Error> {
    let mut headers = Headers::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(Error::HttpMalformed {
                detail: "obsolete line folding is not supported",
            });
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(Error::HttpMalformed {
                detail: "header line missing colon",
            })?;
        let name = std::str::from_utf8(&line[..colon]).map_err(|_| Error::HttpMalformed {
            detail: "header name not utf8",
        })?;
        let mut value_bytes = &line[colon + 1..];
        while matches!(value_bytes.first(), Some(b' ') | Some(b'\t')) {
            value_bytes = &value_bytes[1..];
        }
        let value = std::str::from_utf8(value_bytes).map_err(|_| Error::HttpMalformed {
            detail: "header value not utf8",
        })?;
        headers.push(name, value.trim_end().to_string());
    }
    Ok(headers)
}

fn read_exact_capped<R: Read>(stream: &mut R, n: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).map_err(map_io_err)?;
    Ok(buf)
}

fn read_line_capped<R: Read>(stream: &mut R, max_len: usize) -> Result<Vec<u8>, Error> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).map_err(map_io_err)?;
        if n == 0 {
            return Err(Error::HttpMalformed {
                detail: "unexpected eof reading line",
            });
        }
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        line.push(byte[0]);
        if line.len() > max_len {
            return Err(Error::HttpMalformed {
                detail: "line exceeds maximum length",
            });
        }
    }
}

fn read_to_eof_capped<R: Read>(stream: &mut R, max_body: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).map_err(map_io_err)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > max_body {
            return Err(Error::BodyTooLarge { limit: max_body });
        }
    }
    Ok(out)
}

fn read_chunked_body<R: Read>(stream: &mut R, max_body: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    loop {
        let size_line = read_line_capped(stream, MAX_CHUNK_LINE)?;
        let size_str = std::str::from_utf8(&size_line).map_err(|_| Error::HttpMalformed {
            detail: "chunk size line not utf8",
        })?;
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_str, 16).map_err(|_| Error::HttpMalformed {
            detail: "invalid chunk size",
        })?;

        if size == 0 {
            loop {
                let trailer_line = read_line_capped(stream, MAX_HEADER_BLOCK)?;
                if trailer_line.is_empty() {
                    break;
                }
            }
            break;
        }

        let size = size as usize;
        if out.len() + size > max_body {
            return Err(Error::BodyTooLarge { limit: max_body });
        }
        let data = read_exact_capped(stream, size)?;
        out.extend_from_slice(&data);
        let crlf = read_exact_capped(stream, 2)?;
        if crlf != b"\r\n" {
            return Err(Error::HttpMalformed {
                detail: "chunk data not terminated by crlf",
            });
        }
    }
    Ok(out)
}

fn read_body<R: Read>(
    stream: &mut R,
    status: u16,
    method: Method,
    headers: &Headers,
    max_body: usize,
) -> Result<Vec<u8>, Error> {
    if status == 204 || status == 304 || method == Method::Head {
        return Ok(Vec::new());
    }

    let transfer_encoding = headers.get("transfer-encoding");
    let content_length = headers.get("content-length");

    match (transfer_encoding, content_length) {
        (Some(_), Some(_)) => Err(Error::HttpMalformed {
            detail: "both transfer-encoding and content-length present",
        }),
        (Some(te), None) => {
            if te.eq_ignore_ascii_case("chunked") {
                read_chunked_body(stream, max_body)
            } else {
                Err(Error::HttpMalformed {
                    detail: "unsupported transfer-encoding",
                })
            }
        }
        (None, Some(cl)) => {
            let n: usize = cl.trim().parse().map_err(|_| Error::HttpMalformed {
                detail: "invalid content-length",
            })?;
            if n > max_body {
                return Err(Error::BodyTooLarge { limit: max_body });
            }
            read_exact_capped(stream, n)
        }
        (None, None) => read_to_eof_capped(stream, max_body),
    }
}

fn parse_response<R: Read>(
    stream: &mut R,
    method: Method,
    max_body: usize,
) -> Result<Response, Error> {
    let (header_bytes, leftover) = read_header_block(stream)?;
    let lines = split_crlf(&header_bytes);
    let (status_line, header_lines) = lines.split_first().ok_or(Error::HttpMalformed {
        detail: "empty response",
    })?;
    let status = parse_status_line(status_line)?;
    let headers = parse_headers(header_lines)?;

    let mut body_reader = BodyReader {
        prefix: leftover,
        pos: 0,
        inner: stream,
    };
    let body = read_body(&mut body_reader, status, method, &headers, max_body)?;

    Ok(Response {
        status,
        headers,
        body,
    })
}

fn pem_error(detail: &'static str) -> Error {
    Error::CaBundle { detail }
}

pub(crate) fn parse_pem_certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut certs = Vec::new();
    let mut lines = pem.lines();
    while let Some(line) = lines.next() {
        if line.trim() != BEGIN {
            continue;
        }
        let mut b64 = String::new();
        let mut closed = false;
        for l in lines.by_ref() {
            let l = l.trim();
            if l == END {
                closed = true;
                break;
            }
            b64.push_str(l);
        }
        if !closed {
            return Err(pem_error("unterminated PEM certificate block"));
        }
        let der = base64_decode(&b64)?;
        certs.push(CertificateDer::from(der));
    }
    Ok(certs)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, Error> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in s.bytes().filter(|&b| b != b'=') {
        let v = val(b).ok_or_else(|| pem_error("invalid base64 in certificate"))?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(bytes: &[u8], method: Method) -> Result<Response, Error> {
        let mut cur = Cursor::new(bytes.to_vec());
        parse_response(&mut cur, method, DEFAULT_MAX_BODY)
    }

    #[test]
    fn content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let resp = parse(raw, Method::Get).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn chunked_three_chunks() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n";
        let resp = parse(raw, Method::Get).unwrap();
        assert_eq!(resp.body, b"foobar");
    }

    #[test]
    fn chunked_with_extension() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=bar\r\nhello\r\n0\r\n\r\n";
        let resp = parse(raw, Method::Get).unwrap();
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn chunked_with_trailer() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Trailer: v\r\n\r\n";
        let resp = parse(raw, Method::Get).unwrap();
        assert_eq!(resp.body, b"hi");
    }

    #[test]
    fn chunked_split_across_reads() {
        struct Slow<'a> {
            data: &'a [u8],
            pos: usize,
        }
        impl<'a> Read for Slow<'a> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                let n = 1.min(buf.len()).min(self.data.len() - self.pos);
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n";
        let mut slow = Slow { data: raw, pos: 0 };
        let resp = parse_response(&mut slow, Method::Get, DEFAULT_MAX_BODY).unwrap();
        assert_eq!(resp.body, b"foobar");
    }

    #[test]
    fn rejects_both_transfer_encoding_and_content_length() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\nhello";
        assert!(matches!(
            parse(raw, Method::Get),
            Err(Error::HttpMalformed { .. })
        ));
    }

    #[test]
    fn rejects_obsolete_line_folding() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Foo: bar\r\n baz\r\n\r\n";
        assert!(matches!(
            parse(raw, Method::Get),
            Err(Error::HttpMalformed { .. })
        ));
    }

    #[test]
    fn rejects_oversized_header_block() {
        let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEADER_BLOCK + 100));
        assert!(matches!(
            parse(&raw, Method::Get),
            Err(Error::HttpMalformed { .. })
        ));
    }

    #[test]
    fn rejects_body_exceeding_max() {
        let mut cur =
            Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789".to_vec());
        let result = parse_response(&mut cur, Method::Get, 5);
        assert!(matches!(result, Err(Error::BodyTooLarge { limit: 5 })));
    }

    #[test]
    fn rejects_truncated_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        assert!(parse(raw, Method::Get).is_err());
    }

    #[test]
    fn head_response_has_no_body_even_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let resp = parse(raw, Method::Head).unwrap();
        assert!(resp.body.is_empty());
    }

    #[test]
    fn link_header_two_values_with_quoted_rel() {
        let raw =
            b"HTTP/1.1 200 OK\r\nLink: <https://a>;rel=\"next\", <https://b>;rel=\"prev\"\r\n\r\n";
        let resp = parse(raw, Method::Get).unwrap();
        let links = resp.headers.link();
        assert_eq!(
            links,
            vec![
                ("https://a".to_string(), "next".to_string()),
                ("https://b".to_string(), "prev".to_string()),
            ]
        );
    }

    #[test]
    fn two_separate_link_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nLink: <https://a>;rel=\"next\"\r\nLink: <https://b>;rel=\"prev\"\r\n\r\n";
        let resp = parse(raw, Method::Get).unwrap();
        let links = resp.headers.link();
        assert_eq!(
            links,
            vec![
                ("https://a".to_string(), "next".to_string()),
                ("https://b".to_string(), "prev".to_string()),
            ]
        );
    }
}
