//! A minimal stub DNS resolver, hand-written.
//!
//! Two jobs: resolve `A`/`AAAA` so `http.rs` never touches the system
//! resolver, and query `TXT` directly against authoritative nameservers to
//! confirm DNS-01 propagation.
//!
//! Resolver selection order: `--resolver` flag, then `CERTWAY_RESOLVER`,
//! then `/etc/resolv.conf`'s `nameserver` lines, then fail with
//! `NoResolver`. There is no fifth step — a public-resolver fallback would
//! disclose the user's domains to a third party.

use crate::error::Error;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// DNS wire port. Always 53 for every real query this module makes —
/// `--resolver <ip>` takes an address only, deliberately: RFC 1035 defines
/// no port syntax, and inventing an `ip:port` extension would be a made-up
/// flag surface. The one exception is `pebble-challtestsrv`'s nonstandard
/// `:8053` test fixture, which is why the `*_at_port` variants below exist
/// as a separate, test-only path instead of parameterizing this constant.
const DNS_PORT: u16 = 53;

const UDP_TIMEOUT_SECS: u64 = 5;
/// Total UDP send attempts: the initial send plus this many retries.
const UDP_RETRIES: u32 = 2;
/// UDP DNS messages are capped at 512 octets by RFC 1035; this buffer is
/// generous headroom for a well-behaved server, not a size this module ever
/// asks for (no EDNS0).
const MAX_UDP_MESSAGE: usize = 4096;
/// Prefixed 2-byte length field on a TCP DNS message can claim up to 65535
/// bytes; this is the hard cap this module will ever read for one message.
const MAX_TCP_MESSAGE: usize = 65535;
const TCP_TIMEOUT_SECS: u64 = 5;

/// Total pointer jumps allowed while expanding one compressed name.
/// RFC 1035 leaves this cap to the implementation; exceeding it returns
/// `DnsCompressionLoop` instead of looping or hanging on a hostile chain.
/// Named as its own constant so raising it later is a one-line change.
const MAX_POINTER_JUMPS: u32 = 64;

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Ns,
    Txt,
}

impl RecordType {
    fn wire_value(self) -> u16 {
        match self {
            RecordType::A => TYPE_A,
            RecordType::Aaaa => TYPE_AAAA,
            RecordType::Ns => TYPE_NS,
            RecordType::Txt => TYPE_TXT,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Ns => "NS",
            RecordType::Txt => "TXT",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(String),
    /// Every character-string in this record's RDATA, concatenated with no
    /// separator — never a plain string cast, since a TXT record can carry
    /// several character-strings back to back.
    Txt(String),
    /// A record type this module has no use for. `RDLENGTH` already
    /// advanced the cursor past it; the bytes themselves are discarded.
    Other,
}

// ---------------------------------------------------------------------
// Name encoding (write side)
// ---------------------------------------------------------------------

/// Encodes `name` as length-prefixed labels terminated by a zero octet.
/// Per RFC 1035 §3.1: each label 1-63 bytes, total wire name (labels plus
/// length octets, plus the terminator) at most 255.
fn encode_name(name: &str) -> Result<Vec<u8>, Error> {
    let trimmed = name.trim_end_matches('.');
    let mut out = Vec::new();
    if trimmed.is_empty() {
        out.push(0);
        return Ok(out);
    }
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(Error::DnsNameTooLong {
                name: name.to_string(),
            });
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    if out.len() > 255 {
        return Err(Error::DnsNameTooLong {
            name: name.to_string(),
        });
    }
    Ok(out)
}

fn random_id() -> Result<u16, Error> {
    let rng = SystemRandom::new();
    let mut buf = [0u8; 2];
    // `ring::rand::SystemRandom` failing is exceptionally rare (a kernel
    // entropy-source problem) and has no dedicated variant in this crate's
    // closed error set — `DnsMalformed` is the least-wrong fit among what
    // already exists.
    rng.fill(&mut buf).map_err(|_| Error::DnsMalformed {
        detail: "system rng unavailable",
    })?;
    Ok(u16::from_be_bytes(buf))
}

fn build_query(id: u16, name: &str, rtype: RecordType) -> Result<Vec<u8>, Error> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1, everything else clear
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    msg.extend(encode_name(name)?);
    msg.extend_from_slice(&rtype.wire_value().to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(msg)
}

// ---------------------------------------------------------------------
// Name decoding (read side) — the compression trap
// ---------------------------------------------------------------------

/// Expands a domain name starting at `start`, following compression
/// pointers per RFC 1035 §4.1.4. Returns the name and the offset **just
/// past the pointer or terminator that ended the in-line reading** — never
/// the offset reached by following a pointer. Conflating the two
/// desynchronizes every record parsed after this one.
fn parse_name(buf: &[u8], start: usize) -> Result<(String, usize), Error> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut pos = start;
    let mut jumps: u32 = 0;
    let mut end_pos: Option<usize> = None;

    loop {
        if pos >= buf.len() {
            return Err(Error::DnsMalformed {
                detail: "name runs past end of message",
            });
        }
        let len_byte = buf[pos];
        match len_byte & 0xC0 {
            0x00 => {
                let len = (len_byte & 0x3F) as usize;
                if len == 0 {
                    pos += 1;
                    if end_pos.is_none() {
                        end_pos = Some(pos);
                    }
                    break;
                }
                let label_start = pos + 1;
                let label_end = label_start + len;
                if label_end > buf.len() {
                    return Err(Error::DnsMalformed {
                        detail: "label runs past end of message",
                    });
                }
                labels.push(&buf[label_start..label_end]);
                pos = label_end;
            }
            0xC0 => {
                if pos + 1 >= buf.len() {
                    return Err(Error::DnsMalformed {
                        detail: "truncated compression pointer",
                    });
                }
                let target = (((len_byte & 0x3F) as usize) << 8) | (buf[pos + 1] as usize);
                if end_pos.is_none() {
                    end_pos = Some(pos + 2);
                }
                // Forward-pointer defense: the target must be strictly less
                // than the offset this *specific* pointer was read at — not
                // the name's start. Checking against `pos` (reassigned on
                // every jump) is what makes this comparison tighten at each
                // hop; a genuine A->B->A cycle is mathematically impossible
                // once every hop strictly decreases. The jump cap below is
                // an independent, deliberate second layer: it bounds a
                // long-but-monotonic pointer chain, and is what keeps this
                // safe even if this check were ever weakened by a future
                // change.
                if target >= pos {
                    return Err(Error::DnsMalformed {
                        detail: "compression pointer does not point backward",
                    });
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(Error::DnsCompressionLoop);
                }
                if target >= buf.len() {
                    return Err(Error::DnsMalformed {
                        detail: "compression pointer past end of message",
                    });
                }
                pos = target;
            }
            _ => {
                return Err(Error::DnsMalformed {
                    detail: "reserved label length prefix",
                })
            }
        }
    }

    let name = labels
        .iter()
        .map(|l| String::from_utf8_lossy(l))
        .collect::<Vec<_>>()
        .join(".");
    Ok((name, end_pos.expect("end_pos set on every loop exit path")))
}

fn read_u16(buf: &[u8], pos: usize) -> Result<u16, Error> {
    buf.get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or(Error::DnsMalformed {
            detail: "message truncated reading a 16-bit field",
        })
}

fn read_u32(buf: &[u8], pos: usize) -> Result<u32, Error> {
    buf.get(pos..pos + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(Error::DnsMalformed {
            detail: "message truncated reading a 32-bit field",
        })
}

struct RawRecord {
    #[allow(dead_code)]
    // name is parsed for cursor correctness; callers key by request, not by owner name
    name: String,
    rtype: u16,
    rdata: RData,
}

fn decode_rdata(buf: &[u8], rtype: u16, start: usize, end: usize) -> Result<RData, Error> {
    match rtype {
        TYPE_A => {
            let bytes = buf.get(start..end).ok_or(Error::DnsMalformed {
                detail: "A rdata past end of message",
            })?;
            if bytes.len() != 4 {
                return Err(Error::DnsMalformed {
                    detail: "A rdata is not 4 bytes",
                });
            }
            Ok(RData::A(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        TYPE_AAAA => {
            let bytes = buf.get(start..end).ok_or(Error::DnsMalformed {
                detail: "AAAA rdata past end of message",
            })?;
            if bytes.len() != 16 {
                return Err(Error::DnsMalformed {
                    detail: "AAAA rdata is not 16 bytes",
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Ok(RData::Aaaa(Ipv6Addr::from(octets)))
        }
        TYPE_NS => {
            // A domain-name RDATA may itself use compression, and any
            // pointer inside it is an absolute offset into the whole
            // message — so this decodes from `buf` directly, not from an
            // isolated rdata sub-slice. The returned cursor is discarded:
            // RDLENGTH alone still governs how far the *outer* record
            // cursor advances, not wherever a followed pointer landed.
            let (name, _) = parse_name(buf, start)?;
            Ok(RData::Ns(name))
        }
        TYPE_TXT => {
            let mut pos = start;
            let mut out = Vec::new();
            while pos < end {
                let len = buf[pos] as usize;
                pos += 1;
                let str_end = pos + len;
                if str_end > end {
                    return Err(Error::DnsMalformed {
                        detail: "TXT character-string exceeds rdata",
                    });
                }
                out.extend_from_slice(&buf[pos..str_end]);
                pos = str_end;
            }
            if pos != end {
                return Err(Error::DnsMalformed {
                    detail: "TXT rdata not fully consumed",
                });
            }
            Ok(RData::Txt(String::from_utf8_lossy(&out).into_owned()))
        }
        _ => Ok(RData::Other),
    }
}

/// Parses one resource record starting at `pos`. `RDLENGTH` is authoritative
/// for how far the returned cursor advances, even for a record type this
/// module does not interpret — content is never used to infer length.
fn parse_record(buf: &[u8], pos: usize) -> Result<(RawRecord, usize), Error> {
    let (name, pos) = parse_name(buf, pos)?;
    let rtype = read_u16(buf, pos)?;
    let pos = pos + 2;
    let _class = read_u16(buf, pos)?;
    let pos = pos + 2;
    let _ttl = read_u32(buf, pos)?;
    let pos = pos + 4;
    let rdlength = read_u16(buf, pos)? as usize;
    let pos = pos + 2;
    let rdata_end = pos.checked_add(rdlength).ok_or(Error::DnsMalformed {
        detail: "rdlength overflows",
    })?;
    if rdata_end > buf.len() {
        return Err(Error::DnsMalformed {
            detail: "rdata past end of message",
        });
    }
    let rdata = decode_rdata(buf, rtype, pos, rdata_end)?;
    Ok((RawRecord { name, rtype, rdata }, rdata_end))
}

struct ParsedMessage {
    qr: bool,
    tc: bool,
    rcode: u8,
    question_name: Option<String>,
    question_type: Option<u16>,
    answers: Vec<RawRecord>,
}

/// The ID is deliberately not part of this struct: `validate_response`
/// checks it directly off the raw bytes *before* calling this, so an
/// ID-mismatched packet is discarded without paying for a full parse.
fn parse_message(buf: &[u8]) -> Result<ParsedMessage, Error> {
    if buf.len() < 12 {
        return Err(Error::DnsMalformed {
            detail: "message shorter than the header",
        });
    }
    let flags = read_u16(buf, 2)?;
    let qr = flags & 0x8000 != 0;
    let tc = flags & 0x0200 != 0;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = read_u16(buf, 4)?;
    let ancount = read_u16(buf, 6)?;
    let nscount = read_u16(buf, 8)?;
    let arcount = read_u16(buf, 10)?;

    let mut pos = 12usize;
    let mut question_name = None;
    let mut question_type = None;
    for i in 0..qdcount {
        let (name, next) = parse_name(buf, pos)?;
        let qtype = read_u16(buf, next)?;
        let _qclass = read_u16(buf, next + 2)?;
        pos = next + 4;
        if i == 0 {
            question_name = Some(name);
            question_type = Some(qtype);
        }
    }

    let mut answers = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        let (rec, next) = parse_record(buf, pos)?;
        pos = next;
        answers.push(rec);
    }
    // Authority and additional sections carry no data this module reads,
    // but they must still be walked with the same record parser to keep
    // the cursor consistent (and to bounds-check them) — never assumed
    // absent just because we don't use them.
    for _ in 0..nscount {
        let (_, next) = parse_record(buf, pos)?;
        pos = next;
    }
    for _ in 0..arcount {
        let (_, next) = parse_record(buf, pos)?;
        pos = next;
    }

    Ok(ParsedMessage {
        qr,
        tc,
        rcode,
        question_name,
        question_type,
        answers,
    })
}

// ---------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------

enum Validated {
    Answer(Vec<RData>),
    Truncated,
    /// ID mismatch or the question doesn't echo the query — discard and
    /// keep waiting. This, not an error, is what makes off-path spoofing
    /// require winning a race rather than just sending one packet.
    Discard,
}

fn validate_response(
    buf: &[u8],
    id: u16,
    name: &str,
    rtype: RecordType,
) -> Result<Validated, Error> {
    // A header-level read failure (too short to even hold a 12-byte header)
    // is noise from whatever's on the wire, not a structural failure of a
    // message that otherwise matched our query — discard rather than error,
    // so a single garbled packet can't abort a query that still has retry
    // budget left.
    let Ok(header_id) = read_u16(buf, 0) else {
        return Ok(Validated::Discard);
    };
    if header_id != id {
        return Ok(Validated::Discard);
    }

    // Past this point the ID matches, so any further structural problem is
    // a real error, not spoofing noise to wait out.
    let msg = parse_message(buf)?;

    if !msg.qr {
        return Err(Error::DnsMalformed {
            detail: "response has QR clear",
        });
    }
    if msg.tc {
        return Ok(Validated::Truncated);
    }

    let echoes = msg
        .question_name
        .as_deref()
        .is_some_and(|n| n.eq_ignore_ascii_case(name.trim_end_matches('.')))
        && msg.question_type == Some(rtype.wire_value());
    if !echoes {
        return Ok(Validated::Discard);
    }

    match msg.rcode {
        0 => {}
        3 => {
            return Err(Error::DnsNoRecord {
                name: name.to_string(),
                kind: rtype.as_str(),
            })
        }
        _ => {
            return Err(Error::DnsMalformed {
                detail: "response rcode indicates failure",
            })
        }
    }

    let records = msg
        .answers
        .into_iter()
        .filter(|r| r.rtype == rtype.wire_value())
        .map(|r| r.rdata)
        .collect();
    Ok(Validated::Answer(records))
}

enum Attempt {
    Answer(Vec<RData>),
    Truncated,
    /// Nothing valid arrived within this attempt's window — resend.
    SoftTimeout,
}

fn udp_attempt(
    server: IpAddr,
    port: u16,
    msg: &[u8],
    id: u16,
    name: &str,
    rtype: RecordType,
) -> Result<Attempt, Error> {
    let bind_addr: IpAddr = if server.is_ipv6() {
        Ipv6Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    };
    let sock = UdpSocket::bind((bind_addr, 0)).map_err(|e| Error::Connect {
        host: server.to_string(),
        port,
        source: e,
    })?;
    sock.connect((server, port)).map_err(|e| Error::Connect {
        host: server.to_string(),
        port,
        source: e,
    })?;
    sock.set_read_timeout(Some(Duration::from_secs(UDP_TIMEOUT_SECS)))
        .map_err(|e| Error::Connect {
            host: server.to_string(),
            port,
            source: e,
        })?;
    sock.send(msg).map_err(|e| Error::Connect {
        host: server.to_string(),
        port,
        source: e,
    })?;

    let deadline = Instant::now() + Duration::from_secs(UDP_TIMEOUT_SECS);
    let mut buf = [0u8; MAX_UDP_MESSAGE];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Attempt::SoftTimeout);
        }
        let _ = sock.set_read_timeout(Some(remaining));
        match sock.recv(&mut buf) {
            Ok(n) => match validate_response(&buf[..n], id, name, rtype)? {
                Validated::Discard => continue,
                Validated::Truncated => return Ok(Attempt::Truncated),
                Validated::Answer(records) => return Ok(Attempt::Answer(records)),
            },
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(Attempt::SoftTimeout)
            }
            Err(_) => return Ok(Attempt::SoftTimeout),
        }
    }
}

fn tcp_query(
    server: IpAddr,
    port: u16,
    msg: &[u8],
    id: u16,
    name: &str,
    rtype: RecordType,
) -> Result<Vec<RData>, Error> {
    use std::io::{Read, Write};

    let mut stream = TcpStream::connect_timeout(
        &(server, port).into(),
        Duration::from_secs(TCP_TIMEOUT_SECS),
    )
    .map_err(|e| Error::Connect {
        host: server.to_string(),
        port,
        source: e,
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(TCP_TIMEOUT_SECS)))
        .map_err(|e| Error::Connect {
            host: server.to_string(),
            port,
            source: e,
        })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(TCP_TIMEOUT_SECS)))
        .map_err(|e| Error::Connect {
            host: server.to_string(),
            port,
            source: e,
        })?;

    let len = u16::try_from(msg.len()).map_err(|_| Error::DnsMalformed {
        detail: "query too large for tcp framing",
    })?;
    let mut framed = Vec::with_capacity(msg.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(msg);
    stream.write_all(&framed).map_err(|e| Error::Connect {
        host: server.to_string(),
        port,
        source: e,
    })?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| Error::Connect {
            host: server.to_string(),
            port,
            source: e,
        })?;
    let body_len = u16::from_be_bytes(len_buf) as usize;
    if body_len > MAX_TCP_MESSAGE {
        return Err(Error::DnsMalformed {
            detail: "tcp response exceeds maximum message size",
        });
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).map_err(|e| Error::Connect {
        host: server.to_string(),
        port,
        source: e,
    })?;

    match validate_response(&body, id, name, rtype)? {
        Validated::Answer(records) => Ok(records),
        Validated::Truncated => Err(Error::DnsMalformed {
            detail: "tcp response set the tc bit",
        }),
        Validated::Discard => Err(Error::DnsMalformed {
            detail: "tcp response did not match the query",
        }),
    }
}

/// The one query primitive every lookup in this module goes through: UDP
/// first with a 5-second timeout and two retries, falling back to TCP (with
/// its 2-byte length prefix) the moment a response sets the TC bit.
fn query_with_port(
    server: IpAddr,
    port: u16,
    name: &str,
    rtype: RecordType,
) -> Result<Vec<RData>, Error> {
    let id = random_id()?;
    let msg = build_query(id, name, rtype)?;

    for _ in 0..=UDP_RETRIES {
        match udp_attempt(server, port, &msg, id, name, rtype)? {
            Attempt::Answer(records) => return Ok(records),
            Attempt::Truncated => return tcp_query(server, port, &msg, id, name, rtype),
            Attempt::SoftTimeout => continue,
        }
    }
    Err(Error::DnsTimeout {
        name: name.to_string(),
        resolver: server,
    })
}

pub fn query(server: IpAddr, name: &str, rtype: RecordType) -> Result<Vec<RData>, Error> {
    query_with_port(server, DNS_PORT, name, rtype)
}

#[cfg(test)]
pub(crate) fn query_at_port(
    server: IpAddr,
    port: u16,
    name: &str,
    rtype: RecordType,
) -> Result<Vec<RData>, Error> {
    query_with_port(server, port, name, rtype)
}

fn query_a_at(server: IpAddr, port: u16, name: &str) -> Result<Vec<Ipv4Addr>, Error> {
    Ok(query_with_port(server, port, name, RecordType::A)?
        .into_iter()
        .filter_map(|r| match r {
            RData::A(ip) => Some(ip),
            _ => None,
        })
        .collect())
}

fn query_aaaa_at(server: IpAddr, port: u16, name: &str) -> Result<Vec<Ipv6Addr>, Error> {
    Ok(query_with_port(server, port, name, RecordType::Aaaa)?
        .into_iter()
        .filter_map(|r| match r {
            RData::Aaaa(ip) => Some(ip),
            _ => None,
        })
        .collect())
}

fn query_ns_at(server: IpAddr, port: u16, name: &str) -> Result<Vec<String>, Error> {
    Ok(query_with_port(server, port, name, RecordType::Ns)?
        .into_iter()
        .filter_map(|r| match r {
            RData::Ns(host) => Some(host),
            _ => None,
        })
        .collect())
}

/// The set of TXT values at `name` on this one server — set-equality
/// against this is what `check_propagation` requires from *every*
/// authoritative nameserver, not just membership: a wildcard record with
/// two values isn't "propagated" until both are visible everywhere.
fn query_txt_set_at(server: IpAddr, port: u16, name: &str) -> Result<HashSet<String>, Error> {
    Ok(query_with_port(server, port, name, RecordType::Txt)?
        .into_iter()
        .filter_map(|r| match r {
            RData::Txt(v) => Some(v),
            _ => None,
        })
        .collect())
}

// ---------------------------------------------------------------------
// Resolver selection
// ---------------------------------------------------------------------

/// Parses `nameserver` lines from `/etc/resolv.conf` text. Pure, so it's
/// testable without a filesystem — `read_resolv_conf` is the one impure
/// caller, mirroring `cli::env`'s detect/resolve split.
pub(crate) fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let rest = line.strip_prefix("nameserver")?;
            let rest = rest.strip_prefix(char::is_whitespace)?;
            rest.trim().parse::<IpAddr>().ok()
        })
        .collect()
}

fn read_resolv_conf() -> Vec<IpAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|t| parse_resolv_conf(&t))
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct Resolver {
    nameservers: Vec<IpAddr>,
}

impl Resolver {
    /// The four-step order documented on this module: `--resolver` flag,
    /// then `CERTWAY_RESOLVER`, then `/etc/resolv.conf`, then `NoResolver`
    /// — deliberately with no further fallback. `explicit` is
    /// `--resolver`'s parsed value.
    pub fn discover(explicit: Option<IpAddr>) -> Result<Resolver, Error> {
        if let Some(ip) = explicit {
            return Ok(Resolver {
                nameservers: vec![ip],
            });
        }
        if let Ok(val) = std::env::var("CERTWAY_RESOLVER") {
            if let Ok(ip) = val.trim().parse::<IpAddr>() {
                return Ok(Resolver {
                    nameservers: vec![ip],
                });
            }
        }
        let nameservers = read_resolv_conf();
        if nameservers.is_empty() {
            return Err(Error::NoResolver);
        }
        Ok(Resolver { nameservers })
    }

    /// The configured resolver this build actually queries. A minimal stub
    /// resolver: always the first configured nameserver, never a pool.
    pub fn primary(&self) -> IpAddr {
        self.nameservers[0]
    }

    pub fn resolve_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, Error> {
        query_a_at(self.primary(), DNS_PORT, name)
    }

    pub fn resolve_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, Error> {
        query_aaaa_at(self.primary(), DNS_PORT, name)
    }

    /// Every address `host` resolves to, `A` and `AAAA` combined — the one
    /// entry point `http.rs`'s connector uses. Errors only if *both* record
    /// types come back empty or failing.
    pub fn resolve_addrs(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        let a = self.resolve_a(host);
        let aaaa = self.resolve_aaaa(host);
        let mut out = Vec::new();
        if let Ok(v) = &a {
            out.extend(v.iter().copied().map(IpAddr::V4));
        }
        if let Ok(v) = &aaaa {
            out.extend(v.iter().copied().map(IpAddr::V6));
        }
        if out.is_empty() {
            return Err(a
                .err()
                .or_else(|| aaaa.err())
                .unwrap_or(Error::DnsNoRecord {
                    name: host.to_string(),
                    kind: "A/AAAA",
                }));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// /etc/hosts — not the system resolver, a static file this module reads
// itself (same category as /etc/resolv.conf). Needed so a plain "localhost"
// URL keeps working without forcing --resolver just to reach it.
// ---------------------------------------------------------------------

pub(crate) fn parse_hosts_file(text: &str, host: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                return None;
            }
            let mut parts = line.split_whitespace();
            let ip: IpAddr = parts.next()?.parse().ok()?;
            if parts.any(|n| n.eq_ignore_ascii_case(host)) {
                Some(ip)
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn hosts_file_lookup(host: &str) -> Vec<IpAddr> {
    std::fs::read_to_string("/etc/hosts")
        .map(|t| parse_hosts_file(&t, host))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------
// DNS-01 propagation check
// ---------------------------------------------------------------------

const PROPAGATION_CAP_SECS: u64 = 300;
const PROPAGATION_POLL_SECS: u64 = 2;
const INTERRUPT_GRANULARITY_MS: u64 = 100;

pub enum Propagated {
    Yes,
    /// The interrupt predicate fired before propagation was confirmed —
    /// not an error, the caller (which owns cleanup) decides what happens
    /// next.
    Interrupted,
}

/// Successive suffixes of `domain`, longest first, stopping at two labels
/// — never the bare TLD. The registrable-domain walk this module and
/// `dns_provider::cloudflare`'s zone discovery both use: querying `NS` (or,
/// for Cloudflare, `/zones?name=`) at each candidate and stopping at the
/// first hit is how a delegation this program cannot know about in advance
/// (`a.b.example.com` whether the zone is `example.com` or `b.example.com`)
/// gets found without needing a public-suffix-list dependency to track.
pub(crate) fn suffix_candidates(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Vec::new();
    }
    (0..=labels.len() - 2)
        .map(|i| labels[i..].join("."))
        .collect()
}

/// Discovers the authoritative nameservers for `domain` by walking `NS`
/// queries from the full name up to the registrable domain, climbing on
/// either an empty (NODATA) answer or any query failure — an NS delegation
/// legitimately answers NODATA at every non-apex name, so only an empty
/// result at *every* candidate is meaningful, not the first one.
///
/// Falls back to the already-configured resolver itself when no level
/// yields an NS answer. This is a deliberate fallback, not the primary
/// path: `pebble-challtestsrv`, this project's own DNS-01 test fixture,
/// has no NS record concept at all and answers every NS query with RCODE 4
/// (Not Implemented) — verified live. Real authoritative infrastructure
/// answers NS directly; this fallback is what keeps propagation-checking
/// meaningful in an environment (or a split-horizon setup) where that walk
/// can never succeed.
pub fn discover_authoritative(resolver: &Resolver, domain: &str) -> Vec<IpAddr> {
    discover_authoritative_via(resolver.primary(), DNS_PORT, domain)
}

/// The walk itself, at an explicit port — split out from
/// `discover_authoritative` (which is always port 53 in production) so a
/// unit test can drive it against a fake in-process responder instead of a
/// real authoritative server. No live server has ever been walked
/// end-to-end in this project's own test environment (see this function's
/// doc comment above); the fake-responder test is the cheaper substitute —
/// it proves the traversal and the NS/A parsing byte-for-byte, not the
/// live network path.
fn discover_authoritative_via(nameserver: IpAddr, port: u16, domain: &str) -> Vec<IpAddr> {
    for candidate in suffix_candidates(domain) {
        let Ok(ns_hosts) = query_ns_at(nameserver, port, &candidate) else {
            continue;
        };
        if ns_hosts.is_empty() {
            continue;
        }
        let ips: Vec<IpAddr> = ns_hosts
            .iter()
            .filter_map(|h| query_a_at(nameserver, port, h).ok())
            .flatten()
            .map(IpAddr::V4)
            .collect();
        if !ips.is_empty() {
            return ips;
        }
    }
    vec![nameserver]
}

#[cfg(test)]
pub(crate) fn discover_authoritative_at_port(
    nameserver: IpAddr,
    port: u16,
    domain: &str,
) -> Vec<IpAddr> {
    discover_authoritative_via(nameserver, port, domain)
}

fn all_servers_confirm(servers: &[IpAddr], name: &str, expected: &HashSet<String>) -> bool {
    servers.iter().all(
        |&server| matches!(query_txt_set_at(server, DNS_PORT, name), Ok(got) if got == *expected),
    )
}

fn sleep_interruptible(total: Duration, interrupt: &dyn Fn() -> bool) {
    let step = Duration::from_millis(INTERRUPT_GRANULARITY_MS);
    let mut waited = Duration::ZERO;
    while waited < total {
        if interrupt() {
            return;
        }
        std::thread::sleep(step);
        waited += step;
    }
}

/// Polls every authoritative nameserver for `record_name` every 2 seconds,
/// capped at 300, until every one returns exactly `expected` (set-equality,
/// not membership — a wildcard record can carry two TXT values at once,
/// and both need to be visible everywhere before this counts as
/// propagated). Never a fixed sleep: too short burns a rate-limit slot on
/// a failed validation, too long wastes the user's time on a network where
/// propagation was already fast.
///
/// `interrupt` is checked at ~100ms granularity so a signal-driven shutdown
/// (SIGINT/SIGTERM) reaches the caller promptly instead of waiting out the
/// full 2-second tick, matching `challenge::Http01Server::serve_until`'s
/// existing `&dyn Fn() -> bool` shape.
/// `servers` is the caller's already-discovered authoritative set
/// (`discover_authoritative`) — kept as a separate parameter rather than a
/// `Resolver`+domain pair so a caller juggling several name groups (the
/// two-record wildcard case still shares one name, but an order can also
/// name unrelated base domains) can discover once per group and report
/// what it found, instead of this function silently re-discovering it on
/// every single poll tick.
pub fn check_propagation(
    servers: &[IpAddr],
    record_name: &str,
    expected: &HashSet<String>,
    interrupt: &dyn Fn() -> bool,
) -> Result<Propagated, Error> {
    let start = Instant::now();
    loop {
        if interrupt() {
            return Ok(Propagated::Interrupted);
        }
        if all_servers_confirm(servers, record_name, expected) {
            return Ok(Propagated::Yes);
        }
        if start.elapsed() >= Duration::from_secs(PROPAGATION_CAP_SECS) {
            return Err(Error::PollExhausted {
                resource: "dns propagation",
                elapsed_secs: start.elapsed().as_secs(),
            });
        }
        sleep_interruptible(Duration::from_secs(PROPAGATION_POLL_SECS), interrupt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    // -- encode_name --------------------------------------------------

    #[test]
    fn encode_name_matches_rfc1035_worked_example() {
        // F.ISI.ARPA -> 01 46 03 49 53 49 04 41 52 50 41 00 (RFC 1035 §4.1.4).
        assert_eq!(
            encode_name("F.ISI.ARPA").unwrap(),
            vec![1, b'F', 3, b'I', b'S', b'I', 4, b'A', b'R', b'P', b'A', 0]
        );
    }

    #[test]
    fn encode_name_rejects_label_over_63_bytes() {
        let label = "a".repeat(64);
        let name = format!("{label}.example.com");
        assert!(matches!(
            encode_name(&name),
            Err(Error::DnsNameTooLong { .. })
        ));
    }

    #[test]
    fn encode_name_rejects_total_length_over_255() {
        // 4 labels of 63 bytes plus length octets exceeds 255 comfortably.
        let label = "a".repeat(63);
        let name = format!("{label}.{label}.{label}.{label}");
        assert!(matches!(
            encode_name(&name),
            Err(Error::DnsNameTooLong { .. })
        ));
    }

    // -- parse_name: the compression trap ------------------------------

    fn header(id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(12);
        h.extend_from_slice(&id.to_be_bytes());
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&an.to_be_bytes());
        h.extend_from_slice(&ns.to_be_bytes());
        h.extend_from_slice(&ar.to_be_bytes());
        h
    }

    #[test]
    fn parse_name_plain_labels_no_compression() {
        let mut buf = header(1, 0, 0, 0, 0, 0);
        buf.extend(encode_name("example.com").unwrap());
        let (name, next) = parse_name(&buf, 12).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(next, buf.len());
    }

    #[test]
    fn parse_name_follows_a_single_valid_pointer() {
        // "example.com" written once at offset 12; a second name at offset
        // 30 is a bare pointer back to it.
        let mut buf = header(1, 0, 0, 0, 0, 0);
        let first_offset = buf.len();
        buf.extend(encode_name("example.com").unwrap());
        while buf.len() < 30 {
            buf.push(0xAA); // padding, never read
        }
        let pointer_offset = buf.len();
        buf.push(0xC0 | ((first_offset >> 8) as u8));
        buf.push((first_offset & 0xFF) as u8);

        let (name, next) = parse_name(&buf, pointer_offset).unwrap();
        assert_eq!(name, "example.com");
        // Cursor lands just past the 2-byte pointer, not past the name it
        // pointed to — matches `parse_name`'s documented contract: the
        // returned offset is where the in-line reading ended, never where
        // a followed pointer led.
        assert_eq!(next, pointer_offset + 2);
    }

    #[test]
    fn parse_name_rejects_forward_pointer() {
        // A pointer at offset 12 targeting offset 20 (higher than itself).
        let mut buf = header(1, 0, 0, 0, 0, 0);
        let ptr_offset = buf.len();
        buf.push(0xC0 | ((20u16 >> 8) as u8));
        buf.push((20u16 & 0xFF) as u8);
        while buf.len() < 25 {
            buf.push(0);
        }
        let result = parse_name(&buf, ptr_offset);
        assert!(
            matches!(result, Err(Error::DnsMalformed { .. })),
            "expected a forward-pointer error, got {result:?}"
        );
    }

    #[test]
    fn parse_name_rejects_pointer_past_end_of_message() {
        // A correct forward-pointer check (target strictly less than the
        // offset the pointer was read at) already implies the target is
        // in-bounds, since that offset is itself always < buf.len() — so
        // the *distinct* "past end" hazard this test isolates is the
        // pointer's own 2-byte encoding running off the end of the message
        // (only its first byte present), not a wild target value.
        let mut buf = header(1, 0, 0, 0, 0, 0);
        let ptr_offset = buf.len();
        buf.push(0xC0); // top bits set: this is a pointer... but no second byte follows
        let result = parse_name(&buf, ptr_offset);
        assert!(matches!(result, Err(Error::DnsMalformed { .. })));
    }

    #[test]
    fn parse_name_rejects_reserved_length_prefix_bits() {
        for top_bits in [0x40u8, 0x80u8] {
            let mut buf = header(1, 0, 0, 0, 0, 0);
            let pos = buf.len();
            buf.push(top_bits); // 01 or 10 in the top two bits
            buf.push(0);
            let result = parse_name(&buf, pos);
            assert!(
                matches!(result, Err(Error::DnsMalformed { .. })),
                "top bits {top_bits:#x} must error"
            );
        }
    }

    #[test]
    fn parse_name_at_end_with_no_terminator_errors_not_panics() {
        let mut buf = header(1, 0, 0, 0, 0, 0);
        let pos = buf.len();
        buf.push(3); // claims a 3-byte label
        buf.push(b'a');
        buf.push(b'b'); // but only 2 bytes follow before the buffer ends
        assert!(parse_name(&buf, pos).is_err());
    }

    /// A pointer chain longer than the 64-jump cap, every hop strictly
    /// decreasing (so the forward-pointer check never fires — this
    /// exercises the cap as its own, independent defense). Run on a helper
    /// thread so an uncapped implementation would hang the test process
    /// rather than the test itself; `recv_timeout` is what turns "hangs
    /// forever" into "fails loudly within 500ms" if the cap regresses.
    #[test]
    fn pointer_chain_exceeding_cap_errors_within_a_time_bound() {
        // A chain of pointers, each pointing to the one immediately before
        // it: offset 12 is a bare root label ("."), and each subsequent
        // pointer is written at the buffer's current end (so its own
        // offset is always strictly greater than the one it targets — the
        // forward-pointer check never fires, isolating the jump cap as the
        // only thing that can stop this). `LINKS` exceeds
        // `MAX_POINTER_JUMPS`, so parsing from the last pointer must hit
        // the cap partway down the chain.
        const LINKS: usize = (MAX_POINTER_JUMPS as usize) + 5;
        let mut buf = header(1, 0, 0, 0, 0, 0);
        buf.push(0); // offset 12: zero-length label, name "."
        let mut prev_offset: u16 = 12;
        let mut last_offset: u16 = prev_offset;
        for _ in 0..LINKS {
            let this_offset = buf.len() as u16;
            buf.push(0xC0 | ((prev_offset >> 8) as u8));
            buf.push((prev_offset & 0xFF) as u8);
            prev_offset = this_offset;
            last_offset = this_offset;
        }
        let start = last_offset as usize;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = parse_name(&buf, start);
            let _ = tx.send(result);
        });
        let result = rx
            .recv_timeout(Duration::from_millis(500))
            .expect("parse_name must return within 500ms");
        assert!(
            matches!(result, Err(Error::DnsCompressionLoop)),
            "expected DnsCompressionLoop, got {result:?}"
        );
    }

    // -- decode_rdata: TXT split across character-strings --------------

    #[test]
    fn txt_two_character_strings_concatenate_with_no_separator() {
        let mut rdata = Vec::new();
        rdata.push(3);
        rdata.extend_from_slice(b"foo");
        rdata.push(3);
        rdata.extend_from_slice(b"bar");
        let decoded = decode_rdata(&rdata, TYPE_TXT, 0, rdata.len()).unwrap();
        assert_eq!(decoded, RData::Txt("foobar".to_string()));
    }

    #[test]
    fn txt_character_string_exceeding_rdata_errors() {
        let mut rdata = Vec::new();
        rdata.push(10); // claims 10 bytes
        rdata.extend_from_slice(b"short");
        assert!(decode_rdata(&rdata, TYPE_TXT, 0, rdata.len()).is_err());
    }

    // -- validate_response: ID mismatch discards, TC bit retries -------

    fn build_response(
        id: u16,
        flags: u16,
        qname: &str,
        qtype: u16,
        answers: &[u8],
        ancount: u16,
    ) -> Vec<u8> {
        let mut buf = header(id, flags, 1, ancount, 0, 0);
        buf.extend(encode_name(qname).unwrap());
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(answers);
        buf
    }

    fn a_record(name_ptr_offset: u16, ttl: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut rr = Vec::new();
        rr.push(0xC0 | ((name_ptr_offset >> 8) as u8));
        rr.push((name_ptr_offset & 0xFF) as u8);
        rr.extend_from_slice(&TYPE_A.to_be_bytes());
        rr.extend_from_slice(&CLASS_IN.to_be_bytes());
        rr.extend_from_slice(&ttl.to_be_bytes());
        rr.extend_from_slice(&4u16.to_be_bytes());
        rr.extend_from_slice(&ip);
        rr
    }

    #[test]
    fn id_mismatch_is_discarded_not_accepted() {
        // QR=1, RD=1, RA=1 (0x8180), matching question, wrong ID.
        let answers = a_record(12, 60, [127, 0, 0, 1]);
        let resp = build_response(999, 0x8180, "example.com", TYPE_A, &answers, 1);
        let outcome = validate_response(&resp, 1, "example.com", RecordType::A).unwrap();
        assert!(matches!(outcome, Validated::Discard));
    }

    #[test]
    fn tc_bit_set_signals_retry_over_tcp() {
        let resp = build_response(1, 0x8380, "example.com", TYPE_A, &[], 0); // TC bit (0x0200) set
        let outcome = validate_response(&resp, 1, "example.com", RecordType::A).unwrap();
        assert!(matches!(outcome, Validated::Truncated));
    }

    #[test]
    fn rcode_3_maps_to_dns_no_record() {
        let resp = build_response(1, 0x8183, "example.com", TYPE_A, &[], 0); // RCODE=3
        let result = validate_response(&resp, 1, "example.com", RecordType::A);
        assert!(matches!(result, Err(Error::DnsNoRecord { .. })));
    }

    #[test]
    fn rcode_2_maps_to_dns_malformed() {
        let resp = build_response(1, 0x8182, "example.com", TYPE_A, &[], 0); // RCODE=2
        let result = validate_response(&resp, 1, "example.com", RecordType::A);
        assert!(matches!(result, Err(Error::DnsMalformed { .. })));
    }

    #[test]
    fn mismatched_question_is_discarded() {
        let answers = a_record(12, 60, [127, 0, 0, 1]);
        let resp = build_response(1, 0x8180, "not-what-we-asked.example", TYPE_A, &answers, 1);
        let outcome = validate_response(&resp, 1, "example.com", RecordType::A).unwrap();
        assert!(matches!(outcome, Validated::Discard));
    }

    #[test]
    fn matching_answer_is_returned() {
        let answers = a_record(12, 60, [127, 0, 0, 1]);
        let resp = build_response(1, 0x8180, "example.com", TYPE_A, &answers, 1);
        match validate_response(&resp, 1, "example.com", RecordType::A).unwrap() {
            Validated::Answer(recs) => {
                assert_eq!(recs.len(), 1);
                assert_eq!(recs[0], RData::A(Ipv4Addr::new(127, 0, 0, 1)));
            }
            _ => panic!("expected an answer"),
        }
    }

    // -- resolv.conf / hosts parsing ------------------------------------

    #[test]
    fn parse_resolv_conf_reads_nameserver_lines() {
        let text = "domain example.com\nnameserver 1.1.1.1\n# comment\nnameserver 8.8.8.8\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "8.8.8.8".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn parse_resolv_conf_ignores_malformed_lines() {
        let text = "nameserver not-an-ip\nnameserver 2.2.2.2\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec!["2.2.2.2".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn parse_hosts_file_matches_exact_hostname() {
        let text = "127.0.0.1 localhost\n::1 ip6-localhost\n10.0.0.5 myhost.example alias\n";
        assert_eq!(
            parse_hosts_file(text, "localhost"),
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            parse_hosts_file(text, "alias"),
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        assert!(parse_hosts_file(text, "nope").is_empty());
    }

    #[test]
    fn suffix_candidates_stops_before_bare_tld() {
        assert_eq!(
            suffix_candidates("foo.bar.example.com"),
            vec!["foo.bar.example.com", "bar.example.com", "example.com"]
        );
        assert_eq!(suffix_candidates("example.com"), vec!["example.com"]);
        assert_eq!(suffix_candidates("com"), Vec::<String>::new());
    }

    // -- live transport tests: a fake DNS server on a loopback port -----

    #[test]
    fn query_retries_past_a_wrong_id_response_from_the_real_server() {
        // The fake server sends a decoy (wrong ID) immediately, then a real
        // answer to the same query shortly after — exercising the same
        // "discard, keep waiting" path as `id_mismatch_is_discarded...`,
        // but through the real socket loop rather than direct unit-level
        // validation.
        let sock = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let port = sock.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut buf = [0u8; 512];
            let (n, peer) = sock.recv_from(&mut buf).unwrap();
            let query_id = u16::from_be_bytes([buf[0], buf[1]]);
            let qname_and_rest = &buf[12..n];

            let mut decoy = Vec::new();
            decoy.extend_from_slice(&(query_id.wrapping_add(1)).to_be_bytes());
            decoy.extend_from_slice(&0x8180u16.to_be_bytes());
            decoy.extend_from_slice(&1u16.to_be_bytes());
            decoy.extend_from_slice(&0u16.to_be_bytes());
            decoy.extend_from_slice(&0u16.to_be_bytes());
            decoy.extend_from_slice(&0u16.to_be_bytes());
            decoy.extend_from_slice(qname_and_rest);
            sock.send_to(&decoy, peer).unwrap();

            let mut real = Vec::new();
            real.extend_from_slice(&query_id.to_be_bytes());
            real.extend_from_slice(&0x8180u16.to_be_bytes());
            real.extend_from_slice(&1u16.to_be_bytes());
            real.extend_from_slice(&1u16.to_be_bytes());
            real.extend_from_slice(&0u16.to_be_bytes());
            real.extend_from_slice(&0u16.to_be_bytes());
            real.extend_from_slice(qname_and_rest);
            real.extend(a_record(12, 60, [203, 0, 113, 9]));
            sock.send_to(&real, peer).unwrap();
        });

        let result = query_at_port(
            Ipv4Addr::LOCALHOST.into(),
            port,
            "test.example",
            RecordType::A,
        )
        .unwrap();
        handle.join().unwrap();
        assert_eq!(result, vec![RData::A(Ipv4Addr::new(203, 0, 113, 9))]);
    }

    /// Grabs a port number free on *both* TCP and UDP simultaneously, by
    /// retrying: `cargo test`'s default parallelism means a different test
    /// in this same binary can grab a just-freed ephemeral port in the
    /// narrow window between probing it and rebinding it explicitly —
    /// verified live as the cause of an intermittent `AddrInUse` panic
    /// here before this loop existed. A handful of attempts is enough;
    /// this isn't racing anything adversarial, just ordinary ephemeral
    /// port churn from sibling tests.
    fn bind_tcp_and_udp_same_port() -> (TcpListener, UdpSocket) {
        for _ in 0..20 {
            let probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let tcp = match TcpListener::bind(("127.0.0.1", port)) {
                Ok(l) => l,
                Err(_) => continue,
            };
            match UdpSocket::bind(("127.0.0.1", port)) {
                Ok(u) => return (tcp, u),
                Err(_) => continue, // tcp dropped at end of this iteration; retry with a fresh port
            }
        }
        panic!("could not find a port free on both TCP and UDP after 20 attempts");
    }

    #[test]
    fn tc_bit_over_udp_retries_over_tcp_and_returns_the_tcp_answer() {
        let (tcp_listener, udp_sock) = bind_tcp_and_udp_same_port();
        let port = udp_sock.local_addr().unwrap().port();
        udp_sock
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let udp_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, peer) = udp_sock.recv_from(&mut buf).unwrap();
            let query_id = u16::from_be_bytes([buf[0], buf[1]]);
            let qname_and_rest = &buf[12..n];
            let mut truncated = Vec::new();
            truncated.extend_from_slice(&query_id.to_be_bytes());
            truncated.extend_from_slice(&0x8380u16.to_be_bytes()); // QR+RD+RA+TC
            truncated.extend_from_slice(&1u16.to_be_bytes());
            truncated.extend_from_slice(&0u16.to_be_bytes());
            truncated.extend_from_slice(&0u16.to_be_bytes());
            truncated.extend_from_slice(&0u16.to_be_bytes());
            truncated.extend_from_slice(qname_and_rest);
            udp_sock.send_to(&truncated, peer).unwrap();
        });

        let tcp_handle = std::thread::spawn(move || {
            let (mut stream, _) = tcp_listener.accept().unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).unwrap();
            let query_id = u16::from_be_bytes([body[0], body[1]]);
            let qname_and_rest = &body[12..];

            let mut real = Vec::new();
            real.extend_from_slice(&query_id.to_be_bytes());
            real.extend_from_slice(&0x8180u16.to_be_bytes());
            real.extend_from_slice(&1u16.to_be_bytes());
            real.extend_from_slice(&1u16.to_be_bytes());
            real.extend_from_slice(&0u16.to_be_bytes());
            real.extend_from_slice(&0u16.to_be_bytes());
            real.extend_from_slice(qname_and_rest);
            real.extend(a_record(12, 60, [198, 51, 100, 7]));

            let mut framed = Vec::new();
            framed.extend_from_slice(&(real.len() as u16).to_be_bytes());
            framed.extend_from_slice(&real);
            stream.write_all(&framed).unwrap();
        });

        let result = query_at_port(
            Ipv4Addr::LOCALHOST.into(),
            port,
            "test.example",
            RecordType::A,
        )
        .unwrap();
        udp_handle.join().unwrap();
        tcp_handle.join().unwrap();
        assert_eq!(result, vec![RData::A(Ipv4Addr::new(198, 51, 100, 7))]);
    }

    #[test]
    fn no_response_at_all_times_out_as_dns_timeout() {
        // Bind a socket, get a port, then drop it so nothing ever answers —
        // the send lands on a closed port and every read simply times out.
        // Uses a short-timeout private helper path is unavailable, so this
        // test accepts the real UDP_TIMEOUT_SECS*3 budget; kept as the one
        // slow test in this module, matching this project's convention of
        // marking genuinely slow tests rather than hiding the cost.
        let taken_port = {
            let probe = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
            probe.local_addr().unwrap().port()
        };
        let result = query_at_port(
            Ipv4Addr::LOCALHOST.into(),
            taken_port,
            "test.example",
            RecordType::A,
        );
        assert!(matches!(result, Err(Error::DnsTimeout { .. })));
    }

    fn ns_record(name_ptr_offset: u16, ttl: u32, nsdname: &str) -> Vec<u8> {
        let mut rr = Vec::new();
        rr.push(0xC0 | ((name_ptr_offset >> 8) as u8));
        rr.push((name_ptr_offset & 0xFF) as u8);
        rr.extend_from_slice(&TYPE_NS.to_be_bytes());
        rr.extend_from_slice(&CLASS_IN.to_be_bytes());
        rr.extend_from_slice(&ttl.to_be_bytes());
        let rdata = encode_name(nsdname).unwrap();
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(&rdata);
        rr
    }

    /// The cheaper substitute for a live NS walk this project's own test
    /// fixture (pebble-challtestsrv) can never exercise, per this module's
    /// own doc comment on `discover_authoritative`: a fake server that
    /// answers three queries in the exact sequence the walk makes —
    /// NODATA at the full name (climb), an NS answer at the registrable
    /// domain, then an A answer for that NS host — proves the traversal,
    /// the climb-on-empty-answer rule, and NS/A parsing byte-for-byte.
    /// It does not prove the live network path; it proves everything else.
    #[test]
    fn discover_authoritative_climbs_past_nodata_then_resolves_the_ns_host() {
        let sock = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let port = sock.local_addr().unwrap().port();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];

            // 1: NS for "sub.example.com" (the full identifier) -> NODATA.
            let (n, peer) = sock.recv_from(&mut buf).unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            let resp = build_response(id, 0x8180, "sub.example.com", TYPE_NS, &[], 0);
            sock.send_to(&resp, peer).unwrap();
            let _ = n;

            // 2: NS for "example.com" (climbed one level) -> ns1.example.com.
            let (n, peer) = sock.recv_from(&mut buf).unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            let ns_rr = ns_record(12, 3600, "ns1.example.com");
            let resp = build_response(id, 0x8180, "example.com", TYPE_NS, &ns_rr, 1);
            sock.send_to(&resp, peer).unwrap();
            let _ = n;

            // 3: A for "ns1.example.com" -> 203.0.113.53.
            let (n, peer) = sock.recv_from(&mut buf).unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            let a_rr = a_record(12, 3600, [203, 0, 113, 53]);
            let resp = build_response(id, 0x8180, "ns1.example.com", TYPE_A, &a_rr, 1);
            sock.send_to(&resp, peer).unwrap();
            let _ = n;
        });

        let servers =
            discover_authoritative_at_port(Ipv4Addr::LOCALHOST.into(), port, "sub.example.com");
        handle.join().unwrap();
        assert_eq!(servers, vec![IpAddr::from(Ipv4Addr::new(203, 0, 113, 53))]);
    }
}
