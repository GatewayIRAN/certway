use crate::error::Error;
use std::collections::HashMap;
use tinyjson::JsonValue;

const MAX_INPUT: usize = 1_000_000;
const MAX_DEPTH: u32 = 32;

/// Total wrapper around tinyjson::JsonValue. Every accessor returns a
/// Result/Option instead of panicking, because every JsonValue this program
/// parses originates from a remote ACME server response.
pub struct Json(JsonValue);

impl Json {
    pub fn parse(bytes: &[u8]) -> Result<Json, Error> {
        if bytes.len() > MAX_INPUT {
            return Err(Error::BodyTooLarge { limit: MAX_INPUT });
        }
        let text = std::str::from_utf8(bytes).map_err(|e| Error::JsonParse {
            detail: e.to_string(),
        })?;
        check_depth(text)?;
        let value: JsonValue =
            text.parse()
                .map_err(|e: tinyjson::JsonParseError| Error::JsonParse {
                    detail: e.to_string(),
                })?;
        Ok(Json(value))
    }

    fn map(&self) -> Option<&HashMap<String, JsonValue>> {
        self.0.get::<HashMap<String, JsonValue>>()
    }

    fn field(&self, field: &'static str) -> Option<&JsonValue> {
        self.map()?.get(field)
    }

    pub fn has(&self, field: &'static str) -> bool {
        self.field(field).is_some()
    }

    pub fn str(&self, field: &'static str) -> Result<&str, Error> {
        self.field(field)
            .ok_or(Error::JsonMissing { field })?
            .get::<String>()
            .map(String::as_str)
            .ok_or(Error::JsonType {
                field,
                expected: "string",
            })
    }

    pub fn opt_str(&self, field: &'static str) -> Option<&str> {
        self.field(field)?.get::<String>().map(String::as_str)
    }

    pub fn array(&self, field: &'static str) -> Result<Vec<Json>, Error> {
        self.field(field)
            .ok_or(Error::JsonMissing { field })?
            .get::<Vec<JsonValue>>()
            .map(|items| items.iter().cloned().map(Json).collect())
            .ok_or(Error::JsonType {
                field,
                expected: "array",
            })
    }

    pub fn opt_array(&self, field: &'static str) -> Option<Vec<Json>> {
        self.field(field)?
            .get::<Vec<JsonValue>>()
            .map(|items| items.iter().cloned().map(Json).collect())
    }

    pub fn object(&self, field: &'static str) -> Result<Json, Error> {
        let value = self.field(field).ok_or(Error::JsonMissing { field })?;
        value
            .get::<HashMap<String, JsonValue>>()
            .map(|_| Json(value.clone()))
            .ok_or(Error::JsonType {
                field,
                expected: "object",
            })
    }

    pub fn opt_object(&self, field: &'static str) -> Option<Json> {
        let value = self.field(field)?;
        value.get::<HashMap<String, JsonValue>>()?;
        Some(Json(value.clone()))
    }

    pub fn bool(&self, field: &'static str) -> Result<bool, Error> {
        self.field(field)
            .ok_or(Error::JsonMissing { field })?
            .get::<bool>()
            .copied()
            .ok_or(Error::JsonType {
                field,
                expected: "bool",
            })
    }

    /// The value itself as a string, for elements of an array.
    pub fn as_str(&self) -> Result<&str, Error> {
        self.0
            .get::<String>()
            .map(String::as_str)
            .ok_or(Error::JsonType {
                field: "<self>",
                expected: "string",
            })
    }
}

/// Scans raw JSON text for bracket nesting depth without parsing, so
/// pathologically deep input is rejected before it reaches tinyjson's
/// recursive-descent parser (which would otherwise risk a stack overflow).
fn check_depth(text: &str) -> Result<(), Error> {
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut escaped = false;
    for b in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(Error::JsonParse {
                        detail: "nesting exceeds maximum depth".to_string(),
                    });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// A value to be serialized by write_object. Payloads this program sends
/// must never be assembled with format!, because a value containing a quote
/// would produce a malformed request body.
pub enum JsonVal<'a> {
    Str(&'a str),
    Bool(bool),
    /// Already-valid JSON, e.g. a nested object built by a previous
    /// write_object call.
    Raw(&'a str),
    Array(Vec<JsonVal<'a>>),
}

pub fn write_object(pairs: &[(&str, JsonVal)]) -> String {
    let mut out = String::from("{");
    for (i, (key, val)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_escaped_string(&mut out, key);
        out.push(':');
        write_value(&mut out, val);
    }
    out.push('}');
    out
}

fn write_value(out: &mut String, val: &JsonVal) {
    match val {
        JsonVal::Str(s) => write_escaped_string(out, s),
        JsonVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonVal::Raw(raw) => out.push_str(raw),
        JsonVal::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
    }
}

fn write_escaped_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Json {
        Json::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn str_missing_field() {
        let j = parse(r#"{"a":"x"}"#);
        assert!(matches!(j.str("b"), Err(Error::JsonMissing { field: "b" })));
    }

    #[test]
    fn str_wrong_type() {
        let j = parse(r#"{"a":1}"#);
        // "a" is a number, not representable via our str accessor -> type error.
        assert!(matches!(
            j.str("a"),
            Err(Error::JsonType { field: "a", .. })
        ));
    }

    #[test]
    fn str_on_null() {
        let j = parse(r#"{"a":null}"#);
        assert!(matches!(
            j.str("a"),
            Err(Error::JsonType { field: "a", .. })
        ));
    }

    #[test]
    fn opt_str_missing_and_null_are_none() {
        let j = parse(r#"{"a":null}"#);
        assert!(j.opt_str("a").is_none());
        assert!(j.opt_str("z").is_none());
    }

    #[test]
    fn array_missing_field() {
        let j = parse(r#"{}"#);
        assert!(matches!(
            j.array("items"),
            Err(Error::JsonMissing { field: "items" })
        ));
    }

    #[test]
    fn array_wrong_type() {
        let j = parse(r#"{"items":"not an array"}"#);
        assert!(matches!(
            j.array("items"),
            Err(Error::JsonType { field: "items", .. })
        ));
    }

    #[test]
    fn array_on_null() {
        let j = parse(r#"{"items":null}"#);
        assert!(matches!(j.array("items"), Err(Error::JsonType { .. })));
    }

    #[test]
    fn object_missing_field() {
        let j = parse(r#"{}"#);
        assert!(matches!(
            j.object("child"),
            Err(Error::JsonMissing { field: "child" })
        ));
    }

    #[test]
    fn object_wrong_type() {
        let j = parse(r#"{"child":5}"#);
        assert!(matches!(
            j.object("child"),
            Err(Error::JsonType { field: "child", .. })
        ));
    }

    #[test]
    fn object_on_null() {
        let j = parse(r#"{"child":null}"#);
        assert!(matches!(j.object("child"), Err(Error::JsonType { .. })));
    }

    #[test]
    fn bool_missing_field() {
        let j = parse(r#"{}"#);
        assert!(matches!(
            j.bool("ok"),
            Err(Error::JsonMissing { field: "ok" })
        ));
    }

    #[test]
    fn bool_wrong_type() {
        let j = parse(r#"{"ok":"yes"}"#);
        assert!(matches!(
            j.bool("ok"),
            Err(Error::JsonType { field: "ok", .. })
        ));
    }

    #[test]
    fn bool_on_null() {
        let j = parse(r#"{"ok":null}"#);
        assert!(matches!(j.bool("ok"), Err(Error::JsonType { .. })));
    }

    #[test]
    fn has_field() {
        let j = parse(r#"{"a":1}"#);
        assert!(j.has("a"));
        assert!(!j.has("b"));
    }

    #[test]
    fn as_str_on_array_element() {
        let j = parse(r#"{"items":["x","y"]}"#);
        let items = j.array("items").unwrap();
        assert_eq!(items[0].as_str().unwrap(), "x");
        assert_eq!(items[1].as_str().unwrap(), "y");
    }

    #[test]
    fn nesting_40_levels_rejected() {
        let mut s = String::new();
        for _ in 0..40 {
            s.push('[');
        }
        s.push('1');
        for _ in 0..40 {
            s.push(']');
        }
        assert!(matches!(
            Json::parse(s.as_bytes()),
            Err(Error::JsonParse { .. })
        ));
    }

    #[test]
    fn nesting_at_limit_accepted() {
        let mut s = String::new();
        for _ in 0..32 {
            s.push('[');
        }
        s.push('1');
        for _ in 0..32 {
            s.push(']');
        }
        assert!(Json::parse(s.as_bytes()).is_ok());
    }

    #[test]
    fn input_over_2mb_rejected_before_parsing() {
        let huge = vec![b' '; 2_000_000];
        assert!(matches!(
            Json::parse(&huge),
            Err(Error::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn duplicate_keys_last_wins_no_panic() {
        let j = parse(r#"{"a":"first","a":"second"}"#);
        assert_eq!(j.str("a").unwrap(), "second");
    }

    #[test]
    fn write_object_escapes_special_characters() {
        let s = write_object(&[("k", JsonVal::Str("a\"b\\c\nd\te\u{01}"))]);
        assert_eq!(s, "{\"k\":\"a\\\"b\\\\c\\nd\\te\\u0001\"}");
    }

    #[test]
    fn write_object_round_trips_through_parse() {
        let s = write_object(&[
            ("name", JsonVal::Str("a\"quoted\"value")),
            ("ok", JsonVal::Bool(true)),
            (
                "tags",
                JsonVal::Array(vec![JsonVal::Str("x"), JsonVal::Str("y")]),
            ),
        ]);
        let parsed = Json::parse(s.as_bytes()).unwrap();
        assert_eq!(parsed.str("name").unwrap(), "a\"quoted\"value");
        assert!(parsed.bool("ok").unwrap());
        let tags = parsed.array("tags").unwrap();
        assert_eq!(tags[0].as_str().unwrap(), "x");
        assert_eq!(tags[1].as_str().unwrap(), "y");
    }

    #[test]
    fn malformed_json_never_panics() {
        let cases: &[&[u8]] = &[
            b"",
            b"{",
            b"{\"a\":}",
            b"{\"a\": \"unterminated}",
            b"not json at all",
            b"{\"a\":1,}",
            b"[1,2,",
            b"\x00\x01\x02",
        ];
        for case in cases {
            let _ = Json::parse(case);
        }
    }
}
