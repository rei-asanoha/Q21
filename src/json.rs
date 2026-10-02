//! Minimal JSON.
//!
//! Enough for a JSON-RPC API, not one byte more. Written here rather than
//! imported for the same reason as everything else: this module reads data
//! coming from any client at all, and a dependency we have not reviewed is an
//! attack surface we do not know.
//!
//! # What is deliberately missing
//!
//! No floats. An API that exposes monetary amounts must never pass them
//! through a `double`: `0.1 + 0.2 != 0.3` in IEEE 754, and a naive client that
//! reads back a balance encoded that way loses units. Amounts go out as an
//! integer of indivisible units **and** as a formatted string. The client
//! chooses, but no approximate conversion happens on our side.
//!
//! # Bounds
//!
//! Nesting depth and document size are bounded at parse time.
//! Without that, `[[[[[...]]]]]` over a few megabytes blows the stack through
//! recursion - a denial of service that fits in one line of `curl`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Maximum accepted nesting depth.
pub const MAX_DEPTH: usize = 32;

/// Maximum size of a parsed document, in bytes.
pub const MAX_INPUT: usize = 1024 * 1024;

/// A JSON value.
///
/// Objects are ordered: two encodings of the same object are identical,
/// which makes tests deterministic and responses diffable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Signed integer. No float exists in this module, by choice.
    Int(i64),
    /// Unsigned integer above `i64::MAX`.
    ///
    /// Encoded as a **number**, never as a string: a numeric field that
    /// changes type depending on its value is a trap for every client, and
    /// the bridge to an injection when that client inserts the value into a
    /// page.
    UInt(u64),
    Str(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> JsonObj {
        JsonObj(BTreeMap::new())
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn int(v: impl Into<i64>) -> Json {
        Json::Int(v.into())
    }

    /// 64-bit unsigned integer.
    ///
    /// Above `i64::MAX` we switch to a string rather than truncate: a wrong
    /// monetary value is worse than a value of another type.
    /// An integer stays an integer.
    ///
    /// This function used to switch to a **string** above `i64::MAX`. A field
    /// the client believes numeric therefore changed type without warning: the
    /// value went into an insertion point meant for a number, or into a
    /// comparison that no longer compared anything. That is the bridge between
    /// a counter and an injection.
    ///
    /// JSON does not bound integers; it is JavaScript that loses precision
    /// above 2^53. The type, however, must not vary.
    pub fn u64(v: u64) -> Json {
        if v <= i64::MAX as u64 {
            Json::Int(v as i64)
        } else {
            Json::UInt(v)
        }
    }

    pub fn array(v: Vec<Json>) -> Json {
        Json::Array(v)
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// A numeric field must arrive as a number.
    ///
    /// This function used to accept a **string** and convert it. The bound
    /// the parser places on integers - `i64::MAX` - could therefore be bypassed
    /// by putting the number in quotes, and that is how a `sendtoaddress`
    /// overflowed an addition and stopped the node.
    ///
    /// Nothing legitimate needs this leniency.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(v) if *v >= 0 => Some(*v as u64),
            Json::UInt(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(v) => Some(v),
            _ => None,
        }
    }

    /// Encodes as compact JSON.
    pub fn encode(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(v) => {
                let _ = write!(out, "{v}");
            }
            Json::UInt(v) => {
                let _ = write!(out, "{v}");
            }
            Json::Str(s) => escape(s, out),
            Json::Array(v) => {
                out.push('[');
                for (i, e) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    e.write(out);
                }
                out.push(']');
            }
            Json::Object(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    escape(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Object builder, to write responses without ceremony.
pub struct JsonObj(BTreeMap<String, Json>);

impl JsonObj {
    pub fn set(mut self, key: &str, v: Json) -> JsonObj {
        self.0.insert(key.to_string(), v);
        self
    }
    /// Sets several fields at once - handy for grafting a group computed
    /// separately without breaking the chaining.
    pub fn set_all<'a>(mut self, fields: impl IntoIterator<Item = (&'a str, Json)>) -> JsonObj {
        for (key, v) in fields {
            self.0.insert(key.to_string(), v);
        }
        self
    }
    pub fn build(self) -> Json {
        Json::Object(self.0)
    }
}

/// Escapes a string per RFC 8259.
///
/// Control characters must be escaped; forgetting them produces a document
/// that half of all parsers reject and the other half interpret
/// differently.
fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            // --- Output that is safe whatever the insertion context.
            //
            // `<`, `>` and `/` make it possible to close a `<script>` from a
            // JSON string placed in a page. U+2028 and U+2029 are line
            // terminators for JavaScript, but not for JSON: a string that
            // contains them breaks a `<script>` that embeds it.
            //
            // These escapes remain perfectly standard JSON: every parser reads
            // them back identically. They cost nothing and they close an
            // entire class of problems for our clients.
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '/' => out.push_str("\\u002f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum JsonError {
    DocumentTooLarge(usize),
    NestingTooDeep,
    UnexpectedChar {
        position: usize,
        found: char,
    },
    UnexpectedEnd,
    InvalidNumber,
    InvalidEscape,
    TrailingBytes,
    /// The same key twice in one object: an ambiguous document.
    DuplicateKey(String),
}

/// Parses a JSON document.
pub fn parse(input: &str) -> Result<Json, JsonError> {
    if input.len() > MAX_INPUT {
        return Err(JsonError::DocumentTooLarge(input.len()));
    }
    let chars: Vec<char> = input.chars().collect();
    let mut p = Parser {
        c: &chars,
        i: 0,
        depth: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != p.c.len() {
        return Err(JsonError::TrailingBytes);
    }
    Ok(v)
}

struct Parser<'a> {
    c: &'a [char],
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while self.i < self.c.len() && matches!(self.c[self.i], ' ' | '\t' | '\n' | '\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Result<char, JsonError> {
        self.c.get(self.i).copied().ok_or(JsonError::UnexpectedEnd)
    }

    fn expect(&mut self, c: char) -> Result<(), JsonError> {
        if self.peek()? != c {
            return Err(JsonError::UnexpectedChar {
                position: self.i,
                found: self.c[self.i],
            });
        }
        self.i += 1;
        Ok(())
    }

    fn literal(&mut self, word: &str) -> Result<(), JsonError> {
        for c in word.chars() {
            self.expect(c)?;
        }
        Ok(())
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        // The depth counter is the only thing that keeps
        // `[[[[[[...]]]]]]` from overflowing the stack.
        if self.depth > MAX_DEPTH {
            return Err(JsonError::NestingTooDeep);
        }
        match self.peek()? {
            'n' => {
                self.literal("null")?;
                Ok(Json::Null)
            }
            't' => {
                self.literal("true")?;
                Ok(Json::Bool(true))
            }
            'f' => {
                self.literal("false")?;
                Ok(Json::Bool(false))
            }
            '"' => Ok(Json::Str(self.string()?)),
            '[' => self.array(),
            '{' => self.object(),
            c if c == '-' || c.is_ascii_digit() => self.number(),
            c => Err(JsonError::UnexpectedChar {
                position: self.i,
                found: c,
            }),
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect('"')?;
        let mut s = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                '"' => return Ok(s),
                '\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'b' => s.push('\u{08}'),
                        'f' => s.push('\u{0c}'),
                        'u' => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let h = self.peek()?;
                                self.i += 1;
                                code =
                                    code * 16 + h.to_digit(16).ok_or(JsonError::InvalidEscape)?;
                            }
                            s.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(JsonError::InvalidEscape),
                    }
                }
                c => s.push(c),
            }
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.i;
        if self.peek()? == '-' {
            self.i += 1;
        }
        while self.i < self.c.len() && self.c[self.i].is_ascii_digit() {
            self.i += 1;
        }
        // JSON containing a float is rejected rather than rounded: a plain
        // error is better than a silently wrong amount.
        if self.i < self.c.len() && matches!(self.c[self.i], '.' | 'e' | 'E') {
            return Err(JsonError::InvalidNumber);
        }
        let text: String = self.c[start..self.i].iter().collect();
        if let Ok(v) = text.parse::<i64>() {
            return Ok(Json::Int(v));
        }
        // Between `i64::MAX` and `u64::MAX`: a perfectly valid number in
        // JSON, which this module represents separately rather than rejecting
        // it or converting it to a string.
        text.parse::<u64>()
            .map(Json::UInt)
            .map_err(|_| JsonError::InvalidNumber)
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.expect('[')?;
        self.depth += 1;
        let mut v = Vec::new();
        self.skip_ws();
        if self.peek()? == ']' {
            self.i += 1;
            self.depth -= 1;
            return Ok(Json::Array(v));
        }
        loop {
            self.skip_ws();
            v.push(self.value()?);
            self.skip_ws();
            match self.peek()? {
                ',' => self.i += 1,
                ']' => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Json::Array(v));
                }
                c => {
                    return Err(JsonError::UnexpectedChar {
                        position: self.i,
                        found: c,
                    })
                }
            }
        }
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.expect('{')?;
        self.depth += 1;
        let mut m = BTreeMap::new();
        self.skip_ws();
        if self.peek()? == '}' {
            self.i += 1;
            self.depth -= 1;
            return Ok(Json::Object(m));
        }
        loop {
            self.skip_ws();
            let k = self.string()?;
            self.skip_ws();
            self.expect(':')?;
            self.skip_ws();
            let v = self.value()?;
            // --- A repeated key is an ambiguous document, therefore rejected.
            //
            // `BTreeMap::insert` let the **last** occurrence win. An
            // intermediary - application firewall, audit log, filtering
            // relay - that reads the first one then sees something other than
            // the node does. That is exactly the "request smuggling" pattern,
            // carried over to JSON: two readers, two truths, a spend that
            // gets through.
            //
            // RFC 8259 leaves the behavior undefined. Monetary code cannot
            // afford undefined.
            if m.contains_key(&k) {
                return Err(JsonError::DuplicateKey(k));
            }
            m.insert(k, v);
            self.skip_ws();
            match self.peek()? {
                ',' => self.i += 1,
                '}' => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Json::Object(m));
                }
                c => {
                    return Err(JsonError::UnexpectedChar {
                        position: self.i,
                        found: c,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_of_simple_values() {
        assert_eq!(Json::Null.encode(), "null");
        assert_eq!(Json::Bool(true).encode(), "true");
        assert_eq!(Json::Int(-42).encode(), "-42");
        assert_eq!(Json::str("hello").encode(), "\"hello\"");
    }

    #[test]
    fn objects_are_ordered() {
        let a = Json::obj()
            .set("z", Json::Int(1))
            .set("a", Json::Int(2))
            .build();
        let b = Json::obj()
            .set("a", Json::Int(2))
            .set("z", Json::Int(1))
            .build();
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a.encode(), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn compliant_escaping() {
        assert_eq!(Json::str("a\"b").encode(), r#""a\"b""#);
        assert_eq!(Json::str("a\\b").encode(), r#""a\\b""#);
        assert_eq!(Json::str("a\nb").encode(), r#""a\nb""#);
        // Control character: \\u escape required. Omitting it produces a
        // document that half of all parsers reject and the other half
        // interpret differently.
        assert_eq!(Json::str("a\u{1}b").encode(), r#""a\u0001b""#);
        assert_eq!(Json::str("€5").encode(), "\"€5\"");
    }

    /// An integer stays an integer, whatever its size.
    ///
    /// It used to switch to a string above `i64::MAX`: a numeric field
    /// therefore changed type depending on its value, which traps every
    /// client - and opens an injection in one that inserts the value into a
    /// page.
    #[test]
    fn a_large_unsigned_integer_stays_a_number() {
        assert_eq!(Json::u64(42).encode(), "42");
        assert_eq!(Json::u64(u64::MAX).encode(), "18446744073709551615");
        // And it reads back identically.
        let reread = parse(&Json::u64(u64::MAX).encode()).unwrap();
        assert_eq!(reread.as_u64(), Some(u64::MAX));
    }

    #[test]
    fn round_trip_on_a_realistic_document() {
        let v = Json::obj()
            .set("height", Json::u64(206))
            .set("tip", Json::str("abcdef"))
            .set(
                "peers",
                Json::array(vec![Json::str("127.0.0.1:21031"), Json::Null]),
            )
            .set("synced", Json::Bool(true))
            .build();
        assert_eq!(parse(&v.encode()).unwrap(), v);
    }

    #[test]
    fn parsing_common_cases() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse("  true  ").unwrap(), Json::Bool(true));
        assert_eq!(parse("-17").unwrap(), Json::Int(-17));
        assert_eq!(parse("[]").unwrap(), Json::Array(vec![]));
        assert_eq!(parse("{}").unwrap(), Json::Object(BTreeMap::new()));
        assert_eq!(
            parse(r#"{"a":[1,2,{"b":null}]}"#).unwrap().encode(),
            r#"{"a":[1,2,{"b":null}]}"#
        );
    }

    #[test]
    fn escapes_read_back() {
        assert_eq!(parse(r#""a\nb""#).unwrap(), Json::str("a\nb"));
        assert_eq!(parse(r#""A""#).unwrap(), Json::str("A"));
        assert_eq!(parse(r#""\\""#).unwrap(), Json::str("\\"));
    }

    /// A float rejected outright is better than a rounded amount.
    #[test]
    fn floats_are_rejected() {
        assert_eq!(parse("1.5"), Err(JsonError::InvalidNumber));
        assert_eq!(parse("1e10"), Err(JsonError::InvalidNumber));
    }

    /// The check that prevents a denial of service in one line of curl.
    #[test]
    fn absurd_nesting_is_rejected_without_overflowing_the_stack() {
        let deep = "[".repeat(1000) + &"]".repeat(1000);
        assert_eq!(parse(&deep), Err(JsonError::NestingTooDeep));
    }

    #[test]
    fn a_document_too_large_is_rejected() {
        let big = "\"".to_string() + &"a".repeat(MAX_INPUT) + "\"";
        assert!(matches!(parse(&big), Err(JsonError::DocumentTooLarge(_))));
    }

    #[test]
    fn malformed_documents_are_rejected() {
        assert!(parse("").is_err());
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse(r#"{"a"}"#).is_err());
        assert!(parse("junk").is_err());
        assert_eq!(parse("1 2"), Err(JsonError::TrailingBytes));
    }

    /// No input, however twisted, may cause a panic.
    #[test]
    fn no_random_input_causes_a_panic() {
        let alphabet: Vec<char> = "{}[]\",:0123456789tfnul \\/-.eE\u{e9}".chars().collect();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..5_000 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let n = (seed % 60) as usize;
            let mut s = String::new();
            let mut g = seed;
            for _ in 0..n {
                g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                s.push(alphabet[(g >> 33) as usize % alphabet.len()]);
            }
            let _ = parse(&s);
        }
    }

    #[test]
    fn accessors() {
        let v = parse(r#"{"n":7,"s":"x","t":[1,2],"big":18446744073709551615}"#).unwrap();
        assert_eq!(v.get("n").and_then(|x| x.as_u64()), Some(7));
        assert_eq!(v.get("s").and_then(|x| x.as_str()), Some("x"));
        assert_eq!(
            v.get("t").and_then(|x| x.as_array()).map(|a| a.len()),
            Some(2)
        );
        assert_eq!(
            v.get("big").and_then(|x| x.as_u64()),
            Some(u64::MAX),
            "a large integer must read back as a number"
        );
        // And a string is **not** a number: it is through this leniency
        // that a `sendtoaddress` overflowed an addition.
        let v = parse(r#"{"n":"18446744073709551615"}"#).unwrap();
        assert_eq!(
            v.get("n").and_then(|x| x.as_u64()),
            None,
            "a string must not be accepted as an integer"
        );
        // A repeated key makes the document ambiguous: rejected.
        assert!(matches!(
            parse(r#"{"method":"getinfo","method":"sendtoaddress"}"#),
            Err(JsonError::DuplicateKey(_))
        ));
        assert!(v.get("absent").is_none());
    }
}
