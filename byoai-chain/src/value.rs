//! JSON value model with Python `json` semantics, a `json.loads`-compatible parser and a
//! `json.dumps`-compatible serializer. The goal is byte identity with CPython 3.10+.
//!
//! Python behaviours reproduced on purpose:
//! - ints keep arbitrary precision (stored as their decimal text, "-0" becomes "0");
//! - floats print like `float.__repr__` (shortest round-trip, `1e-05`, `1e+16`, `1.0`);
//! - NaN / Infinity / -Infinity are accepted and printed (allow_nan=True default);
//! - duplicate keys: last value wins, first position kept (dict update semantics);
//! - `sort_keys` orders by code point (Rust `str` byte order == code point order);
//! - `ensure_ascii` escapes everything outside 0x20..0x7e as lowercase `\uXXXX`
//!   (surrogate pairs above U+FFFF); without it only `"` `\` and C0 controls are escaped.

#![forbid(unsafe_code)]

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Canonical decimal text of a Python int (no leading zeros, no "-0").
    Int(String),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    /// Insertion-ordered; keys unique (last write wins, first position kept).
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    /// Copy of an object without one key (Python `{k: v for k, v in d.items() if k != key}`).
    pub fn without(&self, key: &str) -> Value {
        match self {
            Value::Object(items) => Value::Object(items.iter().filter(|(k, _)| k != key).cloned().collect()),
            other => other.clone(),
        }
    }
    /// Python `==` between a JSON number value and a Python int (used for `seq` checks).
    pub fn eq_int(&self, n: i64) -> bool {
        match self {
            Value::Int(s) => s.parse::<i64>().map(|v| v == n).unwrap_or(false),
            Value::Float(f) => *f == n as f64,
            Value::Bool(b) => (*b as i64) == n, // Python: True == 1
            _ => false,
        }
    }
    pub fn obj_insert(items: &mut Vec<(String, Value)>, key: String, val: Value) {
        if let Some(slot) = items.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = val;
        } else {
            items.push((key, val));
        }
    }
}

// ------------------------------------------------------------------ errors

#[derive(Debug, Clone, PartialEq)]
pub struct Error(pub String);

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Error(msg.into())
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

// ------------------------------------------------------------------ parser (json.loads)

pub fn parse(text: &str) -> Result<Value> {
    let mut p = Parser { s: text.as_bytes(), src: text, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(Error::new(alloc::format!("extra data at byte {}", p.i)));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    src: &'a str,
    i: usize,
}

const MAX_DEPTH: usize = 512;

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn err<T>(&self, what: &str) -> Result<T> {
        Err(Error::new(alloc::format!("{} at byte {}", what, self.i)))
    }
    fn lit(&mut self, word: &str) -> bool {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            true
        } else {
            false
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return self.err("nesting too deep");
        }
        if self.i >= self.s.len() {
            return self.err("expecting value");
        }
        for (word, v) in [
            ("null", Value::Null),
            ("true", Value::Bool(true)),
            ("false", Value::Bool(false)),
            ("NaN", Value::Float(f64::NAN)),
            ("Infinity", Value::Float(f64::INFINITY)),
            ("-Infinity", Value::Float(f64::NEG_INFINITY)),
        ] {
            if self.lit(word) {
                return Ok(v);
            }
        }
        match self.s[self.i] {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Value::Str(self.string()?)),
            b'-' | b'0'..=b'9' => self.number(),
            _ => self.err("expecting value"),
        }
    }
    fn number(&mut self) -> Result<Value> {
        // Python's NUMBER_RE: (-?(?:0|[1-9]\d*))(\.\d+)?([eE][-+]?\d+)?
        let start = self.i;
        if self.s[self.i] == b'-' {
            self.i += 1;
        }
        let int_start = self.i;
        if self.i < self.s.len() && self.s[self.i] == b'0' {
            self.i += 1;
        } else if self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                self.i += 1;
            }
        } else {
            self.i = start;
            return self.err("expecting value");
        }
        let int_end = self.i;
        let mut is_float = false;
        if self.i + 1 < self.s.len() && self.s[self.i] == b'.' && self.s[self.i + 1].is_ascii_digit() {
            is_float = true;
            self.i += 1;
            while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                self.i += 1;
            }
        }
        if self.i < self.s.len() && (self.s[self.i] == b'e' || self.s[self.i] == b'E') {
            let save = self.i;
            let mut j = self.i + 1;
            if j < self.s.len() && (self.s[j] == b'+' || self.s[j] == b'-') {
                j += 1;
            }
            if j < self.s.len() && self.s[j].is_ascii_digit() {
                while j < self.s.len() && self.s[j].is_ascii_digit() {
                    j += 1;
                }
                self.i = j;
                is_float = true;
            } else {
                self.i = save;
            }
        }
        let text = &self.src[start..self.i];
        if is_float {
            let f: f64 = text.parse().map_err(|_| Error::new("bad float"))?;
            Ok(Value::Float(f))
        } else {
            let neg = int_start > start;
            let digits = &self.src[int_start..int_end];
            if digits == "0" {
                Ok(Value::Int(String::from("0")))
            } else if neg {
                Ok(Value::Int(alloc::format!("-{}", digits)))
            } else {
                Ok(Value::Int(String::from(digits)))
            }
        }
    }
    fn hex4(&mut self) -> Result<u32> {
        if self.i + 4 > self.s.len() {
            return self.err("invalid \\uXXXX escape");
        }
        let h = &self.src[self.i..self.i + 4];
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return self.err("invalid \\uXXXX escape");
        }
        self.i += 4;
        Ok(u32::from_str_radix(h, 16).unwrap())
    }
    fn string(&mut self) -> Result<String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            if self.i >= self.s.len() {
                return self.err("unterminated string");
            }
            let b = self.s[self.i];
            match b {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    if self.i >= self.s.len() {
                        return self.err("unterminated string");
                    }
                    let e = self.s[self.i];
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut c = self.hex4()?;
                            if (0xd800..0xdc00).contains(&c)
                                && self.s[self.i..].starts_with(b"\\u")
                            {
                                let save = self.i;
                                self.i += 2;
                                let c2 = self.hex4()?;
                                if (0xdc00..0xe000).contains(&c2) {
                                    c = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
                                } else {
                                    self.i = save;
                                }
                            }
                            match char::from_u32(c) {
                                Some(ch) => out.push(ch),
                                // Python keeps lone surrogates in str; they cannot be UTF-8
                                // encoded, so every UTF-8 dialect fails on them in Python too.
                                None => return self.err("lone surrogate (unsupported)"),
                            }
                        }
                        _ => return self.err("invalid escape"),
                    }
                }
                0x00..=0x1f => return self.err("invalid control character"), // strict=True
                _ => {
                    let ch_len = utf8_len(b);
                    out.push_str(&self.src[self.i..self.i + ch_len]);
                    self.i += ch_len;
                }
            }
        }
    }
    fn array(&mut self, depth: usize) -> Result<Value> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.i < self.s.len() && self.s[self.i] == b']' {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            if self.i >= self.s.len() {
                return self.err("unterminated array");
            }
            match self.s[self.i] {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return self.err("expecting ',' delimiter"),
            }
        }
    }
    fn object(&mut self, depth: usize) -> Result<Value> {
        self.i += 1;
        let mut items: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.i < self.s.len() && self.s[self.i] == b'}' {
            self.i += 1;
            return Ok(Value::Object(items));
        }
        loop {
            self.ws();
            if self.i >= self.s.len() || self.s[self.i] != b'"' {
                return self.err("expecting property name");
            }
            let k = self.string()?;
            self.ws();
            if self.i >= self.s.len() || self.s[self.i] != b':' {
                return self.err("expecting ':' delimiter");
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            Value::obj_insert(&mut items, k, v);
            self.ws();
            if self.i >= self.s.len() {
                return self.err("unterminated object");
            }
            match self.s[self.i] {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Ok(Value::Object(items));
                }
                _ => return self.err("expecting ',' delimiter"),
            }
        }
    }
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

// ------------------------------------------------------------------ float repr

fn split_sci(sci: &str) -> (String, i32) {
    let (mant, exp) = sci.split_once('e').unwrap();
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    (digits, exp.parse().unwrap())
}

fn digits_value(digits: &str, exp: i32) -> f64 {
    let mut s = String::with_capacity(digits.len() + 8);
    s.push_str(&digits[..1]);
    if digits.len() > 1 {
        s.push('.');
        s.push_str(&digits[1..]);
    }
    let _ = write!(s, "e{}", exp);
    s.parse::<f64>().unwrap_or(f64::NAN)
}

/// Shortest round-trip digits of a finite, non-negative f64, choosing like CPython's
/// `repr` (David Gay dtoa mode 0) when two shortest candidates are equally close:
/// the one whose last digit is even. Rust's own shortest formatter rounds such ties up.
fn shortest_digits(f: f64) -> (String, i32) {
    let (d, e) = split_sci(&alloc::format!("{:e}", f));
    if f == 0.0 {
        return (d, e);
    }
    // Exact decimal expansion: every f64 has at most 767 significant digits.
    let (mut x, xe) = split_sci(&alloc::format!("{:.800e}", f));
    while x.len() > 1 && x.ends_with('0') {
        x.pop();
    }
    if x.len() < 2 || !x.ends_with('5') {
        return (d, e);
    }
    // f lies exactly halfway between lo and hi (both len(x)-1 digits in x's frame).
    let lo: String = String::from(&x[..x.len() - 1]);
    let mut hi_bytes: Vec<u8> = lo.clone().into_bytes();
    let mut i = hi_bytes.len();
    let mut carry = true;
    while carry && i > 0 {
        i -= 1;
        if hi_bytes[i] == b'9' {
            hi_bytes[i] = b'0';
        } else {
            hi_bytes[i] += 1;
            carry = false;
        }
    }
    let (mut hi, mut he) = (String::from_utf8(hi_bytes).unwrap(), xe);
    if carry {
        hi.insert(0, '1');
        hi.pop();
        he += 1;
    }
    while hi.len() > 1 && hi.ends_with('0') {
        hi.pop();
    }
    let mut lo_t = lo.clone();
    while lo_t.len() > 1 && lo_t.ends_with('0') {
        lo_t.pop();
    }
    let lo_ok = digits_value(&lo_t, xe) == f;
    let hi_ok = digits_value(&hi, he) == f;
    if !(lo_ok && hi_ok) || lo_t.len().max(hi.len()) > d.len() {
        return (d, e);
    }
    let lo_even = (lo.as_bytes()[lo.len() - 1] - b'0') % 2 == 0;
    if lo_even { (lo_t, xe) } else { (hi, he) }
}

/// `float.__repr__` for a finite f64, using Rust's shortest round-trip digits.
pub fn py_float_repr(f: f64) -> String {
    if f.is_nan() {
        return String::from("NaN");
    }
    if f.is_infinite() {
        return String::from(if f > 0.0 { "Infinity" } else { "-Infinity" });
    }
    let neg = f.is_sign_negative();
    let (digits, exp) = shortest_digits(f.abs());
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    let decpt = exp + 1; // digits before the decimal point
    if decpt <= -4 || decpt > 16 {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let _ = write!(out, "e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs());
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..(-decpt) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        let d = decpt as usize;
        if digits.len() <= d {
            out.push_str(&digits);
            for _ in digits.len()..d {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            out.push_str(&digits[..d]);
            out.push('.');
            out.push_str(&digits[d..]);
        }
    }
    out
}

// ------------------------------------------------------------------ dumps

#[derive(Clone, Copy, Debug)]
pub struct DumpOpts {
    pub ensure_ascii: bool,
    pub sort_keys: bool,
    /// None = single line. Some(n) = Python `indent=n` (item sep "," + newline, key sep ": ").
    pub indent: Option<usize>,
    /// Single-line separators: compact (",", ":") when true, Python default (", ", ": ") when false.
    pub compact: bool,
}

impl DumpOpts {
    /// json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=...)
    pub const fn canon(ensure_ascii: bool) -> Self {
        DumpOpts { ensure_ascii, sort_keys: true, indent: None, compact: true }
    }
}

pub fn write_py_str(out: &mut String, s: &str, ensure_ascii: bool) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if ensure_ascii && !((' '..='~').contains(&c)) => {
                let cp = c as u32;
                if cp >= 0x10000 {
                    let v = cp - 0x10000;
                    let hi = 0xd800 + (v >> 10);
                    let lo = 0xdc00 + (v & 0x3ff);
                    let _ = write!(out, "\\u{:04x}\\u{:04x}", hi, lo);
                } else {
                    let _ = write!(out, "\\u{:04x}", cp);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn dumps(v: &Value, o: &DumpOpts) -> String {
    let mut out = String::new();
    dump_into(&mut out, v, o, 0);
    out
}

fn newline(out: &mut String, o: &DumpOpts, level: usize) {
    if let Some(n) = o.indent {
        out.push('\n');
        for _ in 0..(n * level) {
            out.push(' ');
        }
    }
}

fn dump_into(out: &mut String, v: &Value, o: &DumpOpts, level: usize) {
    let item_sep = if o.indent.is_some() || o.compact { "," } else { ", " };
    let key_sep = if o.compact && o.indent.is_none() { ":" } else { ": " };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(s) => out.push_str(s),
        Value::Float(f) => out.push_str(&py_float_repr(*f)),
        Value::Str(s) => write_py_str(out, s, o.ensure_ascii),
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                newline(out, o, level + 1);
                dump_into(out, x, o, level + 1);
            }
            newline(out, o, level);
            out.push(']');
        }
        Value::Object(items) => {
            if items.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut refs: Vec<&(String, Value)> = items.iter().collect();
            if o.sort_keys {
                refs.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
            }
            out.push('{');
            for (i, (k, x)) in refs.iter().map(|p| (&p.0, &p.1)).enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                newline(out, o, level + 1);
                write_py_str(out, k, o.ensure_ascii);
                out.push_str(key_sep);
                dump_into(out, x, o, level + 1);
            }
            newline(out, o, level);
            out.push('}');
        }
    }
}

// ------------------------------------------------------------------ CHAP (JCS profile)

const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;

/// chap_coordinator 0.2.13 `canonicalize`: JCS key order (UTF-16 code units), integers only
/// (|n| <= 2^53-1, integral floats printed as ints), strings as `json.dumps(ensure_ascii=False)`.
pub fn chap_canon(v: &Value) -> Result<String> {
    let mut out = String::new();
    chap_into(&mut out, v)?;
    Ok(out)
}

fn chap_int_text(n: i128) -> Result<String> {
    if n.abs() > MAX_SAFE_INTEGER {
        return Err(Error::new("CHAP canonical integers must be within the safe-integer range"));
    }
    Ok(alloc::format!("{}", n))
}

fn chap_into(out: &mut String, v: &Value) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Str(s) => write_py_str(out, s, false),
        Value::Int(s) => {
            let n: i128 = s
                .parse()
                .map_err(|_| Error::new("CHAP canonical integers must be within the safe-integer range"))?;
            out.push_str(&chap_int_text(n)?);
        }
        Value::Float(f) => {
            if !f.is_finite() {
                return Err(Error::new("Non-finite numbers are not permitted in a CHAP canonical value."));
            }
            if f.fract() != 0.0 {
                return Err(Error::new("CHAP canonical numbers must be integers"));
            }
            if f.abs() > 1e30 {
                return Err(Error::new("CHAP canonical integers must be within the safe-integer range"));
            }
            out.push_str(&chap_int_text(*f as i128)?);
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                chap_into(out, x)?;
            }
            out.push(']');
        }
        Value::Object(items) => {
            let mut refs: Vec<&(String, Value)> = items.iter().collect();
            refs.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, x)) in refs.iter().map(|p| (&p.0, &p.1)).enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_py_str(out, k, false);
                out.push(':');
                chap_into(out, x)?;
            }
            out.push('}');
        }
    }
    Ok(())
}
