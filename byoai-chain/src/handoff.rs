//! `handoff` (byoai.handoff/0.1): a case handoff receipt. An analyst's steps, the sources each
//! step read (with their sha256 and when they were fetched), what it produced, and which earlier
//! steps it built on, sealed so an investigator can re-derive every finding without trusting
//! the analyst. This is parallel reconstruction done in the open.
//!
//! Constructions reused, not invented:
//! - steps are a `tfx` chain: row_sha = sha256(canon UTF-8(row without "row_sha")), prev_sha links,
//!   seq from 0, anchored by `rows` and `head` (so truncation is caught);
//! - the seal is the Verified Declaration seal: Ed25519 over canon UTF-8(doc["handoff"]),
//!   `sig` = {alg, key_id, sig_hex}, `pid` = sha256(canon({"r": case, "v": head}))[..24];
//! - the step model (materials -> products) follows in-toto link metadata.
//!
//! Three additions this format carries:
//! 1. fetch timestamps: every source records `fetched_at` apart from the step's `checked_at`;
//! 2. re-derivation: a verifier that holds the sources labels each one VERIFIED, UNGROUNDED or
//!    UNCHECKED by hashing it again;
//! 3. taint: revoking a source or a step marks every step that depends on it.
//!
//! Times are self-asserted and identity is ID_UNCHECKED: the receipt never says more than was checked.
#![forbid(unsafe_code)]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::dialects::{self, canon_u8, sha256_hex};
use crate::value::{Error, Result, Value};

pub const FORMAT: &str = "byoai.handoff/0.1";
pub const IDENTITY: &str = "ID_UNCHECKED";
pub const TIME: &str = "self-asserted";
pub const NOTICE: &str = "This handoff records an analyst's steps and the sha256 of each source as stated by the analyst. Times are self-asserted and identity is not checked. It proves the record has not changed since it was signed and lets anyone holding the sources re-derive each finding. It is not a notarization.";

pub const HANDOFF_KEYS: [&str; 11] = ["analyst", "case", "format", "head", "identity", "issued_at", "notice", "pubkey", "rows", "steps", "time"];
pub const STEP_KEYS: [&str; 9] = ["action", "checked_at", "depends_on", "prev_sha", "products", "row_sha", "seq", "sources", "tool"];
pub const SOURCE_KEYS: [&str; 3] = ["fetched_at", "ref", "sha256"];
pub const PRODUCT_KEYS: [&str; 2] = ["ref", "sha256"];

pub const VERIFIED: &str = "VERIFIED";
pub const UNGROUNDED: &str = "UNGROUNDED";
pub const UNCHECKED: &str = "UNCHECKED";

fn s(x: &str) -> Value {
    Value::Str(x.to_string())
}
fn int(n: i64) -> Value {
    Value::Int(n.to_string())
}
fn obj(items: Vec<(&str, Value)>) -> Value {
    Value::Object(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Strict UTC time YYYY-MM-DDTHH:MM:SSZ with real values (year >= 1970, valid day of month,
/// hour < 24, minute and second < 60), so string order is time order.
pub fn is_utc(t: &str) -> bool {
    let b = t.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return false;
    }
    let num = |a: usize, z: usize| -> Option<u32> {
        if b[a..z].iter().all(|c| c.is_ascii_digit()) {
            core::str::from_utf8(&b[a..z]).ok()?.parse().ok()
        } else {
            None
        }
    };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) = (num(0, 4), num(5, 7), num(8, 10), num(11, 13), num(14, 16), num(17, 19)) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    y >= 1970 && d >= 1 && d <= mdays && h < 24 && mi < 60 && s < 60
}

/// A ref must be a plain relative path, already in its normal form: no leading or trailing "/",
/// no empty, "." or ".." parts, no backslash or NUL. So every re-deriver opens the same file.
pub fn is_plain_ref(r: &str) -> bool {
    !r.is_empty() && !r.contains('\\') && !has_unsafe_chars(r) && r.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}

/// Characters that can rewrite or hide terminal output, reorder text, or make two different
/// names look the same: C0, DEL, C1, line and paragraph separators, bidi marks (U+061C,
/// U+200E/F, U+202A-202E, U+2066-2069), and invisible characters (U+200B-200D, U+2060-2064, U+FEFF).
pub fn is_unsafe_char(c: char) -> bool {
    let u = c as u32;
    u < 0x20
        || (0x7f..=0x9f).contains(&u)
        || u == 0x061c
        || (0x200b..=0x200f).contains(&u)
        || u == 0x2028
        || u == 0x2029
        || (0x202a..=0x202e).contains(&u)
        || (0x2060..=0x2064).contains(&u)
        || (0x2066..=0x2069).contains(&u)
        || u == 0xfeff
}

pub fn has_unsafe_chars(s: &str) -> bool {
    s.chars().any(is_unsafe_char)
}

fn is_sha(x: &str) -> bool {
    x.len() == 64 && x.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn as_int(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Int(t)) => t.parse::<i64>().ok(),
        _ => None,
    }
}

pub fn pid(case: &str, head: &str) -> String {
    let v = obj(vec![("r", s(case)), ("v", s(head))]);
    let h = sha256_hex(canon_u8(&v).as_bytes());
    h[..24].to_string()
}

/// One source or product as the verifier sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub seq: i64,
    pub role: &'static str, // "source" | "product"
    pub r#ref: String,
    pub sha256: String,
    pub label: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub ok: bool,
    /// True when the caller supplied observed hashes: then every item must be re-derived.
    pub rederive_required: bool,
    pub rows: usize,
    pub head: String,
    pub case: String,
    pub problems: Vec<String>,
    pub items: Vec<Item>,
}

impl Report {
    pub fn count(&self, label: &str) -> usize {
        self.items.iter().filter(|i| i.label == label).count()
    }
    pub fn to_value(&self) -> Value {
        let items = self
            .items
            .iter()
            .map(|i| {
                obj(vec![
                    ("seq", int(i.seq)),
                    ("role", s(i.role)),
                    ("ref", s(&i.r#ref)),
                    ("sha256", s(&i.sha256)),
                    ("label", s(i.label)),
                ])
            })
            .collect();
        obj(vec![
            ("ok", Value::Bool(self.ok)),
            ("format", s("handoff")),
            ("case", s(&self.case)),
            ("rows", Value::Int(self.rows.to_string())),
            ("head", s(&self.head)),
            ("first_bad", Value::Null),
            ("rederive_required", Value::Bool(self.rederive_required)),
            ("scope", s(if self.rederive_required { "integrity+rederive" } else { "integrity-only" })),
            ("problems", Value::Array(self.problems.iter().map(|p| s(p)).collect())),
            (
                "rederive",
                obj(vec![
                    ("verified", Value::Int(self.count(VERIFIED).to_string())),
                    ("ungrounded", Value::Int(self.count(UNGROUNDED).to_string())),
                    ("unchecked", Value::Int(self.count(UNCHECKED).to_string())),
                ]),
            ),
            ("items", Value::Array(items)),
        ])
    }
}

/// Field checks on one step row (shared by build and verify). Pushes problems; returns the
/// (role, ref, sha) items it holds.
fn keys_of(v: &Value) -> Vec<&str> {
    match v {
        Value::Object(items) => items.iter().map(|(k, _)| k.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn exact_keys(v: &Value, allowed: &[&str]) -> bool {
    matches!(v, Value::Object(_)) && keys_of(v).iter().all(|k| allowed.contains(k))
}

fn check_step(row: &Value, seq: i64, problems: &mut Vec<String>) -> Vec<(&'static str, String, String)> {
    let mut items = Vec::new();
    if !exact_keys(row, &STEP_KEYS) {
        problems.push(format!("STEP {}: unknown field (allowed: action, tool, sources, products, depends_on, checked_at)", seq));
    }
    for k in ["action", "tool"] {
        match row.get(k).and_then(|v| v.as_str()) {
            Some(v) if !v.trim().is_empty() => {
                if has_unsafe_chars(v) {
                    problems.push(format!("CONTROL_CHARS: step {} \"{}\" holds control or bidi characters", seq, k));
                }
            }
            _ => problems.push(format!("STEP {}: \"{}\" must be a non-empty string", seq, k)),
        }
    }
    let checked = row.get("checked_at").and_then(|v| v.as_str()).unwrap_or("");
    if !is_utc(checked) {
        problems.push(format!("STEP {}: checked_at must be UTC YYYY-MM-DDTHH:MM:SSZ", seq));
    }
    for (role, key) in [("source", "sources"), ("product", "products")] {
        let Some(list) = row.get(key).and_then(|v| v.as_array()) else {
            problems.push(format!("STEP {}: \"{}\" must be a list", seq, key));
            continue;
        };
        if role == "source" && list.is_empty() {
            problems.push(format!("STEP {}: a step must name at least one source", seq));
        }
        for it in list {
            let allowed: &[&str] = if role == "source" { &SOURCE_KEYS } else { &PRODUCT_KEYS };
            if !exact_keys(it, allowed) {
                problems.push(format!("STEP {}: a {} may only hold {}", seq, role, allowed.join(", ")));
            }
            let r = it.get("ref").and_then(|v| v.as_str()).unwrap_or("");
            let h = it.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
            if !is_plain_ref(r) {
                problems.push(format!("REF: step {} {} \"{}\" must be a plain relative path (no /x, x/, //, ., ..)", seq, role, r));
            }
            if !is_sha(h) {
                problems.push(format!("STEP {}: {} \"{}\" has no valid sha256", seq, role, r));
            }
            if role == "source" {
                let f = it.get("fetched_at").and_then(|v| v.as_str()).unwrap_or("");
                if !is_utc(f) {
                    problems.push(format!("STEP {}: source \"{}\" needs fetched_at as UTC YYYY-MM-DDTHH:MM:SSZ", seq, r));
                } else if is_utc(checked) && f > checked {
                    problems.push(format!("FETCH_AFTER_CHECK: step {} source \"{}\" fetched {} after the check at {}", seq, r, f, checked));
                }
            }
            items.push((role, r.to_string(), h.to_string()));
        }
    }
    match row.get("depends_on").and_then(|v| v.as_array()) {
        None => problems.push(format!("STEP {}: \"depends_on\" must be a list", seq)),
        Some(d) => {
            for x in d {
                match as_int(Some(x)) {
                    Some(n) if n >= 0 && n < seq => {}
                    _ => problems.push(format!("DEPENDS: step {} may only depend on an earlier step", seq)),
                }
            }
        }
    }
    items
}

/// Build a signed handoff from analyst step lines (each: action, tool, sources[{ref, sha256,
/// fetched_at}], products[{ref, sha256}], depends_on[ints], checked_at). Refuses any step that
/// fails the same checks the verifier applies.
pub fn build(case: &str, analyst: &str, issued_at: &str, steps_in: &[Value], seed: &[u8; 32]) -> Result<Value> {
    if case.trim().is_empty() || analyst.trim().is_empty() {
        return Err(Error::new("case and analyst must be non-empty"));
    }
    if has_unsafe_chars(case) || has_unsafe_chars(analyst) {
        return Err(Error::new("CONTROL_CHARS: case and analyst may not hold control or bidi characters"));
    }
    if !is_utc(issued_at) {
        return Err(Error::new("issued_at must be UTC YYYY-MM-DDTHH:MM:SSZ"));
    }
    if steps_in.is_empty() {
        return Err(Error::new("a handoff needs at least one step"));
    }
    let mut prev = String::from(dialects::GENESIS);
    let mut steps = Vec::with_capacity(steps_in.len());
    let mut problems = Vec::new();
    for (i, st) in steps_in.iter().enumerate() {
        let seq = i as i64;
        let Value::Object(fields) = st else { return Err(Error::new(format!("step {} is not an object", seq))) };
        let mut row: Vec<(String, Value)> = Vec::new();
        for k in ["action", "tool", "sources", "products", "depends_on", "checked_at"] {
            if let Some((_, v)) = fields.iter().find(|(kk, _)| kk == k) {
                row.push((k.to_string(), v.clone()));
            }
        }
        if fields.iter().any(|(k, _)| !["action", "tool", "sources", "products", "depends_on", "checked_at"].contains(&k.as_str())) {
            row.push(("unknown".to_string(), Value::Null)); // makes check_step report it
        }
        row.push(("seq".to_string(), int(seq)));
        row.push(("prev_sha".to_string(), s(&prev)));
        let rv = Value::Object(row.clone());
        check_step(&rv, seq, &mut problems);
        if let Some(c) = rv.get("checked_at").and_then(|v| v.as_str()) {
            if is_utc(c) && c > issued_at {
                problems.push(format!("ISSUED_BEFORE_CHECK: step {} checked at {} after issue {}", seq, c, issued_at));
            }
        }
        let sha = dialects::tfx_row_sha(&rv);
        row.push(("row_sha".to_string(), s(&sha)));
        steps.push(Value::Object(row));
        prev = sha;
    }
    if !problems.is_empty() {
        return Err(Error::new(problems.join("; ")));
    }
    let pubkey = hex::encode(dialects::ed25519_public(seed));
    let h = obj(vec![
        ("format", s(FORMAT)),
        ("case", s(case)),
        ("analyst", s(analyst)),
        ("identity", s(IDENTITY)),
        ("issued_at", s(issued_at)),
        ("time", s(TIME)),
        ("pubkey", s(&pubkey)),
        ("rows", int(steps.len() as i64)),
        ("head", s(&prev)),
        ("steps", Value::Array(steps)),
        ("notice", s(NOTICE)),
    ]);
    let sig = dialects::ed25519_sign(seed, canon_u8(&h).as_bytes());
    Ok(obj(vec![
        ("handoff", h),
        ("pid", s(&pid(case, &prev))),
        ("sig", obj(vec![("alg", s("ed25519")), ("key_id", s(&pubkey[..16])), ("sig_hex", s(&hex::encode(sig)))])),
    ]))
}

/// Verify a handoff against a pinned public key. `observed` = (ref, sha256) pairs the verifier
/// hashed itself. With `observed` given (even empty), re-derivation is required: any item left
/// UNCHECKED fails the verdict (REDERIVE_INCOMPLETE). With `None` the verdict covers integrity
/// only, every item is UNCHECKED, and `scope` says so.
pub fn verify(doc: &Value, pubkey_hex: &str, observed: Option<&[(String, String)]>) -> Result<Report> {
    let mut problems = Vec::new();
    let empty = Value::Object(Vec::new());
    let h = doc.get("handoff").unwrap_or(&empty);
    if !exact_keys(doc, &["handoff", "pid", "sig"]) || keys_of(doc).len() != 3 {
        problems.push("FIELDS: the file must hold exactly handoff, pid and sig (nothing unsigned beside them)".to_string());
    }
    let sigv = doc.get("sig").unwrap_or(&empty);
    if !exact_keys(sigv, &["alg", "key_id", "sig_hex"]) || keys_of(sigv).len() != 3 {
        problems.push("FIELDS: sig must hold exactly alg, key_id and sig_hex".to_string());
    }
    if !exact_keys(h, &HANDOFF_KEYS) || keys_of(h).len() != HANDOFF_KEYS.len() {
        problems.push("FIELDS: handoff fields differ from byoai.handoff/0.1".to_string());
    }
    let gs = |k: &str| h.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if gs("format") != FORMAT {
        problems.push(format!("FORMAT: not {}", FORMAT));
    }
    if gs("notice") != NOTICE {
        problems.push("NOTICE: the fixed notice was changed".to_string());
    }
    if gs("identity") != IDENTITY || gs("time") != TIME {
        problems.push("LABEL: identity must be ID_UNCHECKED and time self-asserted".to_string());
    }
    let pinned = pubkey_hex.trim().to_ascii_lowercase();
    if gs("pubkey") != pinned {
        problems.push("KEY_MISMATCH: the handoff names a different signing key".to_string());
    }
    if sigv.get("key_id").and_then(|v| v.as_str()) != pinned.get(..16) {
        problems.push("KEY_ID: sig.key_id does not match the pinned key".to_string());
    }
    let alg = doc.get("sig").and_then(|x| x.get("alg")).and_then(|v| v.as_str()).unwrap_or("");
    let sig_hex = doc.get("sig").and_then(|x| x.get("sig_hex")).and_then(|v| v.as_str()).unwrap_or("");
    let pk = <[u8; 32]>::try_from(hex::decode(&pinned).map_err(|_| Error::new("bad public key hex"))?.as_slice())
        .map_err(|_| Error::new("public key must be 32 bytes"))?;
    let sig_ok = alg == "ed25519"
        && hex::decode(sig_hex).ok().and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok()).map(|sig| dialects::ed25519_verify(&pk, canon_u8(h).as_bytes(), &sig)).unwrap_or(false);
    if !sig_ok {
        problems.push("SIGNATURE: the handoff signature does not verify".to_string());
    }
    let case = gs("case");
    let head = gs("head");
    if has_unsafe_chars(&case) || has_unsafe_chars(&gs("analyst")) {
        problems.push("CONTROL_CHARS: case or analyst holds control or bidi characters".to_string());
    }
    if doc.get("pid").and_then(|v| v.as_str()) != Some(pid(&case, &head).as_str()) {
        problems.push("PID: pid does not match case and head".to_string());
    }
    let steps: Vec<Value> = h.get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if steps.is_empty() {
        problems.push("EMPTY: a handoff must record at least one step".to_string());
    }
    let anchor = obj(vec![("rows", h.get("rows").cloned().unwrap_or(Value::Null)), ("head", s(&head))]);
    let (chain_ok, bad, _) = dialects::tfx_check(&steps, Some(&anchor));
    if !chain_ok {
        problems.push(format!("CHAIN_BROKEN at row {}", bad.unwrap_or(0)));
    }
    let issued = gs("issued_at");
    if !is_utc(&issued) {
        problems.push("ISSUED_AT: must be UTC YYYY-MM-DDTHH:MM:SSZ".to_string());
    }
    let mut items = Vec::new();
    for (i, row) in steps.iter().enumerate() {
        let seq = i as i64;
        for (role, r, sha) in check_step(row, seq, &mut problems) {
            let label = match observed.and_then(|o| o.iter().find(|(rr, _)| *rr == r)) {
                None => UNCHECKED,
                Some((_, seen)) if *seen == sha => VERIFIED,
                Some(_) => UNGROUNDED,
            };
            if label == UNGROUNDED {
                problems.push(format!("UNGROUNDED: step {} {} \"{}\" does not hash to the recorded sha256", seq, role, r));
            }
            items.push(Item { seq, role, r#ref: r, sha256: sha, label });
        }
        if let Some(c) = row.get("checked_at").and_then(|v| v.as_str()) {
            if is_utc(c) && is_utc(&issued) && c > issued.as_str() {
                problems.push(format!("ISSUED_BEFORE_CHECK: step {} checked at {} after issue {}", seq, c, issued));
            }
        }
    }
    let unchecked = items.iter().filter(|i| i.label == UNCHECKED).count();
    if observed.is_some() && unchecked > 0 {
        problems.push(format!("REDERIVE_INCOMPLETE: {} items could not be re-derived from the sources", unchecked));
    }
    Ok(Report { ok: problems.is_empty(), rederive_required: observed.is_some(), rows: steps.len(), head, case, problems, items })
}

/// (seq, reasons) for each tainted step.
pub type Tainted = Vec<(i64, Vec<String>)>;

/// Parse a revocation strictly: {"sources": [sha256...], "steps": [n...]}, nothing else, and it
/// must name at least one item. Bad shape is an error (bad input), never "nothing tainted".
pub fn parse_revoked(rv: &Value) -> Result<(Vec<String>, Vec<i64>)> {
    if !exact_keys(rv, &["sources", "steps"]) {
        return Err(Error::new("revoked must be an object with only \"sources\" and \"steps\""));
    }
    let mut srcs = Vec::new();
    if let Some(v) = rv.get("sources") {
        for x in v.as_array().ok_or_else(|| Error::new("revoked.sources must be a list"))? {
            let h = x.as_str().filter(|h| is_sha(h)).ok_or_else(|| Error::new("revoked.sources must hold lowercase 64-hex sha256 strings"))?;
            srcs.push(h.to_string());
        }
    }
    let mut steps = Vec::new();
    if let Some(v) = rv.get("steps") {
        for x in v.as_array().ok_or_else(|| Error::new("revoked.steps must be a list"))? {
            steps.push(as_int(Some(x)).ok_or_else(|| Error::new("revoked.steps must hold step numbers"))?);
        }
    }
    if srcs.is_empty() && steps.is_empty() {
        return Err(Error::new("revoked names nothing"));
    }
    Ok((srcs, steps))
}

/// Taint propagation over a verified handoff. A step is tainted when it is revoked, reads a
/// revoked file, produced a revoked file, depends on a tainted step, or reads a product of a
/// tainted step. "sources" in a revocation names files by sha256 wherever they appear.
/// An unverified handoff is never tainted or cleared: `report.ok == false` means NOT_VERIFIED.
/// A revoked item that matches nothing in the handoff is an error, never a CLEAN result.
pub fn taint(doc: &Value, pubkey_hex: &str, revoked: &Value) -> Result<(Report, Tainted)> {
    let (revoked_sources, revoked_steps) = parse_revoked(revoked)?;
    let rep = verify(doc, pubkey_hex, None)?;
    if !rep.ok {
        return Ok((rep, Vec::new()));
    }
    let mut unmatched: Vec<String> = Vec::new();
    for h in &revoked_sources {
        if !rep.items.iter().any(|i| &i.sha256 == h) {
            unmatched.push(format!("source {}", h));
        }
    }
    for n in &revoked_steps {
        if *n < 0 || *n >= rep.rows as i64 {
            unmatched.push(format!("step {}", n));
        }
    }
    if !unmatched.is_empty() {
        return Err(Error::new(format!("UNMATCHED: revoked {} not in this handoff", unmatched.join(", "))));
    }
    let empty = Value::Object(Vec::new());
    let steps: Vec<Value> = doc.get("handoff").unwrap_or(&empty).get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut tainted: Tainted = Vec::new();
    let mut bad_products: Vec<(String, i64)> = Vec::new();
    for (i, row) in steps.iter().enumerate() {
        let seq = i as i64;
        let mut why = Vec::new();
        if revoked_steps.contains(&seq) {
            why.push("REVOKED_STEP".to_string());
        }
        for src in row.get("sources").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let sha = src.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
            if revoked_sources.iter().any(|r| r == sha) {
                why.push(format!("REVOKED_SOURCE {}", sha));
            }
            if let Some((_, from)) = bad_products.iter().find(|(p, _)| p == sha) {
                why.push(format!("USES_PRODUCT_OF {}", from));
            }
        }
        for d in row.get("depends_on").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            if let Some(n) = as_int(Some(&d)) {
                if tainted.iter().any(|(t, _)| *t == n) {
                    why.push(format!("DEPENDS_ON {}", n));
                }
            }
        }
        for p in row.get("products").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let sha = p.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
            if revoked_sources.iter().any(|r| r == sha) {
                why.push(format!("REVOKED_PRODUCT {}", sha));
            }
        }
        if !why.is_empty() {
            for p in row.get("products").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                if let Some(sha) = p.get("sha256").and_then(|v| v.as_str()) {
                    bad_products.push((sha.to_string(), seq));
                }
            }
            tainted.push((seq, why));
        }
    }
    Ok((rep, tainted))
}

pub fn taint_value(rep: &Report, tainted: &[(i64, Vec<String>)]) -> Value {
    if !rep.ok {
        let mut v = rep.to_value();
        if let Value::Object(items) = &mut v {
            Value::obj_insert(items, "tainted".to_string(), Value::Null);
        }
        return v;
    }
    obj(vec![
        ("ok", Value::Bool(tainted.is_empty())),
        ("format", s("handoff")),
        ("case", s(&rep.case)),
        ("rows", Value::Int(rep.rows.to_string())),
        ("head", s(&rep.head)),
        (
            "tainted",
            Value::Array(
                tainted
                    .iter()
                    .map(|(n, why)| obj(vec![("seq", int(*n)), ("reasons", Value::Array(why.iter().map(|w| s(w)).collect()))]))
                    .collect(),
            ),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::parse;

    const SEED: [u8; 32] = [7u8; 32];
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn steps(extra: &str) -> Vec<Value> {
        let l0 = format!(r#"{{"action":"lookup","tool":"whois","sources":[{{"ref":"a.txt","sha256":"{A}","fetched_at":"2026-11-25T10:00:00Z"}}],"products":[{{"ref":"p0.txt","sha256":"{C}"}}],"depends_on":[],"checked_at":"2026-11-25T10:05:00Z"}}"#);
        let l1 = format!(r#"{{"action":"match","tool":"grep","sources":[{{"ref":"p0.txt","sha256":"{C}","fetched_at":"2026-11-25T10:05:00Z"}}],"products":[],"depends_on":[],"checked_at":"2026-11-25T10:06:00Z"}}"#);
        let l2 = format!(r#"{{"action":"note","tool":"editor","sources":[{{"ref":"b.txt","sha256":"{B}","fetched_at":"2026-11-25T10:01:00Z"}}],"products":[],"depends_on":[{extra}],"checked_at":"2026-11-25T10:07:00Z"}}"#);
        [l0, l1, l2].iter().map(|l| parse(l).unwrap()).collect()
    }
    fn pk() -> String {
        hex::encode(crate::dialects::ed25519_public(&SEED))
    }

    #[test]
    fn build_then_verify() {
        let d = build("CASE-1", "analyst", "2026-11-25T11:00:00Z", &steps(""), &SEED).unwrap();
        let r = verify(&d, &pk(), None).unwrap();
        assert!(r.ok, "{:?}", r.problems);
        assert_eq!(r.rows, 3);
        assert_eq!(r.count(UNCHECKED), 4);
        let none: Vec<(String, String)> = vec![];
        let r = verify(&d, &pk(), Some(&none)).unwrap();
        assert!(!r.ok && r.rederive_required && r.problems.iter().any(|p| p.starts_with("REDERIVE_INCOMPLETE")));
        let obs = vec![("a.txt".to_string(), A.to_string()), ("b.txt".to_string(), C.to_string())];
        let r = verify(&d, &pk(), Some(&obs)).unwrap();
        assert!(!r.ok);
        assert_eq!(r.count(VERIFIED), 1);
        assert_eq!(r.count(UNGROUNDED), 1);
    }

    #[test]
    fn edits_are_caught() {
        let d = build("CASE-1", "analyst", "2026-11-25T11:00:00Z", &steps(""), &SEED).unwrap();
        let t = crate::dialects::canon_u8(&d).replace("\"lookup\"", "\"Lookup\"");
        let r = verify(&parse(&t).unwrap(), &pk(), None).unwrap();
        assert!(r.problems.iter().any(|p| p.starts_with("SIGNATURE")));
        assert!(r.problems.iter().any(|p| p.starts_with("CHAIN_BROKEN")));
        let other = hex::encode(crate::dialects::ed25519_public(&[9u8; 32]));
        assert!(verify(&d, &other, None).unwrap().problems.iter().any(|p| p.starts_with("KEY_MISMATCH")));
    }

    #[test]
    fn refs_must_be_plain() {
        assert!(is_plain_ref("a.txt") && is_plain_ref("sub/a.txt"));
        for bad in ["", "/a", "a/", "a//b", "./a", "a/./b", "../a", "a/..", "a\\b"] {
            assert!(!is_plain_ref(bad), "{bad}");
        }
        let mut s = steps("");
        let x = crate::dialects::canon_u8(&s[0]).replace(r#""ref":"a.txt""#, r#""ref":"sub//a.txt""#);
        s[0] = parse(&x).unwrap();
        assert!(build("C", "a", "2026-11-25T11:00:00Z", &s, &SEED).unwrap_err().0.contains("REF"));
    }

    #[test]
    fn control_chars_are_refused() {
        assert!(build("C1\r\u{1b}[2KVERIFIED", "a", "2026-11-25T11:00:00Z", &steps(""), &SEED).is_err());
        assert!(build("C1", "a\u{202e}", "2026-11-25T11:00:00Z", &steps(""), &SEED).is_err());
        assert!(!is_plain_ref("a\u{1b}.txt"));
        assert!(build("CASE-1\u{200b}", "a", "2026-11-25T11:00:00Z", &steps(""), &SEED).is_err());
        assert!(build("CASE-Café-ü", "Zoë", "2026-11-25T11:00:00Z", &steps(""), &SEED).is_ok());
        let d = build("CASE-1", "analyst", "2026-11-25T11:00:00Z", &steps(""), &SEED).unwrap();
        let t = crate::dialects::canon_u8(&d).replace("\"CASE-1\"", "\"CASE-1\\r\\u001b[2K\"");
        assert!(verify(&parse(&t).unwrap(), &pk(), None).unwrap().problems.iter().any(|p| p.starts_with("CONTROL_CHARS")));
    }

    #[test]
    fn utc_values_are_checked() {
        assert!(is_utc("2024-02-29T23:59:59Z"));
        for bad in ["2023-02-29T00:00:00Z", "0000-00-00T99:99:99Z", "2026-13-01T00:00:00Z", "2026-04-31T00:00:00Z", "2026-01-01T24:00:00Z", "1969-12-31T23:59:59Z", "2026-01-01 00:00:00Z"] {
            assert!(!is_utc(bad), "{bad}");
        }
    }

    #[test]
    fn unsigned_extras_and_empty_are_refused() {
        let d = build("CASE-1", "analyst", "2026-11-25T11:00:00Z", &steps(""), &SEED).unwrap();
        let mut t = crate::dialects::canon_u8(&d);
        t.insert_str(1, r#""verdict":"VERIFIED_BY_COURT","#);
        assert!(verify(&parse(&t).unwrap(), &pk(), None).unwrap().problems.iter().any(|p| p.starts_with("FIELDS")));
        let k = crate::dialects::canon_u8(&d).replace(&format!(r#""key_id":"{}""#, &pk()[..16]), r#""key_id":"deadbeefdeadbeef""#);
        assert!(verify(&parse(&k).unwrap(), &pk(), None).unwrap().problems.iter().any(|p| p.starts_with("KEY_ID")));
        let n = crate::dialects::canon_u8(&d).replace(r#""sig":{"#, r#""sig":{"note":"identity checked","#);
        assert!(verify(&parse(&n).unwrap(), &pk(), None).unwrap().problems.iter().any(|p| p.starts_with("FIELDS")));
        let mut s = steps("");
        let x = crate::dialects::canon_u8(&s[0]).replace(r#""ref":"a.txt""#, r#""extra":1,"ref":"a.txt""#);
        s[0] = parse(&x).unwrap();
        assert!(build("C", "a", "2026-11-25T11:00:00Z", &s, &SEED).is_err());
    }

    #[test]
    fn build_refuses_bad_steps() {
        let mut s = steps("");
        let bad = crate::dialects::canon_u8(&s[0]).replace("2026-11-25T10:00:00Z", "2026-11-25T10:09:00Z");
        s[0] = parse(&bad).unwrap();
        assert!(build("C", "a", "2026-11-25T11:00:00Z", &s, &SEED).unwrap_err().0.contains("FETCH_AFTER_CHECK"));
        assert!(build("C", "a", "2026-11-25T11:00:00Z", &steps("2"), &SEED).unwrap_err().0.contains("DEPENDS"));
        assert!(build("C", "a", "2026-11-25T10:06:30Z", &steps(""), &SEED).unwrap_err().0.contains("ISSUED_BEFORE_CHECK"));
    }

    #[test]
    fn taint_follows_sources_products_and_depends() {
        let d = build("CASE-1", "analyst", "2026-11-25T11:00:00Z", &steps("0"), &SEED).unwrap();
        let (r, t) = taint(&d, &pk(), &parse(&format!(r#"{{"sources":["{A}"]}}"#)).unwrap()).unwrap();
        assert!(r.ok);
        let seqs: Vec<i64> = t.iter().map(|(n, _)| *n).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
        assert!(t[1].1.iter().any(|w| w == "USES_PRODUCT_OF 0"));
        assert!(t[2].1.iter().any(|w| w == "DEPENDS_ON 0"));
        let (_, t) = taint(&d, &pk(), &parse(&format!(r#"{{"sources":["{B}"]}}"#)).unwrap()).unwrap();
        assert_eq!(t.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![2]);
        for bad in [r#"{}"#, r#"[]"#, r#"{"source":[]}"#, r#"{"sources":["a.txt"]}"#, r#"{"steps":[3]}"#, r#"{"steps":[-1]}"#] {
            assert!(taint(&d, &pk(), &parse(bad).unwrap()).is_err(), "{bad}");
        }
        let (_, t) = taint(&d, &pk(), &parse(&format!(r#"{{"sources":["{C}"]}}"#)).unwrap()).unwrap();
        assert_eq!(t.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![0, 1, 2], "a revoked product taints its producer and its users");
        assert!(t[0].1.iter().any(|w| w.starts_with("REVOKED_PRODUCT")));
        let up = A.to_uppercase();
        assert!(taint(&d, &pk(), &parse(&format!(r#"{{"sources":["{up}"]}}"#)).unwrap()).is_err());
    }
}
