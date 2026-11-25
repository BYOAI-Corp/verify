//! One JSON-in/JSON-out entry point shared by every binding (CLI, Python, WASM, JNI).
//!
//! Request: {"op": "...", ...}. Response: a JSON object, always with "ok".
//! - {"op":"canon","dialect":"py-u8"|"py-ascii"|"chap"|"py-indent2","text":"<json>"}
//!     -> {"ok":true,"out":"<canonical text>","sha256":"<hex of out>"}
//! - {"op":"verify","format":"gate","rows":[{"seq","body","prev","hash"}...]}
//! - {"op":"verify","format":"verifylog","text":"<jsonl file text>"}
//! - {"op":"verify","format":"tfx","text":"<ledger jsonl>","anchor":{...}|null}
//! - {"op":"verify","format":"chap","entries":[...]}
//! - {"op":"verify","format":"vdecl-receipt","receipt":{...},"pubkey":"<hex>"}
//! - {"op":"verify","format":"vdecl-seal","seal":{...},"pubkey":"<hex>"}
//!     -> {"ok":bool,"format":..,"rows":n,"head":..,"first_bad":n|null,"problems":[..]}
//! - {"op":"version"} -> {"ok":true,"version":"0.1.0"}
#![forbid(unsafe_code)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::dialects::{self, GateRow};
use crate::value::{chap_canon, dumps, parse, DumpOpts, Error, Result, Value};

fn s(x: &str) -> Value {
    Value::Str(x.to_string())
}
fn int(n: usize) -> Value {
    Value::Int(n.to_string())
}
fn obj(items: Vec<(&str, Value)>) -> Value {
    Value::Object(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
fn out(v: &Value) -> String {
    dumps(v, &DumpOpts::canon(false))
}

fn field<'a>(req: &'a Value, k: &str) -> Result<&'a Value> {
    req.get(k).ok_or_else(|| Error::new(alloc::format!("missing field \"{}\"", k)))
}
fn field_str<'a>(req: &'a Value, k: &str) -> Result<&'a str> {
    field(req, k)?.as_str().ok_or_else(|| Error::new(alloc::format!("field \"{}\" must be a string", k)))
}

/// Canonical text of a JSON document in one of the dialects.
pub fn canon_text(dialect: &str, text: &str) -> Result<String> {
    let v = parse(text)?;
    canon_value(dialect, &v)
}

pub fn canon_value(dialect: &str, v: &Value) -> Result<String> {
    match dialect {
        "py-u8" => Ok(dialects::canon_u8(v)),
        "py-ascii" => Ok(dialects::canon_ascii(v)),
        "chap" => chap_canon(v),
        "py-indent2" => Ok(dialects::vdecl_receipt_bytes(v)),
        other => Err(Error::new(alloc::format!("unknown dialect \"{}\"", other))),
    }
}

/// Result of a verify, independent of binding.
pub struct Verdict {
    pub ok: bool,
    pub format: String,
    pub rows: usize,
    pub head: String,
    pub first_bad: Option<usize>,
    pub problems: Vec<String>,
}

impl Verdict {
    pub fn to_value(&self) -> Value {
        obj(vec![
            ("ok", Value::Bool(self.ok)),
            ("format", s(&self.format)),
            ("rows", int(self.rows)),
            ("head", s(&self.head)),
            ("first_bad", self.first_bad.map(int).unwrap_or(Value::Null)),
            ("problems", Value::Array(self.problems.iter().map(|p| s(p)).collect())),
        ])
    }
}

fn jsonl_rows(text: &str) -> Result<Vec<Value>> {
    // tfx `check`: [json.loads(l) for l in open(p) if l.strip()] (open() iterates on "\n")
    let mut rows = Vec::new();
    for l in text.split_inclusive('\n') {
        if l.trim().is_empty() {
            continue;
        }
        rows.push(parse(l)?);
    }
    Ok(rows)
}

pub fn verify_gate_rows(rows: &[GateRow]) -> Verdict {
    let r = dialects::gate_verify(rows);
    Verdict { ok: r.ok, format: "gate".into(), rows: r.rows, head: r.head, first_bad: if r.ok { None } else { Some(r.rows + 1) }, problems: r.problems }
}

pub fn verify_verifylog(text: &str) -> Verdict {
    let (ok, n, bad, head) = dialects::verifylog_verify(text);
    let problems = match bad {
        Some(l) => vec![alloc::format!("line {}: chain broken", l)],
        None => vec![],
    };
    Verdict { ok, format: "verifylog".into(), rows: n, head, first_bad: bad, problems }
}

pub fn verify_tfx(text: &str, anchor: Option<&Value>) -> Result<Verdict> {
    let rows = jsonl_rows(text)?;
    let (ok, bad, head) = dialects::tfx_check(&rows, anchor);
    let mut problems = Vec::new();
    if let Some(i) = bad {
        problems.push(alloc::format!("CHAIN_BROKEN at row {}", i));
    }
    Ok(Verdict { ok, format: "tfx".into(), rows: rows.len(), head, first_bad: bad, problems })
}

pub fn verify_chap(entries: &[Value]) -> Verdict {
    let r = dialects::chap_verify_export(entries);
    Verdict { ok: r.ok, format: "chap".into(), rows: r.rows, head: r.head, first_bad: None, problems: r.problems }
}

pub fn verify_vdecl_receipt(receipt: &Value, pubkey_hex: &str) -> Result<Verdict> {
    let (sig, dig) = dialects::vdecl_verify_receipt(receipt, pubkey_hex)?;
    let mut problems = Vec::new();
    if !sig {
        problems.push("SIGNATURE: receipt signature does not verify".to_string());
    }
    if !dig {
        problems.push("TSA_DIGEST: tsa.digest does not match sha256(canon(body))".to_string());
    }
    let head = dialects::sha256_hex(dialects::vdecl_receipt_bytes(receipt).as_bytes());
    Ok(Verdict { ok: sig && dig, format: "vdecl-receipt".into(), rows: 1, head, first_bad: None, problems })
}

pub fn verify_vdecl_seal(seal: &Value, pubkey_hex: &str) -> Result<Verdict> {
    let ok = dialects::vdecl_verify_seal(seal, pubkey_hex)?;
    let problems = if ok { vec![] } else { vec!["SEAL_SIGNATURE: seal signature does not verify".to_string()] };
    let empty = Value::Object(Vec::new());
    let head = dialects::sha256_hex(dialects::canon_u8(seal.get("seal").unwrap_or(&empty)).as_bytes());
    Ok(Verdict { ok, format: "vdecl-seal".into(), rows: 1, head, first_bad: None, problems })
}

fn gate_rows_from(v: &Value) -> Result<Vec<GateRow>> {
    let arr = v.as_array().ok_or_else(|| Error::new("\"rows\" must be a list"))?;
    let mut rows = Vec::with_capacity(arr.len());
    for r in arr {
        let seq = match r.get("seq") {
            Some(Value::Int(t)) => t.parse::<i64>().map_err(|_| Error::new("seq out of range"))?,
            _ => return Err(Error::new("row.seq must be an int")),
        };
        let g = |k: &str| r.get(k).and_then(|x| x.as_str()).map(|x| x.to_string()).ok_or_else(|| Error::new(alloc::format!("row.{} must be a string", k)));
        rows.push(GateRow { seq, body: g("body")?, prev: g("prev")?, hash: g("hash")? });
    }
    Ok(rows)
}

fn dispatch(req: &Value) -> Result<Value> {
    match field_str(req, "op")? {
        "version" => Ok(obj(vec![("ok", Value::Bool(true)), ("version", s(crate::VERSION))])),
        "canon" => {
            let c = canon_text(field_str(req, "dialect")?, field_str(req, "text")?)?;
            let h = dialects::sha256_hex(c.as_bytes());
            Ok(obj(vec![("ok", Value::Bool(true)), ("out", Value::Str(c)), ("sha256", Value::Str(h))]))
        }
        "verify" => {
            let v = match field_str(req, "format")? {
                "gate" => verify_gate_rows(&gate_rows_from(field(req, "rows")?)?),
                "verifylog" => verify_verifylog(field_str(req, "text")?),
                "tfx" => {
                    let anc = match req.get("anchor") {
                        None | Some(Value::Null) => None,
                        Some(a) => Some(a),
                    };
                    verify_tfx(field_str(req, "text")?, anc)?
                }
                "chap" => {
                    let e = field(req, "entries")?.as_array().ok_or_else(|| Error::new("\"entries\" must be a list"))?;
                    verify_chap(e)
                }
                "vdecl-receipt" => verify_vdecl_receipt(field(req, "receipt")?, field_str(req, "pubkey")?)?,
                "vdecl-seal" => verify_vdecl_seal(field(req, "seal")?, field_str(req, "pubkey")?)?,
                other => return Err(Error::new(alloc::format!("unknown format \"{}\"", other))),
            };
            Ok(v.to_value())
        }
        other => Err(Error::new(alloc::format!("unknown op \"{}\"", other))),
    }
}

/// The single entry point. Never panics on bad input: errors come back as
/// {"ok":false,"error":"..."}.
pub fn call_json(input: &str) -> String {
    let res = parse(input).and_then(|req| dispatch(&req));
    match res {
        Ok(v) => out(&v),
        Err(e) => out(&obj(vec![("ok", Value::Bool(false)), ("error", Value::Str(e.0))])),
    }
}
