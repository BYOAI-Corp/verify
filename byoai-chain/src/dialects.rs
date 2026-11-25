//! The five BYOAI receipt/chain formats, reproduced from their Python sources:
//!
//! | name       | source (kit)                                   | link / signed bytes                                   |
//! |------------|------------------------------------------------|-------------------------------------------------------|
//! | `gate`     | byoai-gate 0.1.0 `byoai_gate/store.py`         | sha256(prev + "\n" + body_text), body = canon UTF-8   |
//! | `verifylog`| byoaiverify-kit 0.1.0 `gateway/byoai_gateway.py`| sha256(prev + canon_ascii(rec without "hash"))       |
//! | `tfx`      | byoai_tfx 0.1.0 `tfx_v0_1_0_2026-10-30.py`     | row_sha = sha256(canon UTF-8(row without "row_sha"))  |
//! | `chap`     | custody-kit 0.1.0 + chap_coordinator 0.2.13    | sha256(JCS(envelope) + prev), Ed25519 over JCS(env-sig)|
//! | `vdecl`    | verified-declaration 0.1.1 `vdecl_v0_1_1.py`   | Ed25519 over canon UTF-8({"body","tsa"}) / (seal rec) |

#![forbid(unsafe_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::value::{chap_canon, dumps, DumpOpts, Error, Result, Value};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const CHAP_ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
pub fn canon_u8(v: &Value) -> String {
    dumps(v, &DumpOpts::canon(false))
}

/// `json.dumps(v, sort_keys=True, separators=(",", ":"))` (ensure_ascii default True)
pub fn canon_ascii(v: &Value) -> String {
    dumps(v, &DumpOpts::canon(true))
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainReport {
    pub ok: bool,
    pub rows: usize,
    pub head: String,
    pub problems: Vec<String>,
}

fn report(ok: bool, rows: usize, head: String, problems: Vec<String>) -> ChainReport {
    ChainReport { ok, rows, head, problems }
}

// ------------------------------------------------------------------ gate

pub fn gate_link(prev: &str, body_text: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(body_text.as_bytes());
    hex::encode(h.finalize())
}

pub struct GateRow {
    pub seq: i64,
    pub body: String,
    pub prev: String,
    pub hash: String,
}

/// Mirrors `Store.verify()`: same checks, same order, same problem text.
pub fn gate_verify(rows: &[GateRow]) -> ChainReport {
    let (mut prev, mut n, mut expect) = (String::from(GENESIS), 0usize, 1i64);
    for r in rows {
        if r.seq != expect {
            return report(false, n, prev, vec![format!("gap: expected seq {}, found {}", expect, r.seq)]);
        }
        if r.prev != prev {
            return report(false, n, prev, vec![format!("seq {}: prev link broken", r.seq)]);
        }
        let parsed = match crate::value::parse(&r.body) {
            Ok(v) => v,
            Err(_) => return report(false, n, prev, vec![format!("seq {}: body not JSON", r.seq)]),
        };
        if !parsed.get("seq").map(|s| s.eq_int(r.seq)).unwrap_or(false) {
            return report(false, n, prev, vec![format!("seq {}: body seq mismatch", r.seq)]);
        }
        if gate_link(&prev, &r.body) != r.hash {
            return report(false, n, prev, vec![format!("seq {}: hash mismatch (row edited)", r.seq)]);
        }
        prev = r.hash.clone();
        n += 1;
        expect += 1;
    }
    report(true, n, prev, vec![])
}

// ------------------------------------------------------------------ verifylog (byoaiverify)

pub fn verifylog_entry_hash(prev: &str, rec_without_hash: &Value) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(canon_ascii(rec_without_hash).as_bytes());
    hex::encode(h.finalize())
}

/// Python `str.splitlines()` line boundaries.
pub fn py_splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(
            c,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        );
        if brk {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = it.peek() {
                    it.next();
                    end = j + 1;
                }
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Mirrors `verify_chain(path)` on the file text: returns (ok, count, first_bad_line).
pub fn verifylog_verify(text: &str) -> (bool, usize, Option<usize>, String) {
    let lines: Vec<&str> = py_splitlines(text).into_iter().filter(|l| !l.trim().is_empty()).collect();
    let mut prev = String::from(GENESIS);
    for (idx, line) in lines.iter().enumerate() {
        let i = idx + 1;
        let rec = match crate::value::parse(line) {
            Ok(v) => v,
            Err(_) => return (false, i - 1, Some(i), prev),
        };
        if rec.get("prev").and_then(|p| p.as_str()) != Some(prev.as_str()) {
            return (false, i - 1, Some(i), prev);
        }
        let h = verifylog_entry_hash(&prev, &rec.without("hash"));
        if rec.get("hash").and_then(|p| p.as_str()) != Some(h.as_str()) {
            return (false, i - 1, Some(i), prev);
        }
        prev = h;
    }
    (true, lines.len(), None, prev)
}

// ------------------------------------------------------------------ tfx

pub fn tfx_row_sha(row_without_sha: &Value) -> String {
    sha256_hex(canon_u8(row_without_sha).as_bytes())
}

/// Mirrors `check_chain(rows, anc)`: (ok, first_bad_index).
pub fn tfx_check(rows: &[Value], anchor: Option<&Value>) -> (bool, Option<usize>, String) {
    let mut prev = String::from(GENESIS);
    for (i, r) in rows.iter().enumerate() {
        let body = r.without("row_sha");
        let seq_ok = r.get("seq").map(|s| s.eq_int(i as i64)).unwrap_or(false);
        let prev_ok = r.get("prev_sha").and_then(|p| p.as_str()) == Some(prev.as_str());
        let sha = tfx_row_sha(&body);
        let sha_ok = r.get("row_sha").and_then(|p| p.as_str()) == Some(sha.as_str());
        if !(seq_ok && prev_ok && sha_ok) {
            return (false, Some(i), prev);
        }
        prev = sha;
    }
    if let Some(a) = anchor {
        let rows_ok = a.get("rows").map(|n| n.eq_int(rows.len() as i64)).unwrap_or(false);
        let head_ok = a.get("head").and_then(|h| h.as_str()) == Some(prev.as_str());
        if !(rows_ok && head_ok) {
            return (false, Some(rows.len()), prev);
        }
    }
    (true, None, prev)
}

// ------------------------------------------------------------------ chap (custody)

pub fn chap_sha256(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

/// `_link_hash(envelope, prev)` = sha256( JCS(envelope) || prev )
pub fn chap_link(envelope: &Value, prev: &str) -> Result<String> {
    let mut b = chap_canon(envelope)?.into_bytes();
    b.extend_from_slice(prev.as_bytes());
    Ok(chap_sha256(&b))
}

/// chap_coordinator `verify(canonical_bytes, sig, public_key)`
pub fn chap_sig_verify(canonical: &[u8], sig: &str, pubkey: &VerifyingKey) -> bool {
    let Some(raw) = sig.strip_prefix("ed25519:") else { return false };
    let raw = if raw.contains(':') { raw.rsplit(':').next().unwrap_or("") } else { raw };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(raw) else { return false };
    let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else { return false };
    pubkey.verify(canonical, &Signature::from_bytes(&arr)).is_ok()
}

fn jwk_pub(jwk: &Value) -> Option<VerifyingKey> {
    let x = jwk.get("x")?.as_str()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x.trim_end_matches('=')).ok()?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn py_str_of(v: Option<&Value>) -> String {
    // Python f"{x}" == str(x). Lists and dicts fall back to canonical JSON (not used by CHAP seq/from).
    match v {
        Some(Value::Int(s)) | Some(Value::Str(s)) => s.clone(),
        Some(Value::Float(f)) => crate::value::py_float_repr(*f),
        Some(Value::Bool(b)) => String::from(if *b { "True" } else { "False" }),
        Some(Value::Null) | None => String::from("None"),
        Some(other) => canon_u8(other),
    }
}

/// Steps 1 (chain) and 2 (signatures) of custody `verify_export`, same problem text.
/// Step 3 (custody semantics) stays in the custody kit: it is business logic, not chain logic.
pub fn chap_verify_export(entries: &[Value]) -> ChainReport {
    let mut problems = Vec::new();
    let mut prev = String::from(CHAP_ZERO_HASH);
    for e in entries {
        if e.get("prev_hash").and_then(|p| p.as_str()) != Some(prev.as_str()) {
            problems.push(format!("seq {}: chain link broken", py_str_of(e.get("seq"))));
        }
        let env = e.get("envelope").cloned().unwrap_or(Value::Null);
        match chap_link(&env, &prev) {
            Ok(h) => prev = h,
            Err(err) => {
                problems.push(format!("seq {}: {}", py_str_of(e.get("seq")), err));
                return report(false, entries.len(), prev, problems);
            }
        }
    }
    let mut keys: Vec<((String, String), VerifyingKey)> = Vec::new();
    let empty = Value::Object(Vec::new());
    for e in entries {
        let env = e.get("envelope").unwrap_or(&empty);
        let p = env.get("params").unwrap_or(&empty);
        let m = env.get("method").and_then(|m| m.as_str()).unwrap_or("");
        if m == "participant.join" {
            let from = p.get("from").and_then(|f| f.as_str()).unwrap_or("").to_string();
            if let Some(ks) = p.get("jwks").and_then(|j| j.get("keys")).and_then(|k| k.as_array()) {
                for k in ks {
                    if let (Some(kid), Some(pk)) = (k.get("kid").and_then(|x| x.as_str()), jwk_pub(k)) {
                        let key = (from.clone(), kid.to_string());
                        if let Some(slot) = keys.iter_mut().find(|(kk, _)| *kk == key) {
                            slot.1 = pk;
                        } else {
                            keys.push((key, pk));
                        }
                    }
                }
            }
            continue;
        }
        if m == "workspace.create" {
            continue;
        }
        let sig = env.get("sig").and_then(|s| s.as_str()).unwrap_or("");
        let kid = if sig.matches(':').count() >= 2 { sig.split(':').nth(1) } else { None };
        let from = p.get("from").and_then(|f| f.as_str()).unwrap_or("");
        let pubk = kid.and_then(|kid| keys.iter().find(|((f, k), _)| f == from && k == kid).map(|(_, v)| v));
        let stripped = env.without("sig");
        let ok = match (pubk, chap_canon(&stripped)) {
            (Some(pk), Ok(c)) => chap_sig_verify(c.as_bytes(), sig, pk),
            _ => false,
        };
        if !ok {
            problems.push(format!(
                "seq {}: {} signature does not verify for {}",
                py_str_of(e.get("seq")),
                m,
                py_str_of(p.get("from"))
            ));
        }
    }
    report(problems.is_empty(), entries.len(), prev, problems)
}

// ------------------------------------------------------------------ vdecl

fn pub_from_hex(h: &str) -> Result<VerifyingKey> {
    let b = hex::decode(h.trim()).map_err(|_| Error::new("bad public key hex"))?;
    let arr = <[u8; 32]>::try_from(b.as_slice()).map_err(|_| Error::new("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| Error::new("invalid Ed25519 public key"))
}

fn sig_from_hex(h: &str) -> Option<Signature> {
    let b = hex::decode(h).ok()?;
    let arr = <[u8; 64]>::try_from(b.as_slice()).ok()?;
    Some(Signature::from_bytes(&arr))
}

/// Bytes the receipt signature covers: canon({"body": body, "tsa": tsa}).
pub fn vdecl_receipt_message(receipt: &Value) -> String {
    let empty = Value::Object(Vec::new());
    let msg = Value::Object(vec![
        (String::from("body"), receipt.get("body").cloned().unwrap_or(empty.clone())),
        (String::from("tsa"), receipt.get("tsa").cloned().unwrap_or(empty)),
    ]);
    canon_u8(&msg)
}

/// sha256_hex(canon(body)), the digest the RFC 3161 token must carry.
pub fn vdecl_body_digest(receipt: &Value) -> String {
    let empty = Value::Object(Vec::new());
    sha256_hex(canon_u8(receipt.get("body").unwrap_or(&empty)).as_bytes())
}

/// `_receipt_bytes(receipt)`: json.dumps(receipt, indent=2, ensure_ascii=False)
pub fn vdecl_receipt_bytes(receipt: &Value) -> String {
    dumps(receipt, &DumpOpts { ensure_ascii: false, sort_keys: false, indent: Some(2), compact: false })
}

fn sig_ok(pk: &VerifyingKey, msg: &[u8], sig: Option<&Value>) -> bool {
    let hexsig = sig.and_then(|s| s.get("sig_hex")).and_then(|h| h.as_str()).unwrap_or("");
    match sig_from_hex(hexsig) {
        Some(s) => pk.verify(msg, &s).is_ok(),
        None => false,
    }
}

/// SIGNATURE gate + TSA digest match of `verify_receipt` (document, wording and TSA token
/// checks need the document text and openssl and stay in the vdecl kit).
pub fn vdecl_verify_receipt(receipt: &Value, pubkey_hex: &str) -> Result<(bool, bool)> {
    let pk = pub_from_hex(pubkey_hex)?;
    let sig = sig_ok(&pk, vdecl_receipt_message(receipt).as_bytes(), receipt.get("sig"));
    let digest = vdecl_body_digest(receipt);
    let tsa_digest = receipt.get("tsa").and_then(|t| t.get("digest")).and_then(|d| d.as_str()) == Some(digest.as_str());
    Ok((sig, tsa_digest))
}

/// SEAL_SIGNATURE gate of `verify_seal`: Ed25519 over canon(seal["seal"]).
pub fn vdecl_verify_seal(seal: &Value, pubkey_hex: &str) -> Result<bool> {
    let pk = pub_from_hex(pubkey_hex)?;
    let empty = Value::Object(Vec::new());
    let msg = canon_u8(seal.get("seal").unwrap_or(&empty));
    Ok(sig_ok(&pk, msg.as_bytes(), seal.get("sig")))
}

// ------------------------------------------------------------------ Ed25519 helpers

/// Deterministic Ed25519 (RFC 8032): same seed + message => same 64 bytes as `cryptography`.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(pk) => pk.verify(msg, &Signature::from_bytes(sig)).is_ok(),
        Err(_) => false,
    }
}
