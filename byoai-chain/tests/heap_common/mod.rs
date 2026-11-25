//! Shared requests for the heap tests: a properly signed handoff, then the same verify and taint
//! calls the 0.1.0 proof ran under valgrind (success paths, a tampered doc, an unmatched
//! revocation, and a malformed request).
#![forbid(unsafe_code)]

use byoai_chain::handoff;
use byoai_chain::value::{dumps, parse, DumpOpts};

const SEED: [u8; 32] = [7u8; 32];
const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

pub fn requests() -> Vec<String> {
    let lines = [
        format!(r#"{{"action":"lookup","tool":"whois","sources":[{{"ref":"a.txt","sha256":"{A}","fetched_at":"2026-11-25T10:00:00Z"}}],"products":[{{"ref":"p0.txt","sha256":"{C}"}}],"depends_on":[],"checked_at":"2026-11-25T10:05:00Z"}}"#),
        format!(r#"{{"action":"match","tool":"grep","sources":[{{"ref":"p0.txt","sha256":"{C}","fetched_at":"2026-11-25T10:05:00Z"}}],"products":[],"depends_on":[],"checked_at":"2026-11-25T10:06:00Z"}}"#),
        format!(r#"{{"action":"note","tool":"editor","sources":[{{"ref":"b.txt","sha256":"{B}","fetched_at":"2026-11-25T10:01:00Z"}}],"products":[],"depends_on":[0],"checked_at":"2026-11-25T10:07:00Z"}}"#),
    ];
    let steps: Vec<_> = lines.iter().map(|l| parse(l).expect("step json")).collect();
    let doc = handoff::build("CASE-HEAP", "analyst", "2026-11-25T11:00:00Z", &steps, &SEED).expect("build");
    let d = dumps(&doc, &DumpOpts::canon(false));
    let pk = hex::encode(byoai_chain::dialects::ed25519_public(&SEED));
    let tampered = d.replacen("lookup", "lookups", 1);
    assert_ne!(tampered, d, "the tampered fixture must really differ");
    vec![
        format!(r#"{{"op":"verify","format":"handoff","doc":{d},"pubkey":"{pk}","observed":{{"a.txt":"{A}","p0.txt":"{C}","b.txt":"{B}"}}}}"#),
        format!(r#"{{"op":"verify","format":"handoff","doc":{d},"pubkey":"{pk}","observed":{{"a.txt":"{A}"}}}}"#),
        format!(r#"{{"op":"verify","format":"handoff","doc":{d},"pubkey":"{pk}"}}"#),
        format!(r#"{{"op":"taint","doc":{d},"pubkey":"{pk}","revoked":{{"sources":["{A}"],"steps":[1]}}}}"#),
        format!(r#"{{"op":"taint","doc":{tampered},"pubkey":"{pk}","revoked":{{"steps":[1]}}}}"#),
        format!(r#"{{"op":"taint","doc":{d},"pubkey":"{pk}","revoked":{{"steps":[9]}}}}"#),
        r#"{"op":"verify","format":"handoff","doc":{"bad":1},"pubkey":"zz"}"#.to_string(),
    ]
}

/// Sanity check that the fixtures exercise what they claim: first call ok, tampered taint refused.
pub fn check_fixtures(reqs: &[String]) {
    let r0 = byoai_chain::call_json(&reqs[0]);
    assert!(r0.contains("\"ok\":true"), "verify with observed should be ok: {r0}");
    let r3 = byoai_chain::call_json(&reqs[4]);
    assert!(r3.contains("\"ok\":false"), "taint of a tampered doc should be refused: {r3}");
}
