//! byoai-chain CLI.
//!
//!   byoai-chain verify --format gate          <audit.db>
//!   byoai-chain verify --format verifylog     <calls.jsonl>
//!   byoai-chain verify --format tfx           <ledger.jsonl> [--anchor <anchor.json>]
//!   byoai-chain verify --format chap          <chain_export.json>
//!   byoai-chain verify --format vdecl-receipt <receipt.json> --pubkey <hex>
//!   byoai-chain verify --format vdecl-seal    <seal.json>    --pubkey <hex>
//!   byoai-chain canon  --dialect py-u8|py-ascii|chap|py-indent2 [<file>|-]
//!   byoai-chain call   (one JSON request on stdin, JSON response on stdout)
//!   byoai-chain version
//!
//! Add --json to verify for a machine-readable verdict.
//! Exit: 0 verified, 1 not verified, 2 usage or input error.
use std::io::Read;
use std::process::exit;

use byoai_chain::api;
use byoai_chain::dialects::GateRow;
use byoai_chain::value::parse;

fn die(msg: &str) -> ! {
    eprintln!("byoai-chain: {}", msg);
    exit(2)
}

fn read_text(path: &str) -> String {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).unwrap_or_else(|e| die(&e.to_string()));
        return s;
    }
    let b = std::fs::read(path).unwrap_or_else(|e| die(&format!("{}: {}", path, e)));
    String::from_utf8(b).unwrap_or_else(|_| die(&format!("{}: not UTF-8", path)))
}

fn read_gate(path: &str) -> Vec<GateRow> {
    use rusqlite::{Connection, OpenFlags};
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap_or_else(|e| die(&format!("{}: {}", path, e)));
    let mut st = db
        .prepare("SELECT seq, body, prev, hash FROM audit ORDER BY seq")
        .unwrap_or_else(|e| die(&e.to_string()));
    let it = st
        .query_map([], |r| Ok(GateRow { seq: r.get(0)?, body: r.get(1)?, prev: r.get(2)?, hash: r.get(3)? }))
        .unwrap_or_else(|e| die(&e.to_string()));
    it.map(|r| r.unwrap_or_else(|e| die(&e.to_string()))).collect()
}

struct Args {
    pos: Vec<String>,
    format: Option<String>,
    dialect: Option<String>,
    anchor: Option<String>,
    pubkey: Option<String>,
    json: bool,
}

fn parse_args(raw: &[String]) -> Args {
    let mut a = Args { pos: vec![], format: None, dialect: None, anchor: None, pubkey: None, json: false };
    let mut i = 0;
    while i < raw.len() {
        let take = |i: &mut usize| -> String {
            *i += 1;
            raw.get(*i).cloned().unwrap_or_else(|| die(&format!("{} needs a value", raw[*i - 1])))
        };
        match raw[i].as_str() {
            "--format" | "-f" => a.format = Some(take(&mut i)),
            "--dialect" | "-d" => a.dialect = Some(take(&mut i)),
            "--anchor" => a.anchor = Some(take(&mut i)),
            "--pubkey" => a.pubkey = Some(take(&mut i)),
            "--json" => a.json = true,
            x => a.pos.push(x.to_string()),
        }
        i += 1;
    }
    a
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = raw.first().cloned() else { die("usage: byoai-chain verify|canon|call|version (see --help)") };
    let a = parse_args(&raw[1..]);
    match cmd.as_str() {
        "version" | "--version" => println!("byoai-chain {}", byoai_chain::VERSION),
        "call" => println!("{}", api::call_json(&read_text("-"))),
        "canon" => {
            let d = a.dialect.as_deref().unwrap_or_else(|| die("canon needs --dialect"));
            let src = read_text(a.pos.first().map(|s| s.as_str()).unwrap_or("-"));
            match api::canon_text(d, &src) {
                Ok(c) => print!("{}", c),
                Err(e) => die(&e.0),
            }
        }
        "verify" => {
            let f = a.format.as_deref().unwrap_or_else(|| die("verify needs --format"));
            let path = a.pos.first().map(|s| s.as_str()).unwrap_or_else(|| die("verify needs a file"));
            let pubkey = || a.pubkey.clone().unwrap_or_else(|| die("this format needs --pubkey <hex>"));
            let doc = |p: &str| parse(&read_text(p)).unwrap_or_else(|e| die(&format!("{}: {}", p, e.0)));
            let res = match f {
                "gate" => Ok(api::verify_gate_rows(&read_gate(path))),
                "verifylog" => Ok(api::verify_verifylog(&read_text(path))),
                "tfx" => {
                    let anc = a.anchor.as_deref().map(doc);
                    if anc.is_none() && !a.json {
                        println!("WARN no anchor given: tail truncation cannot be detected");
                    }
                    api::verify_tfx(&read_text(path), anc.as_ref())
                }
                "chap" => {
                    let v = doc(path);
                    match v.as_array() {
                        Some(e) => Ok(api::verify_chap(e)),
                        None => die("chap export must be a JSON list of entries"),
                    }
                }
                "vdecl-receipt" => api::verify_vdecl_receipt(&doc(path), &pubkey()),
                "vdecl-seal" => api::verify_vdecl_seal(&doc(path), &pubkey()),
                other => die(&format!("unknown --format {}", other)),
            };
            let v = res.unwrap_or_else(|e| die(&e.0));
            if a.json {
                println!("{}", byoai_chain::value::dumps(&v.to_value(), &byoai_chain::value::DumpOpts::canon(false)));
            } else {
                println!(
                    "{} format={} rows={} head={}",
                    if v.ok { "CHAIN_OK" } else { "CHAIN_BROKEN" },
                    v.format,
                    v.rows,
                    v.head
                );
                for p in &v.problems {
                    println!("  {}", p);
                }
            }
            exit(if v.ok { 0 } else { 1 })
        }
        "-h" | "--help" | "help" => println!("{}", include_str!("main.rs").lines().take_while(|l| l.starts_with("//!")).map(|l| l.trim_start_matches("//!")).collect::<Vec<_>>().join("\n")),
        other => die(&format!("unknown command {}", other)),
    }
}
