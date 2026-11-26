//! byoai-chain CLI.
//!
//!   byoai-chain verify --format gate          <audit.db>
//!   byoai-chain verify --format verifylog     <calls.jsonl>
//!   byoai-chain verify --format tfx           <ledger.jsonl> [--anchor <anchor.json>]
//!   byoai-chain verify --format chap          <chain_export.json>
//!   byoai-chain verify --format vdecl-receipt <receipt.json> --pubkey <hex>
//!   byoai-chain verify --format vdecl-seal    <seal.json>    --pubkey <hex>
//!   byoai-chain verify --format handoff       <handoff.json> --pubkey <hex> [--sources <dir>] [--require-rederive]
//!   byoai-chain taint  <handoff.json> --pubkey <hex> --revoked <revoked.json>
//!   byoai-chain handoff mint --steps <steps.jsonl> --case <ref> --analyst <name> --key <key.pem> --out <handoff.json> [--sources <dir>]
//!   byoai-chain canon  --dialect py-u8|py-ascii|chap|py-indent2 [<file>|-]
//!   byoai-chain call   (one JSON request on stdin, JSON response on stdout)
//!   byoai-chain version
//!
//! Add --json to verify, taint and handoff mint for one machine-readable JSON object.
//! Exit: 0 verified, 1 not verified (or tainted), 2 usage or input error.
//!
//! handoff (byoai.handoff/0.1): a case handoff receipt. Each step line in steps.jsonl holds
//! action, tool, sources [{ref, sha256, fetched_at}], products [{ref, sha256}], depends_on [earlier
//! step numbers] and checked_at (UTC YYYY-MM-DDTHH:MM:SSZ). With --sources, a missing sha256 is
//! hashed from <dir>/<ref>. The key is an Ed25519 PKCS#8 PEM, mode 600 (openssl genpkey -algorithm
//! ed25519). verify --sources re-hashes every ref it finds: VERIFIED, UNGROUNDED (hash differs) or
//! UNCHECKED (not present or not safely readable); --sources requires every item re-derived.
//! revoked.json is {"sources": [sha256...], "steps": [n...]}; a sha names a file wherever it
//! appears (source or product). The handoff CLI is Unix-only (openat, O_NOFOLLOW, file modes).
#![forbid(unsafe_code)]
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
    sources: Option<String>,
    require_rederive: bool,
    revoked: Option<String>,
    steps: Option<String>,
    case: Option<String>,
    analyst: Option<String>,
    key: Option<String>,
    out: Option<String>,
}

fn parse_args(raw: &[String]) -> Args {
    let mut a = Args {
        pos: vec![],
        format: None,
        dialect: None,
        anchor: None,
        pubkey: None,
        json: false,
        sources: None,
        require_rederive: false,
        revoked: None,
        steps: None,
        case: None,
        analyst: None,
        key: None,
        out: None,
    };
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
            "--sources" => a.sources = Some(take(&mut i)),
            "--require-rederive" => a.require_rederive = true,
            "--revoked" => a.revoked = Some(take(&mut i)),
            "--steps" => a.steps = Some(take(&mut i)),
            "--case" => a.case = Some(take(&mut i)),
            "--analyst" => a.analyst = Some(take(&mut i)),
            "--key" => a.key = Some(take(&mut i)),
            "--out" => a.out = Some(take(&mut i)),
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
                "handoff" => {
                    let d = doc(path);
                    // --sources (or --require-rederive) asks for re-derivation: anything left UNCHECKED fails
                    let obs = match a.sources.as_deref() {
                        Some(dir) => Some(hx::observe(&d, dir)),
                        None if a.require_rederive => Some(Vec::new()),
                        None => None,
                    };
                    let r = byoai_chain::handoff::verify(&d, &pubkey(), obs.as_deref()).unwrap_or_else(|e| hx::die(&e.0));
                    let ok = r.ok;
                    if a.json {
                        println!("{}", hx::dump(&r.to_value()));
                    } else {
                        hx::print_report(&r);
                    }
                    exit(if ok { 0 } else { 1 })
                }
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
        "taint" => {
            let path = a.pos.first().map(|s| s.as_str()).unwrap_or_else(|| die("taint needs a handoff file"));
            let pk = a.pubkey.clone().unwrap_or_else(|| die("taint needs --pubkey <hex>"));
            let rv_path = a.revoked.as_deref().unwrap_or_else(|| die("taint needs --revoked <file>"));
            let d = parse(&read_text(path)).unwrap_or_else(|e| hx::die(&format!("{}: {}", path, e.0)));
            let rv = parse(&read_text(rv_path)).unwrap_or_else(|e| hx::die(&format!("{}: {}", rv_path, e.0)));
            let (rep, tainted) = byoai_chain::handoff::taint(&d, &pk, &rv).unwrap_or_else(|e| hx::die(&e.0));
            let v = byoai_chain::handoff::taint_value(&rep, &tainted);
            if a.json {
                println!("{}", hx::dump(&v));
            } else if !rep.ok {
                hx::print_report(&rep);
                println!("taint not computed: the handoff does not verify");
            } else if tainted.is_empty() {
                println!("CLEAN case={} rows={}: no step depends on the revoked items", hx::safe(&rep.case), rep.rows);
            } else {
                println!("TAINTED case={} rows={}: {} of {} steps", hx::safe(&rep.case), rep.rows, tainted.len(), rep.rows);
                for (n, why) in &tainted {
                    println!("  step {}: {}", n, hx::safe(&why.join(", ")));
                }
            }
            exit(if rep.ok && tainted.is_empty() { 0 } else { 1 })
        }
        "handoff" => match a.pos.first().map(|s| s.as_str()) {
            Some("mint") => hx::mint(&a),
            _ => die("usage: byoai-chain handoff mint --steps <steps.jsonl> --case <ref> --analyst <name> --key <key.pem> --out <file> [--sources <dir>]"),
        },
        "-h" | "--help" | "help" => println!("{}", include_str!("main.rs").lines().take_while(|l| l.starts_with("//!")).map(|l| l.trim_start_matches("//!")).collect::<Vec<_>>().join("\n")),
        other => die(&format!("unknown command {}", other)),
    }
}

/// CLI-only handoff helpers: file hashing, key loading, atomic write.
mod hx {
    use super::{exit, parse, read_text, Args};

    /// Exit 2 with a message that may quote text from a handoff or steps file, escaped.
    pub fn die(msg: &str) -> ! {
        super::die(&safe(msg))
    }
    use byoai_chain::handoff::{self, Report};
    use byoai_chain::value::{dumps, DumpOpts, Value};
    #[cfg(unix)]
    use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags};
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::path::Path;

    /// --json output of the handoff commands: ASCII-escaped, so no raw C1 or bidi character from
    /// a forged file reaches a terminal even in JSON (the existing formats keep their 0.1.0 output).
    pub fn dump(v: &Value) -> String {
        dumps(v, &DumpOpts::canon(true))
    }

    /// Text that came from a handoff file, made safe for a terminal: control and bidi characters
    /// are shown escaped (\u{1b}, \r ...) so a forged file cannot redraw or hide output lines.
    pub fn safe(s: &str) -> String {
        s.chars().map(|c| if handoff::is_unsafe_char(c) { c.escape_default().to_string() } else { c.to_string() }).collect()
    }

    /// Open <dir>/<ref> for reading without following any symlink on the way: every component is
    /// opened with O_NOFOLLOW relative to the one before (openat), and the last must be a regular
    /// file by fstat of the opened descriptor. Absolute refs and "..", "." are refused.
    #[cfg(unix)]
    fn open_inside(dir: &str, r: &str) -> Option<std::fs::File> {
        if !handoff::is_plain_ref(r) {
            return None;
        }
        let parts: Vec<&str> = r.split('/').collect();
        let (last, dirs) = parts.split_last()?;
        let mut cur = open(dir, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).ok()?;
        for d in dirs {
            cur = openat(&cur, *d, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).ok()?;
        }
        // Type-check before opening, so a device or FIFO is never opened; then open without
        // following links and confirm it is the same regular file that was checked.
        let pre = statat(&cur, *last, AtFlags::SYMLINK_NOFOLLOW).ok()?;
        if FileType::from_raw_mode(pre.st_mode) != FileType::RegularFile {
            return None;
        }
        let fd = openat(&cur, *last, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty()).ok()?;
        let st = fstat(&fd).ok()?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile || st.st_dev != pre.st_dev || st.st_ino != pre.st_ino {
            return None;
        }
        Some(std::fs::File::from(fd))
    }

    /// Windows: the same check as on Linux, done by byoai-winopen: every part is opened relative
    /// to the handle of the folder before it (NtCreateFile with RootDirectory and OBJ_DONT_REPARSE),
    /// a link of any kind on the way or at the end is refused, each name must be the exact stored
    /// name (not another case, not an 8.3 short name), and the last part must be a plain file.
    /// Absolute refs, "..", ".", '\\' and the characters Windows reserves (: * ? " < > |) are refused.
    #[cfg(windows)]
    fn open_inside(dir: &str, r: &str) -> Option<std::fs::File> {
        if !handoff::is_plain_ref(r) {
            return None;
        }
        let parts: Vec<&str> = r.split('/').collect();
        byoai_winopen::open_inside(std::path::Path::new(dir), &parts)
    }

    /// sha256 of <dir>/<ref>, or None when it cannot be opened safely or read (stays UNCHECKED).
    fn sha_inside(dir: &str, r: &str) -> Option<String> {
        let mut f = open_inside(dir, r)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Some(hex::encode(h.finalize()))
    }

    pub fn observe(doc: &Value, dir: &str) -> Vec<(String, String)> {
        if !Path::new(dir).is_dir() {
            die(&format!("--sources {}: not a folder", dir));
        }
        let mut out: Vec<(String, String)> = Vec::new();
        let empty = Value::Object(Vec::new());
        let steps = doc.get("handoff").unwrap_or(&empty).get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        for row in steps {
            for key in ["sources", "products"] {
                for it in row.get(key).and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                    if let Some(r) = it.get("ref").and_then(|v| v.as_str()) {
                        if out.iter().any(|(k, _)| k == r) {
                            continue;
                        }
                        if let Some(h) = sha_inside(dir, r) {
                            out.push((r.to_string(), h));
                        }
                    }
                }
            }
        }
        out
    }

    pub fn print_report(r: &Report) {
        let (v, u, c) = (r.count(handoff::VERIFIED), r.count(handoff::UNGROUNDED), r.count(handoff::UNCHECKED));
        let only_rederive = !r.problems.is_empty() && r.problems.iter().all(|p| p.starts_with("REDERIVE_INCOMPLETE"));
        let head = if r.ok && !r.rederive_required {
            "VERIFIED (integrity only: no source was re-derived)"
        } else if r.ok {
            "VERIFIED"
        } else if only_rederive {
            "NOT_VERIFIED (REDERIVE_INCOMPLETE)"
        } else {
            "NOT_VERIFIED"
        };
        println!("{} handoff case={} rows={} head={} sources: {} verified, {} ungrounded, {} unchecked", head, safe(&r.case), r.rows, safe(&r.head), v, u, c);
        for p in &r.problems {
            println!("  {}", safe(p));
        }
        for i in &r.items {
            println!("  {:<10} step {} {} {}", i.label, i.seq, i.role, safe(&i.r#ref));
        }
    }

    fn utc_now() -> String {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_else(|_| die("clock before 1970")).as_secs() as i64;
        let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
        // civil_from_days (Howard Hinnant)
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
    }

    fn load_seed(path: &str) -> [u8; 32] {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let md = std::fs::metadata(path).unwrap_or_else(|e| die(&format!("{}: {}", path, e)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if md.permissions().mode() & 0o077 != 0 {
                die(&format!("{}: private key must be mode 600 (chmod 600 {})", path, path));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = md;
            eprintln!("KEY_PERMISSIONS_UNCHECKED {}: Windows file permissions (ACLs) are not checked; keep the key where only you can read it", safe(path));
        }
        let pem = read_text(path);
        let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(&pem).unwrap_or_else(|_| die(&format!("{}: not an Ed25519 PKCS#8 PEM private key", path)));
        sk.to_bytes()
    }

    /// Fill a missing sha256 from <dir>/<ref>; refuse a stated sha256 that is not a string or that
    /// differs from the file in <dir>.
    fn fill_hashes(step: &mut Value, dir: Option<&str>) {
        let Value::Object(fields) = step else { die("each step line must be a JSON object") };
        for (k, v) in fields.iter_mut() {
            if k != "sources" && k != "products" {
                continue;
            }
            let Value::Array(list) = v else { continue };
            for it in list.iter_mut() {
                let Value::Object(f) = it else { continue };
                let r = f.iter().find(|(k, _)| k == "ref").and_then(|(_, v)| v.as_str()).unwrap_or("").to_string();
                let stated = match f.iter().find(|(k, _)| k == "sha256") {
                    None => None,
                    Some((_, Value::Str(s))) if !s.is_empty() => Some(s.clone()),
                    Some(_) => die(&format!("\"{}\": sha256 must be a non-empty string", r)),
                };
                let seen = dir.and_then(|d| sha_inside(d, &r));
                match (stated, seen) {
                    (Some(s), Some(h)) if s != h => die(&format!("STATED_SHA_MISMATCH: \"{}\" is stated as {} but the file in --sources hashes to {}", r, s, h)),
                    (Some(_), _) => {}
                    (None, Some(h)) => Value::obj_insert(f, "sha256".to_string(), Value::Str(h)),
                    (None, None) => die(&format!("\"{}\" has no sha256 and is not a regular file inside --sources", r)),
                }
            }
        }
    }

    /// Write `text` to `out` only if `out` does not exist, atomically: temp file, fsync, then
    /// hard_link (fails if `out` appeared meanwhile, never replaces it), then drop the temp name.
    fn write_new(out: &Path, text: &str) -> Result<(), String> {
        let dir = out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let tmp = dir.join(format!(".{}.tmp{}", out.file_name().and_then(|n| n.to_str()).unwrap_or("handoff"), std::process::id()));
        let res = (|| -> Result<(), String> {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e| format!("{}: {}", tmp.display(), e))?;
            f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            std::fs::hard_link(&tmp, out).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    format!("{}: exists; refusing to overwrite", out.display())
                } else {
                    // the output is published with a hard link so it can never overwrite a file;
                    // FAT and exFAT drives (most USB sticks) and some network shares have none
                    format!("{}: {} (the output folder must allow hard links: FAT/exFAT drives and some network shares do not; write to a local NTFS, ext4 or similar folder)", out.display(), e)
                }
            })
        })();
        let _ = std::fs::remove_file(&tmp);
        res
    }

    pub fn mint(a: &Args) -> ! {
        let need = |o: &Option<String>, n: &str| o.clone().unwrap_or_else(|| die(&format!("handoff mint needs {}", n)));
        let (steps_p, case, analyst, key_p, out_p) = (need(&a.steps, "--steps"), need(&a.case, "--case"), need(&a.analyst, "--analyst"), need(&a.key, "--key"), need(&a.out, "--out"));
        let out = Path::new(&out_p);
        if std::fs::symlink_metadata(out).is_ok() {
            die(&format!("{}: exists; refusing to overwrite", out_p));
        }
        if let Some(d) = a.sources.as_deref() {
            if !Path::new(d).is_dir() {
                die(&format!("--sources {}: not a folder", d));
            }
        }
        let mut steps = Vec::new();
        for (n, line) in read_text(&steps_p).split('\n').enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut v = parse(line).unwrap_or_else(|e| die(&format!("{} line {}: {}", steps_p, n + 1, e.0)));
            fill_hashes(&mut v, a.sources.as_deref());
            steps.push(v);
        }
        let seed = load_seed(&key_p);
        let doc = handoff::build(&case, &analyst, &utc_now(), &steps, &seed).unwrap_or_else(|e| die(&e.0));
        let pubkey = hex::encode(byoai_chain::dialects::ed25519_public(&seed));
        let rep = handoff::verify(&doc, &pubkey, None).unwrap_or_else(|e| die(&e.0));
        if !rep.ok {
            println!("NOT_VERIFIED: the minted handoff failed its own check; nothing written");
            for p in &rep.problems {
                println!("  {}", safe(p));
            }
            exit(1)
        }
        let text = format!("{}\n", dumps(&doc, &DumpOpts { ensure_ascii: false, sort_keys: true, indent: Some(2), compact: false }));
        write_new(out, &text).unwrap_or_else(|e| die(&e));
        let pid = doc.get("pid").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if a.json {
            let v = Value::Object(vec![
                ("ok".to_string(), Value::Bool(true)),
                ("out".to_string(), Value::Str(out_p.clone())),
                ("case".to_string(), Value::Str(case.clone())),
                ("rows".to_string(), Value::Int(rep.rows.to_string())),
                ("head".to_string(), Value::Str(rep.head.clone())),
                ("pid".to_string(), Value::Str(pid)),
                ("pubkey".to_string(), Value::Str(pubkey)),
            ]);
            println!("{}", dump(&v));
        } else {
            println!("MINTED {} case={} rows={} head={} pid={} pubkey={}", safe(&out_p), safe(&case), rep.rows, rep.head, pid, pubkey);
        }
        exit(0)
    }
}
