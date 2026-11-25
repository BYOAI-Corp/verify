//! byoai-release: seal a BYOAI release and verify it.
//!
//!   byoai-release keygen --out <key file>
//!   byoai-release seal <folder> --key <key file> --repo <owner/name> --release <tag>
//!                 [--upstream <url>@<commit>]... [--check <name>=<result>]...
//!   byoai-release verify <folder> --pubkey <hex>
//!
//! A seal is two files written into the release folder:
//! - MANIFEST.sha256: one line per file, "<sha256>  <path>", sorted by path. Any
//!   `sha256sum -c MANIFEST.sha256` checks it.
//! - RECEIPT.json: {"seal": {...}, "sig": {"alg": "ed25519", "sig_hex": ...}}. The seal names
//!   the repository, the release, the manifest's sha256, where the content came from, and the
//!   checks it passed. The signature is Ed25519 over the seal in byoai-chain's "py-u8" canonical
//!   form, so `byoai-chain verify --format vdecl-seal RECEIPT.json --pubkey <hex>` checks it too.
//!
//! The private key never leaves the machine that seals. Verifying needs only the public key.
//! Exit: 0 done / verified, 1 not verified, 2 usage or input error.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use byoai_chain::dialects::{canon_u8, ed25519_public, ed25519_sign, sha256_hex, vdecl_verify_seal};
use byoai_chain::value::{self, Value};

const FORMAT: &str = "byoai.release/0.1";
const MANIFEST: &str = "MANIFEST.sha256";
const RECEIPT: &str = "RECEIPT.json";

fn die(code: i32, msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(code)
}

fn s(x: &str) -> Value {
    Value::Str(x.to_string())
}

fn obj(items: Vec<(&str, Value)>) -> Value {
    Value::Object(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Every file under `root`, as sorted relative paths with '/' separators. Skips .git and the
/// two seal files. Refuses links and anything that is not a plain file or folder.
fn files(root: &Path) -> Result<Vec<String>, String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), String> {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if rel == ".git" || rel == MANIFEST || rel == RECEIPT {
                continue;
            }
            let m = fs::symlink_metadata(&p).map_err(|e| format!("{rel}: {e}"))?;
            if m.file_type().is_symlink() {
                return Err(format!("{rel} is a link; a release holds plain files only"));
            } else if m.is_dir() {
                walk(root, &p, out)?;
            } else if m.is_file() {
                if rel.contains('\n') || rel.contains("  ") {
                    return Err(format!("{rel:?}: a file name with a line break or two spaces cannot go in the manifest"));
                }
                out.push(rel);
            } else {
                return Err(format!("{rel} is not a plain file"));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort();
    if out.is_empty() {
        return Err(format!("{} holds no files", root.display()));
    }
    Ok(out)
}

fn manifest_text(root: &Path) -> Result<(String, usize), String> {
    let list = files(root)?;
    let mut text = String::new();
    for rel in &list {
        let bytes = fs::read(root.join(rel)).map_err(|e| format!("{rel}: {e}"))?;
        text.push_str(&format!("{}  {}\n", sha256_hex(&bytes), rel));
    }
    Ok((text, list.len()))
}

fn read_key(path: &Path) -> [u8; 32] {
    let t = fs::read_to_string(path).unwrap_or_else(|e| die(2, &format!("cannot read the key {}: {e}", path.display())));
    let b = hex::decode(t.trim()).unwrap_or_else(|_| die(2, "the key file is not hex"));
    b.try_into().unwrap_or_else(|_| die(2, "the key file must hold 32 bytes (64 hex characters)"))
}

struct Args {
    pos: Vec<String>,
    opts: BTreeMap<String, Vec<String>>,
}

fn args(raw: &[String]) -> Args {
    let mut pos = Vec::new();
    let mut opts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut i = 0;
    while i < raw.len() {
        if let Some(k) = raw[i].strip_prefix("--") {
            let v = raw.get(i + 1).cloned().unwrap_or_else(|| die(2, &format!("--{k} needs a value")));
            opts.entry(k.to_string()).or_default().push(v);
            i += 2;
        } else {
            pos.push(raw[i].clone());
            i += 1;
        }
    }
    Args { pos, opts }
}

fn one(a: &Args, k: &str) -> String {
    match a.opts.get(k).map(|v| v.as_slice()) {
        Some([v]) => v.clone(),
        Some(_) => die(2, &format!("--{k} given more than once")),
        None => die(2, &format!("--{k} is required")),
    }
}

fn keygen(a: &Args) {
    let out = PathBuf::from(one(a, "out"));
    if out.exists() {
        die(2, &format!("{} exists already; a signing key is never overwritten", out.display()));
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap_or_else(|e| die(2, &format!("no randomness: {e}")));
    {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        o.mode(0o600);
        let mut f = o.open(&out).unwrap_or_else(|e| die(2, &format!("cannot write {}: {e}", out.display())));
        f.write_all(format!("{}\n", hex::encode(seed)).as_bytes()).unwrap();
    }
    println!("KEYGEN_OK private key in {} (owner only; never shared)", out.display());
    println!("PUBKEY {}", hex::encode(ed25519_public(&seed)));
}

fn seal(a: &Args) {
    let root = PathBuf::from(a.pos.get(1).cloned().unwrap_or_else(|| die(2, "usage: seal <folder> --key <file> --repo <owner/name> --release <tag>")));
    let seed = read_key(Path::new(&one(a, "key")));
    let repo = one(a, "repo");
    let release = one(a, "release");
    let (text, n) = manifest_text(&root).unwrap_or_else(|e| die(2, &e));
    let upstream: Vec<Value> = a
        .opts
        .get("upstream")
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|u| match u.rsplit_once('@') {
            Some((url, commit)) if !url.is_empty() && !commit.is_empty() => obj(vec![("source", s(url)), ("commit", s(commit))]),
            _ => die(2, &format!("--upstream {u:?} must be <url>@<commit>")),
        })
        .collect();
    let checks: Vec<Value> = a
        .opts
        .get("check")
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|c| match c.split_once('=') {
            Some((k, v)) if !k.is_empty() && !v.is_empty() => obj(vec![("name", s(k)), ("result", s(v))]),
            _ => die(2, &format!("--check {c:?} must be <name>=<result>")),
        })
        .collect();
    let pubkey = hex::encode(ed25519_public(&seed));
    let body = obj(vec![
        ("format", s(FORMAT)),
        ("repo", s(&repo)),
        ("release", s(&release)),
        ("issued_at", s(&chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))),
        ("files", Value::Int(n.to_string())),
        ("manifest", s(MANIFEST)),
        ("manifest_sha256", s(&sha256_hex(text.as_bytes()))),
        ("upstream", Value::Array(upstream)),
        ("checks", Value::Array(checks)),
        ("pubkey", s(&pubkey)),
    ]);
    let sig = ed25519_sign(&seed, canon_u8(&body).as_bytes());
    let receipt = obj(vec![("seal", body), ("sig", obj(vec![("alg", s("ed25519")), ("sig_hex", s(&hex::encode(sig)))]))]);
    let pretty = value::dumps(&receipt, &value::DumpOpts { ensure_ascii: false, sort_keys: false, indent: Some(2), compact: false });
    fs::write(root.join(MANIFEST), &text).unwrap_or_else(|e| die(2, &format!("cannot write {MANIFEST}: {e}")));
    fs::write(root.join(RECEIPT), format!("{pretty}\n")).unwrap_or_else(|e| die(2, &format!("cannot write {RECEIPT}: {e}")));
    println!("SEAL_OK {repo} {release}: {n} files, manifest sha256 {}, signed by {pubkey}", sha256_hex(text.as_bytes()));
}

fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    match v {
        Value::Object(items) => items.iter().find(|(kk, _)| kk == k).map(|(_, vv)| vv),
        _ => None,
    }
}

fn get_str<'a>(v: &'a Value, k: &str) -> &'a str {
    match get(v, k) {
        Some(Value::Str(x)) => x,
        _ => "",
    }
}

fn verify(a: &Args) {
    let root = PathBuf::from(a.pos.get(1).cloned().unwrap_or_else(|| die(2, "usage: verify <folder> --pubkey <hex>")));
    let pubkey = one(a, "pubkey").to_ascii_lowercase();
    let rtext = fs::read_to_string(root.join(RECEIPT)).unwrap_or_else(|e| die(2, &format!("no {RECEIPT}: {e}")));
    let receipt = value::parse(&rtext).unwrap_or_else(|e| die(2, &format!("{RECEIPT} is not valid JSON: {e}")));
    let body = get(&receipt, "seal").unwrap_or_else(|| die(2, &format!("{RECEIPT} has no seal")));
    let mut problems = Vec::new();
    match vdecl_verify_seal(&receipt, &pubkey) {
        Ok(true) => {}
        Ok(false) => problems.push("SIGNATURE: the seal is not signed by this public key".to_string()),
        Err(e) => problems.push(format!("SIGNATURE: {e}")),
    }
    if get_str(body, "format") != FORMAT {
        problems.push(format!("FORMAT: not {FORMAT}"));
    }
    if get_str(body, "pubkey") != pubkey {
        problems.push("PUBKEY: the seal names another key".to_string());
    }
    let on_disk = fs::read_to_string(root.join(MANIFEST)).unwrap_or_default();
    if sha256_hex(on_disk.as_bytes()) != get_str(body, "manifest_sha256") {
        problems.push(format!("MANIFEST: {MANIFEST} is not the one that was sealed"));
    }
    match manifest_text(&root) {
        Ok((now, _)) if now == on_disk => {}
        Ok((now, _)) => {
            let want: BTreeMap<&str, &str> = on_disk.lines().filter_map(|l| l.split_once("  ").map(|(h, p)| (p, h))).collect();
            let have: BTreeMap<&str, &str> = now.lines().filter_map(|l| l.split_once("  ").map(|(h, p)| (p, h))).collect();
            for (p, h) in &want {
                match have.get(p) {
                    None => problems.push(format!("MISSING: {p}")),
                    Some(h2) if h2 != h => problems.push(format!("CHANGED: {p}")),
                    _ => {}
                }
            }
            for p in have.keys().filter(|p| !want.contains_key(*p)) {
                problems.push(format!("ADDED: {p}"));
            }
        }
        Err(e) => problems.push(format!("FILES: {e}")),
    }
    if problems.is_empty() {
        println!(
            "VERIFIED {} {}: {} files, sealed {} by {}",
            get_str(body, "repo"),
            get_str(body, "release"),
            match get(body, "files") { Some(Value::Int(n)) => n.clone(), _ => "?".into() },
            get_str(body, "issued_at"),
            pubkey
        );
    } else {
        for p in &problems {
            println!("{p}");
        }
        println!("NOT_VERIFIED {} problem(s)", problems.len());
        std::process::exit(1);
    }
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let a = args(&raw);
    match a.pos.first().map(|x| x.as_str()) {
        Some("keygen") => keygen(&a),
        Some("seal") => seal(&a),
        Some("verify") => verify(&a),
        Some("version") => println!("byoai-release {} (byoai-chain {})", env!("CARGO_PKG_VERSION"), byoai_chain::VERSION),
        _ => die(2, "usage: byoai-release keygen --out <file> | seal <folder> --key <file> --repo <owner/name> --release <tag> [--upstream <url>@<commit>]... [--check <name>=<result>]... | verify <folder> --pubkey <hex> | version"),
    }
}
