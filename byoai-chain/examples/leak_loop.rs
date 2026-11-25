//! Test helper (not shipped): runs every request line of a file through `call_json`
//! N times, for valgrind. LEAK_CONTROL=1 leaks each response on purpose (positive control). Prints one sha256 over all responses so runs can be compared.
use sha2::{Digest, Sha256};
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&a[1]).unwrap();
    let rounds: usize = a.get(2).map(|s| s.parse().unwrap()).unwrap_or(1);
    let mut h = Sha256::new();
    let mut n = 0usize;
    for _ in 0..rounds {
        for line in text.split('\n').filter(|l| !l.is_empty()) {
            let resp = byoai_chain::call_json(line);
            h.update(resp.as_bytes());
            if std::env::var("LEAK_CONTROL").is_ok() {
                std::mem::forget(resp); // positive control: valgrind must report this
            }
            n += 1;
        }
    }
    println!("calls={} responses_sha256={}", n, hex::encode(h.finalize()));
}
