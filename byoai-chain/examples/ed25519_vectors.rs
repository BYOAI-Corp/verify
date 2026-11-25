//! Test helper (not shipped): reads "seed_hex msg_hex" lines ("-" = empty message), prints "pub_hex sig_hex".
use std::io::BufRead;
fn main() {
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut it = line.split_whitespace();
        let (Some(s), Some(m)) = (it.next(), it.next()) else { continue };
        let seed: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        let msg = if m == "-" { Vec::new() } else { hex::decode(m).unwrap() };
        let sig = byoai_chain::dialects::ed25519_sign(&seed, &msg);
        let pk = byoai_chain::dialects::ed25519_public(&seed);
        assert!(byoai_chain::dialects::ed25519_verify(&pk, &msg, &sig));
        println!("{} {}", hex::encode(pk), hex::encode(sig));
    }
}
