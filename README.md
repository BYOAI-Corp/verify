# BYOAI verify

The open checker for everything BYOAI publishes. Every BYOAI release carries a seal; this repository
holds the code that checks it, so you never have to take "verified" on trust.

- **byoai-release**: seals a release folder (`MANIFEST.sha256` with the sha256 of every file, and
  `RECEIPT.json`, a seal signed with Ed25519) and verifies one.
- **byoai-chain**: BYOAI's receipt and hash-chain core. Among its formats, `vdecl-seal` checks the
  same seal on its own: a second, independent way to verify.
  From 0.2.0 it also writes and checks **case handoff receipts** (see below).

**Just want to check a receipt?** Read [How to check a BYOAI or Sworn receipt](docs/CHECK_A_RECEIPT.md).
Each [release](https://github.com/BYOAI-Corp/verify/releases/latest) has a one-file web checker that
works offline in any browser, ready-to-run Linux programs, and a signed list of every download.

## Verify a BYOAI release

```bash
cargo install --locked --git https://github.com/BYOAI-Corp/verify byoai-release
cd <a BYOAI repository you cloned>
byoai-release verify . --pubkey "$(cat BYOAI_RELEASE_PUBKEY)"
```

- `VERIFIED <repo> <release>: <n> files, sealed <time> by <key>`: every file is exactly what BYOAI
  sealed, and the seal is signed by BYOAI's key.
- `NOT_VERIFIED`: each problem is named: `CHANGED`, `ADDED` or `MISSING` for a file, `MANIFEST` if
  the manifest was rewritten, `SIGNATURE` if the seal was edited or signed by another key.

Without the checker: `sha256sum -c MANIFEST.sha256` checks the files. `byoai-chain verify --format
vdecl-seal RECEIPT.json --pubkey <key>` (also in this repository) is a second, independent check of
the signature.

Verify a fresh clone: build output (`target/`, `node_modules/`) left in the folder shows up as `ADDED`.

BYOAI's public key is in each repository's `BYOAI_RELEASE_PUBKEY`. Check it against the copy pinned on the organisation page, https://github.com/byoai-corp, which is kept in a separate repository (`byoai-corp/.github`): a key copied into a tampered repository will not match it.

## What a seal says

```json
{
  "seal": {
    "format": "byoai.release/0.1",
    "repo": "byoai-corp/skills",
    "release": "v0.1.0",
    "issued_at": "...",
    "files": 92,
    "manifest": "MANIFEST.sha256",
    "manifest_sha256": "...",
    "upstream": [{ "source": "...", "commit": "..." }],
    "checks": [{ "name": "...", "result": "..." }],
    "pubkey": "..."
  },
  "sig": { "alg": "ed25519", "sig_hex": "..." }
}
```

The signature covers the seal in a fixed canonical form (sorted keys, no spaces, UTF-8), so it
cannot be edited without breaking. `upstream` records the open-source sources a release was built
from, and `checks` records the checks it passed before sealing.

## Case handoff receipts (byoai-chain 0.2.0)

A handoff (`byoai.handoff/0.1`) is a signed, hash-chained record of an analyst's steps: for each
step, the sources it read (with their sha256 and when they were fetched), what it produced, and
which earlier steps it built on. Anyone holding the sources can re-derive every finding without
trusting the analyst.

```bash
openssl genpkey -algorithm ed25519 -out key.pem && chmod 600 key.pem
byoai-chain handoff mint --steps steps.jsonl --sources ./sources --case CASE-1 --analyst "A. Analyst" \
  --key key.pem --out handoff.json
byoai-chain verify --format handoff handoff.json --pubkey <hex> --sources ./sources
byoai-chain taint handoff.json --pubkey <hex> --revoked revoked.json
```

- Each line of `steps.jsonl` holds `action`, `tool`, `sources` `[{ref, fetched_at}]`, `products`
  `[{ref}]`, `depends_on` (earlier step numbers) and `checked_at` (UTC `YYYY-MM-DDTHH:MM:SSZ`).
  With `--sources`, mint fills in each sha256 from `<dir>/<ref>`.
- `verify` without `--sources` checks integrity only and says so. With `--sources` every source and
  product is hashed again: `VERIFIED`, `UNGROUNDED` (the file differs) or `UNCHECKED`; anything left
  unchecked fails the verdict. Refs are plain relative paths and are never read through a link.
- `taint` marks every step that reads or produced a revoked file (by sha256), uses a tainted step's
  output, or depends on a tainted step. A revocation that matches nothing in the handoff is refused.
- The receipt never claims more than was checked: identity is `ID_UNCHECKED` and times are
  `self-asserted`. The step model follows in-toto's materials and products; the seal is the same
  Ed25519 construction as `vdecl-seal`.

The five earlier formats are unchanged and give byte-identical results to 0.1.0.

## Build and test

```bash
cargo build --release
bash proof/proof_release.sh target/release/byoai-release target/release/byoai-chain   # ends RELEASE_PROOF_GREEN
cargo build --release -p byoai-chain --features cli
bash proof/proof_handoff.sh target/release/byoai-chain [<byoai-chain 0.1.0>] [target/release/byoai-release]
                                                      # ends PROOF_GREEN (needs openssl, python3 cryptography)
cargo test --release -p byoai-chain --features cli --test heap_handoff --test heap_control -- --test-threads=1
```

The web checker (`web/checker.template.html`, filled by `web/build_checker.sh`) is byoai-chain built
for the browser plus the unchanged 0.1.0 web loader, in one HTML file with no network access:

```bash
cargo build --release --locked --target wasm32-unknown-unknown -p byoai-chain --features wasm --lib
bash web/build_checker.sh target/wasm32-unknown-unknown/release/byoai_chain.wasm byoai-receipt-checker.html
```

Memory: the handoff path is safe Rust (`#![forbid(unsafe_code)]`, which the proof checks), and the
heap test runs the handoff verify and taint calls under the `dhat` allocator and requires the live
heap to return to where it was; its control leaks on purpose and must be seen.

To build the `byoai-chain` command as well: `cargo build --release -p byoai-chain --features cli`.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
