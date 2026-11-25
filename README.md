# BYOAI verify

The open checker for everything BYOAI publishes. Every BYOAI release carries a seal; this repository
holds the code that checks it, so you never have to take "verified" on trust.

- **byoai-release**: seals a release folder (`MANIFEST.sha256` with the sha256 of every file, and
  `RECEIPT.json`, a seal signed with Ed25519) and verifies one.
- **byoai-chain**: BYOAI's receipt and hash-chain core. Among its formats, `vdecl-seal` checks the
  same seal on its own: a second, independent way to verify.

## Verify a BYOAI release

```bash
cargo install --locked --git https://github.com/byoai-corp/verify byoai-release
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

## Build and test

```bash
cargo build --release
bash proof/proof_release.sh target/release/byoai-release target/release/byoai-chain   # ends RELEASE_PROOF_GREEN
```

To build the `byoai-chain` command as well: `cargo build --release -p byoai-chain --features cli`.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
