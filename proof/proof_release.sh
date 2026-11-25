#!/usr/bin/env bash
# Proof for byoai-release: seal, verify, and every planted fault refused. Ends RELEASE_PROOF_GREEN.
set -u
R="$(readlink -f "${1:?byoai-release binary}")"; C="$(readlink -f "${2:?byoai-chain binary}")"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
P=0; F=0; ok() { P=$((P+1)); echo "PASS  $*"; }; no() { F=$((F+1)); echo "FAIL  $*"; }
chk() { local n="$1"; shift; if "$@"; then ok "$n"; else no "$n"; fi; }
mkdir -p "$W/rel/skills/a" && echo "alpha" >"$W/rel/skills/a/SKILL.md" && echo "readme" >"$W/rel/README.md" && echo "MIT" >"$W/rel/LICENSE"
K="$(cd "$W" && "$R" keygen --out "$W/key.hex")"; PUB="$(sed -n 's/^PUBKEY //p' <<<"$K")"
chk "keygen writes an owner-only key and prints its public key" bash -c '[ "$(stat -c %a "$1")" = 600 ] && [[ "$2" =~ ^[0-9a-f]{64}$ ]]' _ "$W/key.hex" "$PUB"
chk "keygen never overwrites a key" bash -c '! "$1" keygen --out "$2" >/dev/null 2>&1' _ "$R" "$W/key.hex"
O="$("$R" seal "$W/rel" --key "$W/key.hex" --repo byoai-corp/test --release v0.1.0 --upstream https://example.org/x@abc123 --check guide-check=GUIDE_OK 2>&1)"
chk "seal writes MANIFEST.sha256 and RECEIPT.json (3 files)" bash -c 'grep -q "^SEAL_OK byoai-corp/test v0.1.0: 3 files" <<<"$1" && [ -f "$2/MANIFEST.sha256" ] && [ -f "$2/RECEIPT.json" ]' _ "$O" "$W/rel"
chk "plain sha256sum checks the manifest" bash -c 'cd "$1" && sha256sum --quiet -c MANIFEST.sha256' _ "$W/rel"
chk "byoai-release verify: VERIFIED" bash -c '"$1" verify "$2" --pubkey "$3" | grep -q "^VERIFIED byoai-corp/test v0.1.0: 3 files"' _ "$R" "$W/rel" "$PUB"
chk "the open checker byoai-chain verifies the same seal (vdecl-seal)" bash -c '"$1" verify --format vdecl-seal "$2/RECEIPT.json" --pubkey "$3" >/dev/null' _ "$C" "$W/rel" "$PUB"
chk "the receipt names the upstream and the checks" bash -c 'grep -q "\"commit\": \"abc123\"" "$1" && grep -q "\"result\": \"GUIDE_OK\"" "$1"' _ "$W/rel/RECEIPT.json"
cp -r "$W/rel" "$W/t1"; echo "changed" >>"$W/t1/skills/a/SKILL.md"
chk "planted: a changed file is NOT_VERIFIED and named" bash -c 'O="$("$1" verify "$2" --pubkey "$3")"; [ $? = 1 ] && grep -q "^CHANGED: skills/a/SKILL.md" <<<"$O"' _ "$R" "$W/t1" "$PUB"
cp -r "$W/rel" "$W/t2"; echo "x" >"$W/t2/extra.md"
chk "planted: an added file is NOT_VERIFIED and named" bash -c '"$1" verify "$2" --pubkey "$3" | grep -q "^ADDED: extra.md"' _ "$R" "$W/t2" "$PUB"
cp -r "$W/rel" "$W/t3"; rm "$W/t3/LICENSE"
chk "planted: a removed file is NOT_VERIFIED and named" bash -c '"$1" verify "$2" --pubkey "$3" | grep -q "^MISSING: LICENSE"' _ "$R" "$W/t3" "$PUB"
cp -r "$W/rel" "$W/t4"; sed -i 's/abc123/def456/' "$W/t4/RECEIPT.json"
chk "planted: an edited receipt fails its signature (both checkers)" bash -c '"$1" verify "$2" --pubkey "$3" | grep -q "^SIGNATURE" && ! "$4" verify --format vdecl-seal "$2/RECEIPT.json" --pubkey "$3" >/dev/null' _ "$R" "$W/t4" "$PUB" "$C"
cp -r "$W/rel" "$W/t5"; echo "fake" >>"$W/t5/README.md"; (cd "$W/t5" && sha256sum README.md LICENSE skills/a/SKILL.md | sort -k2 >MANIFEST.sha256)
chk "planted: a rewritten manifest does not match the sealed one" bash -c '"$1" verify "$2" --pubkey "$3" | grep -q "^MANIFEST"' _ "$R" "$W/t5" "$PUB"
(cd "$W" && "$R" keygen --out "$W/other.hex" >/dev/null); OPUB="$(cd "$W" && "$R" seal "$W/rel" --key "$W/other.hex" --repo x/y --release z >/dev/null; sed -n 's/.*"pubkey": "\([0-9a-f]*\)".*/\1/p' "$W/rel/RECEIPT.json")"
chk "planted: a release sealed with another key is NOT_VERIFIED for BYOAI's key" bash -c '"$1" verify "$2" --pubkey "$3" | grep -q "^NOT_VERIFIED"' _ "$R" "$W/rel" "$PUB"
mkdir -p "$W/t6" && echo a >"$W/t6/a" && ln -s /etc/passwd "$W/t6/link"
chk "planted: a link in the folder is refused at seal time" bash -c '! "$1" seal "$2" --key "$3" --repo x/y --release z >/dev/null 2>&1' _ "$R" "$W/t6" "$W/key.hex"
echo; T=$((P+F)); if [ "$F" = 0 ]; then echo "RELEASE_PROOF_GREEN $P/$T"; else echo "RELEASE_PROOF_RED $F of $T failed"; exit 1; fi
