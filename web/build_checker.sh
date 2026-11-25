#!/usr/bin/env bash
# Build the offline receipt checker: one HTML file with byoai-chain's WebAssembly inside it.
#   web/build_checker.sh <byoai_chain.wasm> <out.html>
# The WASM comes from: cargo build --release --locked --target wasm32-unknown-unknown -p byoai-chain --features wasm --lib
# Ends with CHECKER_BUILT <out> <sha256 of out>, or CHECKER_FAIL <why>.
set -u
CHECKER_VERSION="0.1.0"
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$HERE/.."
WASM="${1:?wasm file}"; OUT="${2:?output html}"
fail() { echo "CHECKER_FAIL $*"; exit 1; }
[ -f "$WASM" ] || fail "no wasm at $WASM"
[ -e "$OUT" ] && fail "$OUT exists; not overwriting"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/byoai-chain/Cargo.toml" | head -1)"
KEY="$(tr -d '[:space:]' < "$ROOT/BYOAI_RELEASE_PUBKEY")"
[[ "$KEY" =~ ^[0-9a-f]{64}$ ]] || fail "BYOAI_RELEASE_PUBKEY is not 64 hex characters"
WSHA="$(sha256sum "$WASM" | cut -d' ' -f1)"
TMP="$(mktemp "$OUT.tmp.XXXX")" || fail "temp file"
python3 -I - "$HERE/checker.template.html" "$WASM" "$TMP" "$VERSION" "$CHECKER_VERSION" "$WSHA" "$KEY" <<'EOF' || { rm -f "$TMP"; fail "fill template"; }
import base64, sys
tpl, wasm, out, ver, cver, wsha, key = sys.argv[1:8]
s = open(tpl, encoding="utf-8").read()
fill = {"@WASM_B64@": base64.b64encode(open(wasm, "rb").read()).decode("ascii"), "@WASM_SHA256@": wsha,
        "@VERSION@": ver, "@CHECKER_VERSION@": cver, "@BYOAI_KEY@": key, "@BYOAI_KEY_SHORT@": key[:16]}
for k, v in fill.items():
    if k not in s:
        sys.exit("placeholder missing from template: " + k)
    s = s.replace(k, v)
import hashlib, re
# the Content-Security-Policy allows exactly this page's one inline script, by its sha256
scripts = re.findall(r"<script>(.*?)</script>", s, re.S)
if len(scripts) != 1 or "@SCRIPT_HASH@" not in s:
    sys.exit("expected exactly one inline script and a @SCRIPT_HASH@ placeholder")
s = s.replace("@SCRIPT_HASH@", "sha256-" + base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode("ascii"))
left = re.findall(r"@[A-Z_0-9]+@", s)
if left:
    sys.exit("unfilled placeholders: " + ", ".join(sorted(set(left))))
open(out, "w", encoding="utf-8").write(s)
EOF
chmod 644 "$TMP" && mv -n "$TMP" "$OUT" && [ ! -e "$TMP" ] || { rm -f "$TMP"; fail "could not move into place"; }
echo "CHECKER_BUILT $OUT $(sha256sum "$OUT" | cut -d' ' -f1) (byoai-chain $VERSION, checker $CHECKER_VERSION, wasm $WSHA)"
