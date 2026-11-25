#!/usr/bin/env bash
# Proof for byoai-chain 0.2.0 handoff (byoai.handoff/0.1): mint, verify, re-derive, taint, and every
# planted defect caught. Ends with exactly one of PROOF_GREEN, PROOF_GREEN_WITH_SKIPS, PROOF_RED.
#   proof_handoff.sh <byoai-chain 0.2.0> [<byoai-chain 0.1.0 baseline>] [<byoai-release>]
# Memory: the heap test is tests/heap_handoff.rs (cargo test, with a deliberate-leak control);
# this proof checks that every handoff-path source file still forbids unsafe code.
set -u
C="$(readlink -f "${1:?byoai-chain 0.2.0 binary}")"
OLD="${2:+$(readlink -f "$2")}"; REL="${3:+$(readlink -f "$3")}"
HERE="$(cd "$(dirname "$0")" && pwd)"; X="$HERE/crosscheck_handoff.py"; PY="$HERE/fixture_edit.py"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
# python3 may be a version-manager shim (mise, pyenv, asdf) that writes into HOME: find the real
# interpreter once, before HOME changes, and run it isolated (-I) through a wrapper on PATH
PYREAL="$(python3 -I -c 'import sys; print(sys.executable)' 2>/dev/null)"
mkdir -p "$W/bin"; if [ -n "$PYREAL" ] && [ -x "$PYREAL" ]; then printf '#!/usr/bin/env bash\nexec %q -I "$@"\n' "$PYREAL" >"$W/bin/python3"; else printf '#!/bin/sh\nexit 127\n' >"$W/bin/python3"; fi
chmod +x "$W/bin/python3"; export PATH="$W/bin:$PATH"
export HOME="$W/home"; mkdir -p "$HOME"            # throwaway HOME: nothing may land in the real one
P=0; F=0; S=0
ok() { P=$((P+1)); echo "PASS  $*"; }; no() { F=$((F+1)); echo "FAIL  $*"; }; skip() { local n="$1"; shift; S=$((S+n)); echo "SKIP  ($n checks) $*"; }
chk() { local n="$1"; shift; if "$@"; then ok "$n"; else no "$n"; fi; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
pubhex() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \n'; }
HAVE_PY=0; python3 -c "import cryptography" 2>/dev/null && HAVE_PY=1
# edit <in> <out> <python statements on d>: JSON fixture edits without shell quoting games
edit() { python3 "$PY" "$1" "$2" "$3"; }

# ---------------------------------------------------------------- fixtures
mkdir -p "$W/src" "$W/case"
printf 'registry record: example-shop.test registered to Example Holdings LLC\n' >"$W/src/registry.txt"
printf 'profile page: handle exampleseller, joined 2021\n' >"$W/src/profile.html"
printf 'unrelated: weather 2026-11-24 sunny\n' >"$W/src/weather.txt"
printf 'match: handle exampleseller -> Example Holdings LLC\n' >"$W/src/match.txt"
openssl genpkey -algorithm ed25519 -out "$W/key.pem" 2>/dev/null && chmod 600 "$W/key.pem"
openssl genpkey -algorithm ed25519 -out "$W/other.pem" 2>/dev/null && chmod 600 "$W/other.pem"
PUB="$(pubhex "$W/key.pem")"; OPUB="$(pubhex "$W/other.pem")"
cat >"$W/steps.jsonl" <<'EOF'
{"action":"registry lookup for example-shop.test","tool":"whois","sources":[{"ref":"registry.txt","fetched_at":"2026-11-24T10:00:00Z"}],"products":[{"ref":"match.txt"}],"depends_on":[],"checked_at":"2026-11-24T10:05:00Z"}
{"action":"link the seller handle to the registrant","tool":"manual review","sources":[{"ref":"match.txt","fetched_at":"2026-11-24T10:05:00Z"},{"ref":"profile.html","fetched_at":"2026-11-24T10:02:00Z"}],"products":[],"depends_on":[],"checked_at":"2026-11-24T10:10:00Z"}
{"action":"case note citing step 0","tool":"editor","sources":[{"ref":"profile.html","fetched_at":"2026-11-24T10:02:00Z"}],"products":[],"depends_on":[0],"checked_at":"2026-11-24T10:12:00Z"}
{"action":"unrelated context","tool":"browser","sources":[{"ref":"weather.txt","fetched_at":"2026-11-24T09:00:00Z"}],"products":[],"depends_on":[],"checked_at":"2026-11-24T10:13:00Z"}
EOF
H="$W/case/handoff.json"
RS="$(sha "$W/src/registry.txt")"; printf '{"sources":["%s"]}\n' "$RS" >"$W/rev1.json"; printf '{"steps":[3]}\n' >"$W/rev2.json"

# ---------------------------------------------------------------- mint
O="$("$C" handoff mint --steps "$W/steps.jsonl" --case CASE-2026-0001 --analyst "Analyst A" --key "$W/key.pem" --out "$H" --sources "$W/src" 2>&1)"; RC=$?
chk "mint writes a handoff and names the signing key" bash -c '[ "$1" = 0 ] && [ -f "$2" ] && grep -q "^MINTED .* rows=4 .* pubkey=$3$" <<<"$4"' _ "$RC" "$H" "$PUB" "$O"
chk "mint hashes each source from --sources (registry.txt sha recorded)" grep -q "\"sha256\": \"$RS\"" "$H"
chk "the receipt says identity ID_UNCHECKED and time self-asserted" bash -c 'grep -q "\"identity\": \"ID_UNCHECKED\"" "$1" && grep -q "\"time\": \"self-asserted\"" "$1"' _ "$H"
chk "mint never overwrites (exit 2)" bash -c '"$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4" --sources "$5" >/dev/null 2>&1; [ $? = 2 ]' _ "$C" "$W/steps.jsonl" "$W/key.pem" "$H" "$W/src"
cp "$W/key.pem" "$W/open.pem"; chmod 644 "$W/open.pem"
chk "planted: a private key readable by others is refused (exit 2)" bash -c '"$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/k.json" --sources "$5" >/dev/null 2>&1; [ $? = 2 ] && [ ! -e "$4/k.json" ]' _ "$C" "$W/steps.jsonl" "$W/open.pem" "$W" "$W/src"
printf 'not a key\n' >"$W/bad.pem"; chmod 600 "$W/bad.pem"
chk "planted: a file that is not an Ed25519 PKCS#8 key is refused (exit 2)" bash -c '"$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/b.json" --sources "$5" >/dev/null 2>&1; [ $? = 2 ]' _ "$C" "$W/steps.jsonl" "$W/bad.pem" "$W" "$W/src"
chk "the private key is never printed" bash -c '! grep -q "PRIVATE" <<<"$1"' _ "$O"

# ---------------------------------------------------------------- verify and re-derive
O="$("$C" verify --format handoff "$H" --pubkey "$PUB")"; RC=$?
chk "verify without sources says integrity only, all 6 items UNCHECKED (never counted as re-derived)" bash -c '[ "$1" = 0 ] && grep -q "^VERIFIED (integrity only: no source was re-derived) handoff case=CASE-2026-0001 rows=4 .* 0 verified, 0 ungrounded, 6 unchecked" <<<"$2"' _ "$RC" "$O"
chk "--require-rederive with nothing re-derived is NOT_VERIFIED (exit 1)" bash -c '"$1" verify --format handoff "$2" --pubkey "$3" --require-rederive >/dev/null; [ $? = 1 ]' _ "$C" "$H" "$PUB"
O="$("$C" verify --format handoff "$H" --pubkey "$PUB" --sources "$W/src")"; RC=$?
chk "re-derived from the sources: 6 VERIFIED, exit 0" bash -c '[ "$1" = 0 ] && grep -q "^VERIFIED handoff .* 6 verified, 0 ungrounded, 0 unchecked" <<<"$2"' _ "$RC" "$O"
J="$("$C" verify --format handoff "$H" --pubkey "$PUB" --sources "$W/src" --json)"
chk "--json prints one object with ok, rederive counts and rederive_required" python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["ok"] is True and d["rederive_required"] is True and d["rederive"]=={"verified":6,"ungrounded":0,"unchecked":0}' "$J"
REQ="$(python3 -c 'import json,sys; print(json.dumps({"op":"verify","format":"handoff","doc":json.load(open(sys.argv[1])),"pubkey":sys.argv[2],"observed":{"registry.txt":sys.argv[3]}}))' "$H" "$PUB" "$RS")"
chk "the JSON API: observed for 1 of 6 items is NOT ok (REDERIVE_INCOMPLETE), scope integrity+rederive" python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["ok"] is False and d["scope"]=="integrity+rederive" and d["rederive"]=={"verified":1,"ungrounded":0,"unchecked":5} and any(p.startswith("REDERIVE_INCOMPLETE") for p in d["problems"])' "$("$C" call <<<"$REQ")"
REQ0="$(python3 -c 'import json,sys; print(json.dumps({"op":"verify","format":"handoff","doc":json.load(open(sys.argv[1])),"pubkey":sys.argv[2],"observed":{}}))' "$H" "$PUB")"
chk "planted: the JSON API with observed {} re-derives nothing and is NOT ok" python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["ok"] is False and d["rederive"]["verified"]==0' "$("$C" call <<<"$REQ0")"
REQN="$(python3 -c 'import json,sys; print(json.dumps({"op":"verify","format":"handoff","doc":json.load(open(sys.argv[1])),"pubkey":sys.argv[2]}))' "$H" "$PUB")"
chk "the JSON API without observed is ok but labelled scope integrity-only" python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["ok"] is True and d["scope"]=="integrity-only" and d["rederive_required"] is False' "$("$C" call <<<"$REQN")"
if [ "$HAVE_PY" = 1 ]; then
  chk "cross-check: Python cryptography agrees on canon bytes, row chain, pid and signature" bash -c 'python3 "$1" check "$2" "$3" | grep -q ^XCHECK_OK' _ "$X" "$H" "$PUB"
else skip 1 "Python cryptography missing: cross-check not run"; fi

cp -r "$W/src" "$W/s1"; sed -i 's/Holdings/Holding/' "$W/s1/registry.txt"
chk "planted: one changed byte in a source is UNGROUNDED (edit really changed the file)" bash -c '[ "$(sha256sum "$2/registry.txt" | cut -d" " -f1)" != "$5" ] && O="$("$1" verify --format handoff "$3" --pubkey "$4" --sources "$2")"; [ $? = 1 ] && grep -q "^  UNGROUNDED: step 0 source \"registry.txt\"" <<<"$O"' _ "$C" "$W/s1" "$H" "$PUB" "$RS"
cp -r "$W/src" "$W/s2"; mv "$W/s2/profile.html" "$W/s2/t"; mv "$W/s2/weather.txt" "$W/s2/profile.html"; mv "$W/s2/t" "$W/s2/weather.txt"
chk "planted: two swapped source files are UNGROUNDED wherever they are used (3 items)" bash -c 'O="$("$1" verify --format handoff "$3" --pubkey "$4" --sources "$2")"; [ $? = 1 ] && [ "$(grep -c "^  UNGROUNDED: " <<<"$O")" = 3 ]' _ "$C" "$W/s2" "$H" "$PUB"
cp -r "$W/src" "$W/s3"; rm "$W/s3/weather.txt"
chk "planted: a missing source stays UNCHECKED and --sources fails it (REDERIVE_INCOMPLETE, exit 1)" bash -c 'O="$("$1" verify --format handoff "$3" --pubkey "$4" --sources "$2")"; [ $? = 1 ] && grep -q "^NOT_VERIFIED (REDERIVE_INCOMPLETE) .* 5 verified, 0 ungrounded, 1 unchecked" <<<"$O"' _ "$C" "$W/s3" "$H" "$PUB"
mkdir -p "$W/empty"
chk "planted: --sources pointing at an empty folder re-derives nothing and fails (exit 1)" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3" --sources "$4")"; [ $? = 1 ] && grep -q "0 verified, 0 ungrounded, 6 unchecked" <<<"$O"' _ "$C" "$H" "$PUB" "$W/empty"

# ---------------------------------------------------------------- escapes from --sources
if [ "$HAVE_PY" = 1 ]; then
  # Each escape is signed properly (resign) so only the escape can fail, and records the TRUE sha of
  # the outside file, so a naive path join would wrongly say VERIFIED.
  mkdir -p "$W/s4/in" "$W/outside" && cp "$W/src/"* "$W/s4/in/"
  printf 'outside secret\n' >"$W/s4/outside.txt"; cp "$W/s4/outside.txt" "$W/outside/outside.txt"
  ln -s "$W/s4/outside.txt" "$W/s4/in/link.txt"; ln -s "$W/outside" "$W/s4/in/sub"
  cp "$W/s4/outside.txt" "$W/s4/in/plain.txt"
  OS="$(sha "$W/s4/outside.txt")"; i=0
  for R in ../outside.txt link.txt sub/outside.txt plain.txt; do
    i=$((i+1))
    edit "$H" "$W/esc$i.raw" "s=d['handoff']['steps'][3]['sources'][0]; s['ref']='$R'; s['sha256']='$OS'"
    python3 "$X" resign "$W/esc$i.raw" "$W/key.pem" "$W/esc$i.json"
  done
  i=0
  for R in ../outside.txt link.txt sub/outside.txt; do
    i=$((i+1))
    chk "planted: ref $R reaching outside --sources is never read (UNCHECKED, signature clean, exit 1)" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3" --sources "$4")"; [ $? = 1 ] && grep -qF "UNCHECKED  step 3 source $5" <<<"$O" && ! grep -qE "^  (SIGNATURE|CHAIN|PID|FIELDS|KEY)" <<<"$O"' _ "$C" "$W/esc$i.json" "$PUB" "$W/s4/in" "$R"
  done
  chk "control: the same file placed really inside --sources is VERIFIED (proves the escape fixtures)" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3" --sources "$4")"; [ $? = 0 ] && grep -qF "VERIFIED   step 3 source plain.txt" <<<"$O"' _ "$C" "$W/esc4.json" "$PUB" "$W/s4/in"
  sed '4s/"ref":"weather.txt"/"ref":"sub\/outside.txt"/' "$W/steps.jsonl" >"$W/esc_mint.jsonl"
  chk "planted: mint will not hash through a symlinked folder inside --sources (exit 2, names the file)" bash -c 'grep -q "sub/outside.txt" "$2" && O="$("$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/escm.json" --sources "$5" 2>&1)"; [ $? = 2 ] && grep -q "sub/outside.txt\" has no sha256 and is not a regular file inside --sources" <<<"$O" && [ ! -e "$4/escm.json" ]' _ "$C" "$W/esc_mint.jsonl" "$W/key.pem" "$W" "$W/s4/in"
  mkdir -p "$W/s4/in/realsub" && cp "$W/s4/outside.txt" "$W/s4/in/realsub/outside.txt"; sed 's#"ref":"sub/outside.txt"#"ref":"realsub/outside.txt"#' "$W/esc_mint.jsonl" >"$W/real_mint.jsonl"
  chk "control: the same mint through a real subfolder succeeds" bash -c '"$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/realm.json" --sources "$5" >/dev/null 2>&1 && [ -f "$4/realm.json" ]' _ "$C" "$W/real_mint.jsonl" "$W/key.pem" "$W" "$W/s4/in"
  edit "$H" "$W/odd.raw" "s=d['handoff']['steps'][0]['sources'][0]; s['ref']='registry.txt/'"; python3 "$X" resign "$W/odd.raw" "$W/key.pem" "$W/odd.json"
  chk "planted: a signed ref not in plain form (registry.txt/) is refused (REF) and never re-derived" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3" --sources "$4")"; [ $? = 1 ] && grep -q "^  REF: step 0 source" <<<"$O" && grep -qF "UNCHECKED  step 0 source registry.txt/" <<<"$O"' _ "$C" "$W/odd.json" "$PUB" "$W/src"
else skip 7 "Python cryptography missing: --sources escape defects not planted"; fi

# ---------------------------------------------------------------- edited, truncated, laundered, unsigned extras, wrong key
cp "$H" "$W/e.json"; sed -i 's/case note citing step 0/case note citing step 1/' "$W/e.json"
chk "planted: an edited step fails SIGNATURE and CHAIN_BROKEN (edit really changed the file)" bash -c '[ "$(sha256sum "$2" | cut -d" " -f1)" != "$(sha256sum "$4" | cut -d" " -f1)" ] && O="$("$1" verify --format handoff "$2" --pubkey "$3")"; [ $? = 1 ] && grep -q "^  SIGNATURE" <<<"$O" && grep -q "^  CHAIN_BROKEN at row 2" <<<"$O"' _ "$C" "$W/e.json" "$PUB" "$H"
edit "$H" "$W/trunc.json" "d['handoff']['steps'].pop()"
chk "planted: a dropped last step is caught (anchor rows/head)" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3")"; [ $? = 1 ] && grep -q "^  CHAIN_BROKEN at row 3" <<<"$O"' _ "$C" "$W/trunc.json" "$PUB"
if [ "$HAVE_PY" = 1 ]; then
  python3 "$X" relabel "$H" "$W/key.pem" "$W/laundered.json"
  chk "planted: identity laundered to ID_VERIFIED and re-signed with the real key: signature holds, LABEL refuses it" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3")"; [ $? = 1 ] && grep -q "^  LABEL" <<<"$O" && ! grep -q "^  SIGNATURE" <<<"$O"' _ "$C" "$W/laundered.json" "$PUB"
  edit "$H" "$W/empty.raw" "d['handoff']['steps']=[]"; python3 "$X" resign "$W/empty.raw" "$W/key.pem" "$W/emptyh.json"
  chk "planted: a properly signed handoff with no steps is NOT_VERIFIED (EMPTY), and taint refuses it" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3")"; [ $? = 1 ] && grep -q "^  EMPTY" <<<"$O" && ! grep -q "^  SIGNATURE" <<<"$O" && O2="$("$1" taint "$2" --pubkey "$3" --revoked "$4")"; [ $? = 1 ] && grep -q "taint not computed" <<<"$O2"' _ "$C" "$W/emptyh.json" "$PUB" "$W/rev1.json"
else skip 2 "Python cryptography missing: laundered-label and empty-handoff defects not planted"; fi
edit "$H" "$W/x1.json" "d['verdict']='VERIFIED_BY_COURT'"
edit "$H" "$W/x2.json" "d['sig']['key_id']='deadbeefdeadbeef'"
edit "$H" "$W/x3.json" "d['sig']['note']='identity checked'"
chk "planted: an unsigned top-level claim beside the seal is refused (FIELDS) even with sources re-derived" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3" --sources "$4")"; [ $? = 1 ] && grep -q "^  FIELDS" <<<"$O"' _ "$C" "$W/x1.json" "$PUB" "$W/src"
chk "planted: an edited sig.key_id is refused (KEY_ID)" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3")"; [ $? = 1 ] && grep -q "^  KEY_ID" <<<"$O"' _ "$C" "$W/x2.json" "$PUB"
chk "planted: an extra unsigned field inside sig is refused (FIELDS)" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3")"; [ $? = 1 ] && grep -q "^  FIELDS" <<<"$O"' _ "$C" "$W/x3.json" "$PUB"
edit "$H" "$W/spoof.json" "d['handoff']['case']='C1\\r\\x1b[2KVERIFIED handoff case=C1 rows=4 sources: 6 verified, 0 ungrounded, 0 unchecked\\x1b[8m'; d['handoff']['steps'][3]['sources'][0]['ref']='w\\x1b[8m.txt'"
chk "planted: a forged file with terminal control characters cannot redraw the verdict (no raw ESC/CR reaches the terminal, line 1 NOT_VERIFIED, CONTROL_CHARS named)" bash -c 'grep -q "x1b\|u001b" "$2" && "$1" verify --format handoff "$2" --pubkey "$3" --sources "$4" >"$5/spoof.out"; [ $? = 1 ] && ! grep -qP "[\x00-\x08\x0b-\x1f\x7f]" "$5/spoof.out" && head -1 "$5/spoof.out" | grep -q "^NOT_VERIFIED " && grep -q "^  CONTROL_CHARS" "$5/spoof.out" && "$1" taint "$2" --pubkey "$3" --revoked "$6" >"$5/spoof2.out"; ! grep -qP "[\x00-\x08\x0b-\x1f\x7f]" "$5/spoof2.out" && head -1 "$5/spoof2.out" | grep -q "^NOT_VERIFIED "' _ "$C" "$W/spoof.json" "$PUB" "$W/src" "$W" "$W/rev2.json"
chk "planted: mint refuses a case name with control characters (exit 2, CONTROL_CHARS)" bash -c 'O="$("$1" handoff mint --steps "$2" --case "$(printf "C\033[2K")" --analyst A --key "$3" --out "$4/cc.json" --sources "$5" 2>&1)"; [ $? = 2 ] && grep -q CONTROL_CHARS <<<"$O" && ! grep -qP "\x1b" <<<"$O"' _ "$C" "$W/steps.jsonl" "$W/key.pem" "$W" "$W/src"
chk "planted: verify against another key is KEY_MISMATCH and SIGNATURE" bash -c 'O="$("$1" verify --format handoff "$2" --pubkey "$3")"; [ $? = 1 ] && grep -q "^  KEY_MISMATCH" <<<"$O" && grep -q "^  SIGNATURE" <<<"$O"' _ "$C" "$H" "$OPUB"

# ---------------------------------------------------------------- mint refuses bad steps
sed '1s/"fetched_at":"2026-11-24T10:00:00Z"/"fetched_at":"2026-11-24T11:00:00Z"/' "$W/steps.jsonl" >"$W/late.jsonl"
chk "planted: a source fetched after its check is refused at mint (FETCH_AFTER_CHECK, exit 2)" bash -c 'O="$("$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/late.json" --sources "$5" 2>&1)"; [ $? = 2 ] && grep -q FETCH_AFTER_CHECK <<<"$O" && [ ! -e "$4/late.json" ]' _ "$C" "$W/late.jsonl" "$W/key.pem" "$W" "$W/src"
sed '3s/"depends_on":\[0\]/"depends_on":[3]/' "$W/steps.jsonl" >"$W/fwd.jsonl"
chk "planted: depending on a later step is refused at mint (DEPENDS, exit 2)" bash -c 'O="$("$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/fwd.json" --sources "$5" 2>&1)"; [ $? = 2 ] && grep -q DEPENDS <<<"$O"' _ "$C" "$W/fwd.jsonl" "$W/key.pem" "$W" "$W/src"
sed '4s/"ref":"weather.txt"/"ref":"..\/key.pem"/' "$W/steps.jsonl" >"$W/esc.jsonl"
chk "planted: mint will not hash a file outside --sources via ../ (exit 2)" bash -c 'grep -q "../key.pem" "$2" && "$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/esc.json" --sources "$5" >/dev/null 2>&1; [ $? = 2 ]' _ "$C" "$W/esc.jsonl" "$W/key.pem" "$W" "$W/src"
sed '2s/"checked_at":"2026-11-24T10:10:00Z"/"checked_at":"2026-02-30T10:10:00Z"/' "$W/steps.jsonl" >"$W/feb30.jsonl"
chk "planted: an impossible date (Feb 30) is refused at mint (exit 2, checked_at named)" bash -c 'grep -q 2026-02-30 "$2" && O="$("$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/feb.json" --sources "$5" 2>&1)"; [ $? = 2 ] && grep -q "STEP 1: checked_at must be UTC" <<<"$O"' _ "$C" "$W/feb30.jsonl" "$W/key.pem" "$W" "$W/src"
sed '1s/"ref":"registry.txt"/"ref":"sub\/\/registry.txt"/' "$W/steps.jsonl" >"$W/dbl.jsonl"
chk "planted: a ref not in plain form (sub//registry.txt) is refused at mint (exit 2, REF)" bash -c 'grep -q "sub//registry" "$2" && O="$("$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/dbl.json" --sources "$5" 2>&1)"; [ $? = 2 ] && grep -q "sub//registry.txt" <<<"$O"' _ "$C" "$W/dbl.jsonl" "$W/key.pem" "$W" "$W/src"
Z="$(printf '0%.0s' $(seq 64))"
sed "1s/\"ref\":\"registry.txt\"/\"ref\":\"registry.txt\",\"sha256\":\"$Z\"/" "$W/steps.jsonl" >"$W/zero.jsonl"
chk "planted: a stated sha256 that differs from the file is refused at mint (STATED_SHA_MISMATCH, exit 2)" bash -c 'grep -q "\"sha256\":\"0000" "$2" && O="$("$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/zero.json" --sources "$5" 2>&1)"; [ $? = 2 ] && grep -q STATED_SHA_MISMATCH <<<"$O"' _ "$C" "$W/zero.jsonl" "$W/key.pem" "$W" "$W/src"
sed '1s/"ref":"registry.txt"/"ref":"registry.txt","extra":{"x":1e400}/' "$W/steps.jsonl" >"$W/extra.jsonl"
chk "planted: an unknown key on a source item is refused at mint (exit 2, names the allowed keys)" bash -c 'grep -q 1e400 "$2" && O="$("$1" handoff mint --steps "$2" --case X --analyst A --key "$3" --out "$4/extra.json" --sources "$5" 2>&1)"; [ $? = 2 ] && grep -q "a source may only hold fetched_at, ref, sha256" <<<"$O" && [ ! -e "$4/extra.json" ]' _ "$C" "$W/extra.jsonl" "$W/key.pem" "$W" "$W/src"
race_bad=0; race_ok=0
for i in $(seq 1 60); do
  "$C" handoff mint --steps "$W/steps.jsonl" --case R --analyst A --key "$W/key.pem" --out "$W/race.json" --sources "$W/src" >/dev/null 2>&1 & p1=$!
  "$C" handoff mint --steps "$W/steps.jsonl" --case R --analyst A --key "$W/key.pem" --out "$W/race.json" --sources "$W/src" >/dev/null 2>&1 & p2=$!
  wait $p1; r1=$?; wait $p2; r2=$?
  { [ "$r1" = 0 ] && [ "$r2" = 0 ]; } && race_bad=$((race_bad+1))
  { [ "$r1" = 0 ] || [ "$r2" = 0 ]; } && "$C" verify --format handoff "$W/race.json" --pubkey "$PUB" >/dev/null && race_ok=$((race_ok+1))
  rm -f "$W/race.json"
done
chk "planted: 60 rounds of two concurrent mints to one --out: never both succeed, the winner always verifies, no temp file left" bash -c '[ "$1" = 0 ] && [ "$2" = 60 ] && ! ls -A "$3" | grep -q "^\.race"' _ "$race_bad" "$race_ok" "$W"

# ---------------------------------------------------------------- taint
O="$("$C" taint "$H" --pubkey "$PUB" --revoked "$W/rev1.json")"; RC=$?
chk "taint: revoking the registry record taints steps 0, 1 (uses its product) and 2 (depends on 0); step 3 stays clean" bash -c '[ "$1" = 1 ] && grep -q "^TAINTED case=CASE-2026-0001 rows=4: 3 of 4 steps" <<<"$2" && grep -q "^  step 1: USES_PRODUCT_OF 0" <<<"$2" && grep -q "^  step 2: DEPENDS_ON 0" <<<"$2" && ! grep -q "^  step 3" <<<"$2"' _ "$RC" "$O"
printf '{"steps":[3]}\n' >"$W/rev2.json"
chk "taint: revoking step 3 taints only step 3 (--json)" bash -c 'O="$("$1" taint "$2" --pubkey "$3" --revoked "$4" --json)"; [ $? = 1 ] && python3 -c "import json,sys; d=json.loads(sys.argv[1]); assert [t[\"seq\"] for t in d[\"tainted\"]]==[3] and d[\"ok\"] is False" "$O"' _ "$C" "$H" "$PUB" "$W/rev2.json"
printf '{"sources":["%s"]}\n' "$(sha "$W/src/weather.txt")" >"$W/rev3.json"
chk "taint: revoking a source no later step builds on taints only its own step (step 3)" bash -c 'O="$("$1" taint "$2" --pubkey "$3" --revoked "$4")"; [ $? = 1 ] && grep -q "1 of 4 steps" <<<"$O" && grep -q "^  step 3: REVOKED_SOURCE" <<<"$O"' _ "$C" "$H" "$PUB" "$W/rev3.json"
printf '{"sources":["%s"]}\n' "$(sha "$W/src/match.txt")" >"$W/rev4.json"
chk "taint: revoking a file step 0 produced taints step 0 (REVOKED_PRODUCT), its user step 1 and dependent step 2" bash -c 'O="$("$1" taint "$2" --pubkey "$3" --revoked "$4")"; [ $? = 1 ] && grep -q "3 of 4 steps" <<<"$O" && grep -q "^  step 0: REVOKED_PRODUCT" <<<"$O" && grep -q "^  step 2: DEPENDS_ON 0" <<<"$O"' _ "$C" "$H" "$PUB" "$W/rev4.json"
UP="$(tr a-f A-F <<<"$RS")"; AA="$(printf 'a%.0s' $(seq 64))"; n=0; tried=0
while IFS= read -r R; do
  tried=$((tried+1)); printf '%s\n' "$R" >"$W/bad_rev.json"; "$C" taint "$H" --pubkey "$PUB" --revoked "$W/bad_rev.json" >/dev/null 2>&1; [ $? = 2 ] && n=$((n+1))
done <<EOF
{}
[]
{"sources":[],"steps":[]}
{"source":["$RS"]}
{"sources":["registry.txt"]}
{"sources":["$UP"]}
{"steps":[99]}
{"steps":[-1]}
{"sources":"$RS"}
{"sources":["$AA"]}
EOF
chk "planted: 10 revocations that are malformed or match nothing are refused (exit 2), never CLEAN" bash -c '[ "$1" = 10 ] && [ "$2" = 10 ]' _ "$tried" "$n"
chk "planted: the JSON API refuses an unmatched revocation (ok false, UNMATCHED)" python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["ok"] is False and "UNMATCHED" in d["error"]' "$(python3 -c 'import json,sys; print(json.dumps({"op":"taint","doc":json.load(open(sys.argv[1])),"pubkey":sys.argv[2],"revoked":{"steps":[7]}}))' "$H" "$PUB" | "$C" call)"
chk "planted: taint refuses to clear an edited handoff (exit 1, not computed)" bash -c 'O="$("$1" taint "$2" --pubkey "$3" --revoked "$4")"; [ $? = 1 ] && grep -q "taint not computed" <<<"$O"' _ "$C" "$W/e.json" "$PUB" "$W/rev2.json"

# ---------------------------------------------------------------- regression against 0.1.0
if [ -n "$OLD" ] && [ -x "$OLD" ]; then
  printf '{"z":1,"a":[1.5,1e-05,"caf\\u00e9",true,null],"m":{"y":"\\u2028","b":-0}}\n' >"$W/sample.json"
  same=1; for d in py-u8 py-ascii chap py-indent2; do cmp -s <("$OLD" canon --dialect "$d" "$W/sample.json" 2>&1) <("$C" canon --dialect "$d" "$W/sample.json" 2>&1) || same=0; done
  chk "regression: canon output identical to 0.1.0 in all four dialects" test "$same" = 1
  python3 "$HERE/diff_existing_formats.py" "$W/diff.jsonl" 1500; nd=0; nl=0
  while IFS= read -r q; do nl=$((nl+1)); [ "$("$OLD" call <<<"$q" 2>&1)" = "$("$C" call <<<"$q" 2>&1)" ] || nd=$((nd+1)); done <"$W/diff.jsonl"
  chk "regression: 1,500 random requests across the five existing formats and junk give byte-identical responses to 0.1.0" bash -c '[ "$1" = 1500 ] && [ "$2" = 0 ]' _ "$nl" "$nd"
  if [ -n "$REL" ] && [ -x "$REL" ]; then
    chk "regression: the byoai-release proof stays green with 0.2.0" bash -c 'bash "$1/proof_release.sh" "$2" "$3" | tail -1 | grep -q ^RELEASE_PROOF_GREEN' _ "$HERE" "$REL" "$C"
    mkdir -p "$W/rel" && echo a >"$W/rel/a"; RP="$(cd "$W" && "$REL" keygen --out "$W/rk.hex" | sed -n 's/^PUBKEY //p')"; "$REL" seal "$W/rel" --key "$W/rk.hex" --repo x/y --release v0 >/dev/null 2>&1
    A1="$("$OLD" verify --format vdecl-seal "$W/rel/RECEIPT.json" --pubkey "${RP:-none}" --json 2>&1)"; A2="$("$C" verify --format vdecl-seal "$W/rel/RECEIPT.json" --pubkey "${RP:-none}" --json 2>&1)"
    chk "regression: vdecl-seal --json verdict ok and byte-identical to 0.1.0" bash -c '[ -n "$1" ] && [ "$1" = "$2" ] && grep -q "\"ok\":true" <<<"$1"' _ "$A1" "$A2"
  else skip 2 "no byoai-release binary: release regression not run"; fi
else skip 4 "no 0.1.0 baseline binary: regression not run"; fi

# ---------------------------------------------------------------- memory safety
# The handoff path must stay safe Rust: then the compiler rules out use-after-free and overruns,
# and the heap test (tests/heap_handoff.rs, with a deliberate-leak control) covers leaks.
SRC="$HERE/../byoai-chain/src"; FILES="handoff.rs api.rs value.rs dialects.rs main.rs"
nounsafe() { local d="$1" f; for f in $FILES; do [ -f "$d/$f" ] && grep -q '^#!\[forbid(unsafe_code)\]' "$d/$f" && ! grep -qw unsafe "$d/$f" || return 1; done; }
chk "memory safety: every handoff-path source file forbids unsafe code and contains none" nounsafe "$SRC"
mkdir -p "$W/srcu" && for f in $FILES; do cp "$SRC/$f" "$W/srcu/"; done; printf '\nfn planted() { unsafe { } }\n' >>"$W/srcu/handoff.rs"
planted_unsafe_caught() { ! cmp -s "$SRC/handoff.rs" "$W/srcu/handoff.rs" && ! nounsafe "$W/srcu"; }
chk "planted: an unsafe block added to handoff.rs is caught (edit really changed the file)" planted_unsafe_caught

chk "nothing was written to HOME" bash -c '[ -z "$(ls -A "$1")" ]' _ "$HOME"

echo; T=$((P+F+S))
if [ "$F" -gt 0 ]; then echo "$F of $T failed"; echo "PROOF_RED"; exit 1
elif [ "$S" -gt 0 ]; then echo "$P passed, $S checks skipped of $T"; echo "PROOF_GREEN_WITH_SKIPS"
else echo "$P/$T passed"; echo "PROOF_GREEN"; fi
