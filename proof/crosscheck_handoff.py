"""Independent Python check of a byoai.handoff/0.1 receipt (proof helper, not shipped as a tool).

  crosscheck_handoff.py check   <handoff.json> <pubkey_hex>   -> prints XCHECK_OK or XCHECK_FAIL <why>
  crosscheck_handoff.py relabel <handoff.json> <key.pem> <out> -> launders identity to ID_VERIFIED and re-signs
                                                                (a planted defect: the Rust verifier must refuse it)
  crosscheck_handoff.py resign  <handoff.json> <key.pem> <out> -> recomputes row_sha chain, rows, head, pid and the
                                                                signature over whatever the file now holds, so a
                                                                planted edit is caught for its own reason, not SIGNATURE
Recomputes, in Python, exactly what the Rust code hashes and signs: canon = json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=False); row_sha chain; pid; Ed25519 over canon(doc["handoff"]).
"""
import hashlib
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def check(path, pub_hex):
    d = json.load(open(path, encoding="utf-8"))
    h = d["handoff"]
    prev = "0" * 64
    for i, row in enumerate(h["steps"]):
        body = {k: v for k, v in row.items() if k != "row_sha"}
        if row["seq"] != i or row["prev_sha"] != prev or sha(canon(body).encode()) != row["row_sha"]:
            return f"row {i}"
        prev = row["row_sha"]
    if h["head"] != prev or h["rows"] != len(h["steps"]):
        return "anchor"
    if d["pid"] != sha(canon({"r": h["case"], "v": prev}).encode())[:24]:
        return "pid"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(d["sig"]["sig_hex"]), canon(h).encode())
    except Exception:
        return "signature"
    return None


def relabel(path, pem, out):
    d = json.load(open(path, encoding="utf-8"))
    d["handoff"]["identity"] = "ID_VERIFIED"
    sk = load_pem_private_key(open(pem, "rb").read(), password=None)
    d["sig"]["sig_hex"] = sk.sign(canon(d["handoff"]).encode()).hex()
    open(out, "w", encoding="utf-8").write(json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def resign(path, pem, out):
    d = json.load(open(path, encoding="utf-8"))
    h = d["handoff"]
    prev = "0" * 64
    for i, row in enumerate(h["steps"]):
        row["seq"] = i
        row["prev_sha"] = prev
        row.pop("row_sha", None)
        row["row_sha"] = prev = sha(canon(row).encode())
    h["rows"] = len(h["steps"])
    h["head"] = prev
    d["pid"] = sha(canon({"r": h["case"], "v": prev}).encode())[:24]
    sk = load_pem_private_key(open(pem, "rb").read(), password=None)
    d["sig"]["sig_hex"] = sk.sign(canon(h).encode()).hex()
    open(out, "w", encoding="utf-8").write(json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    if sys.argv[1] == "check":
        why = check(sys.argv[2], sys.argv[3])
        print("XCHECK_OK" if why is None else f"XCHECK_FAIL {why}")
        sys.exit(0 if why is None else 1)
    elif sys.argv[1] == "resign":
        resign(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        relabel(sys.argv[2], sys.argv[3], sys.argv[4])
