"""Differential requests for the five existing formats (and junk), for an old-vs-new comparison.
Adapted from the independent reviewer's diffgen.py (2026-11-25). Usage: diff_existing_formats.py <out.jsonl> [n]"""
import hashlib, json, random, sys
random.seed(7)
def rnd(d=0):
    r = random.random()
    if d > 3 or r < 0.3: return random.choice([None, True, False, 0, -0, 1, 2**80, 1.5, 1e-05, 1e16, -2.5, "", "é", " ", "a\"b\\", "x"*3])
    if r < 0.6: return [rnd(d+1) for _ in range(random.randint(0, 3))]
    return {random.choice(["a", "z", "seq", "prev", "hash", "row_sha", "prev_sha", "é"]): rnd(d+1) for _ in range(random.randint(0, 3))}
def canon(v): return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
G = "0"*64
out = open(sys.argv[1], "w")
for i in range(int(sys.argv[2]) if len(sys.argv) > 2 else 3000):
    k = random.choice(["canon", "gate", "verifylog", "tfx", "chap", "vr", "vs", "bad"])
    if k == "canon": q = {"op": "canon", "dialect": random.choice(["py-u8", "py-ascii", "chap", "py-indent2", "nope"]), "text": json.dumps(rnd())}
    elif k == "gate": q = {"op": "verify", "format": "gate", "rows": [{"seq": j+1, "body": json.dumps({"seq": j+1}), "prev": G, "hash": G} for j in range(random.randint(0, 2))]}
    elif k == "verifylog": q = {"op": "verify", "format": "verifylog", "text": "\n".join(json.dumps(rnd()) for _ in range(2))}
    elif k == "tfx":
        rows = []; prev = G
        for j in range(random.randint(0, 3)):
            r = {"seq": j, "prev_sha": prev, "x": rnd()}; s = hashlib.sha256(canon(r).encode()).hexdigest(); r["row_sha"] = s; prev = s; rows.append(r)
        if rows and random.random() < 0.5: rows[-1]["x"] = "tamper"
        q = {"op": "verify", "format": "tfx", "text": "\n".join(json.dumps(r) for r in rows), "anchor": random.choice([None, {"rows": len(rows), "head": prev}, rnd()])}
    elif k == "chap": q = {"op": "verify", "format": "chap", "entries": [rnd() for _ in range(2)]}
    elif k == "vr": q = {"op": "verify", "format": "vdecl-receipt", "receipt": rnd(), "pubkey": random.choice(["00"*32, "zz", ""])}
    elif k == "vs": q = {"op": "verify", "format": "vdecl-seal", "seal": rnd(), "pubkey": random.choice(["00"*32, "zz", ""])}
    else: q = rnd()
    out.write(json.dumps(q) + "\n")
