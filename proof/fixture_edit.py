"""Proof helper: fixture_edit.py <in.json> <out.json> "<python statements on d>" (writes a tampered copy)."""
import json
import sys

d = json.load(open(sys.argv[1], encoding="utf-8"))
exec(sys.argv[3], {"d": d})
json.dump(d, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False)
