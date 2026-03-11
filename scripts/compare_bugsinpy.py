#!/usr/bin/env python3
"""Compare old vs new BugsInPy eval results."""
import json, sys

old_path = "results/bugsinpy_eval_20260228_135813.json"
new_path = "results/bugsinpy_eval_post_fix.json"

with open(old_path) as f:
    old = json.load(f)
with open(new_path) as f:
    new = json.load(f)

old_keras = {r["bug_id"]: r for r in old if r["project"] == "keras"}
new_keras = {r["bug_id"]: r for r in new if r["project"] == "keras"}

print("Bug# | Old Classification     | New Classification     | Changed?")
print("-----|------------------------|------------------------|--------")
diffs = 0
for bid in sorted(old_keras.keys()):
    old_cls = old_keras[bid]["classification"]
    new_cls = new_keras.get(bid, {}).get("classification", "MISSING")
    changed = old_cls != new_cls
    if changed:
        diffs += 1
    mark = " <-- CHANGED" if changed else ""
    print(f"  {bid:2d} | {old_cls:22s} | {new_cls:22s} |{mark}")

print(f"\nTotal differences: {diffs}")
print()

for label, data in [
    ("Old (Feb 28)", old),
    ("New (post-fix, keras only)", [r for r in new if r["project"] == "keras"]),
    ("New (all projects)", new),
]:
    tp = sum(1 for r in data if r["classification"] == "TRUE_POSITIVE")
    fn = sum(1 for r in data if r["classification"] == "FALSE_NEGATIVE")
    fp = sum(1 for r in data if r["classification"] == "FALSE_POSITIVE")
    bb = sum(1 for r in data if r["classification"] == "BOTH_BUG")
    np_ = sum(1 for r in data if r["classification"] == "NO_PATCH")
    err = sum(1 for r in data if r["classification"] == "ERROR")
    total = len(data)
    det_denom = tp + fn + bb
    det_rate = f"{tp/det_denom*100:.1f}%" if det_denom else "N/A"
    print(f"{label}: TP={tp} FN={fn} FP={fp} BB={bb} NP={np_} ERR={err} Total={total}  DetRate={det_rate}")
