#!/usr/bin/env python3
"""Quick run on a handful of test files to validate opcode support."""
import json, os, sys, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a3_python.analyzer import Analyzer

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "tests", "synthetic_suite")
manifest_path = os.path.join(BASE, "GROUND_TRUTH_MANIFEST.json")
with open(manifest_path) as f:
    manifest = json.load(f)

CATEGORIES = ["ASSERT_FAIL", "DIV_ZERO", "NULL_PTR", "BOUNDS", "PANIC"]
a = Analyzer(timeout_ms=8000, verbose=False)

tp = fp = tn = fn = unk_bug = unk_safe = err = 0

for cat in CATEGORIES:
    files = manifest.get("bug_types", {}).get(cat, {})
    for filename, info in files.items():
        expected = info["expected"]
        full_path = os.path.join(BASE, cat, filename)
        if not os.path.exists(full_path):
            continue
        try:
            result = a.analyze_file(full_path)
            verdict = str(result.verdict) if hasattr(result, 'verdict') else str(result)
        except Exception as e:
            verdict = "ERROR"
            err += 1

        is_bug = "BUG" in verdict
        is_safe = "SAFE" in verdict

        if expected == "BUG":
            if is_bug: tp += 1
            elif is_safe: fn += 1; print(f"  FN {cat}/{filename}")
            else: unk_bug += 1
        else:
            if is_safe: tn += 1
            elif is_bug: fp += 1; print(f"  FP {cat}/{filename}")
            else: unk_safe += 1

        tag = "OK" if ((is_bug and expected=="BUG") or (is_safe and expected=="SAFE")) else "XX"
        sys.stdout.write(f"  {tag} {cat}/{filename:45s} exp={expected:4s} got={verdict}\n")
        sys.stdout.flush()

print(f"\n=== SUMMARY ({', '.join(CATEGORIES)}) ===")
print(f"TP={tp}  TN={tn}  FP={fp}  FN={fn}  UNK_BUG={unk_bug}  UNK_SAFE={unk_safe}  ERR={err}")
total_known = tp+fp+tn+fn
if tp+fp > 0: print(f"Precision: {tp/(tp+fp):.3f}")
if tp+fn > 0: print(f"Recall:    {tp/(tp+fn):.3f}")
if total_known > 0: print(f"Accuracy:  {(tp+tn)/total_known:.3f}")
