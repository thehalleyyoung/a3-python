#!/usr/bin/env python3
"""Run A3 on the full synthetic_suite and compare against ground truth."""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a3_python.analyzer import Analyzer

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "tests", "synthetic_suite")
manifest_path = os.path.join(BASE, "GROUND_TRUTH_MANIFEST.json")
with open(manifest_path) as f:
    manifest = json.load(f)

a = Analyzer(timeout_ms=10000, verbose=False)

tp = fp = tn = fn = unknown_on_bug = unknown_on_safe = 0
errors = []

for bug_type, files in manifest.get("bug_types", {}).items():
    for filename, info in files.items():
        expected = info["expected"]  # "BUG" or "SAFE"
        full_path = os.path.join(BASE, bug_type, filename)
        if not os.path.exists(full_path):
            continue

    try:
        result = a.analyze_file(full_path)
        verdict = str(result.verdict) if hasattr(result, 'verdict') else str(result)
    except Exception as e:
        verdict = f"ERROR:{e}"

    is_bug = "BUG" in verdict
    is_safe = "SAFE" in verdict
    is_unknown = (not is_bug and not is_safe)

    if expected == "BUG":
        if is_bug:
            tp += 1
        elif is_safe:
            fn += 1
            errors.append(f"FN  {bug_type}/{filename}: expected BUG got {verdict}")
        else:
            unknown_on_bug += 1
    else:  # expected SAFE
        if is_safe:
            tn += 1
        elif is_bug:
            fp += 1
            errors.append(f"FP  {bug_type}/{filename}: expected SAFE got {verdict}")
        else:
            unknown_on_safe += 1

total = tp + fp + tn + fn + unknown_on_bug + unknown_on_safe
print(f"Total: {total}")
print(f"  TP (bug found):    {tp}")
print(f"  TN (safe proven):  {tn}")
print(f"  FP (false alarm):  {fp}")
print(f"  FN (missed bug):   {fn}")
print(f"  UNKNOWN on BUG:    {unknown_on_bug}")
print(f"  UNKNOWN on SAFE:   {unknown_on_safe}")
if tp + fp > 0:
    print(f"  Precision:         {tp/(tp+fp):.3f}")
if tp + fn > 0:
    print(f"  Recall:            {tp/(tp+fn):.3f}")
if tp + fp + tn + fn > 0:
    acc = (tp + tn) / (tp + fp + tn + fn)
    print(f"  Accuracy (known):  {acc:.3f}")

if errors:
    print(f"\n--- Errors ({len(errors)}) ---")
    for e in errors[:20]:
        print(f"  {e}")
