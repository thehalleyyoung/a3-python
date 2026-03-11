#!/usr/bin/env python3
"""Check: do TP cases crash when run concretely? (for concrete exec filter safety)"""
import subprocess, json
from pathlib import Path

suite = Path("tests/synthetic_suite")
manifest = json.load(open(suite / "GROUND_TRUTH_MANIFEST.json"))

tp_crash = 0
tp_ok = 0
tn_crash = 0
tn_ok = 0

for bt, files in manifest["bug_types"].items():
    for fname, info in files.items():
        fpath = suite / bt / fname
        if not fpath.exists():
            continue
        expected = info["expected"]
        try:
            proc = subprocess.run(
                ["/opt/homebrew/bin/python3.11", str(fpath)],
                capture_output=True, timeout=5,
            )
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            rc = -1  # timeout
        except Exception:
            rc = -2

        if expected == "BUG":
            if rc != 0:
                tp_crash += 1
            else:
                tp_ok += 1
                print(f"  TP runs clean: {bt}/{fname}")
        else:
            if rc != 0:
                tn_crash += 1
                print(f"  TN crashes!:   {bt}/{fname}  rc={rc}")
            else:
                tn_ok += 1

print(f"\nBUG cases: {tp_crash} crash, {tp_ok} run clean")
print(f"SAFE cases: {tn_ok} run clean, {tn_crash} crash")
print(f"Concrete filter would convert {tp_ok} TP→FN (false negatives)")
print(f"Concrete filter would convert {tn_crash} TN→FP (false positives kept)")
