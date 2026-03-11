#!/usr/bin/env python3
"""Check counterexample details for FP cases."""
from pathlib import Path
from a3_python.analyzer import Analyzer

fps = [
    ("BOUNDS", "tn_01_index_with_bounds_check.py"),
    ("BOUNDS", "tn_03_range_based_iteration.py"),
    ("FP_DOMAIN", "tn_03_asin_clamped.py"),
    ("NULL_PTR", "tn_03_type_narrowing_isinstance.py"),
    ("DOUBLE_FREE", "tn_01_single_close_guard.py"),
]

for cat, fname in fps:
    p = Path(f"tests/synthetic_suite/{cat}/{fname}")
    a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=True)
    r = a.analyze_file(p)
    if r.verdict != "BUG":
        continue
    ce = r.counterexample or {}
    dse_val = ce.get("dse_validated", "?")
    dse_status = ce.get("dse_result", {}).get("status", "?")
    final = ce.get("final_state", {})
    exc = final.get("exception", "?")
    tc_reached = final.get("type_confusion_reached", "?")
    print(f"{cat:15s} {fname:50s}  bug={r.bug_type:20s} dse_validated={dse_val}  dse_status={dse_status}  exc={exc}  tc={tc_reached}")
