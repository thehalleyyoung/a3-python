#!/usr/bin/env python3
"""Quick check: what bug types does baseline report on each FP case?"""
from pathlib import Path
from a3_python.analyzer import Analyzer

fps = [
    ("BOUNDS", "tn_01_index_with_bounds_check.py"),
    ("BOUNDS", "tn_03_range_based_iteration.py"),
    ("BOUNDS", "tn_04_enumerate_safe_access.py"),
    ("ASSERT_FAIL", "tn_03_debug_only_assertions.py"),
    ("ASSERT_FAIL", "tn_05_loop_invariant_maintained.py"),
    ("FP_DOMAIN", "tn_03_asin_clamped.py"),
    ("NULL_PTR", "tn_03_type_narrowing_isinstance.py"),
    ("PANIC", "tn_03_exception_chaining.py"),
    ("STACK_OVERFLOW", "tn_02_iterative_conversion.py"),
    ("UNINIT_MEMORY", "tn_02_default_init_in_constructor.py"),
    ("DOUBLE_FREE", "tn_01_single_close_guard.py"),
    ("DOUBLE_FREE", "tn_02_idempotent_cleanup.py"),
    ("DOUBLE_FREE", "tn_03_context_manager_proper.py"),
    ("DOUBLE_FREE", "tn_04_flag_based_prevention.py"),
    ("DOUBLE_FREE", "tn_05_separate_resources.py"),
]

for cat, fname in fps:
    p = Path(f"tests/synthetic_suite/{cat}/{fname}")
    a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=True)
    r = a.analyze_file(p)
    bt = getattr(r, "bug_type", "?") or "?"
    print(f"{cat:20s} {fname:50s} verdict={r.verdict:7s} reported_bug={bt}")
