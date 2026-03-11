#!/usr/bin/env python3
"""Test the kitchensink FP fixes on the 15 persistent FP cases + all TPs."""
from pathlib import Path
from a3_python.analyzer import Analyzer

# The 15 persistent FP cases (expected SAFE, baseline says BUG)
fp_cases = [
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

# Also the intermittent FP
fp_cases.append(("NULL_PTR", "tn_05_all_paths_assign_non_none.py"))

print("=== FP cases (expected: SAFE) ===")
fixed = 0
still_fp = 0
for cat, fname in fp_cases:
    p = Path(f"tests/synthetic_suite/{cat}/{fname}")
    a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=True)
    r = a.analyze_file_kitchensink(p)
    status = "FIXED ✓" if r.verdict == "SAFE" else "STILL FP ✗"
    if r.verdict == "SAFE":
        fixed += 1
    else:
        still_fp += 1
    print(f"  {status:12s} {cat:20s} {fname:50s} verdict={r.verdict}")

print(f"\n  Fixed: {fixed}/{len(fp_cases)}, Still FP: {still_fp}/{len(fp_cases)}")

# Now check that NO true positives were broken
print("\n=== TP spot-checks (expected: BUG) ===")
tp_cases = [
    ("DIV_ZERO", "tp_01_direct_literal.py"),
    ("DIV_ZERO", "tp_05_conditional_path_to_zero.py"),
    ("BOUNDS", "tp_01_list_index_out_of_range.py"),
    ("NULL_PTR", "tp_01_method_call_on_none.py"),
    ("ASSERT_FAIL", "tp_01_unconditional_assert_false.py"),
    ("DOUBLE_FREE", "tp_03_nested_context_double_exit.py"),
    ("PANIC", "tp_01_unhandled_exception.py"),
    ("FP_DOMAIN", "tp_01_sqrt_negative.py"),
]

tp_ok = 0
tp_broken = 0
for cat, fname in tp_cases:
    p = Path(f"tests/synthetic_suite/{cat}/{fname}")
    a = Analyzer(verbose=False, enable_concolic=True, enable_interprocedural=True)
    r = a.analyze_file_kitchensink(p)
    status = "OK ✓" if r.verdict == "BUG" else "BROKEN ✗"
    if r.verdict == "BUG":
        tp_ok += 1
    else:
        tp_broken += 1
    print(f"  {status:12s} {cat:20s} {fname:50s} verdict={r.verdict}")

print(f"\n  TP OK: {tp_ok}/{len(tp_cases)}, TP Broken: {tp_broken}/{len(tp_cases)}")
