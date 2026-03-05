#!/usr/bin/env python3.11
"""Diagnose all A3 failure cases — what bug_type is being reported."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from a3_python.analyzer import Analyzer

a = Analyzer(timeout_ms=10000, verbose=False)

cases = [
    # FALSE POSITIVES (A3 says BUG, truth is SAFE)
    ('FP', 'tests/synthetic_suite/PANIC/tn_01_proper_exception_handling.py'),
    ('FP', 'tests/synthetic_suite/PANIC/tn_02_graceful_degradation.py'),
    ('FP', 'tests/synthetic_suite/PANIC/tn_03_exception_chaining.py'),
    ('FP', 'tests/synthetic_suite/DIV_ZERO/tn_03_exception_handler.py'),
    ('FP', 'tests/synthetic_suite/NULL_PTR/tn_03_type_narrowing_isinstance.py'),
    ('FP', 'tests/synthetic_suite/FP_DOMAIN/tn_03_asin_clamped.py'),
    ('FP', 'tests/synthetic_suite/FP_DOMAIN/tn_04_exception_handler.py'),
    ('FP', 'tests/synthetic_suite/BOUNDS/tn_03_range_based_iteration.py'),
    ('FP', 'tests/synthetic_suite/BOUNDS/tn_04_enumerate_safe_access.py'),
    ('FP', 'tests/synthetic_suite/ASSERT_FAIL/tn_03_debug_only_assertions.py'),
    ('FP', 'tests/synthetic_suite/ASSERT_FAIL/tn_05_loop_invariant_maintained.py'),
    ('FP', 'tests/synthetic_suite/UNINIT_MEMORY/tn_04_try_except_both_branches.py'),
    ('FP', 'tests/synthetic_suite/DOUBLE_FREE/tn_01_single_close_guard.py'),
    ('FP', 'tests/synthetic_suite/STACK_OVERFLOW/tn_02_iterative_conversion.py'),
    # FALSE NEGATIVES (A3 says SAFE, truth is BUG)
    ('FN', 'tests/synthetic_suite/BOUNDS/tp_01_list_index_out_of_range.py'),
    ('FN', 'tests/synthetic_suite/BOUNDS/tp_02_negative_index_beyond_length.py'),
    ('FN', 'tests/synthetic_suite/BOUNDS/tp_03_dict_missing_key.py'),
    ('FN', 'tests/synthetic_suite/BOUNDS/tp_04_computed_index_overflow.py'),
    ('FN', 'tests/synthetic_suite/BOUNDS/tp_05_tuple_indexing_past_end.py'),
    ('FN', 'tests/synthetic_suite/UNINIT_MEMORY/tp_01_variable_used_before_assignment.py'),
    ('FN', 'tests/synthetic_suite/UNINIT_MEMORY/tp_03_loop_conditional_init.py'),
    ('FN', 'tests/synthetic_suite/UNINIT_MEMORY/tp_05_class_attribute_uninitialized.py'),
    ('FN', 'tests/synthetic_suite/NULL_PTR/tp_02_attribute_access_on_none_return.py'),
    ('FN', 'tests/synthetic_suite/DOUBLE_FREE/tp_02_socket_double_close.py'),
]

print(f"{'Tag':3s}  {'Verdict':7s}  {'BugType':25s}  File")
print("-" * 90)
for tag, path in cases:
    try:
        r = a.analyze_file(path)
        v = str(r.verdict) if hasattr(r, 'verdict') else str(r)
        bt = str(getattr(r, 'bug_type', ''))
    except Exception as e:
        v = 'ERROR'
        bt = str(e)[:40]
    fname = path.split('synthetic_suite/')[-1]
    print(f'{tag:3s}  {v:7s}  {bt:25s}  {fname}')
