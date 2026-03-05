#!/usr/bin/env python3
"""Quick validation of opcode implementations."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a3_python.analyzer import Analyzer

test_cases = [
    ('tests/synthetic_suite/ASSERT_FAIL/tn_01_always_true_condition.py', 'SAFE'),
    ('tests/synthetic_suite/ASSERT_FAIL/tp_01_unconditional_assert_false.py', 'BUG'),
    ('tests/synthetic_suite/DIV_ZERO/tn_01_nonzero_check.py', 'SAFE'),
    ('tests/synthetic_suite/DIV_ZERO/tp_01_direct_literal.py', 'BUG'),
    ('tests/synthetic_suite/NULL_PTR/tn_01_none_check_before_use.py', 'SAFE'),
    ('tests/synthetic_suite/NULL_PTR/tp_01_method_call_on_none.py', 'BUG'),
]

a = Analyzer(timeout_ms=10000, verbose=False)
for path, expected in test_cases:
    try:
        result = a.analyze_file(path)
        verdict = result.verdict if hasattr(result, 'verdict') else str(result)
        v = str(verdict)
        if ('SAFE' in v and expected == 'SAFE') or ('BUG' in v and expected == 'BUG'):
            ok = 'PASS'
        else:
            ok = 'FAIL'
        fname = os.path.basename(path)
        print(f'{ok}  {fname:45s}  expected={expected:4s}  got={v}')
    except Exception as e:
        fname = os.path.basename(path)
        print(f'FAIL {fname:45s}  expected={expected:4s}  ERROR={e}')
