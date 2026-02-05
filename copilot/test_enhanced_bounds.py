#!/usr/bin/env python3
"""Test enhanced BOUNDS detection with length tracking."""

from pyfromscratch.semantics.bytecode_summaries import BytecodeAbstractInterpreter

# Test 1: len > 2 check should make x[1] safe
def test_len_gt_2(x):
    if len(x) > 2:
        return x[1]  # Should be SAFE
    return 0

# Test 2: len == 5 check should make x[3] safe but x[5] unsafe
def test_len_eq_5(x):
    if len(x) == 5:
        a = x[3]  # Should be SAFE (index 3 < length 5)
        b = x[5]  # Should be BUG (index 5 >= length 5)
    return 0

# Test 3: No check should flag x[2] as uncertain
def test_no_guard(x):
    return x[2]  # Should be LOW CONFIDENCE BUG

# Test 4: len >= 1 makes x[0] safe but x[1] uncertain
def test_len_ge_1(x):
    if len(x) >= 1:
        a = x[0]  # Should be SAFE
        b = x[1]  # Should be uncertain/low conf
    return 0

# Test 5: Empty list obvious bug
def test_empty_list():
    x = []
    return x[0]  # Should be HIGH CONFIDENCE BUG

tests = [
    (test_len_gt_2, "len > 2, access x[1] (SAFE)"),
    (test_len_eq_5, "len == 5, access x[3] (SAFE) and x[5] (BUG)"),
    (test_no_guard, "no guard, access x[2] (LOW CONF BUG)"),
    (test_len_ge_1, "len >= 1, access x[0] (SAFE) and x[1] (uncertain)"),
    (test_empty_list, "x = [], access x[0] (HIGH CONF BUG)"),
]

print("Testing enhanced BOUNDS detection:\n")

for func, desc in tests:
    analyzer = BytecodeAbstractInterpreter(
        code=func.__code__,
        func_name=func.__name__,
        qualified_name=func.__name__,
        callee_summaries={},
    )
    summary = analyzer.analyze()
    
    bounds_bugs = [b for b in analyzer.potential_bugs if b.bug_type == 'BOUNDS']
    
    print(f"{desc}")
    print(f"  Function: {func.__name__}")
    if bounds_bugs:
        for bug in bounds_bugs:
            guarded_str = " (guarded)" if bug.is_guarded else ""
            print(f"    BOUNDS at line {bug.line_number}, confidence={bug.confidence:.2f}{guarded_str}")
    else:
        print(f"    No BOUNDS bugs found")
    print()
