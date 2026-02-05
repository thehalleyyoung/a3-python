#!/usr/bin/env python3
"""Test the short-circuit evaluation tracking with real-world patterns."""

from pyfromscratch.semantics.bytecode_summaries import BytecodeAbstractInterpreter, Emptiness

# Real-world pattern 1: DeepSpeed-like (SAFE because of len check first)
def safe_pattern(child_params):
    if len(child_params) > 0 and child_params[0].numel() == 0:
        return True
    return False

# Real-world pattern 2: Buggy pattern (accessing index without guard)
def buggy_or_pattern(x):
    # This is buggy because if x is falsy, x[0] will fail
    if x or x[0]:
        return 1
    return 0

# Real-world pattern 3: Safe AND pattern
def safe_and_pattern(x):
    # This is safe because x must be truthy when x[0] is evaluated
    if x and x[0]:
        return 1
    return 0

# Real-world pattern 4: Buggy NOT pattern
def buggy_not_or_pattern(results):
    # If results is empty, results[0] will fail
    if not results or results[0] is None:
        return None
    return results[0]

# Real-world pattern 5: Safe because of explicit len check
def safe_len_check(items):
    if len(items) == 0 or items[0] is None:
        return None
    return items[0]

# Real-world pattern 6: Buggy - indexing without any guard
def buggy_no_guard(data):
    return data[0]

patterns = [
    (safe_pattern, "len > 0 and x[0] (SAFE)", False),
    (buggy_or_pattern, "x or x[0] (BUG)", True),
    (safe_and_pattern, "x and x[0] (SAFE)", False),
    # Note: 'not x or x[0]' is actually SAFE - if we reach x[0], x was truthy
    (buggy_not_or_pattern, "not x or x[0] (SAFE - x truthy)", False),
    # Now correctly tracked - len == 0 being false means non-empty
    (safe_len_check, "len == 0 or x[0] (SAFE - now tracked!)", False),
    (buggy_no_guard, "x[0] no guard (LOW CONF expected)", True),
]

print("Testing short-circuit evaluation tracking:\n")

for func, desc, expect_bug in patterns:
    analyzer = BytecodeAbstractInterpreter(
        code=func.__code__,
        func_name=func.__name__,
        qualified_name=func.__name__,
        callee_summaries={},
    )
    summary = analyzer.analyze()
    
    high_conf_bounds = [b for b in analyzer.potential_bugs 
                        if b.bug_type == 'BOUNDS' and b.confidence >= 0.7]
    low_conf_bounds = [b for b in analyzer.potential_bugs 
                       if b.bug_type == 'BOUNDS' and b.confidence < 0.7]
    
    has_any_bounds = bool(high_conf_bounds or low_conf_bounds)
    status = "✓" if (has_any_bounds == expect_bug) else "✗"
    print(f"{status} {desc}")
    if high_conf_bounds:
        for b in high_conf_bounds:
            print(f"    HIGH CONF: BOUNDS at line {b.line_number}, confidence={b.confidence}")
    if low_conf_bounds:
        for b in low_conf_bounds:
            print(f"    LOW CONF: BOUNDS at line {b.line_number}, confidence={b.confidence}")
    if not (high_conf_bounds or low_conf_bounds):
        print(f"    No BOUNDS bugs found")
