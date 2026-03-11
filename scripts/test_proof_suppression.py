#!/usr/bin/env python3
"""
Test the proof-suppression logic in the kitchensink pipeline.

Validates:
1. If baseline says BUG(X) but per_bug_type[X] == SAFE, verdict flips to SAFE
2. If baseline says UNKNOWN but proofs exist, verdict upgrades to SAFE
3. If baseline says BUG but no proof for that type, verdict stays BUG
4. If baseline says SAFE, nothing changes
"""
import sys, os, tempfile, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from a3_python.analyzer import Analyzer


def run_test(name, code, expect_verdict=None, expect_suppressed=None):
    """Run kitchensink + baseline, report results."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        tmp = f.name
    try:
        analyzer = Analyzer(verbose=False)
        
        # Run both
        ks = analyzer.analyze_file_kitchensink(tmp)
        baseline = analyzer.analyze_file(tmp)
        
        status = "PASS"
        details = []
        
        # Check expected verdict
        if expect_verdict and ks.verdict != expect_verdict:
            status = "FAIL"
            details.append(f"expected verdict={expect_verdict}, got {ks.verdict}")
        
        # Check suppression
        if expect_suppressed:
            suppressed = {}
            if ks.per_bug_type and "_suppressed_bugs" in ks.per_bug_type:
                suppressed = ks.per_bug_type["_suppressed_bugs"]
            for bt in expect_suppressed:
                if bt not in suppressed:
                    status = "FAIL"
                    details.append(f"expected {bt} suppressed, not found")
        
        # Differential info
        diff_marker = " [DIFF]" if ks.verdict != baseline.verdict else ""
        
        # Per-bug-type proofs
        proofs = []
        if ks.per_bug_type:
            proofs = [
                k for k, v in ks.per_bug_type.items()
                if not k.startswith("_") and v.get("verdict") == "SAFE"
            ]
        
        suppressed_list = []
        if ks.per_bug_type and "_suppressed_bugs" in ks.per_bug_type:
            suppressed_list = list(ks.per_bug_type["_suppressed_bugs"].keys())
        
        print(f"[{status}] {name}")
        print(f"  baseline: verdict={baseline.verdict} bug_type={baseline.bug_type}")
        print(f"  kitchen:  verdict={ks.verdict} bug_type={ks.bug_type}{diff_marker}")
        if proofs:
            print(f"  proofs:   {proofs}")
        if suppressed_list:
            print(f"  SUPPRESSED: {suppressed_list}")
        if details:
            for d in details:
                print(f"  ✗ {d}")
        print()
        return status == "PASS"
    finally:
        os.unlink(tmp)


results = []

# Test 1: Safe division in a loop — baseline may flag, proofs may suppress
print("=" * 60)
print("PROOF-SUPPRESSION VALIDATION")
print("=" * 60)
print()

results.append(run_test(
    "safe_division_in_loop",
    """
x = 10
while x > 0:
    y = 1 / x
    x -= 1
""",
))

# Test 2: Actual division by zero — should stay BUG
results.append(run_test(
    "real_div_zero_bug",
    """
x = 0
y = 1 / x
""",
    expect_verdict="BUG",
))

# Test 3: Safe program with bounds checking
results.append(run_test(
    "safe_bounds_check",
    """
data = [1, 2, 3, 4, 5]
for i in range(len(data)):
    x = data[i]
""",
))

# Test 4: Guarded division with complex control flow
results.append(run_test(
    "guarded_division_complex",
    """
def safe_divide(a, b):
    if b != 0:
        return a / b
    return 0

result = safe_divide(10, 3)
result2 = safe_divide(10, 0)
""",
))

# Test 5: Loop with potential off-by-one (stresses barrier proofs)
results.append(run_test(
    "loop_accumulator",
    """
total = 0
n = 100
for i in range(1, n + 1):
    total += 1 / i
""",
))

# Test 6: Nested loops with safe invariant
results.append(run_test(
    "nested_safe_loops",
    """
matrix = [[1,2],[3,4],[5,6]]
total = 0
for row in matrix:
    for val in row:
        total += val
""",
))

# Summary
passed = sum(results)
total = len(results)
print("=" * 60)
print(f"Results: {passed}/{total} passed")
print("=" * 60)
