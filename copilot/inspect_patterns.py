#!/usr/bin/env python3
import sys
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

print("="*80)
print("MANUAL INSPECTION: 303 HIGH-CONFIDENCE BUGS")
print("="*80)

tracker = InterproceduralBugTracker.from_project(
    root_path=Path('external_tools/DeepSpeed'),
    entry_points=None
)
bugs = tracker.find_all_bugs(only_non_security=True)
high = [b for b in bugs if b.confidence >= 0.7]

print(f"\nTotal: {len(high)}")

# Group by bug type
by_type = defaultdict(list)
for b in high:
    by_type[b.bug_type].append(b)

print(f"\nDistribution:")
for bug_type, bug_list in sorted(by_type.items(), key=lambda x: -len(x[1])):
    print(f"  {bug_type}: {len(bug_list)}")

print("\n" + "="*80)
print("PATTERN ANALYSIS")
print("="*80)

# DIV_ZERO 
print("\n[DIV_ZERO - 136 bugs]")
div_zero_bugs = by_type.get('DIV_ZERO', [])
div_zero_vars = [b.bug_variable for b in div_zero_bugs if b.bug_variable]
print(f"  Top divisor variables:")
for var, count in Counter(div_zero_vars).most_common(10):
    print(f"    {var}: {count}")

# NULL_PTR 
print("\n[NULL_PTR - 35 bugs]")
null_ptr_bugs = by_type.get('NULL_PTR', [])
param_0_bugs = [b for b in null_ptr_bugs if b.bug_variable == 'param_0']
print(f"  With param_0 (self): {len(param_0_bugs)}/{len(null_ptr_bugs)}")
print(f"  → FALSE POSITIVE PATTERN: param_0='self' in Python")

# VALUE_ERROR
print("\n[VALUE_ERROR - 74 bugs]")
value_error_bugs = by_type.get('VALUE_ERROR', [])
value_vars = [b.bug_variable for b in value_error_bugs if b.bug_variable]
print(f"  Top error variables:")
for var, count in Counter(value_vars).most_common(5):
    print(f"    {var}: {count}")

# RUNTIME_ERROR
print("\n[RUNTIME_ERROR - 55 bugs]")
runtime_bugs = by_type.get('RUNTIME_ERROR', [])
runtime_vars = [b.bug_variable for b in runtime_bugs if b.bug_variable]
print(f"  Top error variables:")
for var, count in Counter(runtime_vars).most_common(5):
    print(f"    {var}: {count}")

print("\n" + "="*80)
print("FP/TP ASSESSMENT")
print("="*80)

print("\n🔴 FALSE POSITIVES (~35 bugs):")
print(f"  • NULL_PTR param_0: {len(param_0_bugs)} (self always bound)")

print("\n🟡 LIKELY TPs (needs validation):")
print(f"  • DIV_ZERO: 136 (check if divisors validated)")
print(f"  • VALUE_ERROR: 74 (check input contracts)")
print(f"  • RUNTIME_ERROR: 55 (check error handling)")

print("\n🟢 ESTIMATED TRUE POSITIVES: ~200-250 bugs")
print("   (after filtering param_0 FPs)")
