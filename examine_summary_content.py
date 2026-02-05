#!/usr/bin/env python3
"""
Examine what we actually have in crash summaries for stdlib detection.
"""
import sys
from pathlib import Path
import pickle
from collections import Counter

cache_file = Path('results/deepspeed_crash_summaries.pkl')
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)

print("="*80)
print("WHAT WE HAVE IN CRASH SUMMARIES")
print("="*80)
print()

# Look at a few summaries in detail
for i, (func_name, summary) in enumerate(list(summaries.items())[:5]):
    print(f"\n{i+1}. Function: {func_name}")
    print(f"   May trigger: {summary.may_trigger if hasattr(summary, 'may_trigger') else 'N/A'}")
    print(f"   Guarded bugs: {summary.guarded_bugs if hasattr(summary, 'guarded_bugs') else 'N/A'}")
    print(f"   Has side effects: {summary.has_side_effects if hasattr(summary, 'has_side_effects') else 'N/A'}")
    print(f"   Param nullability: {summary.param_nullability if hasattr(summary, 'param_nullability') else 'N/A'}")
    print(f"   Return guarantees: {summary.return_guarantees if hasattr(summary, 'return_guarantees') else 'N/A'}")
    
    # Check if we have guard info
    if hasattr(summary, 'intra_guard_facts'):
        print(f"   Guard facts: {len(summary.intra_guard_facts)}")
    
    # Check if we have any way to detect stdlib usage
    if hasattr(summary, 'guard_type_to_vars'):
        print(f"   Guard types: {summary.guard_type_to_vars}")

print()
print("="*80)
print("POSSIBLE APPROACHES")
print("="*80)
print()

print("Since we don't have bytecode instructions, we need to use:")
print()
print("1. Function qualified_name - may contain stdlib modules")
print("2. Guard information - may reveal stdlib contracts")
print("3. Return guarantees - may show stdlib postconditions")
print("4. Parameter requirements - may show stdlib preconditions")
print()

# Check function names
stdlib_modules = ['math', 'os', 'sys', 're', 'json', 'itertools', 'functools', 'collections']
stdlib_funcs_in_names = Counter()

for func_name, summary in summaries.items():
    func_lower = func_name.lower()
    for module in stdlib_modules:
        if module in func_lower:
            stdlib_funcs_in_names[module] += 1

print("Stdlib module references in function names:")
for module, count in stdlib_funcs_in_names.most_common():
    print(f"  {module}: {count}")

print()
print("="*80)
print("RECOMMENDATION")
print("="*80)
print()
print("Without bytecode instructions, we need a different approach:")
print()
print("1. Use guard_type_to_vars to detect protective patterns")
print("2. Use return_guarantees to infer safe return values")
print("3. Use param_nullability to track non-null requirements")
print("4. Use qualified_name to identify stdlib functions with known contracts")
print()
print("For example:")
print("- If return_guarantees shows 'non_negative', we know result >= 0")
print("- If guard_type_to_vars shows 'comparison' guards, we can infer bounds")
print("- If qualified_name contains known safe stdlib, apply contracts")
