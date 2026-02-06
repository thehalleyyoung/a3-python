#!/usr/bin/env python3
"""Comprehensive audit of the analysis pipeline:
1. What bug types exist?
2. Is DSE/concolic actually being used?
3. Which bugs are security vs non-security?
4. Where are the gaps?
"""
import pickle
from collections import Counter, defaultdict

with open('results/deepspeed_crash_summaries.pkl', 'rb') as f:
    summaries = pickle.load(f)

print(f"Total summaries: {len(summaries)}")
print()

# 1. ALL bug types across all summaries
all_bug_types = Counter()
all_trigger_types = Counter()
guarded_bug_types = Counter()
unguarded_bug_types = Counter()

functions_with_bugs = 0
functions_analyzed = 0

for func_name, s in summaries.items():
    functions_analyzed += 1
    
    # may_trigger: raw bug types the function can trigger
    for t in getattr(s, 'may_trigger', set()):
        all_trigger_types[t] += 1
    
    gc = getattr(s, 'guard_counts', {})
    gb = getattr(s, 'guarded_bugs', set())
    
    if gc:
        functions_with_bugs += 1
    
    for bug_type, (guarded, total) in gc.items():
        all_bug_types[bug_type] += 1
        if bug_type in gb:
            guarded_bug_types[bug_type] += 1
        else:
            unguarded_bug_types[bug_type] += 1

print("=" * 70)
print("1. RAW TRIGGER TYPES (what may_trigger contains)")
print("=" * 70)
for t, c in all_trigger_types.most_common():
    print(f"  {c:5d}  {t}")

print()
print("=" * 70)
print(f"2. BUG TYPES IN guard_counts ({sum(all_bug_types.values())} total across {functions_with_bugs} functions)")
print("=" * 70)

# Categorize
interprocedural = Counter()
intraprocedural = Counter()
for bt, c in all_bug_types.items():
    if bt.startswith('interprocedural_'):
        prefix = '_'.join(bt.split('_')[:3])
        interprocedural[prefix] += c
    else:
        intraprocedural[bt] += c

print("\n  Intra-procedural:")
for bt, c in intraprocedural.most_common():
    g = sum(1 for k, v in guarded_bug_types.items() if k == bt)
    u = sum(1 for k, v in unguarded_bug_types.items() if k == bt)
    print(f"    {c:5d}  {bt}  (guarded: {guarded_bug_types.get(bt,0)}, unguarded: {unguarded_bug_types.get(bt,0)})")

print("\n  Inter-procedural (aggregated by prefix):")
for prefix, c in interprocedural.most_common():
    # Count guarded vs unguarded for this prefix
    g = sum(v for k, v in guarded_bug_types.items() if k.startswith(prefix.replace('_from', '_')))
    u = sum(v for k, v in unguarded_bug_types.items() if k.startswith(prefix.replace('_from', '_')))
    print(f"    {c:5d}  {prefix}_*  (guarded: {g}, unguarded: {u})")

# 3. What's NOT being checked?
print()
print("=" * 70)
print("3. SECURITY vs NON-SECURITY BUG TYPES")
print("=" * 70)
from pyfromscratch.unsafe.registry import SECURITY_BUG_TYPES
print(f"  Security types: {sorted(SECURITY_BUG_TYPES)}")
print(f"  Non-security types found: {sorted(intraprocedural.keys())}")
missing_non_security = {'BOUNDS', 'TYPE_CONFUSION', 'ASSERT_FAIL', 
                        'INTEGER_OVERFLOW', 'FP_DOMAIN', 'STACK_OVERFLOW', 
                        'MEMORY_LEAK', 'ITERATOR_INVALID', 'UNINITIALIZED_VAR',
                        'DEADLOCK', 'RACE_CONDITION', 'RESOURCE_LEAK',
                        'INFINITE_LOOP', 'UNREACHABLE_CODE'}
found_types = set(intraprocedural.keys())
print(f"  Types mentioned in code but NOT found: {missing_non_security - found_types}")

# 4. Check if may_raise is being tracked
print()
print("=" * 70)
print("4. EXCEPTION TYPES (may_raise)")
print("=" * 70)
exception_counter = Counter()
for func_name, s in summaries.items():
    for exc in getattr(s, 'may_raise', set()):
        exception_counter[str(exc)] += 1
for exc, c in exception_counter.most_common(20):
    print(f"  {c:5d}  {exc}")

# 5. Summary fields that might have additional info
print()
print("=" * 70)
print("5. SAMPLE SUMMARY FIELDS")
print("=" * 70)
sample = list(summaries.values())[0]
for attr in sorted(dir(sample)):
    if not attr.startswith('_'):
        val = getattr(sample, attr)
        if not callable(val):
            print(f"  {attr}: {type(val).__name__} = {repr(val)[:100]}")
