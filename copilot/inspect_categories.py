"""Check how many remaining NULL_PTR bugs are on 'self' or import attribute access."""
import pickle, sys, dis
from pathlib import Path
from collections import Counter
sys.path.insert(0, '.')

from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

with open('results/deepspeed_crash_summaries_v2.pkl', 'rb') as f:
    summaries = pickle.load(f)

engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)

# Collect remaining
remaining = []
for func_name, summary in summaries.items():
    gc = getattr(summary, 'guard_counts', {})
    gb = getattr(summary, 'guarded_bugs', set())
    for bug_type, (guarded_count, total_count) in gc.items():
        if bug_type in gb:
            continue
        is_safe, cert = engine.verify_via_deep_barriers(bug_type, '<v>', summary)
        if not is_safe:
            remaining.append((func_name, bug_type, summary))

null_remaining = [(n, bt, s) for n, bt, s in remaining if bt == 'NULL_PTR']
print(f"Remaining NULL_PTR: {len(null_remaining)}")

# Check which are methods (have 'self' or 'cls' as first param)
is_method = 0
is_standalone = 0
method_names = []
standalone_names = []
for n, bt, s in null_remaining:
    params = getattr(s, 'parameters', [])
    param_names = getattr(s, 'param_names', [])
    if not param_names:
        # Try to get from qualified name
        if '.' in n:
            parts = n.split('.')
            # If there's a class-like name before the function name
            if len(parts) >= 2 and parts[-2][0].isupper():
                is_method += 1
                method_names.append(n)
                continue
    if param_names and param_names[0] in ('self', 'cls'):
        is_method += 1
        method_names.append(n)
    else:
        is_standalone += 1
        standalone_names.append(n)

print(f"  Methods (likely self.*): {is_method}")
print(f"  Standalone functions:    {is_standalone}")

# Check if remaining functions are test functions
test_funcs = sum(1 for n in standalone_names if 'test' in n.lower())
print(f"  Of standalone, test functions: {test_funcs}")

# Check function categories
categories = Counter()
for n, bt, s in remaining:
    if 'test' in n.lower() or n.startswith('tests.'):
        categories['test'] += 1
    elif '.op_builder.' in n or n.startswith('op_builder.'):
        categories['op_builder'] += 1
    elif '__init__' in n:
        categories['init'] += 1
    else:
        categories['other'] += 1

print(f"\nAll remaining by category:")
for cat, cnt in categories.most_common():
    print(f"  {cnt:4d}  {cat}")

# Check what percentage of NULL_PTR are on method attribute access (self.*)
print(f"\nMethod NULL_PTR functions (first 10):")
for n in method_names[:10]:
    s = summaries[n]
    print(f"  {n}")
    print(f"    guard_counts: {s.guard_counts}")
    # Check crash_locations  
    cl = getattr(s, 'crash_locations', [])
    if cl:
        print(f"    crash_locations: {cl[:3]}")

# For DIV_ZERO remaining
div_remaining = [(n, bt, s) for n, bt, s in remaining if bt == 'DIV_ZERO']
print(f"\nRemaining DIV_ZERO: {len(div_remaining)}")
for n, bt, s in div_remaining[:5]:
    print(f"  {n}")
    # Check if it's a test function
    if 'test' in n.lower():
        print(f"    [TEST FUNCTION]")
