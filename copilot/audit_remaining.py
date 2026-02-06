#!/usr/bin/env python3
"""Check the 125 remaining bugs: are they intra-procedural? What makes them unresolvable?
Also check: what other bug types SHOULD we be finding but aren't?"""
import pickle
from collections import Counter
from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

with open('results/deepspeed_crash_summaries.pkl', 'rb') as f:
    summaries = pickle.load(f)

engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)

# Collect the 125 remaining
remaining = []
for func_name, summary in summaries.items():
    gc = getattr(summary, 'guard_counts', {})
    gb = getattr(summary, 'guarded_bugs', set())
    for bug_type, (guarded_count, total_count) in gc.items():
        if bug_type not in gb and guarded_count == 0:
            is_safe, cert = engine.verify_via_deep_barriers(bug_type, '<v>', summary)
            if not is_safe:
                remaining.append((func_name, bug_type, summary, guarded_count, total_count))

print(f"=== {len(remaining)} REMAINING BUGS ===\n")

# Split by type
null_ptr = [(f, b, s, g, t) for f, b, s, g, t in remaining if b == 'NULL_PTR']
div_zero = [(f, b, s, g, t) for f, b, s, g, t in remaining if b == 'DIV_ZERO']

print(f"NULL_PTR: {len(null_ptr)}")
print(f"DIV_ZERO: {len(div_zero)}")

# For each: check what info we have
print(f"\n--- Sample NULL_PTR bugs (first 15) ---")
for func_name, bug_type, s, gc, tc in null_ptr[:15]:
    rg = getattr(s, 'return_guarantees', set())
    mt = getattr(s, 'may_trigger', set())
    vp = getattr(s, 'validated_params', {})
    pn = getattr(s, 'param_nullability', {})
    analyzed = getattr(s, 'analyzed', '?')
    print(f"  {func_name}:")
    print(f"    guard_counts={gc}/{tc}, analyzed={analyzed}")
    print(f"    may_trigger={mt}, param_nullability={pn}")
    print(f"    validated_params={vp}")
    print(f"    return_guarantees={rg}")

print(f"\n--- Sample DIV_ZERO bugs (first 15) ---")
for func_name, bug_type, s, gc, tc in div_zero[:15]:
    dp = getattr(s, 'divisor_params', set())
    mt = getattr(s, 'may_trigger', set())
    vp = getattr(s, 'validated_params', {})
    analyzed = getattr(s, 'analyzed', '?')
    print(f"  {func_name}:")
    print(f"    guard_counts={gc}/{tc}, analyzed={analyzed}")
    print(f"    may_trigger={mt}, divisor_params={dp}")
    print(f"    validated_params={vp}")

# Now check: what bug types COULD we be detecting but aren't?
print(f"\n=== BUG TYPES WE'RE NOT DETECTING ===")
print(f"Total functions: {len(summaries)}")
# Count how many have may_raise for various exceptions
from collections import Counter
exception_types = Counter()
for s in summaries.values():
    for exc in getattr(s, 'may_raise', set()):
        exception_types[str(exc)] += 1

print(f"Exception types found in may_raise:")
for exc, c in exception_types.most_common():
    print(f"  {c:5d}  {exc}")

# How many trigger RUNTIME_ERROR, VALUE_ERROR etc but are not in guard_counts?
trigger_vs_guard = Counter()
for s in summaries.values():
    for t in getattr(s, 'may_trigger', set()):
        gc = getattr(s, 'guard_counts', {})
        if t in gc:
            trigger_vs_guard[f"{t} (has guard_counts)"] += 1
        else:
            trigger_vs_guard[f"{t} (NO guard_counts)"] += 1

print(f"\nmay_trigger vs guard_counts:")
for k, c in trigger_vs_guard.most_common():
    print(f"  {c:5d}  {k}")
