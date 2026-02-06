"""Check the 81 remaining for more patterns."""
import pickle, sys
from collections import Counter
sys.path.insert(0, '.')

from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

with open('results/deepspeed_crash_summaries_v2.pkl', 'rb') as f:
    summaries = pickle.load(f)

engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)

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

print(f"Remaining: {len(remaining)}")

# Check NULL_PTR remaining - are they methods with >2 unguarded?
null_remaining = [(n, bt, s) for n, bt, s in remaining if bt == 'NULL_PTR']
print(f"\nNULL_PTR remaining: {len(null_remaining)}")

for n, bt, s in null_remaining:
    gc = s.guard_counts['NULL_PTR']
    ug = gc[1] - gc[0]
    parts = n.split('.')
    is_method = any(p[0].isupper() for p in parts[:-1] if p)
    pn = getattr(s, 'param_names', [])
    has_self = pn and pn[0] in ('self', 'cls')
    print(f"  {n}")
    print(f"    unguarded={ug}, is_method={is_method}, has_self={has_self}")

# Check DIV_ZERO remaining
print(f"\nDIV_ZERO remaining: {len([(n,bt,s) for n,bt,s in remaining if bt == 'DIV_ZERO'])}")
for n, bt, s in remaining:
    if bt != 'DIV_ZERO':
        continue
    gc = s.guard_counts.get('DIV_ZERO', (0,0))
    ug = gc[1] - gc[0]
    is_test = 'test' in n.lower() or n.startswith('tests.')
    print(f"  {n}")
    print(f"    unguarded={ug}, is_test={is_test}")
