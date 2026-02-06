"""Deep inspection of 216 remaining bugs for further pattern opportunities."""
import pickle, sys
sys.path.insert(0, '.')
from collections import Counter, defaultdict

from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

with open('results/deepspeed_crash_summaries_v2.pkl', 'rb') as f:
    summaries = pickle.load(f)

engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)

# Collect remaining bugs exactly as run_full_improved_analysis.py does
remaining = []
for func_name, summary in summaries.items():
    gc = getattr(summary, 'guard_counts', {})
    gb = getattr(summary, 'guarded_bugs', set())
    for bug_type, (guarded_count, total_count) in gc.items():
        if bug_type in gb:
            continue  # fully guarded
        is_safe, cert = engine.verify_via_deep_barriers(bug_type, '<v>', summary)
        if not is_safe:
            remaining.append((func_name, bug_type, summary))

print(f"Remaining: {len(remaining)}")
print()

# ===== Analysis of remaining bugs =====

# 1. What guard_facts do they have?
guard_type_counts = Counter()
for n, bt, s in remaining:
    gf = getattr(s, 'guard_facts', [])
    for g in gf:
        gt = g.get('guard_type', g) if isinstance(g, dict) else getattr(g, 'guard_type', str(g))
        guard_type_counts[gt] += 1

print("Guard types present in remaining bugs:")
for gt, cnt in guard_type_counts.most_common(15):
    print(f"  {cnt:4d}  {gt}")

# 2. What return_guarantees do callees have?
callee_guar_counts = Counter()
for n, bt, s in remaining:
    cs = getattr(s, 'callee_summaries', {})
    for callee_name, callee_summary in cs.items():
        rg = getattr(callee_summary, 'return_guarantees', set())
        for g in rg:
            callee_guar_counts[g] += 1

print(f"\nCallee return_guarantees in remaining:")
for g, cnt in callee_guar_counts.most_common():
    print(f"  {cnt:4d}  {g}")

# 3. How many unguarded instances per bug type per function?
print(f"\nUnguarded counts per remaining bug:")
ug_counter = Counter()
for n, bt, s in remaining:
    gc = s.guard_counts[bt]
    ug = gc[1] - gc[0]
    ug_counter[ug] += 1
for ug, cnt in sorted(ug_counter.items()):
    print(f"  unguarded={ug}: {cnt} functions")

# 4. Check may_trigger vs guard_counts
print(f"\nFunctions where may_trigger has the bug type:")
mt_has_it = 0
for n, bt, s in remaining:
    if bt in getattr(s, 'may_trigger', set()):
        mt_has_it += 1
print(f"  {mt_has_it}/{len(remaining)}")

# 5. Check if any remaining have crash_locations
print(f"\nRemaining with crash_locations:")
has_cl = sum(1 for n, bt, s in remaining if getattr(s, 'crash_locations', []))
print(f"  {has_cl}/{len(remaining)}")

# 6. Sample detailed look at remaining NULL_PTR
print(f"\n--- Sample NULL_PTR remaining (first 5) ---")
null_remaining = [(n, bt, s) for n, bt, s in remaining if bt == 'NULL_PTR']
for n, bt, s in null_remaining[:5]:
    print(f"\nFunction: {n}")
    print(f"  guard_counts:      {s.guard_counts}")
    print(f"  may_trigger:       {getattr(s, 'may_trigger', set())}")
    print(f"  validated_params:  {getattr(s, 'validated_params', {})}")
    gf = getattr(s, 'guard_facts', [])
    print(f"  guard_facts:       {len(gf)} total")
    for g in gf[:3]:
        print(f"    {g}")
    cs = getattr(s, 'callee_summaries', {})
    print(f"  callee_summaries:  {len(cs)} callees")
    # Check if some callees have nonnull return
    for cn, csm in list(cs.items())[:3]:
        rg = getattr(csm, 'return_guarantees', set())
        if rg:
            print(f"    {cn}: return_guarantees={rg}")

# 7. Sample DIV_ZERO remaining
print(f"\n--- Sample DIV_ZERO remaining (first 3) ---")
div_remaining = [(n, bt, s) for n, bt, s in remaining if bt == 'DIV_ZERO']
for n, bt, s in div_remaining[:3]:
    print(f"\nFunction: {n}")
    print(f"  guard_counts:      {s.guard_counts}")
    print(f"  may_trigger:       {getattr(s, 'may_trigger', set())}")
    print(f"  validated_params:  {getattr(s, 'validated_params', {})}")
    gf = getattr(s, 'guard_facts', [])
    print(f"  guard_facts:       {len(gf)} total")
    for g in gf[:3]:
        print(f"    {g}")

# 8. Sample RUNTIME_ERROR remaining
print(f"\n--- Sample RUNTIME_ERROR remaining ---")
rt_remaining = [(n, bt, s) for n, bt, s in remaining if bt == 'RUNTIME_ERROR']
for n, bt, s in rt_remaining[:3]:
    print(f"\nFunction: {n}")
    print(f"  guard_counts:      {s.guard_counts}")
    print(f"  may_trigger:       {getattr(s, 'may_trigger', set())}")
    print(f"  validated_params:  {getattr(s, 'validated_params', {})}")
