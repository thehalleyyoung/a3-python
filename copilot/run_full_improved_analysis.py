#!/usr/bin/env python3
"""
Full DeepSpeed analysis with all improvements:
1. Regenerate crash summaries (picks up new raise-based bug tracking)
2. Build code objects for DSE
3. Run enhanced barrier engine (Patterns 1-10) with DSE confirmation
4. Report FPs, true positives, and unverified
"""
import sys
import time
import pickle
import logging
from pathlib import Path
from collections import Counter, defaultdict

logging.basicConfig(level=logging.WARNING)

# Step 1: Regenerate summaries with the fixed _check_raise
print("=" * 70)
print("STEP 1: REGENERATING CRASH SUMMARIES")
print("=" * 70)

deepspeed_path = Path('external_tools/DeepSpeed')
if not deepspeed_path.exists():
    print(f"DeepSpeed not found at {deepspeed_path}")
    sys.exit(1)

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer

t0 = time.time()
call_graph = build_call_graph_from_directory(deepspeed_path)
print(f"  Call graph: {len(call_graph.functions)} functions ({time.time()-t0:.1f}s)")

t1 = time.time()
computer = BytecodeCrashSummaryComputer(call_graph)
summaries = computer.compute_all()
print(f"  Summaries: {len(summaries)} ({time.time()-t1:.1f}s)")

# Save new summaries (clear unpicklable fields)
cache_path = Path('results/deepspeed_crash_summaries_v2.pkl')
cache_path.parent.mkdir(exist_ok=True)
for s in summaries.values():
    s.bytecode_instructions = []  # These contain unpicklable code objects
with open(cache_path, 'wb') as f:
    pickle.dump(summaries, f)
print(f"  Saved to {cache_path}")

# Step 2: Build code objects for DSE
print()
print("=" * 70)
print("STEP 2: BUILDING CODE OBJECTS FOR DSE")
print("=" * 70)

from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

t2 = time.time()
code_objects = EnhancedDeepBarrierTheoryEngine.build_code_objects_from_call_graph(call_graph)
print(f"  Code objects built: {len(code_objects)} ({time.time()-t2:.1f}s)")

# Step 3: Bug type coverage
print()
print("=" * 70)
print("STEP 3: BUG TYPE COVERAGE")
print("=" * 70)

new_types = Counter()
new_trigger_types = Counter()
for s in summaries.values():
    for bt in getattr(s, 'guard_counts', {}):
        new_types[bt] += 1
    for bt in getattr(s, 'may_trigger', set()):
        new_trigger_types[bt] += 1

print(f"  guard_counts types: {dict(new_types.most_common())}")
print(f"  may_trigger types:  {dict(new_trigger_types.most_common())}")

# Step 4: Run enhanced barriers + DSE on all bugs
print()
print("=" * 70)
print("STEP 4: ENHANCED BARRIER + DSE ANALYSIS")
print("=" * 70)

engine = EnhancedDeepBarrierTheoryEngine(
    all_summaries=summaries,
    code_objects=code_objects,
)

total_bugs = 0
fully_guarded = 0
unguarded_bugs = []

for func_name, summary in summaries.items():
    gc = getattr(summary, 'guard_counts', {})
    gb = getattr(summary, 'guarded_bugs', set())
    for bug_type, (guarded_count, total_count) in gc.items():
        total_bugs += 1
        if bug_type in gb:
            fully_guarded += 1
        else:
            unguarded_bugs.append((func_name, bug_type, summary))

print(f"  Total bug instances:       {total_bugs}")
print(f"  Fully guarded (Papers):    {fully_guarded}")
print(f"  Unguarded:                 {len(unguarded_bugs)}")

# Run barriers on unguarded
proven_fp = 0
remaining = []
barrier_counts = Counter()

for func_name, bug_type, summary in unguarded_bugs:
    is_safe, cert = engine.verify_via_deep_barriers(bug_type, '<v>', summary)
    if is_safe:
        proven_fp += 1
        barrier_counts[cert.barrier_type.value] += 1
    else:
        remaining.append((func_name, bug_type, summary))

print(f"\n  Barrier results on unguarded:")
print(f"    Proven FP:   {proven_fp}/{len(unguarded_bugs)} ({100*proven_fp/len(unguarded_bugs):.1f}%)")
print(f"    Remaining:   {len(remaining)}/{len(unguarded_bugs)}")
print(f"\n  Barrier contributions:")
for bt, cnt in sorted(barrier_counts.items(), key=lambda x: -x[1]):
    print(f"    {cnt:5d}  {bt}")

# Grand total
grand_fp = fully_guarded + proven_fp
print(f"\n  {'='*50}")
print(f"  GRAND TOTAL PROVEN FP: {grand_fp}/{total_bugs} ({100*grand_fp/total_bugs:.1f}%)")
print(f"  REMAINING TO REVIEW:   {len(remaining)}/{total_bugs} ({100*len(remaining)/total_bugs:.1f}%)")

# Step 5: DSE results — true positives
print()
print("=" * 70)
print("STEP 5: DSE RESULTS (TRUE POSITIVES / CONFIRMED FPs)")
print("=" * 70)

dse_results = engine.get_dse_results()
dse_reachable = {k: v for k, v in dse_results.items() if v[0] == 'reachable'}
dse_unreachable = {k: v for k, v in dse_results.items() if v[0] == 'unreachable'}
dse_error = {k: v for k, v in dse_results.items() if v[0] == 'error'}

print(f"  DSE analyzed:          {len(dse_results)}")
print(f"  DSE confirmed FP:      {len(dse_unreachable)}")
print(f"  DSE confirmed TP:      {len(dse_reachable)}")
print(f"  DSE errors:            {len(dse_error)}")

if dse_reachable:
    print(f"\n  TRUE POSITIVES (DSE-confirmed reachable bugs):")
    for func_name, (status, bug_type, cex) in sorted(dse_reachable.items()):
        print(f"    ⚠️  {bug_type} in {func_name}")

# Step 6: Breakdown of remaining by type
print()
print("=" * 70)
print("STEP 6: REMAINING BUGS BREAKDOWN (potential true positives)")
print("=" * 70)

remaining_types = Counter(bt for _, bt, _ in remaining)
for bt, cnt in remaining_types.most_common():
    print(f"  {cnt:5d}  {bt}")

# Categorize remaining
test_bugs = []
prod_bugs = []
for func_name, bug_type, summary in remaining:
    is_test = (func_name.startswith('tests.') or 'test_' in func_name 
               or '.tests.' in func_name)
    parts = func_name.split('.')
    is_test = is_test or any(p.startswith('Test') for p in parts)
    if is_test:
        test_bugs.append((func_name, bug_type, summary))
    else:
        prod_bugs.append((func_name, bug_type, summary))

print(f"\n  Production code bugs:  {len(prod_bugs)}")
print(f"  Test-only code bugs:   {len(test_bugs)}")

if prod_bugs:
    print(f"\n  PRODUCTION BUGS TO INVESTIGATE:")
    for func_name, bug_type, summary in prod_bugs[:30]:
        vp = getattr(summary, 'validated_params', {})
        gc = summary.guard_counts.get(bug_type, (0, 0))
        ug = gc[1] - gc[0]
        print(f"    {bug_type:15s} ({ug} unguarded) {func_name}")

# Step 7: Save full results
print()
print("=" * 70)
print("STEP 7: SAVING RESULTS")
print("=" * 70)

results = {
    'total_bugs': total_bugs,
    'fully_guarded': fully_guarded,
    'barrier_proven_fp': proven_fp,
    'grand_fp': grand_fp,
    'remaining_count': len(remaining),
    'remaining': [(fn, bt) for fn, bt, _ in remaining],
    'dse_reachable': {k: (v[0], v[1]) for k, v in dse_reachable.items()},
    'dse_unreachable': list(dse_unreachable.keys()),
    'prod_bugs': [(fn, bt) for fn, bt, _ in prod_bugs],
    'test_bugs': [(fn, bt) for fn, bt, _ in test_bugs],
}

results_path = Path('results/full_analysis_results.pkl')
with open(results_path, 'wb') as f:
    pickle.dump(results, f)
print(f"  Saved to {results_path}")

print()
print("=" * 70)
print("DONE")
print("=" * 70)
