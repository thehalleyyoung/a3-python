#!/usr/bin/env python3
"""
Final test: enhanced barriers + unanalyzed-callee barrier on all 329 bugs.
"""

import pickle, logging
from pathlib import Path
from collections import Counter
from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine
from pyfromscratch.barriers.deep_barrier_theory import BarrierType

logging.basicConfig(level=logging.WARNING)

cache_file = Path('results/deepspeed_crash_summaries.pkl')
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)

# Collect unguarded bugs
unguarded = []
for func_name, summary in summaries.items():
    if hasattr(summary, 'guarded_bugs') and summary.guarded_bugs:
        for bug_type in summary.guarded_bugs:
            gc = (0, 0)
            if hasattr(summary, 'guard_counts') and bug_type in summary.guard_counts:
                gc = summary.guard_counts[bug_type]
            if gc[0] == 0:
                unguarded.append({'function': func_name, 'bug_type': bug_type, 'summary': summary})

engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)

proven_safe = 0
true_bugs = []
barrier_counts = Counter()

for bug in unguarded:
    is_safe, cert = engine.verify_via_deep_barriers(bug['bug_type'], '<v>', bug['summary'])
    if is_safe:
        proven_safe += 1
        barrier_counts[cert.barrier_type] += 1
    else:
        true_bugs.append(bug)

print("=" * 70)
print(f"FINAL: {len(unguarded)} unguarded bugs")
print(f"  Proven FP : {proven_safe}/{len(unguarded)} ({proven_safe/len(unguarded)*100:.1f}%)")
print(f"  Remaining : {len(true_bugs)}")
print("=" * 70)
print()
print("Barrier contributions:")
for bt, cnt in barrier_counts.most_common():
    print(f"  {bt.value:30s}: {cnt:3d}")
print()

if true_bugs:
    print(f"{len(true_bugs)} bugs still flagged:")
    for b in true_bugs:
        src = b['bug_type'].replace('interprocedural_nonnull_from_', '')
        print(f"  {b['function']:55s} ← {src}")
else:
    print("✓  ALL 329 unguarded bugs proven to be false positives.")
