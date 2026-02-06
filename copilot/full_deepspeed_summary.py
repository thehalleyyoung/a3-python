#!/usr/bin/env python3
"""Final summary: Complete DeepSpeed FP analysis across all bug categories."""
import pickle
from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

with open('results/deepspeed_crash_summaries.pkl', 'rb') as f:
    summaries = pickle.load(f)

# Categorize all bugs
total_bugs = 0
fully_guarded = 0       # all instances guarded by Papers #1-20
partially_guarded = 0
unguarded = 0

fully_guarded_bugs = []
partially_guarded_bugs = []
unguarded_bugs = []

for func_name, summary in summaries.items():
    gc = getattr(summary, 'guard_counts', {})
    gb = getattr(summary, 'guarded_bugs', set())
    for bug_type, (guarded_count, total_count) in gc.items():
        total_bugs += 1
        if bug_type in gb:
            fully_guarded += 1
            fully_guarded_bugs.append((func_name, bug_type, summary))
        elif guarded_count > 0:
            partially_guarded += 1
            partially_guarded_bugs.append((func_name, bug_type, summary))
        else:
            unguarded += 1
            unguarded_bugs.append((func_name, bug_type, summary))

print("=" * 70)
print("COMPLETE DEEPSPEED ANALYSIS")
print("=" * 70)
print(f"Total functions analyzed: {len(summaries)}")
print(f"Total bug instances:      {total_bugs}")
print()

# Papers #1-20 guards
print("--- Papers #1-20 Guards ---")
print(f"  Fully guarded (proven FP):    {fully_guarded}")
print(f"  Partially guarded:            {partially_guarded}")
print(f"  Unguarded:                    {unguarded}")
print()

# Deep Barrier Theory on unguarded bugs
engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)
proven_fp = 0
remaining = 0

for func_name, bug_type, summary in unguarded_bugs:
    is_safe, cert = engine.verify_via_deep_barriers(bug_type, '<v>', summary)
    if is_safe:
        proven_fp += 1
    else:
        remaining += 1

print("--- Deep Barrier Theory (8 Patterns) on Unguarded ---")
print(f"  Proven FP by barriers:        {proven_fp}/{unguarded}")
print(f"  Remaining (potential real):    {remaining}/{unguarded}")
print()

# Now try on partially guarded too
partial_proven = 0
partial_remaining = 0
for func_name, bug_type, summary in partially_guarded_bugs:
    is_safe, cert = engine.verify_via_deep_barriers(bug_type, '<v>', summary)
    if is_safe:
        partial_proven += 1
    else:
        partial_remaining += 1

print("--- Deep Barrier Theory on Partially Guarded ---")
print(f"  Proven FP by barriers:        {partial_proven}/{partially_guarded}")
print(f"  Remaining:                    {partial_remaining}/{partially_guarded}")
print()

# Grand total
total_fp = fully_guarded + proven_fp + partial_proven
total_remaining = remaining + partial_remaining
print("=" * 70)
print(f"GRAND TOTAL PROVEN FP: {total_fp}/{total_bugs} ({100*total_fp/total_bugs:.1f}%)")
print(f"REMAINING TO REVIEW:   {total_remaining}/{total_bugs} ({100*total_remaining/total_bugs:.1f}%)")
print("=" * 70)
