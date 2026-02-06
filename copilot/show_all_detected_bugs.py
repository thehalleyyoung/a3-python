#!/usr/bin/env python3
"""
Show ALL bugs detected in DeepSpeed, regardless of verification status.
"""

import pickle
from pathlib import Path
from collections import defaultdict, Counter

cache_file = Path('results/deepspeed_crash_summaries.pkl')

if not cache_file.exists():
    print(f"Cache file not found: {cache_file}")
    exit(1)

with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)

print("=" * 80)
print(f"ALL BUGS DETECTED IN DEEPSPEED ({len(summaries)} functions analyzed)")
print("=" * 80)
print()

all_bugs = []

for func_name, summary in summaries.items():
    # guarded_bugs is a set of bug type strings
    if hasattr(summary, 'guarded_bugs') and summary.guarded_bugs:
        for bug_type in summary.guarded_bugs:
            # Get guard counts to see if it's guarded or not
            guard_count = (0, 0)
            if hasattr(summary, 'guard_counts') and bug_type in summary.guard_counts:
                guard_count = summary.guard_counts[bug_type]  # (guarded_count, total_count)
            
            all_bugs.append({
                'function': func_name,
                'bug_type': bug_type,
                'guarded_count': guard_count[0],
                'total_count': guard_count[1],
                'summary': summary
            })

print(f"Total bugs detected: {len(all_bugs)}")
print()

# Group by type
by_type = defaultdict(list)
for bug in all_bugs:
    by_type[bug['bug_type']].append(bug)

print("=" * 80)
print("BUGS BY TYPE")
print("=" * 80)
print()

for bug_type in sorted(by_type.keys()):
    bugs = by_type[bug_type]
    print(f"{bug_type}: {len(bugs)} bugs")
    print("-" * 80)
    
    # Separate into unguarded (potential real bugs) and guarded (likely FPs)
    unguarded = [b for b in bugs if b['guarded_count'] == 0]
    partially_guarded = [b for b in bugs if 0 < b['guarded_count'] < b['total_count']]
    fully_guarded = [b for b in bugs if b['guarded_count'] == b['total_count'] and b['total_count'] > 0]
    
    print(f"  Unguarded (potential real bugs): {len(unguarded)}")
    print(f"  Partially guarded: {len(partially_guarded)}")
    print(f"  Fully guarded (likely FPs): {len(fully_guarded)}")
    print()
    
    if unguarded:
        print(f"  Unguarded {bug_type} bugs:")
        for bug in unguarded[:20]:
            print(f"    {bug['function']} (total: {bug['total_count']} instances)")
        if len(unguarded) > 20:
            print(f"    ... and {len(unguarded) - 20} more")
        print()
    
    if partially_guarded[:5]:
        print(f"  Partially guarded examples:")
        for bug in partially_guarded[:5]:
            print(f"    {bug['function']} ({bug['guarded_count']}/{bug['total_count']} guarded)")
        print()

print("=" * 80)
print("SUMMARY")
print("=" * 80)
print()

type_counts = Counter(bug['bug_type'] for bug in all_bugs)
total_unguarded = sum(1 for bug in all_bugs if bug['guarded_count'] == 0)
total_fully_guarded = sum(1 for bug in all_bugs if bug['guarded_count'] == bug['total_count'] and bug['total_count'] > 0)

for bug_type, count in type_counts.most_common():
    bugs_of_type = [b for b in all_bugs if b['bug_type'] == bug_type]
    unguarded_count = sum(1 for b in bugs_of_type if b['guarded_count'] == 0)
    print(f"  {bug_type:30s} {count:6,}  (unguarded: {unguarded_count})")

print()
print(f"Total: {len(all_bugs):,} bugs across {len(summaries):,} functions")
print()
print("=" * 80)
print("NEXT STEP: Run full 25-paper verification on these bugs")
print("=" * 80)
print()
print("The analysis we ran was incomplete (only 15 bugs analyzed).")
print("To analyze all bugs, run:")
print()
print("  timeout 3600 test_venv/bin/python run_deepspeed_with_stats.py 2>&1 | \\")
print("    tee results/deepspeed_complete_$(date +%Y%m%d_%H%M%S).log")
