#!/usr/bin/env python3
"""
Check if bugs have bug_variable set.
"""
from pathlib import Path
from collections import defaultdict
from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

print("Building call graph...")
deepspeed_path = Path('external_tools/DeepSpeed/deepspeed')
call_graph = build_call_graph_from_directory(deepspeed_path)

print(f"Loading cached crash summaries...")
import pickle
cache_file = Path('results/deepspeed_crash_summaries.pkl')
with open(cache_file, 'rb') as f:
    crash_summaries = pickle.load(f)

print("Creating bug tracker...")
tracker = InterproceduralBugTracker(
    crash_summaries=crash_summaries,
    call_graph=call_graph,
    entry_points=set(call_graph.functions.keys()),
    reachable_functions=set(call_graph.functions.keys()),
)

print("Finding bugs...")
all_bugs = tracker.find_all_bugs()

# Check bug_variable field
bugs_with_var = 0
bugs_without_var = 0
bugs_by_type = defaultdict(lambda: {'with_var': 0, 'without_var': 0})

for bug in all_bugs:
    bug_var = getattr(bug, 'bug_variable', getattr(bug, 'variable', None))
    bug_type = bug.bug_type
    
    if bug_var:
        bugs_with_var += 1
        bugs_by_type[bug_type]['with_var'] += 1
    else:
        bugs_without_var += 1
        bugs_by_type[bug_type]['without_var'] += 1

print(f"\n{'='*60}")
print(f"BUG VARIABLE ANALYSIS")
print(f"{'='*60}")
print(f"\nTotal bugs: {len(all_bugs)}")
print(f"  With bug_variable: {bugs_with_var} ({100*bugs_with_var/len(all_bugs):.1f}%)")
print(f"  WITHOUT bug_variable: {bugs_without_var} ({100*bugs_without_var/len(all_bugs):.1f}%)")

print(f"\nBy bug type:")
for bug_type in sorted(bugs_by_type.keys()):
    with_var = bugs_by_type[bug_type]['with_var']
    without_var = bugs_by_type[bug_type]['without_var']
    total = with_var + without_var
    print(f"  {bug_type:20s}: {with_var:3d} with var, {without_var:3d} without ({100*without_var/total:.1f}% missing)")

print(f"\n{'='*60}")
print("CONCLUSION:")
print(f"{'='*60}")
if bugs_without_var > len(all_bugs) * 0.5:
    print("⚠️  CRITICAL: >50% of bugs are missing bug_variable!")
    print("   This causes Layers 2-5 to be skipped entirely.")
    print("   FIX: Populate bug_variable in bug detection.")
else:
    print("✓ Most bugs have bug_variable set")
