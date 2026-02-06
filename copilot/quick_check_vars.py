#!/usr/bin/env python3
"""
Check what's happening with bug_variable now.
"""
from pathlib import Path
from collections import defaultdict
import pickle

cache_file = Path('results/deepspeed_crash_summaries.pkl')
with open(cache_file, 'rb') as f:
    crash_summaries = pickle.load(f)

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

print("Building call graph...")
deepspeed_path = Path('external_tools/DeepSpeed/deepspeed')
call_graph = build_call_graph_from_directory(deepspeed_path)

print("Creating bug tracker...")
tracker = InterproceduralBugTracker(
    crash_summaries=crash_summaries,
    call_graph=call_graph,
    entry_points=set(call_graph.functions.keys()),
    reachable_functions=set(call_graph.functions.keys()),
)

print("Finding bugs...")
all_bugs = tracker.find_all_bugs()

# Check bug_variable
bugs_with_var = 0
bugs_without_var = 0

for bug in all_bugs[:10]:  # Check first 10
    bug_var = getattr(bug, 'bug_variable', None)
    print(f"\nBug: {bug.bug_type}")
    print(f"  bug_variable: {bug_var}")
    print(f"  func: {getattr(bug, 'crash_function', 'unknown')}")
    
    if bug_var:
        bugs_with_var += 1
    else:
        bugs_without_var += 1

print(f"\n{'='*60}")
print(f"Of first 10 bugs:")
print(f"  With bug_variable: {bugs_with_var}")
print(f"  Without bug_variable: {bugs_without_var}")
