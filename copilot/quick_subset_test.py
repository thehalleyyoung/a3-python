#!/usr/bin/env python3
"""
Quick test on a small subset of DeepSpeed to see paper contributions.
"""
import sys
import time
import logging
from pathlib import Path
from collections import defaultdict

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

# Set up stats handler
class StatsHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.stats = defaultdict(int)
        
    def emit(self, record):
        msg = record.getMessage()
        if '✓ [PHASE -2' in msg:
            self.stats['Phase -2'] += 1
        elif '✓ [LAYER 0:' in msg:
            self.stats['Layer 0'] += 1
        elif '✓ [LAYER 2' in msg or '✓ [PHASE 3' in msg:
            self.stats['Layer 2'] += 1
        elif '✓ [LAYER 3' in msg or '✓ [PHASE 6' in msg:
            self.stats['Layer 3'] += 1
        elif '✓ [LAYER 4' in msg or '✓ [PHASE 4' in msg:
            self.stats['Layer 4'] += 1
        elif '✓ [LAYER 5' in msg or '✓ [PHASE 7' in msg:
            self.stats['Layer 5'] += 1

stats_handler = StatsHandler()
stats_handler.setLevel(logging.WARNING)
logging.root.addHandler(stats_handler)

print("="*80)
print("QUICK TEST: Small subset of DeepSpeed")
print("="*80)

# Use just the compile subdirectory (much smaller)
subset_path = Path('external_tools/DeepSpeed/deepspeed/inference')
if not subset_path.exists():
    subset_path = Path('external_tools/DeepSpeed/deepspeed/runtime')

print(f"\n[1/3] Building call graph from {subset_path}...")
t0 = time.time()
call_graph = build_call_graph_from_directory(subset_path)
t1 = time.time()
print(f"  Functions: {len(call_graph.functions)}")
print(f"  Time: {t1-t0:.1f}s")

print(f"\n[2/3] Computing crash summaries...")
t0 = time.time()
summary_computer = BytecodeCrashSummaryComputer(call_graph)
crash_summaries = summary_computer.compute_all()
t1 = time.time()
print(f"  Summaries: {len(crash_summaries)}")
print(f"  Time: {t1-t0:.1f}s")

# Clear bytecode to avoid pickle issues
for summary in crash_summaries.values():
    summary.bytecode_instructions = []

print(f"\n[3/3] Finding bugs with 25-paper verification...")
t0 = time.time()

# Train Layer 0
from pyfromscratch.barriers.extreme_verification import get_extreme_verifier
extreme_verifier = get_extreme_verifier()
if hasattr(extreme_verifier, 'fast_filters'):
    extreme_verifier.fast_filters.learn_from_codebase(crash_summaries)

tracker = InterproceduralBugTracker(
    crash_summaries=crash_summaries,
    call_graph=call_graph,
    entry_points=set(call_graph.functions.keys()),
    reachable_functions=set(call_graph.functions.keys()),
)

all_bugs = tracker.find_all_bugs()
t1 = time.time()

# Group by type
bugs_by_type = defaultdict(list)
for bug in all_bugs:
    bugs_by_type[bug.bug_type].append(bug)

print(f"  Analysis time: {t1-t0:.1f}s")
print(f"  Total bugs found: {len(all_bugs)}")

print("\n" + "="*80)
print("RESULTS")
print("="*80)

print(f"\nBugs by type:")
for bug_type, bugs in sorted(bugs_by_type.items()):
    print(f"  {bug_type:20s}: {len(bugs)}")

print(f"\n" + "="*80)
print("VERIFICATION STATISTICS")
print("="*80)

total_verified = sum(stats_handler.stats.values())
print(f"\nTotal FPs caught: {total_verified}")

for phase, count in sorted(stats_handler.stats.items()):
    pct = 100 * count / total_verified if total_verified > 0 else 0
    print(f"  {phase:30s}: {count:3d} FPs ({pct:.1f}%)")

print(f"\n{'='*80}")
if stats_handler.stats.get('Layer 0', 0) > 0:
    print("✓ Layer 0 (Papers #21-25) IS catching FPs!")
else:
    print("✗ Layer 0 not catching FPs yet")

if any('Layer' in k and k != 'Layer 0' for k in stats_handler.stats):
    print("✓ Deeper layers (Papers #1-20) ARE catching FPs!")
else:
    print("✗ Deeper layers not catching FPs yet")
