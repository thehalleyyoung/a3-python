#!/usr/bin/env python3
"""
Quick test on a few DeepSpeed files to verify 25-paper tracking.
"""
import sys
import time
import logging
from pathlib import Path
from collections import Counter

sys.path.insert(0, '.')

# Set WARNING level to see paper invocations
logging.basicConfig(
    level=logging.WARNING,
    format='%(message)s'
)

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer

print('='*70)
print('QUICK TEST: DeepSpeed subset with 25-paper verification')
print('='*70)
print()

# Use a small subdirectory instead of specific files
test_dir = Path('external_tools/DeepSpeed/deepspeed/utils')

print(f'Testing directory: {test_dir}')
print()

print('[1/3] Building call graph...')
call_graph = build_call_graph_from_directory(test_dir)
print(f'  Functions: {len(call_graph.functions)}')
print()

print('[2/3] Computing crash summaries...')
crash_computer = BytecodeCrashSummaryComputer(call_graph)
crash_summaries = crash_computer.compute_all()
print(f'  Summaries: {len(crash_summaries)}')
print()

print('[3/3] Finding bugs (watch for ✓ lines showing which paper proves safety)...')
print('-'*70)

# Manually create tracker with our limited data
tracker = InterproceduralBugTracker(
    call_graph=call_graph,
    entry_points=set(call_graph.functions.keys()),
    reachable_functions=set(call_graph.functions.keys()),
    taint_summaries={},
    crash_summaries=crash_summaries,
    combined_summaries={},
)

bugs = tracker.find_all_bugs(only_non_security=True)

print('-'*70)
print()
print('RESULTS:')
print(f'  Total bugs: {len(bugs)}')

if bugs:
    counts = Counter(b.bug_type for b in bugs)
    print('  By type:')
    for bug_type, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f'    {bug_type}: {count}')
    
    print()
    print('Sample bugs:')
    for bug in bugs[:5]:
        print(f'  - {bug.bug_type} in {bug.crash_function}')

print()
print('='*70)
print('Look for ✓ lines above showing which phase/paper caught FPs!')
print('='*70)
