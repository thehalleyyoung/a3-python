#!/usr/bin/env python3
"""
Measure ACTUAL performance of Layer 0 optimizations on DeepSpeed.
"""
import time
from pathlib import Path
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from collections import Counter

print('='*70)
print('REAL MEASUREMENT: DeepSpeed Analysis')
print('='*70)
print()

start_total = time.time()

# Build phase
print('[1/2] Building call graph and summaries...')
start = time.time()
tracker = InterproceduralBugTracker.from_project(
    Path('external_tools/DeepSpeed'), 
    None
)
build_time = time.time() - start
print(f'      Build time: {build_time:.1f}s')
print()

# Analysis phase
print('[2/2] Running bug detection...')
start = time.time()
bugs = tracker.find_all_bugs(only_non_security=True)
analysis_time = time.time() - start

total_time = time.time() - start_total

print()
print('='*70)
print('RESULTS')
print('='*70)
print(f'Build time:     {build_time:.1f}s')
print(f'Analysis time:  {analysis_time:.1f}s')
print(f'Total time:     {total_time:.1f}s')
print()
print(f'Total bugs:     {len(bugs)}')
print(f'Analysis rate:  {len(bugs)/analysis_time:.2f} bugs/second')
print()

counts = Counter(b.bug_type for b in bugs)
print('Breakdown by type:')
for bug_type, count in sorted(counts.items(), key=lambda x: -x[1]):
    print(f'  {bug_type:20s}: {count:4d}')

print()
print('='*70)
