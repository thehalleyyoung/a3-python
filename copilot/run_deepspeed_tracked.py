#!/usr/bin/env python3
"""
Run DeepSpeed analysis with detailed paper tracking.
Shows which of the 25 papers actually proves safety for each bug.
"""
import sys
import time
import logging
from pathlib import Path
from collections import Counter

sys.path.insert(0, '.')

# Set WARNING level to see paper invocations (logged as warnings for visibility)
logging.basicConfig(
    level=logging.WARNING,
    format='%(message)s'
)

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

print('='*70)
print('DEEPSPEED ANALYSIS WITH 25-PAPER VERIFICATION')
print('='*70)
print()
print('Tracking which papers prove bugs safe:')
print('  Phase -2: Quick pre-check (heuristics)')
print('  Phase -1: Bayesian probabilistic FP scoring')
print('  Phase 0:  Semantic patterns (self, exceptions)')
print('  Layer 0:  Papers #21-25 (fast barriers)')
print('  Layers 1-5: Papers #1-20 (full verification)')
print()
print('='*70)
print()

start_time = time.time()

print('[1/2] Building tracker (loading codebase)...')
tracker = InterproceduralBugTracker.from_project(
    Path('external_tools/DeepSpeed'),
    None
)
build_time = time.time() - start_time
print(f'  Build time: {build_time:.1f}s')
print()

print('[2/2] Finding bugs with 25-paper verification...')
print('  (Watch for ✓ lines showing which paper proves safety)')
print()

analysis_start = time.time()
bugs = tracker.find_all_bugs(only_non_security=True)
analysis_time = time.time() - analysis_start

print()
print('='*70)
print('RESULTS')
print('='*70)
print(f'Total bugs found: {len(bugs)}')
print(f'Analysis time: {analysis_time:.1f}s ({len(bugs)/analysis_time:.1f} bugs/sec)')
print()

# Breakdown by type
counts = Counter(b.bug_type for b in bugs)
print('Breakdown by type:')
for bug_type, count in sorted(counts.items(), key=lambda x: -x[1]):
    print(f'  {bug_type}: {count}')

print()
print('='*70)
print('Note: Check the output above for ✓ lines showing which papers')
print('      actually proved bugs safe and were filtered out.')
print('='*70)
