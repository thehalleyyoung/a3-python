"""Measure actual FP reduction on DeepSpeed with deployed strategies."""
import sys
import logging
from pathlib import Path
from collections import Counter
sys.path.insert(0, '.')

# Suppress warnings, only show strategy hits
logging.basicConfig(level=logging.WARNING, format='%(asctime)s [%(levelname)s] %(message)s')

# Enable INFO for extreme verification to see strategy hits
extreme_logger = logging.getLogger('pyfromscratch.barriers.extreme_verification')
extreme_logger.setLevel(logging.INFO)

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

print('='*80)
print('MEASURING FP REDUCTION WITH DEPLOYED STRATEGIES')
print('='*80)
print('\nAnalyzing DeepSpeed (this will take ~30 minutes)...')
print('Watching for strategy activations...\n')

tracker = InterproceduralBugTracker.from_project(Path('external_tools/DeepSpeed'), None)
bugs = tracker.find_all_bugs(only_non_security=True)
high = [b for b in bugs if b.confidence >= 0.7]

print(f'\n{"="*80}')
print('RESULTS')
print('='*80)
print(f'\nTotal bugs: {len(bugs)}')
print(f'HIGH confidence (>=0.7): {len(high)}')

counts = Counter(b.bug_type for b in high)
print(f'\nBy type:')
for t, c in sorted(counts.items(), key=lambda x: -x[1]):
    print(f'  {t}: {c}')

print(f'\n{"="*80}')
print('COMPARISON')
print('='*80)
print(f'BASELINE (before strategies): 303 bugs')
print(f'CURRENT (with strategies):    {len(high)} bugs')
print(f'REDUCTION:                    {303 - len(high)} bugs ({(303-len(high))/303*100:.1f}%)')
print('='*80)
