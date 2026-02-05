"""Run DeepSpeed analysis with deployed FP reduction strategies."""
import sys
import logging
from pathlib import Path
from collections import Counter
sys.path.insert(0, '.')

# Set up logging to show strategy activations
logging.basicConfig(
    level=logging.WARNING,
    format='%(message)s'
)

# Enable INFO for extreme verification to see strategy hits
extreme_logger = logging.getLogger('pyfromscratch.barriers.extreme_verification')
extreme_logger.setLevel(logging.INFO)

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

print('='*80)
print('DEEPSPEED ANALYSIS WITH DEPLOYED FP REDUCTION STRATEGIES')
print('='*80)
print('\nAnalyzing DeepSpeed (~30 minutes)...')
print('Watch for [EXTREME] [STRATEGY N] messages showing FP elimination\n')

tracker = InterproceduralBugTracker.from_project(
    Path('external_tools/DeepSpeed'), 
    None
)

bugs = tracker.find_all_bugs(only_non_security=True)
high = [b for b in bugs if b.confidence >= 0.7]

print(f'\n{"="*80}')
print('RESULTS WITH FP REDUCTION STRATEGIES')
print('='*80)
print(f'\nTotal bugs: {len(bugs)}')
print(f'HIGH confidence (>=0.7): {len(high)}')

counts = Counter(b.bug_type for b in high)
print(f'\nBy type:')
for t, c in sorted(counts.items(), key=lambda x: -x[1]):
    print(f'  {t}: {c}')

# Check for param_0 (should be 0)
null_ptrs = [b for b in high if b.bug_type == 'NULL_PTR']
param_0 = [b for b in null_ptrs if b.bug_variable == 'param_0']

print(f'\n{"="*80}')
print('FP REDUCTION ANALYSIS')
print('='*80)
print(f'NULL_PTR param_0: {len(param_0)} (should be 0 - filtered by Phase 0)')
print(f'NULL_PTR remaining: {len(null_ptrs)}')

print(f'\n{"="*80}')
print('COMPARISON')
print('='*80)
print(f'BASELINE (before strategies):  303 bugs')
print(f'CURRENT (with strategies):     {len(high)} bugs')
print(f'REDUCTION:                     {303 - len(high)} bugs')
print(f'PERCENTAGE:                    {(303 - len(high))/303*100:.1f}%')
print('='*80)

# Save results
with open('results/deepspeed_with_strategies.txt', 'w') as f:
    f.write(f'DeepSpeed Analysis with FP Reduction Strategies\n')
    f.write(f'=' * 80 + '\n\n')
    f.write(f'Total bugs: {len(bugs)}\n')
    f.write(f'HIGH confidence: {len(high)}\n\n')
    f.write(f'By type:\n')
    for t, c in sorted(counts.items(), key=lambda x: -x[1]):
        f.write(f'  {t}: {c}\n')
    f.write(f'\nBaseline: 303 bugs\n')
    f.write(f'Current:  {len(high)} bugs\n')
    f.write(f'Reduction: {303 - len(high)} bugs ({(303-len(high))/303*100:.1f}%)\n')

print(f'\nResults saved to results/deepspeed_with_strategies.txt')
