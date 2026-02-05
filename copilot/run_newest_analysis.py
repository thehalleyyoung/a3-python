"""Run DeepSpeed analysis with newest FP reduction strategies."""
import sys
import time
import json
from pathlib import Path
from collections import Counter
from datetime import datetime
sys.path.insert(0, '.')

print('='*80)
print('DEEPSPEED ANALYSIS WITH FP REDUCTION STRATEGIES')
print('='*80)
print(f'Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
print('Analyzing DeepSpeed with all 4 deployed strategies...\n')

start_time = time.time()

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

# Run analysis
tracker = InterproceduralBugTracker.from_project(
    Path('external_tools/DeepSpeed'), 
    None
)

bugs = tracker.find_all_bugs(only_non_security=True)
high = [b for b in bugs if b.confidence >= 0.7]

elapsed = time.time() - start_time

# Collect results
results = {
    'timestamp': datetime.now().isoformat(),
    'elapsed_seconds': int(elapsed),
    'elapsed_minutes': elapsed / 60,
    'total_bugs': len(bugs),
    'high_confidence_count': len(high),
    'baseline_bugs': 303,
}

# Count by type
type_counts = Counter(b.bug_type for b in high)
results['bug_type_counts'] = dict(type_counts)

# Check for param_0 (should be 0 after strategies)
null_ptrs = [b for b in high if b.bug_type == 'NULL_PTR']
param_0 = [b for b in null_ptrs if b.bug_variable == 'param_0']
results['null_ptr_param_0_count'] = len(param_0)
results['null_ptr_total'] = len(null_ptrs)

# Calculate FP reduction
results['fp_reduction'] = 303 - len(high)
results['fp_reduction_percent'] = (303 - len(high)) / 303 * 100

# Sample bugs
results['sample_bugs'] = []
for bug in high[:10]:
    results['sample_bugs'].append({
        'type': bug.bug_type,
        'function': bug.func_name,
        'line': bug.line_number,
        'variable': bug.bug_variable,
        'confidence': bug.confidence,
    })

# Save results
with open('results/newest_deepspeed_analysis.json', 'w') as f:
    json.dump(results, f, indent=2)

# Print results
print(f'\n{"="*80}')
print('RESULTS WITH FP REDUCTION STRATEGIES')
print('='*80)
print(f'\nExecution time: {elapsed/60:.1f} minutes')
print(f'\nTotal bugs: {len(bugs)}')
print(f'HIGH confidence (>=0.7): {len(high)}')
print(f'\nBy type:')
for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
    print(f'  {t}: {c}')

print(f'\n{"="*80}')
print('FP REDUCTION ANALYSIS')
print('='*80)
print(f'NULL_PTR param_0: {len(param_0)} (should be 0 - Phase 0 filter)')
print(f'NULL_PTR remaining: {len(null_ptrs)}')

print(f'\n{"="*80}')
print('COMPARISON TO BASELINE')
print('='*80)
print(f'Baseline (before strategies):  303 bugs')
print(f'Current (with strategies):     {len(high)} bugs')
print(f'FP Reduction:                  {303 - len(high)} bugs ({(303-len(high))/303*100:.1f}%)')
print('='*80)

print(f'\n✅ Results saved to: results/newest_deepspeed_analysis.json')
print(f'Completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
