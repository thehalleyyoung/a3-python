#!/usr/bin/env python3
"""Compare DSE-verified results against baseline."""

from pathlib import Path
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from collections import Counter

root = Path('external_tools/pygoat')

print("Building tracker for pygoat...")
tracker = InterproceduralBugTracker.from_project(root)

# Get bugs without DSE (with FP reduction to match DSE mode)
print("Finding bugs (without DSE verification)...")
bugs_without_dse = tracker.find_all_bugs(apply_fp_reduction=True)

# Reset for second analysis
print("Finding bugs (with DSE verification)...")
tracker2 = InterproceduralBugTracker.from_project(root)
# Use apply_fp_reduction=True to match
bugs_with_dse = tracker2.find_all_bugs_with_dse_verification(max_dse_steps=50, apply_fp_reduction=True)

print()
print('=== COMPARISON ===')
print(f'Without DSE verification: {len(bugs_without_dse)} bugs')
print(f'With DSE verification: {len(bugs_with_dse)} bugs')
print(f'Reduction: {len(bugs_without_dse) - len(bugs_with_dse)} bugs ({100*(len(bugs_without_dse) - len(bugs_with_dse))/len(bugs_without_dse):.1f}%)')

print()
print('=== KEY TRUE POSITIVES (from validation report) ===')

# Check for validated vulnerabilities
validated = {
    'SQL_INJECTION': 4,
    'COMMAND_INJECTION': 7,
    'CODE_INJECTION': 6,
    'UNSAFE_DESERIALIZATION': 6,
    'REFLECTED_XSS': 10,
    'PATH_INJECTION': 13,
    'XXE': 2,
    'CLEARTEXT_LOGGING': 3,
    'WEAK_CRYPTO': 8,
}

without = Counter(b.bug_type for b in bugs_without_dse)
with_dse = Counter(b.bug_type for b in bugs_with_dse)

print(f"{'Bug Type':<25} {'Validated':<10} {'Without DSE':<12} {'With DSE':<10} {'Status'}")
print('-' * 70)

lost_tps = 0
for bug_type, validated_count in validated.items():
    wo = without.get(bug_type, 0)
    w = with_dse.get(bug_type, 0)
    # Check related types too
    if bug_type == 'CODE_INJECTION':
        wo += without.get('EVAL_INJECTION', 0) + without.get('EXEC_INJECTION', 0)
        w += with_dse.get('EVAL_INJECTION', 0) + with_dse.get('EXEC_INJECTION', 0)
    elif bug_type == 'UNSAFE_DESERIALIZATION':
        wo += without.get('PICKLE_INJECTION', 0)
        w += with_dse.get('PICKLE_INJECTION', 0)
    
    if w >= validated_count:
        status = 'OK'
    elif w > 0:
        status = f'PARTIAL ({w}/{validated_count})'
        lost_tps += validated_count - w
    else:
        status = 'LOST'
        lost_tps += validated_count
    
    print(f'{bug_type:<25} {validated_count:<10} {wo:<12} {w:<10} {status}')

print()
print(f'=== NULL_PTR and BOUNDS (non-security bugs) ===')
print(f"NULL_PTR: Without={without.get('NULL_PTR', 0)}, With DSE={with_dse.get('NULL_PTR', 0)}")
print(f"BOUNDS: Without={without.get('BOUNDS', 0)}, With DSE={with_dse.get('BOUNDS', 0)}")

print()
print('=== SUMMARY ===')
print(f'Potential lost true positives: {lost_tps}')
print(f'False positive reduction: {len(bugs_without_dse) - len(bugs_with_dse)} bugs')
print(f'FP reduction rate: {100*(len(bugs_without_dse) - len(bugs_with_dse))/len(bugs_without_dse):.1f}%')
