#!/usr/bin/env python3
"""Analyze DSE verification breakdown."""

from pathlib import Path
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.unsafe.registry import SECURITY_BUG_TYPES
from collections import Counter

root = Path('external_tools/pygoat')
tracker = InterproceduralBugTracker.from_project(root)

# Get all bugs
bugs_all = tracker.find_all_bugs(apply_fp_reduction=False)

# Verify with DSE
tracker2 = InterproceduralBugTracker.from_project(root)
confirmed, refuted, unknown = tracker2.verify_bugs_with_dse(bugs_all, max_steps=50)

print(f'Total bugs: {len(bugs_all)}')
print(f'DSE Confirmed: {len(confirmed)}')
print(f'DSE Refuted: {len(refuted)}')
print(f'DSE Unknown: {len(unknown)}')

# Check security bugs specifically
security_refuted = [b for b in refuted if b.bug_type in SECURITY_BUG_TYPES]
print()
print(f'Security bugs refuted by DSE: {len(security_refuted)}')
print('(These may be TRUE POSITIVES that DSE wrongly refuted)')

# Sample refuted security bugs
print()
print('Sample refuted security bugs:')
for bug in security_refuted[:10]:
    print(f'  {bug.bug_type}: {bug.crash_function}')

# Count refuted by type
print()
print('Refuted by type:')
refuted_by_type = Counter(b.bug_type for b in refuted)
for bt, count in sorted(refuted_by_type.items(), key=lambda x: -x[1])[:15]:
    print(f'  {bt}: {count}')
