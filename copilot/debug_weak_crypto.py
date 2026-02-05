#!/usr/bin/env python3
"""Debug WEAK_CRYPTO bug handling."""

from pathlib import Path
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.unsafe.registry import SECURITY_BUG_TYPES

root = Path('external_tools/pygoat')
tracker = InterproceduralBugTracker.from_project(root)

# Get bugs without DSE
bugs_all = tracker.find_all_bugs(apply_fp_reduction=False)

# Find WEAK_CRYPTO bugs
weak_crypto = [b for b in bugs_all if b.bug_type == 'WEAK_CRYPTO']
print(f'WEAK_CRYPTO bugs found: {len(weak_crypto)}')

for bug in weak_crypto:
    print(f'  Function: {bug.crash_function}')
    print(f'  Location: {bug.crash_location}')

# Now run DSE verification
tracker2 = InterproceduralBugTracker.from_project(root)
confirmed, refuted, unknown = tracker2.verify_bugs_with_dse(bugs_all, max_steps=50)

# Check where WEAK_CRYPTO bugs went
weak_confirmed = [b for b in confirmed if b.bug_type == 'WEAK_CRYPTO']
weak_refuted = [b for b in refuted if b.bug_type == 'WEAK_CRYPTO']
weak_unknown = [b for b in unknown if b.bug_type == 'WEAK_CRYPTO']

print()
print(f'WEAK_CRYPTO - Confirmed: {len(weak_confirmed)}')
print(f'WEAK_CRYPTO - Refuted: {len(weak_refuted)}')
print(f'WEAK_CRYPTO - Unknown: {len(weak_unknown)}')

# Check if WEAK_CRYPTO is in SECURITY_BUG_TYPES
print()
print(f"'WEAK_CRYPTO' in SECURITY_BUG_TYPES: {'WEAK_CRYPTO' in SECURITY_BUG_TYPES}")
