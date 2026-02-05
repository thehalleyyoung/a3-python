#!/usr/bin/env python3
"""Debug WEAK_CRYPTO count discrepancy."""

from pathlib import Path
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from collections import Counter

root = Path('external_tools/pygoat')

# Analysis 1: Without DSE
tracker1 = InterproceduralBugTracker.from_project(root)
bugs_without = tracker1.find_all_bugs(apply_fp_reduction=False)
without_count = Counter(b.bug_type for b in bugs_without)
print(f"Without DSE: WEAK_CRYPTO = {without_count.get('WEAK_CRYPTO', 0)}")

# Analysis 2: With DSE verification
tracker2 = InterproceduralBugTracker.from_project(root)
bugs_with = tracker2.find_all_bugs_with_dse_verification(max_dse_steps=50)
with_count = Counter(b.bug_type for b in bugs_with)
print(f"With DSE: WEAK_CRYPTO = {with_count.get('WEAK_CRYPTO', 0)}")

# Check the actual bugs
print()
print("WEAK_CRYPTO bugs in 'without':")
for b in bugs_without:
    if b.bug_type == 'WEAK_CRYPTO':
        print(f"  {b.crash_function}")

print()
print("WEAK_CRYPTO bugs in 'with':")
for b in bugs_with:
    if b.bug_type == 'WEAK_CRYPTO':
        print(f"  {b.crash_function}")
