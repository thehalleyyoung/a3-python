#!/usr/bin/env python3
"""Debug WEAK_CRYPTO flow through verification."""

from pathlib import Path
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

root = Path('external_tools/pygoat')

# Get bugs and verify
tracker = InterproceduralBugTracker.from_project(root)
bugs = tracker.find_all_bugs(apply_fp_reduction=False)

# Get WEAK_CRYPTO bugs
weak_crypto_bugs = [b for b in bugs if b.bug_type == 'WEAK_CRYPTO']
print(f"Input WEAK_CRYPTO bugs: {len(weak_crypto_bugs)}")

# Run verification
confirmed, refuted, unknown = tracker.verify_bugs_with_dse(bugs, max_steps=50)

print(f"Confirmed: {len(confirmed)}")
print(f"Refuted: {len(refuted)}")
print(f"Unknown: {len(unknown)}")
print(f"Total: {len(confirmed) + len(refuted) + len(unknown)}")

# Check WEAK_CRYPTO in each bucket
weak_confirmed = [b for b in confirmed if b.bug_type == 'WEAK_CRYPTO']
weak_refuted = [b for b in refuted if b.bug_type == 'WEAK_CRYPTO']
weak_unknown = [b for b in unknown if b.bug_type == 'WEAK_CRYPTO']

print()
print(f"WEAK_CRYPTO in confirmed: {len(weak_confirmed)}")
print(f"WEAK_CRYPTO in refuted: {len(weak_refuted)}")
print(f"WEAK_CRYPTO in unknown: {len(weak_unknown)}")
print(f"WEAK_CRYPTO total: {len(weak_confirmed) + len(weak_refuted) + len(weak_unknown)}")

# The result of find_all_bugs_with_dse_verification should be confirmed + unknown
result = confirmed + unknown
weak_in_result = [b for b in result if b.bug_type == 'WEAK_CRYPTO']
print()
print(f"WEAK_CRYPTO in final result (confirmed + unknown): {len(weak_in_result)}")
