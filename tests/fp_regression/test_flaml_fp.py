#!/usr/bin/env python3
"""
Test FP reduction on FLAML repo.
"""
import sys
import os
from pathlib import Path
from collections import Counter

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

flaml_path = Path(__file__).parent.parent.parent / 'external_tools' / 'FLAML'

if not flaml_path.exists():
    print(f"FLAML not found at {flaml_path}")
    sys.exit(1)

print(f"Testing FLAML at {flaml_path}")
print("=" * 60)

# Without FP reduction
print("Building call graph...")
tracker = InterproceduralBugTracker.from_project(flaml_path)
print("Analyzing (without FP reduction)...")
bugs_raw = tracker.find_all_bugs(apply_fp_reduction=False)
print(f'Without FP reduction: {len(bugs_raw)} bugs')
types_raw = Counter(b.bug_type for b in bugs_raw)
print(f'  Types: {dict(types_raw)}')

# With FP reduction
print("\nAnalyzing (with FP reduction)...")
tracker2 = InterproceduralBugTracker.from_project(flaml_path)
bugs_filtered = tracker2.find_all_bugs(apply_fp_reduction=True)
print(f'With FP reduction: {len(bugs_filtered)} bugs')
types_filtered = Counter(b.bug_type for b in bugs_filtered)
print(f'  Types: {dict(types_filtered)}')

# Show reduction rate
if len(bugs_raw) > 0:
    reduction = 100 * (1 - len(bugs_filtered) / len(bugs_raw))
    print(f'\nReduction: {reduction:.1f}%')
    
    # Show what was filtered
    print("\nFiltered bug types:")
    for bug_type in types_raw:
        before = types_raw.get(bug_type, 0)
        after = types_filtered.get(bug_type, 0)
        if before > after:
            print(f"  {bug_type}: {before} -> {after} (-{before - after})")
