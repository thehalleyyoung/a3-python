#!/usr/bin/env python3
"""Extract first 100 high-confidence bugs for manual inspection."""

import sys
import json
from pathlib import Path

sys.path.insert(0, '.')
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

print("Loading DeepSpeed bugs...")
tracker = InterproceduralBugTracker.from_project(Path('external_tools/DeepSpeed'), None)
bugs = tracker.find_all_bugs(only_non_security=True)
high = [b for b in bugs if b.confidence >= 0.7]

print(f"Found {len(high)} high-confidence bugs, extracting first 100...")

# Get first 100 with detailed info
results = []
for i, b in enumerate(high[:100], 1):
    bug_info = {
        'id': i,
        'type': b.bug_type,
        'confidence': round(b.confidence, 2),
        'function': b.crash_function,
        'variable': getattr(b, 'bug_variable', None),
        'location': b.crash_location,
        'reason': b.reason[:200] if len(b.reason) > 200 else b.reason,
        'call_chain': b.call_chain[-3:] if len(b.call_chain) > 3 else b.call_chain  # Last 3 callers
    }
    results.append(bug_info)

with open('first_100_bugs.json', 'w') as f:
    json.dump(results, f, indent=2)

print(f"\nSaved {len(results)} bugs to first_100_bugs.json")

# Print summary
print("\nBug type distribution:")
from collections import Counter
counts = Counter(b['type'] for b in results)
for bug_type, count in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"  {bug_type}: {count}")
