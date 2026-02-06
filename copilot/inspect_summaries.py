#!/usr/bin/env python3
"""
Inspect what's actually in the crash summaries.
"""

import pickle
from pathlib import Path

cache_file = Path('results/deepspeed_crash_summaries.pkl')

with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)

print(f"Loaded {len(summaries)} summaries")
print()

# Look at first few summaries
for i, (func_name, summary) in enumerate(list(summaries.items())[:5]):
    print("=" * 80)
    print(f"Function: {func_name}")
    print("=" * 80)
    print(f"Type: {type(summary)}")
    print(f"Attributes: {dir(summary)}")
    print()
    
    # Show relevant attributes
    if hasattr(summary, '__dict__'):
        for attr, value in summary.__dict__.items():
            if not attr.startswith('_'):
                val_str = str(value)[:200]
                print(f"  {attr}: {val_str}")
    print()
    
    if i >= 2:
        break

# Count bugs if they exist
total_with_bugs = 0
bug_attrs = ['guarded_bugs', 'direct_bugs', 'bugs', 'crash_bugs']

for func_name, summary in summaries.items():
    has_bugs = False
    for attr in bug_attrs:
        if hasattr(summary, attr):
            val = getattr(summary, attr)
            if val:
                has_bugs = True
                break
    if has_bugs:
        total_with_bugs += 1

print("=" * 80)
print(f"Functions with bugs: {total_with_bugs} / {len(summaries)}")
