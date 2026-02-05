#!/usr/bin/env python3
import json
from collections import Counter

# Load previous results
with open('results/extreme_deepspeed_results.json') as f:
    prev = json.load(f)

# Load improved results
with open('results/improved_extreme_results.json') as f:
    improved = json.load(f)

print('='*80)
print('COMPARISON: BEFORE vs AFTER IMPROVEMENTS')
print('='*80)
print(f'Previous run:')
print(f'  Total bugs: {prev.get("total_bugs_found", 0)}')
print(f'  HIGH severity: {prev.get("high_severity", 0)}')
print(f'  MEDIUM severity: {prev.get("medium_severity", 0)}')
print(f'  LOW severity: {prev.get("low_severity", 0)}')

print(f'\nImproved run:')
print(f'  Total bugs: {improved.get("total_bugs_found", 0)}')
print(f'  HIGH severity: {improved.get("high_severity", 0)}')
print(f'  MEDIUM severity: {improved.get("medium_severity", 0)}')
print(f'  LOW severity: {improved.get("low_severity", 0)}')

# Check bug types
prev_bugs = prev.get('bugs', [])
improved_bugs = improved.get('bugs', [])

print(f'\nPrevious bug types (first 100 saved):')
prev_types = Counter([b.get('bug_type') for b in prev_bugs])
for bug_type, count in prev_types.most_common():
    print(f'  {bug_type}: {count}')

print(f'\nImproved bug types (first 100 saved):')
improved_types = Counter([b.get('bug_type') for b in improved_bugs])
for bug_type, count in improved_types.most_common():
    print(f'  {bug_type}: {count}')

print(f'\nDIAGNOSIS:')
print(f'  Change in total bugs: {improved.get("total_bugs_found", 0) - prev.get("total_bugs_found", 0):+d}')
print(f'  Change in HIGH bugs: {improved.get("high_severity", 0) - prev.get("high_severity", 0):+d}')
