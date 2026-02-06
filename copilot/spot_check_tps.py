#!/usr/bin/env python3
"""
Manual spot-check of FP_SELF and borderline cases.
Read the actual source for each to determine ground truth.
"""
import json
from pathlib import Path

with open('results/tp_investigation.json') as f:
    bugs = json.load(f)

DEEPSPEED = Path('external_tools/DeepSpeed')

# Get all FP_SELF bugs with their bodies
fp_self = [b for b in bugs if b['verdict'] == 'FP_SELF']

print(f"=== FP_SELF: {len(fp_self)} bugs to spot-check ===\n")

# Group by pattern
simple_returns = []
simple_setters = []
method_self_only = []
other = []

for b in fp_self:
    body = b.get('body', '') or ''
    lines = body.strip().split('\n')
    code = [l.strip() for l in lines[1:] if l.strip() and not l.strip().startswith('#')
            and not l.strip().startswith('"""') and not l.strip().startswith("'''")]
    
    if len(code) <= 2 and code and ('return self.' in code[0]):
        simple_returns.append(b)
    elif len(code) <= 2 and code and ('self.' in code[0] and '=' in code[0]):
        simple_setters.append(b)
    else:
        other.append(b)

print(f"  Simple returns (return self.x):  {len(simple_returns)}")
print(f"  Simple setters (self.x = val):   {len(simple_setters)}")
print(f"  Other methods:                   {len(other)}")

# Show the "other" ones - these need manual review
print(f"\n{'='*70}")
print(f"FP_SELF 'OTHER' - needs manual review ({len(other)}):")
print(f"{'='*70}")
for b in other:
    print(f"\n  {b['bug_type']} in {b['function']}")
    body = b.get('body', '')
    if body:
        for line in body.split('\n')[:10]:
            print(f"    {line}")
    print(f"    VERDICT: {b['verdict']} — {b['reason']}")

# Now check: are the simple returns actually properties? 
# Some `self.x` values are set in __init__ from user-provided params that could be None
print(f"\n{'='*70}")
print(f"SAMPLE: simple return properties")
print(f"{'='*70}")
for b in simple_returns[:10]:
    print(f"  {b['function']}")
    body = b.get('body', '')
    if body:
        for line in body.split('\n')[:4]:
            print(f"    {line}")
    print()

# Check the REAL_BUG NULL_PTR production ones more carefully
print(f"\n{'='*70}")
print(f"REAL_BUG NULL_PTR - production ({len([b for b in bugs if b['verdict']=='REAL_BUG' and b['bug_type']=='NULL_PTR' and not b['is_test']])})")
print(f"{'='*70}")
real_null = [b for b in bugs if b['verdict']=='REAL_BUG' and b['bug_type']=='NULL_PTR' and not b['is_test']]
for b in real_null:
    body = b.get('body', '')
    # Try to determine if it's genuinely reachable
    print(f"\n  {b['function']}")
    if body:
        for line in body.split('\n')[:6]:
            print(f"    {line}")
    print(f"    → {b['reason']}")
