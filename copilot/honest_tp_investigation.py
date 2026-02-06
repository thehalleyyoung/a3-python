#!/usr/bin/env python3
"""
Honest, thorough investigation of every TP candidate.
For each: read the actual source, trace callers, determine if a crash
is genuinely reachable in production.
"""
import json, os, re, subprocess
from pathlib import Path
from collections import defaultdict

DS = Path('external_tools/DeepSpeed')

with open('results/tp_investigation.json') as f:
    bugs = json.load(f)

# Get ALL production bugs (not test), grouped by type
prod = [b for b in bugs if not b['is_test']]
test = [b for b in bugs if b['is_test']]

def read_func(filepath, func_name):
    """Read function source from file."""
    if not filepath or not os.path.exists(filepath):
        return None
    with open(filepath) as f:
        lines = f.readlines()
    # Find the function
    for i, line in enumerate(lines):
        if f'def {func_name}' in line:
            start = i
            indent = len(line) - len(line.lstrip())
            end = i + 1
            for j in range(i + 1, min(len(lines), i + 100)):
                s = lines[j].rstrip()
                if s == '':
                    end = j + 1
                    continue
                ci = len(lines[j]) - len(lines[j].lstrip())
                if ci <= indent and s:
                    break
                end = j + 1
            return ''.join(lines[start:end]).rstrip()
    return None

def grep_callers(func_name, max_results=20):
    """Find callers of a function in DeepSpeed."""
    try:
        result = subprocess.run(
            ['grep', '-rn', func_name, '--include=*.py', str(DS)],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split('\n')
        # Filter out definition, __pycache__, and imports
        callers = []
        for line in lines:
            if '__pycache__' in line:
                continue
            if f'def {func_name}' in line:
                continue
            if line.strip():
                callers.append(line.strip())
        return callers[:max_results]
    except Exception:
        return []

# ================================================================
# INVESTIGATE EVERY DIV_ZERO
# ================================================================
print("=" * 78)
print("  DIV_ZERO INVESTIGATION (19 production + 3 test)")
print("=" * 78)

divzero_bugs = [b for b in prod if b['bug_type'] == 'DIV_ZERO']
for b in divzero_bugs:
    fn = b['function']
    parts = fn.split('.')
    short = parts[-1]
    
    print(f"\n{'─' * 78}")
    print(f"  {fn}")
    print(f"  File: {b.get('file', 'unknown')}")
    
    body = b.get('body', '')
    if body:
        for line in body.split('\n')[:12]:
            print(f"    {line}")
    
    # Find callers
    callers = grep_callers(short)
    if callers:
        print(f"\n  Callers ({len(callers)}):")
        for c in callers[:5]:
            # Shorten path
            c = c.replace(str(DS) + '/', '')
            print(f"    {c[:120]}")
    
    # Manual analysis
    if body:
        # Check what's being divided by
        div_match = re.search(r'(\w+(?:\.\w+)*)\s*(?://|/|%)\s*(\w+(?:\.\w+|\(\))*)', body)
        if div_match:
            print(f"\n  Division: {div_match.group(0)}")
            divisor = div_match.group(2)
            print(f"  Divisor: {divisor}")
            
            # Check if divisor has a guard
            if f'if {divisor}' in body or f'assert {divisor}' in body or f'{divisor} != 0' in body or f'{divisor} > 0' in body:
                print(f"  Guard: YES — divisor is checked before use")
            else:
                print(f"  Guard: NO — divisor is NOT checked")

print()

# ================================================================
# INVESTIGATE KEY NULL_PTR candidates (not already dismissed)
# ================================================================
print("=" * 78)
print("  NULL_PTR INVESTIGATION — remaining candidates")
print("=" * 78)

# Focus on the ones that are MOST likely to be real
# Skip property setters, self-return, framework-injected
interesting_null = []
for b in prod:
    if b['bug_type'] != 'NULL_PTR':
        continue
    fn = b['function']
    body = b.get('body', '') or ''
    
    # Skip simple self patterns already dismissed
    if b['verdict'] in ('FP_SELF', 'FP_FRAMEWORK'):
        continue
    
    # Skip if already investigated as FP_INTERNAL
    interesting_null.append(b)

print(f"\n  {len(interesting_null)} NULL_PTR candidates remaining after filtering")

for b in interesting_null[:30]:
    fn = b['function']
    parts = fn.split('.')
    short = parts[-1]
    body = b.get('body', '') or ''
    
    print(f"\n  {'─' * 70}")
    print(f"  {fn}")
    if body:
        for line in body.split('\n')[:8]:
            print(f"    {line}")
    
    callers = grep_callers(short)
    print(f"  Callers: {len(callers)}")
    for c in callers[:3]:
        c = c.replace(str(DS) + '/', '')
        print(f"    {c[:120]}")

print()

# ================================================================
# RUNTIME_ERROR and VALUE_ERROR
# ================================================================
print("=" * 78)
print("  RUNTIME_ERROR / VALUE_ERROR INVESTIGATION")
print("=" * 78)

for b in prod:
    if b['bug_type'] not in ('RUNTIME_ERROR', 'VALUE_ERROR'):
        continue
    fn = b['function']
    body = b.get('body', '') or ''
    print(f"\n  {b['bug_type']} in {fn}")
    if body:
        for line in body.split('\n')[:10]:
            print(f"    {line}")
    
    if 'raise RuntimeError' in body or 'raise ValueError' in body:
        print(f"  → INTENTIONAL GUARD (deliberate raise)")
    else:
        print(f"  → Needs investigation")
