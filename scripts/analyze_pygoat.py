#!/usr/bin/env python3
"""Analyze PyGoat and compare with CodeQL findings."""
from pyfromscratch.analyzer import Analyzer
from pathlib import Path
import json

pygoat_dir = Path('external_tools/pygoat')
python_files = list(pygoat_dir.rglob('*.py'))

# Filter out migrations and tests
python_files = [f for f in python_files if 'migration' not in str(f) and '__pycache__' not in str(f)]

print(f'Found {len(python_files)} Python files to analyze')

# Analyze key vulnerability files
key_files = [
    'introduction/views.py',
    'introduction/utility.py', 
    'challenge/views.py',
    'introduction/mitre.py',
]

all_bugs = []
analyzer = Analyzer(verbose=False)

for key_file in key_files:
    filepath = pygoat_dir / key_file
    if filepath.exists():
        print(f'Analyzing {key_file}...')
        try:
            result = analyzer.analyze_file(filepath)
            if result.verdict == 'BUG':
                all_bugs.append({
                    'file': key_file,
                    'bug_type': result.bug_type,
                    'details': result.counterexample if hasattr(result, 'counterexample') else None
                })
                print(f'  Found: {result.bug_type}')
        except Exception as e:
            print(f'  Error: {e}')
    else:
        print(f'  File not found: {filepath}')

print(f'\nTotal bugs found in key files: {len(all_bugs)}')
for bug in all_bugs:
    print(f"  {bug['file']}: {bug['bug_type']}")
