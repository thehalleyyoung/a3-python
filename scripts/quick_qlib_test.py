#!/usr/bin/env python3
"""Quick test of barrier analysis on Qlib."""
from pathlib import Path
from pyfromscratch.analyzer import Analyzer

# Test on a simple utils file
filepath = Path('external_tools/Qlib/qlib/utils/data.py')
analyzer = Analyzer(verbose=False, max_depth=20)
result = analyzer.analyze_file(filepath)

print(f'File: qlib/utils/data.py')
print(f'Verdict: {result.verdict}')
if result.barrier:
    print(f'Barrier: {result.barrier.name}')
print(f'Paths: {result.paths_explored}')
