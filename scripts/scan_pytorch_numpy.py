#!/usr/bin/env python3
"""Scan PyTorch's numpy compatibility layer for bugs."""

import sys
import os
sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')

from pyfromscratch.analyzer import Analyzer

analyzer = Analyzer(max_paths=500, max_depth=500, timeout_ms=10000)

# Numpy compatibility files
numpy_files = [
    'torch/_numpy/_reductions_impl.py',
    'torch/_numpy/_getlimits.py',
    'torch/_numpy/_unary_ufuncs_impl.py',
    'torch/_numpy/_casting_dicts.py',
    'torch/_numpy/_binary_ufuncs_impl.py',
    'torch/_numpy/random.py',
    'torch/_numpy/testing/utils.py',
    'torch/_numpy/_dtypes.py',
    'torch/_numpy/linalg.py',
    'torch/_numpy/_ndarray.py',
    'torch/_numpy/_ufuncs.py',
    'torch/_numpy/_util.py',
    'torch/_numpy/_normalizations.py',
    'torch/_numpy/_dtypes_impl.py',
    'torch/_numpy/fft.py',
    'torch/_numpy/_funcs_impl.py',
    'torch/_numpy/_funcs.py',
]

base_dir = '/Users/halleyyoung/Documents/PythonFromScratch/results/public_repos/pytorch'

for f in numpy_files:
    full_path = os.path.join(base_dir, f)
    if os.path.exists(full_path):
        result = analyzer.analyze_file(full_path)
        if result.verdict == 'BUG':
            print(f"{f}: {result.bug_type}")
            ce = result.counterexample
            if isinstance(ce, dict) and result.bug_type != 'PANIC':
                trace = ce.get('trace', [])
                print("  Last 8 trace lines:")
                for line in trace[-8:]:
                    print(f"    {line}")
