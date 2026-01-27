#!/usr/bin/env python3
"""Detailed analysis of PyTorch bugs from the scanner."""

import sys
sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')

from pyfromscratch.analyzer import Analyzer

analyzer = Analyzer(max_paths=500, max_depth=500, timeout_ms=10000)

# Get more details for specific files with non-PANIC bugs
files_to_analyze = [
    'results/public_repos/pytorch/torch/optim/optimizer.py',
    'results/public_repos/pytorch/torch/fx/_symbolic_trace.py',
    'results/public_repos/pytorch/torch/nn/utils/clip_grad.py',
    'results/public_repos/pytorch/torch/optim/_muon.py',
    'results/public_repos/pytorch/torch/utils/data/graph.py',
]

for f in files_to_analyze:
    result = analyzer.analyze_file(f)
    print(f'=== {f} ===')
    print(f'Verdict: {result.verdict}')
    print(f'Bug type: {getattr(result, "bug_type", "N/A")}')
    if hasattr(result, 'details'):
        # print more of the trace
        d = result.details
        if isinstance(d, str):
            try:
                d = eval(d)
            except:
                pass
        if isinstance(d, dict):
            trace = d.get('trace', [])
            print('Trace (last 20 lines):')
            for line in trace[-20:]:
                print(f'  {line}')
    print()
