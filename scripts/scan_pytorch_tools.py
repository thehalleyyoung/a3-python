#!/usr/bin/env python3
"""Scan PyTorch tools (non-torch) for bugs."""

import sys
import os
sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')

from pyfromscratch.analyzer import Analyzer

analyzer = Analyzer(max_paths=500, max_depth=500, timeout_ms=10000)

# Tool files to analyze (outside torch/)
tool_files = [
    './tools/packaging/build_wheel.py',
    './tools/experimental/torchfuzz/runner.py',
    './tools/experimental/torchfuzz/operators/scalar_pointwise.py',
    './tools/experimental/torchfuzz/operators/gather.py',
    './tools/experimental/torchfuzz/operators/argsort.py',
    './tools/experimental/torchfuzz/operators/tensor_pointwise.py',
    './tools/experimental/torchfuzz/operators/nonzero.py',
    './tools/experimental/torchfuzz/operators/masked_select.py',
    './tools/experimental/torchfuzz/operators/registry.py',
    './tools/experimental/torchfuzz/operators/unique.py',
    './tools/experimental/torchfuzz/operators/index_select.py',
    './tools/experimental/torchfuzz/operators/arg.py',
    './tools/experimental/torchfuzz/operators/constant.py',
    './tools/experimental/torchfuzz/operators/base.py',
    './tools/experimental/torchfuzz/operators/item.py',
    './tools/experimental/torchfuzz/checks.py',
    './tools/experimental/torchfuzz/tensor_descriptor.py',
    './tools/experimental/torchfuzz/visualize_graph.py',
    './tools/experimental/torchfuzz/type_promotion.py',
    './tools/vscode_settings.py',
    './tools/gdb/pytorch-gdb.py',
    './tools/extract_scripts.py',
    './tools/iwyu/fixup.py',
    './tools/nvcc_fix_deps.py',
    './tools/substitute.py',
    './tools/linter/adapters/gha_linter.py',
    './tools/linter/adapters/actionlint_linter.py',
]

base_dir = '/Users/halleyyoung/Documents/PythonFromScratch/results/public_repos/pytorch'

for f in tool_files:
    full_path = os.path.join(base_dir, f)
    if os.path.exists(full_path):
        result = analyzer.analyze_file(full_path)
        if result.verdict == 'BUG':
            print(f"{f}: {result.bug_type}")
            ce = result.counterexample
            if isinstance(ce, dict):
                trace = ce.get('trace', [])
                print("  Last 5 trace lines:")
                for line in trace[-5:]:
                    print(f"    {line}")
