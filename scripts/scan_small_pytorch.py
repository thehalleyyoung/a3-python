#!/usr/bin/env python3
"""Scan smaller PyTorch files for bugs."""

import sys
import os
sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')

from pyfromscratch.analyzer import Analyzer

analyzer = Analyzer(max_paths=500, max_depth=500, timeout_ms=10000)

# Small files to analyze
small_files = [
    './torch/_higher_order_ops/foreach_map.py',
    './torch/_higher_order_ops/_invoke_quant.py',
    './torch/_higher_order_ops/strict_mode.py',
    './torch/_higher_order_ops/hints_wrap.py',
    './torch/_higher_order_ops/print.py',
    './torch/_higher_order_ops/run_const_graph.py',
    './torch/_prims/debug_prims.py',
    './torch/_prims/executor.py',
    './torch/_opaque_base.py',
    './torch/_logging/scribe.py',
    './torch/_logging/structured.py',
    './torch/_functorch/_activation_checkpointing/remat_using_tags_for_fwd_loss_bwd_graph_pass.py',
    './torch/_functorch/python_key.py',
    './torch/_functorch/pytree_hacks.py',
    './torch/_functorch/batch_norm_replacement.py',
    './torch/_functorch/_aot_autograd/indexed_dict.py',
    './torch/_functorch/_aot_autograd/logging_utils.py',
    './torch/_functorch/utils.py',
    './torch/_numpy/_getlimits.py',
    './torch/_numpy/_unary_ufuncs_impl.py',
]

base_dir = '/Users/halleyyoung/Documents/PythonFromScratch/results/public_repos/pytorch'

results = []
for f in small_files:
    full_path = os.path.join(base_dir, f)
    if os.path.exists(full_path):
        result = analyzer.analyze_file(full_path)
        if result.verdict == 'BUG' and result.bug_type != 'PANIC':
            results.append({
                'file': f,
                'verdict': result.verdict,
                'bug_type': result.bug_type,
                'counterexample': result.counterexample
            })

print(f"Non-PANIC bugs found: {len(results)}")
for r in results:
    print(f"\n=== {r['file']} ({r['bug_type']}) ===")
    ce = r['counterexample']
    if isinstance(ce, dict):
        trace = ce.get('trace', [])
        print("Last 10 trace lines:")
        for line in trace[-10:]:
            print(f"  {line}")
