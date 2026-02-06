#!/usr/bin/env python3
"""
Examine every bug the enhanced barrier system still calls a true positive.
For each one, show full context so we can manually verify.
"""

import pickle
import logging
from pathlib import Path
from collections import Counter
from pyfromscratch.barriers.enhanced_barrier_theory import (
    EnhancedDeepBarrierTheoryEngine,
)
from pyfromscratch.barriers.deep_barrier_theory import BarrierType

logging.basicConfig(level=logging.WARNING)

cache_file = Path('results/deepspeed_crash_summaries.pkl')
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)

# Collect ALL unguarded bugs
unguarded_bugs = []
for func_name, summary in summaries.items():
    if hasattr(summary, 'guarded_bugs') and summary.guarded_bugs:
        for bug_type in summary.guarded_bugs:
            guard_count = (0, 0)
            if hasattr(summary, 'guard_counts') and bug_type in summary.guard_counts:
                guard_count = summary.guard_counts[bug_type]
            if guard_count[0] == 0:
                unguarded_bugs.append({
                    'function': func_name,
                    'bug_type': bug_type,
                    'summary': summary,
                    'total_count': guard_count[1]
                })

engine = EnhancedDeepBarrierTheoryEngine()

# Run on ALL 329 bugs
true_positives = []
false_positives = []

for bug in unguarded_bugs:
    is_safe, cert = engine.verify_via_deep_barriers(
        bug['bug_type'], '<var>', bug['summary']
    )
    if is_safe:
        false_positives.append((bug, cert))
    else:
        true_positives.append(bug)

print("=" * 90)
print(f"FULL RUN: {len(unguarded_bugs)} unguarded bugs")
print(f"  Proven safe (FP): {len(false_positives)}")
print(f"  Still called TP:  {len(true_positives)}")
print("=" * 90)
print()

# Now examine each TP in detail
for i, bug in enumerate(true_positives, 1):
    func_name = bug['function']
    bug_type = bug['bug_type']
    summary = bug['summary']

    print(f"{'='*90}")
    print(f"TP #{i}: {func_name}")
    print(f"{'='*90}")
    print(f"  Bug type       : {bug_type}")
    print(f"  Total count    : {bug['total_count']}")
    print()

    # Dump every attribute of the summary
    print("  --- Summary attributes ---")
    for attr in sorted(dir(summary)):
        if attr.startswith('_'):
            continue
        val = getattr(summary, attr, None)
        if callable(val):
            continue
        # Truncate long values
        val_str = repr(val)
        if len(val_str) > 200:
            val_str = val_str[:200] + '...'
        print(f"    {attr:35s} = {val_str}")

    print()

    # Why did every barrier fail?
    print("  --- Barrier failure analysis ---")

    # Pattern 1: Assume-Guarantee
    if bug_type.startswith('interprocedural_nonnull_from_'):
        source = bug_type.replace('interprocedural_nonnull_from_', '')
        validated = getattr(summary, 'validated_params', {})
        ret_g = getattr(summary, 'return_guarantees', set())
        precond = getattr(summary, 'preconditions', set())
        accessor_kws = ['get_', 'find_', 'fetch_', 'load_', 'read_', 'parse_']
        type_kws = ['.type', '.dtype', '.shape', '.size', '.length']

        print(f"    Source function : {source}")
        print(f"    Validated params: {validated}")
        print(f"    Return guarantees: {ret_g}")
        print(f"    Preconditions  : {precond}")
        print(f"    Accessor match : {any(kw in source for kw in accessor_kws)}")
        print(f"    Property match : {any(kw in source for kw in type_kws)}")

        # Check module coherence
        func_module = '.'.join(func_name.split('.')[:-1])
        source_module = '.'.join(source.split('.')[:-1])
        print(f"    Func module    : {func_module}")
        print(f"    Source module   : {source_module}")
        print(f"    Same module    : {func_module == source_module}")
    else:
        print(f"    Non-interprocedural bug type: {bug_type}")
        validated = getattr(summary, 'validated_params', {})
        ret_g = getattr(summary, 'return_guarantees', set())
        print(f"    Validated params: {validated}")
        print(f"    Return guarantees: {ret_g}")

    # Pattern 4: Factory
    factory_kws = [
        'factory', 'builder', 'create', 'make', 'get_', 'from_',
        'load', 'parse', 'read', 'fetch', 'find',
        'init_', 'initialize', 'setup',
        'compute', 'calculate', 'evaluate',
        'config', 'settings', 'options',
        'decode', 'deserialize',
        'build', 'construct', 'assemble'
    ]
    print(f"    Factory keyword : {any(kw in func_name.lower() for kw in factory_kws)}")
    print(f"    __init__       : {'__init__' in func_name}")

    print()
