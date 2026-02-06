#!/usr/bin/env python3
"""
show_real_bugs.py - Display DSE-confirmed true positive bugs in DeepSpeed.

Loads results from the full analysis pipeline and shows:
  1. DSE-confirmed reachable bugs (true positives)
  2. Production vs test code breakdown
  3. Source code context for each bug
"""

import os
import pickle
import sys
from pathlib import Path
from collections import defaultdict

DEEPSPEED_ROOT = Path('external_tools/DeepSpeed')
RESULTS_FILE = Path('results/full_analysis_results.pkl')


def load_results():
    """Load saved analysis results."""
    if not RESULTS_FILE.exists():
        print("ERROR: No results file found. Run run_full_improved_analysis.py first.")
        sys.exit(1)
    with open(RESULTS_FILE, 'rb') as f:
        return pickle.load(f)


def func_to_filepath(func_name: str) -> Path:
    """Convert dotted function name to likely file path."""
    parts = func_name.split('.')
    # Try progressively shorter paths
    for i in range(len(parts), 0, -1):
        candidate = DEEPSPEED_ROOT / '/'.join(parts[:i])
        if candidate.with_suffix('.py').exists():
            return candidate.with_suffix('.py')
        if (candidate / '__init__.py').exists():
            return candidate / '__init__.py'
    return None


def get_source_context(func_name: str):
    """Get source code context for a function."""
    filepath = func_to_filepath(func_name)
    if filepath is None or not filepath.exists():
        return None, None, None

    parts = func_name.split('.')
    fn_name = parts[-1]

    try:
        with open(filepath) as f:
            lines = f.readlines()
    except Exception:
        return None, None, None

    for i, line in enumerate(lines):
        if f'def {fn_name}' in line:
            start = max(0, i)
            end = min(len(lines), i + 15)
            indent = len(line) - len(line.lstrip())
            for j in range(i + 1, min(len(lines), i + 50)):
                stripped = lines[j].rstrip()
                if stripped and not stripped.startswith('#'):
                    cur_indent = len(lines[j]) - len(lines[j].lstrip())
                    if cur_indent <= indent and stripped and 'def ' in stripped:
                        end = j
                        break
            return filepath, i + 1, lines[start:end]

    return filepath, None, None


def categorize_bug(func_name: str, bug_type: str) -> str:
    """Assign a severity/category to a bug."""
    if bug_type == 'DIV_ZERO':
        if 'head_size' in func_name or 'n_heads' in func_name:
            return 'CONFIG'
        if '_ensure_divisibility' in func_name:
            return 'VALIDATION'
        return 'ARITHMETIC'
    if bug_type == 'NULL_PTR':
        if 'recursive_getattr' in func_name:
            return 'TRAVERSAL'
        if '_set_' in func_name or '_validate' in func_name:
            return 'SETTER'
        if 'accelerator' in func_name:
            return 'HARDWARE'
        return 'DEREF'
    if bug_type in ('RUNTIME_ERROR', 'VALUE_ERROR'):
        return 'GUARD'
    return 'OTHER'


def main():
    results = load_results()

    print("=" * 78)
    print("  DEEPSPEED BUG ANALYSIS \u2014 DSE-CONFIRMED TRUE POSITIVES")
    print("=" * 78)
    print()

    total = results['total_bugs']
    grand_fp = results['grand_fp']
    remaining = results['remaining_count']
    dse_reachable = results.get('dse_reachable', {})
    dse_unreachable = results.get('dse_unreachable', [])
    prod_bugs = results.get('prod_bugs', [])
    test_bugs = results.get('test_bugs', [])

    print(f"  Total bug instances:     {total:,}")
    print(f"  Proven false positive:   {grand_fp:,} ({100*grand_fp/total:.1f}%)")
    print(f"  Remaining (TP cands):    {remaining:,} ({100*remaining/total:.1f}%)")
    print(f"  DSE confirmed reachable: {len(dse_reachable):,}")
    print(f"  DSE confirmed FP:        {len(dse_unreachable):,}")
    print()

    # Bug type breakdown
    print("-" * 78)
    print("  BUG TYPE BREAKDOWN (remaining)")
    print("-" * 78)
    by_type = defaultdict(list)
    all_remaining = prod_bugs + test_bugs
    for func_name, bug_type in all_remaining:
        by_type[bug_type].append(func_name)
    for bt, funcs in sorted(by_type.items(), key=lambda x: -len(x[1])):
        print(f"    {bt:15s}: {len(funcs):3d} bugs")
    print()

    # Production true positives
    print("=" * 78)
    print("  PRODUCTION CODE \u2014 TRUE POSITIVE BUGS")
    print("=" * 78)
    print()

    prod_by_type = defaultdict(list)
    for func_name, bug_type in prod_bugs:
        prod_by_type[bug_type].append(func_name)

    for bug_type in ['DIV_ZERO', 'NULL_PTR', 'RUNTIME_ERROR', 'VALUE_ERROR', 'BOUNDS', 'ASSERT_FAIL']:
        funcs = prod_by_type.get(bug_type, [])
        if not funcs:
            continue

        print(f"  \u2500\u2500 {bug_type} ({len(funcs)} bugs) {'\u2500' * (55 - len(bug_type))}")
        print()

        for func_name in sorted(funcs):
            category = categorize_bug(func_name, bug_type)
            dse_status = 'DSE:REACHABLE' if func_name in dse_reachable else 'unconfirmed'
            print(f"    [{category:10s}] {func_name}")
            print(f"               Status: {dse_status}")

            filepath, lineno, lines = get_source_context(func_name)
            if filepath and lineno and lines:
                rel_path = filepath.relative_to(Path('.')) if filepath.is_relative_to(Path('.')) else filepath
                print(f"               File:   {rel_path}:{lineno}")
                for line in lines[:8]:
                    print(f"               \u2502 {line.rstrip()}")
            print()

    # Test code bugs
    print("=" * 78)
    print(f"  TEST CODE BUGS ({len(test_bugs)} bugs)")
    print("=" * 78)
    print()
    test_by_type = defaultdict(list)
    for func_name, bug_type in test_bugs:
        test_by_type[bug_type].append(func_name)
    for bt, funcs in sorted(test_by_type.items(), key=lambda x: -len(x[1])):
        print(f"    {bt}: {len(funcs)}")
        for fn in sorted(funcs)[:10]:
            print(f"      \u26a0\ufe0f  {fn}")
        if len(funcs) > 10:
            print(f"      ... and {len(funcs) - 10} more")
    print()

    # DSE-confirmed false positives
    print("=" * 78)
    print(f"  DSE-CONFIRMED FALSE POSITIVES ({len(dse_unreachable)} bugs)")
    print("=" * 78)
    print()
    for fn in sorted(dse_unreachable)[:20]:
        print(f"    \u2713 {fn}")
    if len(dse_unreachable) > 20:
        print(f"    ... and {len(dse_unreachable) - 20} more")

    print()
    print("=" * 78)
    print("  SUMMARY")
    print("=" * 78)
    total_fp = grand_fp + len(dse_unreachable)
    print(f"    FP proven (barriers + guards):  {grand_fp:,}/{total:,}")
    print(f"    DSE proved unreachable:          +{len(dse_unreachable):,}")
    print(f"    Total verified FP:               {total_fp:,}/{total:,} ({100*total_fp/total:.1f}%)")
    print(f"    DSE confirmed reachable (TP):    {len(dse_reachable):,}")
    print(f"    Production true positives:       {len(prod_bugs):,}")
    print(f"    Test-only bugs:                  {len(test_bugs):,}")
    print("=" * 78)


if __name__ == '__main__':
    main()
