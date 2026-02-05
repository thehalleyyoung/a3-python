#!/usr/bin/env python3
"""Verbose analysis with timing, FP inspection, and timeout handling."""

import os
import sys
import time
import signal
from collections import defaultdict

sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryAnalyzer

TIMEOUT_SEC = 5.0

class AnalysisTimeout(Exception):
    pass

def timeout_handler(signum, frame):
    raise AnalysisTimeout()

def analyze_function(code, func_name, file_name):
    start = time.time()
    result = {
        'name': func_name,
        'file': file_name,
        'time': 0,
        'timeout': False,
        'error': None,
        'guards': {},
        'crashes': [],
        'size': len(code.co_code) if hasattr(code, 'co_code') else 0
    }
    
    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SEC)
        
        analyzer = BytecodeCrashSummaryAnalyzer(code, func_name, file_name)
        analyzer.analyze()
        result['guards'] = dict(analyzer.summary.guard_counts)
        result['crashes'] = [(bt, loc.offset, loc.opname) for bt, loc in analyzer.crash_locations]
    except AnalysisTimeout:
        result['timeout'] = True
        result['error'] = 'Timeout'
    except Exception as e:
        result['error'] = str(e)[:80]
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    
    result['time'] = time.time() - start
    return result

def collect_functions(file_path):
    functions = []
    try:
        with open(file_path, 'r') as f:
            source = f.read()
        code = compile(source, file_path, 'exec')
        for const in code.co_consts:
            if hasattr(const, 'co_name') and hasattr(const, 'co_code'):
                functions.append((const.co_name, const))
    except:
        pass
    return functions

def analyze_repo(repo_path, repo_name, max_files=30):
    results = []
    py_files = []
    
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and 'test' not in d.lower()]
        for f in files:
            if f.endswith('.py') and not f.startswith('test'):
                py_files.append(os.path.join(root, f))
    
    py_files = sorted(py_files, key=os.path.getsize)[:max_files]
    
    for fp in py_files:
        rel = os.path.relpath(fp, repo_path)
        for name, code in collect_functions(fp):
            results.append(analyze_function(code, name, f"{repo_name}/{rel}"))
    
    return results

def main():
    base = '/Users/halleyyoung/Documents/PythonFromScratch'
    repos = [
        ('django', 'external_tools/django/django/views'),
        ('pygoat', 'external_tools/pygoat'),
        ('LightGBM', 'external_tools/LightGBM/python-package/lightgbm'),
        ('FLAML', 'external_tools/FLAML/flaml/automl'),
    ]
    
    all_results = []
    
    print("=" * 70)
    print("VERBOSE ANALYSIS WITH TIMING AND FP INSPECTION")
    print("=" * 70)
    
    for name, path in repos:
        full = os.path.join(base, path)
        if not os.path.exists(full):
            continue
        
        print(f"\n{name}:")
        t0 = time.time()
        res = analyze_repo(full, name)
        all_results.extend(res)
        
        timeouts = sum(1 for r in res if r['timeout'])
        errors = sum(1 for r in res if r['error'] and not r['timeout'])
        print(f"  {len(res)} functions, {timeouts} timeouts, {errors} errors, {time.time()-t0:.1f}s")
    
    # Summary
    print("\n" + "=" * 70)
    print("BUG SUMMARY")
    print("=" * 70)
    
    ok = [r for r in all_results if not r['error']]
    totals = defaultdict(lambda: [0, 0])
    
    for r in ok:
        for bt, (g, u) in r['guards'].items():
            totals[bt][0] += g
            totals[bt][1] += u
    
    print(f"\n{'Type':<12} {'Guarded':>8} {'Unguarded':>10} {'%Reduced':>10}")
    print("-" * 45)
    for bt in sorted(totals):
        g, u = totals[bt]
        pct = g / (g + u) * 100 if (g + u) else 0
        print(f"{bt:<12} {g:>8} {u:>10} {pct:>9.1f}%")
    
    # Sample unguarded
    print("\n" + "=" * 70)
    print("SAMPLE UNGUARDED BUGS")
    print("=" * 70)
    
    by_type = defaultdict(list)
    for r in ok:
        for bt, off, op in r['crashes']:
            by_type[bt].append((r['file'], r['name'], off, op))
    
    for bt in ['BOUNDS', 'DIV_ZERO', 'NULL_PTR']:
        items = by_type.get(bt, [])
        print(f"\n{bt} ({len(items)} total):")
        for f, n, off, op in items[:6]:
            print(f"  {f}::{n} @ {off} ({op})")
    
    # Files with most bugs
    print("\n" + "=" * 70)
    print("TOP FILES BY BUG COUNT")
    print("=" * 70)
    
    file_counts = defaultdict(lambda: defaultdict(int))
    for r in ok:
        for bt, _, _ in r['crashes']:
            file_counts[r['file']][bt] += 1
    
    ranked = sorted(file_counts.items(), key=lambda x: sum(x[1].values()), reverse=True)
    for f, counts in ranked[:8]:
        total = sum(counts.values())
        detail = ", ".join(f"{k}:{v}" for k, v in counts.items())
        print(f"  {total:4d}: {f} ({detail})")
    
    # Timeouts
    print("\n" + "=" * 70)
    print("TIMEOUTS")
    print("=" * 70)
    
    timeouts = [r for r in all_results if r['timeout']]
    print(f"\n{len(timeouts)} timeouts (>{TIMEOUT_SEC}s):")
    for r in timeouts[:8]:
        print(f"  {r['file']}::{r['name']} [{r['size']} bytes]")

if __name__ == '__main__':
    main()
