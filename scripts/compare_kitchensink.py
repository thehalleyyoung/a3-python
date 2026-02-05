#!/usr/bin/env python3
"""Compare kitchensink vs regular analysis on synthetic test suite."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.analyzer import Analyzer

# Test files from synthetic suite
STANDALONE = Path('py_synthetic/standalone')
TEST_FILES = sorted(STANDALONE.glob('*.py'))
TEST_FILES = [f for f in TEST_FILES if f.name not in ('evaluate.py', '__init__.py')]

print(f"Testing {len(TEST_FILES)} synthetic test cases\n")
print("=" * 90)
print(f"{'File':<45} {'Regular':>20} {'Kitchensink':>20}")
print("=" * 90)

regular_results = {'BUG': 0, 'SAFE': 0, 'UNKNOWN': 0}
kitchen_results = {'BUG': 0, 'SAFE': 0, 'UNKNOWN': 0}
total_regular_time = 0
total_kitchen_time = 0
differences = []

for filepath in TEST_FILES:
    # Regular analysis
    analyzer_reg = Analyzer(max_depth=100, max_paths=500, enable_concolic=False, verbose=False)
    start = time.time()
    try:
        reg_result = analyzer_reg.analyze_file(filepath)
        reg_time = time.time() - start
    except Exception as e:
        reg_result = type('R', (), {'verdict': 'ERROR', 'bug_type': str(e)[:20]})()
        reg_time = time.time() - start
    
    # Kitchensink analysis
    analyzer_kit = Analyzer(max_depth=100, max_paths=500, enable_concolic=False, verbose=False)
    start = time.time()
    try:
        kit_result = analyzer_kit.analyze_file_kitchensink(filepath)
        kit_time = time.time() - start
    except Exception as e:
        kit_result = type('R', (), {'verdict': 'ERROR', 'bug_type': str(e)[:20]})()
        kit_time = time.time() - start
    
    total_regular_time += reg_time
    total_kitchen_time += kit_time
    
    reg_v = reg_result.verdict
    kit_v = kit_result.verdict
    
    regular_results[reg_v] = regular_results.get(reg_v, 0) + 1
    kitchen_results[kit_v] = kitchen_results.get(kit_v, 0) + 1
    
    reg_str = f"{reg_v} ({reg_time:.2f}s)"
    kit_str = f"{kit_v} ({kit_time:.2f}s)"
    
    if getattr(reg_result, 'bug_type', None):
        reg_str = f"{reg_v}:{reg_result.bug_type[:10]} ({reg_time:.2f}s)"
    if getattr(kit_result, 'bug_type', None):
        kit_str = f"{kit_v}:{kit_result.bug_type[:10]} ({kit_time:.2f}s)"
    
    marker = ""
    if reg_v != kit_v:
        marker = " <-- DIFF"
        differences.append((filepath.name, reg_v, kit_v))
    
    print(f"{filepath.name:<45} {reg_str:>20} {kit_str:>20}{marker}")

print("=" * 90)

print(f"\nSummary:")
print(f"  Regular:     BUG={regular_results.get('BUG',0)}, SAFE={regular_results.get('SAFE',0)}, UNKNOWN={regular_results.get('UNKNOWN',0)}, time={total_regular_time:.1f}s")
print(f"  Kitchensink: BUG={kitchen_results.get('BUG',0)}, SAFE={kitchen_results.get('SAFE',0)}, UNKNOWN={kitchen_results.get('UNKNOWN',0)}, time={total_kitchen_time:.1f}s")

if total_kitchen_time > 0:
    print(f"  Speedup:     {total_regular_time / total_kitchen_time:.2f}x")

if differences:
    print(f"\nDifferences ({len(differences)}):")
    for fname, reg, kit in differences:
        print(f"  {fname}: Regular={reg}, Kitchensink={kit}")
else:
    print(f"\nNo differences between regular and kitchensink modes.")

# Expected results from ground truth
print(f"\n{'='*90}")
print("Ground Truth Comparison:")
print(f"{'='*90}")

import json
gt_path = STANDALONE / 'ground_truth.json'
if gt_path.exists():
    with open(gt_path) as f:
        ground_truth = json.load(f)
    
    reg_tp, reg_fp, reg_fn = 0, 0, 0
    kit_tp, kit_fp, kit_fn = 0, 0, 0
    
    for filepath in TEST_FILES:
        fname = filepath.name
        expected = ground_truth.get(fname, {})
        expected_has_bug = expected.get('has_bug', False)
        
        # Check if regular found bug correctly
        analyzer_reg = Analyzer(max_depth=100, max_paths=500, enable_concolic=False, verbose=False)
        try:
            reg_result = analyzer_reg.analyze_file(filepath)
            reg_found_bug = reg_result.verdict == 'BUG'
        except:
            reg_found_bug = False
        
        analyzer_kit = Analyzer(max_depth=100, max_paths=500, enable_concolic=False, verbose=False)
        try:
            kit_result = analyzer_kit.analyze_file_kitchensink(filepath)
            kit_found_bug = kit_result.verdict == 'BUG'
        except:
            kit_found_bug = False
        
        if expected_has_bug and reg_found_bug:
            reg_tp += 1
        elif expected_has_bug and not reg_found_bug:
            reg_fn += 1
        elif not expected_has_bug and reg_found_bug:
            reg_fp += 1
        
        if expected_has_bug and kit_found_bug:
            kit_tp += 1
        elif expected_has_bug and not kit_found_bug:
            kit_fn += 1
        elif not expected_has_bug and kit_found_bug:
            kit_fp += 1
    
    print(f"  Regular:     TP={reg_tp}, FP={reg_fp}, FN={reg_fn}")
    print(f"  Kitchensink: TP={kit_tp}, FP={kit_fp}, FN={kit_fn}")
    
    if reg_tp + reg_fp > 0:
        reg_prec = reg_tp / (reg_tp + reg_fp)
        print(f"  Regular Precision:     {reg_prec:.1%}")
    if kit_tp + kit_fp > 0:
        kit_prec = kit_tp / (kit_tp + kit_fp)
        print(f"  Kitchensink Precision: {kit_prec:.1%}")
else:
    print("  Ground truth file not found")
