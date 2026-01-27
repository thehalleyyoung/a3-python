#!/usr/bin/env python3
"""
Evaluate our analyzer against the QuixBugs dataset.

QuixBugs contains:
- python_programs/: Buggy versions of classic algorithms
- correct_python_programs/: Fixed versions

We'll compute:
- True Positives (TP): Buggy file detected as BUG
- False Negatives (FN): Buggy file marked SAFE
- False Positives (FP): Correct file marked as BUG
- True Negatives (TN): Correct file marked SAFE

Then compute Precision, Recall, F1
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')

from pyfromscratch.analyzer import Analyzer

# Configuration
QUIXBUGS_DIR = Path('/Users/halleyyoung/Documents/PythonFromScratch/results/public_repos/QuixBugs')
BUGGY_DIR = QUIXBUGS_DIR / 'python_programs'
CORRECT_DIR = QUIXBUGS_DIR / 'correct_python_programs'

# Create analyzer
analyzer = Analyzer(max_paths=500, max_depth=500, timeout_ms=10000)

# Track results
results = {
    'TP': [],  # Buggy detected as BUG
    'FN': [],  # Buggy marked SAFE
    'FP': [],  # Correct marked BUG
    'TN': [],  # Correct marked SAFE
    'buggy_details': {},
    'correct_details': {},
}

# Get list of algorithm files (exclude test files and node.py helper)
buggy_files = sorted([f for f in BUGGY_DIR.glob('*.py') 
                      if not f.name.endswith('_test.py') and f.name != 'node.py'])
correct_files = sorted([f for f in CORRECT_DIR.glob('*.py')
                        if not f.name.endswith('_test.py') and f.name != 'node.py'])

print("=" * 60)
print("ANALYZING BUGGY FILES")
print("=" * 60)

for f in buggy_files:
    try:
        result = analyzer.analyze_file(str(f))
        verdict = result.verdict
        bug_type = getattr(result, 'bug_type', 'N/A')
        
        results['buggy_details'][f.name] = {
            'verdict': verdict,
            'bug_type': bug_type,
            'counterexample': result.counterexample if hasattr(result, 'counterexample') else None
        }
        
        if verdict == 'BUG':
            results['TP'].append(f.name)
            print(f"✓ {f.name}: DETECTED ({bug_type})")
        else:
            results['FN'].append(f.name)
            print(f"✗ {f.name}: MISSED (marked {verdict})")
    except Exception as e:
        results['FN'].append(f.name)
        print(f"✗ {f.name}: ERROR ({e})")

print("\n" + "=" * 60)
print("ANALYZING CORRECT FILES")
print("=" * 60)

for f in correct_files:
    try:
        result = analyzer.analyze_file(str(f))
        verdict = result.verdict
        bug_type = getattr(result, 'bug_type', 'N/A')
        
        results['correct_details'][f.name] = {
            'verdict': verdict,
            'bug_type': bug_type,
            'counterexample': result.counterexample if hasattr(result, 'counterexample') else None
        }
        
        if verdict == 'BUG':
            results['FP'].append(f.name)
            print(f"✗ {f.name}: FALSE POSITIVE ({bug_type})")
        else:
            results['TN'].append(f.name)
            print(f"✓ {f.name}: CORRECTLY SAFE")
    except Exception as e:
        results['TN'].append(f.name)
        print(f"? {f.name}: ERROR treated as SAFE ({e})")

# Calculate metrics
TP = len(results['TP'])
FN = len(results['FN'])
FP = len(results['FP'])
TN = len(results['TN'])

precision = TP / (TP + FP) if (TP + FP) > 0 else 0
recall = TP / (TP + FN) if (TP + FN) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0

print("\n" + "=" * 60)
print("RESULTS SUMMARY")
print("=" * 60)
print(f"\nConfusion Matrix:")
print(f"                 Predicted BUG    Predicted SAFE")
print(f"  Actually BUG      TP={TP:3d}           FN={FN:3d}")
print(f"  Actually SAFE     FP={FP:3d}           TN={TN:3d}")

print(f"\nMetrics:")
print(f"  Precision: {precision:.3f} ({TP}/{TP+FP})")
print(f"  Recall:    {recall:.3f} ({TP}/{TP+FN})")
print(f"  F1 Score:  {f1:.3f}")
print(f"  Accuracy:  {accuracy:.3f}")

print(f"\n{'=' * 60}")
print("DETAILED ANALYSIS")
print("=" * 60)

if results['TP']:
    print(f"\n✓ TRUE POSITIVES (buggy files correctly detected):")
    for name in results['TP']:
        details = results['buggy_details'][name]
        print(f"  - {name}: {details['bug_type']}")

if results['FN']:
    print(f"\n✗ FALSE NEGATIVES (buggy files missed):")
    for name in results['FN']:
        details = results['buggy_details'].get(name, {})
        verdict = details.get('verdict', 'ERROR')
        print(f"  - {name}: marked as {verdict}")

if results['FP']:
    print(f"\n✗ FALSE POSITIVES (correct files flagged as buggy):")
    for name in results['FP']:
        details = results['correct_details'][name]
        print(f"  - {name}: {details['bug_type']}")

print("\n" + "=" * 60)
print("FAILURE ANALYSIS")
print("=" * 60)

# Analyze why we failed on False Negatives
print("\nAnalyzing why analyzer missed bugs in FALSE NEGATIVES:")
for name in results['FN'][:5]:  # First 5
    buggy_path = BUGGY_DIR / name
    correct_path = CORRECT_DIR / name
    if buggy_path.exists() and correct_path.exists():
        with open(buggy_path) as f:
            buggy_code = f.read()
        with open(correct_path) as f:
            correct_code = f.read()
        
        # Simple diff
        buggy_lines = buggy_code.strip().split('\n')
        correct_lines = correct_code.strip().split('\n')
        
        print(f"\n  {name}:")
        for i, (b, c) in enumerate(zip(buggy_lines, correct_lines)):
            if b != c:
                print(f"    Line {i+1}:")
                print(f"      BUGGY:   {b}")
                print(f"      CORRECT: {c}")
                break

# Save detailed results
import json
output_file = '/Users/halleyyoung/Documents/PythonFromScratch/results/quixbugs_evaluation.json'
with open(output_file, 'w') as f:
    json.dump({
        'metrics': {
            'TP': TP, 'FN': FN, 'FP': FP, 'TN': TN,
            'precision': precision, 'recall': recall, 'f1': f1, 'accuracy': accuracy
        },
        'TP_files': results['TP'],
        'FN_files': results['FN'],
        'FP_files': results['FP'],
        'TN_files': results['TN'],
    }, f, indent=2)

print(f"\nResults saved to: {output_file}")
