#!/usr/bin/env python3
"""Quick evaluation with timeout per test"""
import sys
import json
import signal
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from py_synthetic.ground_truth_new import GROUND_TRUTH
from pyfromscratch.analyzer import Analyzer

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Timeout")

results = {
    'correct': 0,
    'incorrect': 0,
    'unknown': 0,
    'timeout': 0,
    'details': [],
    'tp': 0,
    'tn': 0,
    'fp': 0,
    'fn': 0
}

standalone_dir = Path('py_synthetic/standalone')

for i, (test_file, ground_truth) in enumerate(GROUND_TRUTH.items(), 1):
    test_path = standalone_dir / test_file
    
    if not test_path.exists():
        print(f'[{i}/{len(GROUND_TRUTH)}] SKIP: {test_file} not found')
        continue
    
    print(f'[{i}/{len(GROUND_TRUTH)}] Analyzing {test_file}...', end=' ', flush=True)
    
    try:
        # Set timeout to 30 seconds per test (increased for complex list comprehensions)
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(30)
        
        analyzer = Analyzer(verbose=False, max_paths=500, max_depth=1000)
        analysis_result = analyzer.analyze_file(test_path)
        
        signal.alarm(0)  # Cancel alarm
        
        actual_verdict = analysis_result.verdict
        expected_verdict = ground_truth['expected_verdict']
        
        is_correct = (actual_verdict == expected_verdict)
        
        if is_correct:
            results['correct'] += 1
            if expected_verdict == 'BUG':
                results['tp'] += 1
                print(f'✓ BUG (TP)')
            else:
                results['tn'] += 1
                print(f'✓ SAFE (TN)')
        elif actual_verdict == 'UNKNOWN':
            results['unknown'] += 1
            print(f'? UNKNOWN (expected {expected_verdict})')
        else:
            results['incorrect'] += 1
            if expected_verdict == 'BUG':
                results['fn'] += 1
                print(f'✗ FALSE NEGATIVE (got {actual_verdict}, expected BUG)')
            else:
                results['fp'] += 1
                print(f'✗ FALSE POSITIVE (got BUG, expected SAFE)')
        
        bug_types = [b.bug_type for b in analysis_result.bugs] if hasattr(analysis_result, 'bugs') else []
        
        results['details'].append({
            'file': test_file,
            'expected': expected_verdict,
            'actual': actual_verdict,
            'correct': is_correct,
            'bugs_found': bug_types,
            'description': ground_truth.get('description', '')
        })
        
    except TimeoutError:
        signal.alarm(0)
        known_issue = ground_truth.get('known_issues', '')
        if known_issue:
            print(f'⏱ TIMEOUT (expected {expected_verdict}) - KNOWN ISSUE: {known_issue}')
        else:
            print(f'⏱ TIMEOUT (expected {expected_verdict})')
        results['timeout'] += 1
        results['details'].append({
            'file': test_file,
            'expected': expected_verdict,
            'actual': 'TIMEOUT',
            'correct': False,
            'known_issues': known_issue
        })
    except Exception as e:
        signal.alarm(0)
        print(f'ERROR: {e}')
        results['unknown'] += 1
        results['details'].append({
            'file': test_file,
            'expected': expected_verdict,
            'actual': 'ERROR',
            'correct': False,
            'error': str(e)
        })

# Print summary
print('\n' + '='*60)
print('EVALUATION SUMMARY')
print('='*60)
print(f'Total tests: {len(GROUND_TRUTH)}')
print(f'Correct: {results["correct"]} ({results["correct"]/len(GROUND_TRUTH)*100:.1f}%)')
print(f'Incorrect: {results["incorrect"]}')
print(f'Unknown: {results["unknown"]}')
print(f'Timeout: {results["timeout"]}')
print()
print(f'True Positives (TP): {results["tp"]}')
print(f'True Negatives (TN): {results["tn"]}')
print(f'False Positives (FP): {results["fp"]}')
print(f'False Negatives (FN): {results["fn"]}')
print()
if results['tp'] + results['fp'] > 0:
    precision = results['tp'] / (results['tp'] + results['fp'])
    print(f'Precision: {precision:.2%}')
if results['tp'] + results['fn'] > 0:
    recall = results['tp'] / (results['tp'] + results['fn'])
    print(f'Recall: {recall:.2%}')
if results['correct'] + results['incorrect'] > 0:
    accuracy = results['correct'] / (results['correct'] + results['incorrect'])
    print(f'Accuracy: {accuracy:.2%}')

# Save results
with open('py_synthetic/evaluation_new_results.json', 'w') as f:
    json.dump(results, f, indent=2)
print(f'\nResults saved to py_synthetic/evaluation_new_results.json')
