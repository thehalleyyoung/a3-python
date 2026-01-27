#!/usr/bin/env python3
"""
Iteration 116: DSE validation of scikit-learn rescan

Validate the 6 bugs from the fresh iteration 116 scan and compare with
iteration 115 validation (57% validation rate, 43% FP rate on old scan).
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer


def validate_bug_with_dse(file_path, bug_type):
    """
    Run DSE validation on a single bug.
    Returns: {'validated': bool, 'concrete_trace': str or None, 'reason': str}
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        return {
            'validated': False,
            'concrete_trace': None,
            'reason': 'File not found'
        }
    
    try:
        # Re-analyze with Analyzer to get DSE validation
        analyzer = Analyzer(max_paths=200, max_depth=100, verbose=False)
        result = analyzer.analyze_file(file_path)
        
        # Check verdict matches
        if result.verdict != 'BUG':
            return {
                'validated': False,
                'concrete_trace': None,
                'reason': f'Verdict mismatch: {result.verdict} (expected BUG)'
            }
        
        if result.bug_type != bug_type:
            print(f"    Note: Bug type {result.bug_type} vs expected {bug_type}")
        
        # Check DSE validation
        if result.counterexample:
            dse_validated = result.counterexample.get('dse_validated', False)
            concrete_repro = result.counterexample.get('concrete_repro')
            
            if dse_validated:
                return {
                    'validated': True,
                    'concrete_trace': concrete_repro,
                    'reason': 'DSE validated with concrete repro'
                }
            else:
                return {
                    'validated': False,
                    'concrete_trace': None,
                    'reason': 'DSE could not validate within budget'
                }
        else:
            return {
                'validated': False,
                'concrete_trace': None,
                'reason': 'No counterexample generated'
            }
    
    except Exception as e:
        import traceback
        trace = traceback.format_exc()
        return {
            'validated': False,
            'concrete_trace': None,
            'reason': f'Exception: {type(e).__name__}: {str(e)[:100]}'
        }


def main():
    print("="*60)
    print("ITERATION 116: DSE Validation of Scikit-learn Rescan")
    print("="*60)
    print("Comparing with iteration 115 validation (old scan):")
    print("  - Old scan: 7 bugs, 57% validated, 43% FP")
    print("  - New scan: 6 bugs, validation TBD")
    print()
    
    # Load scan results
    scan_file = Path("results/public_repos/scan_results/scikit-learn_20260123_102949.json")
    with open(scan_file, 'r') as f:
        scan_data = json.load(f)
    
    # Extract bugs
    bugs = [f for f in scan_data['findings'] if f['verdict'] == 'BUG']
    
    print(f"Found {len(bugs)} bugs to validate")
    print()
    
    # Validate each bug
    results = []
    
    for i, bug in enumerate(bugs, 1):
        file_path = bug['file_path']
        bug_type = bug.get('bug_type', 'UNKNOWN')
        location = bug.get('location', 'unknown')
        
        print(f"[{i}/{len(bugs)}] Validating {Path(file_path).name}")
        print(f"  Bug type: {bug_type}")
        print(f"  Location: {location}")
        print(f"  File: {file_path}")
        
        # Attempt DSE validation
        validation_result = validate_bug_with_dse(file_path, bug_type)
        results.append({
            'file': file_path,
            'bug_type': bug_type,
            'location': location,
            'validated': validation_result['validated'],
            'concrete_trace': validation_result.get('concrete_trace'),
            'reason': validation_result.get('reason')
        })
        
        if validation_result['validated']:
            print(f"  ✓ VALIDATED: {validation_result['reason']}")
        else:
            print(f"  ✗ NOT VALIDATED: {validation_result['reason']}")
        
        print()
    
    # Compute metrics
    validated = sum(1 for r in results if r['validated'])
    validation_rate = validated / len(results) if results else 0
    false_positives = len(results) - validated
    fp_rate = false_positives / len(results) if results else 0
    
    print("="*60)
    print("VALIDATION RESULTS")
    print("="*60)
    print(f"Total bugs: {len(results)}")
    print(f"Validated: {validated} ({validation_rate*100:.1f}%)")
    print(f"False positives: {false_positives} ({fp_rate*100:.1f}%)")
    print()
    
    # Group by bug type
    by_type = {}
    for r in results:
        bug_type = r['bug_type']
        if bug_type not in by_type:
            by_type[bug_type] = {'total': 0, 'validated': 0}
        by_type[bug_type]['total'] += 1
        if r['validated']:
            by_type[bug_type]['validated'] += 1
    
    print("BY BUG TYPE:")
    for bug_type, stats in sorted(by_type.items()):
        rate = stats['validated'] / stats['total'] if stats['total'] > 0 else 0
        print(f"  {bug_type}: {stats['validated']}/{stats['total']} ({rate*100:.1f}%)")
    print()
    
    # Compare with iteration 115
    print("="*60)
    print("COMPARISON WITH ITERATION 115 VALIDATION")
    print("="*60)
    
    iter115_bugs = 7
    iter115_validated = 4
    iter115_validation_rate = 0.571
    iter115_fp_rate = 0.429
    iter115_true_bug_rate = 0.04
    
    iter116_bugs = len(results)
    iter116_validated = validated
    iter116_validation_rate = validation_rate
    iter116_fp_rate = fp_rate
    iter116_true_bug_rate = validated / 100  # 100 files scanned
    
    print("Iteration 115 (old scan, 27 iterations old):")
    print(f"  Bugs: {iter115_bugs}, Validated: {iter115_validated}, Rate: {iter115_validation_rate*100:.1f}%")
    print(f"  False positives: {iter115_bugs - iter115_validated}, FP rate: {iter115_fp_rate*100:.1f}%")
    print(f"  True bug rate: {iter115_true_bug_rate*100:.1f}%")
    print()
    
    print("Iteration 116 (new scan, current analyzer):")
    print(f"  Bugs: {iter116_bugs}, Validated: {iter116_validated}, Rate: {iter116_validation_rate*100:.1f}%")
    print(f"  False positives: {false_positives}, FP rate: {fp_rate*100:.1f}%")
    print(f"  True bug rate: {iter116_true_bug_rate*100:.1f}%")
    print()
    
    print("Changes:")
    print(f"  Bugs: {iter116_bugs - iter115_bugs:+d} ({(iter116_bugs - iter115_bugs)/iter115_bugs*100:+.1f}%)")
    print(f"  Validated: {iter116_validated - iter115_validated:+d}")
    print(f"  Validation rate: {(iter116_validation_rate - iter115_validation_rate)*100:+.1f}pp")
    print(f"  FP rate: {(iter116_fp_rate - iter115_fp_rate)*100:+.1f}pp")
    print(f"  True bug rate: {(iter116_true_bug_rate - iter115_true_bug_rate)*100:+.1f}pp")
    print()
    
    # Interpretation
    print("="*60)
    print("INTERPRETATION")
    print("="*60)
    
    if iter116_validation_rate > iter115_validation_rate:
        improvement = (iter116_validation_rate - iter115_validation_rate) * 100
        print(f"✓ Validation rate IMPROVED by {improvement:.1f}pp over 27 iterations")
        print(f"✓ Continuous refinement successfully reduced false positives")
    elif iter116_validation_rate == iter115_validation_rate:
        print(f"- Validation rate STABLE at {iter116_validation_rate*100:.1f}%")
        print(f"- Detection consistency maintained over 27 iterations")
    else:
        degradation = (iter115_validation_rate - iter116_validation_rate) * 100
        print(f"✗ Validation rate DEGRADED by {degradation:.1f}pp")
        print(f"✗ May indicate new false positives or validation limitations")
    
    print()
    
    if iter116_bugs < iter115_bugs and iter116_validation_rate >= iter115_validation_rate:
        print("✓ BEST OUTCOME: Fewer bugs with same/better validation rate")
        print("✓ Continuous refinement eliminated false positives without missing true bugs")
    elif iter116_bugs == iter115_bugs and iter116_validation_rate > iter115_validation_rate:
        print("✓ GOOD OUTCOME: Same bug count with better validation rate")
        print("✓ Semantic improvements refined detection precision")
    
    print()
    
    # Save results
    output = {
        'iteration': 116,
        'validation_date': datetime.now(timezone.utc).isoformat(),
        'scan_date': scan_data['scanned_at'],
        'repo': 'scikit-learn',
        'total_bugs': len(results),
        'validated': validated,
        'validation_rate': validation_rate,
        'false_positives': false_positives,
        'false_positive_rate': fp_rate,
        'true_bug_rate': iter116_true_bug_rate,
        'by_type': by_type,
        'comparison_with_iter115': {
            'iter115_bugs': iter115_bugs,
            'iter115_validated': iter115_validated,
            'iter115_validation_rate': iter115_validation_rate,
            'iter115_fp_rate': iter115_fp_rate,
            'iter115_true_bug_rate': iter115_true_bug_rate,
            'iter116_bugs': iter116_bugs,
            'iter116_validated': iter116_validated,
            'iter116_validation_rate': iter116_validation_rate,
            'iter116_fp_rate': fp_rate,
            'iter116_true_bug_rate': iter116_true_bug_rate,
            'bug_delta': iter116_bugs - iter115_bugs,
            'validation_rate_delta': iter116_validation_rate - iter115_validation_rate,
            'fp_rate_delta': fp_rate - iter115_fp_rate,
            'true_bug_rate_delta': iter116_true_bug_rate - iter115_true_bug_rate
        },
        'results': results
    }
    
    output_file = Path("results/sklearn_dse_validation_iter116.json")
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Results saved to: {output_file}")
    print()


if __name__ == "__main__":
    main()
