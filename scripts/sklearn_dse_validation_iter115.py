#!/usr/bin/env python3
"""
Iteration 115: DSE Validation of scikit-learn Bugs

Target: 7 PANIC bugs from scikit-learn scan (iteration 88, rescanned 20260123_090244)
Goal: Validate each bug with DSE to determine true positive vs false positive rate
Following numpy (100% validation) and ansible (100% validation) methodology
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))
from pyfromscratch.analyzer import Analyzer

# Bug list from scan
BUGS_TO_VALIDATE = [
    {
        "file": "results/public_repos/clones/scikit-learn/sklearn/_min_dependencies.py",
        "bug_type": "PANIC",
        "expected": "TP"  # Will validate
    },
    {
        "file": "results/public_repos/clones/scikit-learn/sklearn/exceptions.py",
        "bug_type": "PANIC",
        "expected": "TP"
    },
    {
        "file": "results/public_repos/clones/scikit-learn/benchmarks/plot_tsne_mnist.py",
        "bug_type": "PANIC",
        "expected": "TP"
    },
    {
        "file": "results/public_repos/clones/scikit-learn/doc/api_reference.py",
        "bug_type": "PANIC",
        "expected": "TP"
    },
    {
        "file": "results/public_repos/clones/scikit-learn/doc/sphinxext/override_pst_pagetoc.py",
        "bug_type": "PANIC",
        "expected": "TP"
    },
    {
        "file": "results/public_repos/clones/scikit-learn/build_tools/azure/get_selected_tests.py",
        "bug_type": "PANIC",
        "expected": "TP"
    },
    {
        "file": "results/public_repos/clones/scikit-learn/build_tools/github/vendor.py",
        "bug_type": "PANIC",
        "expected": "TP"
    }
]

def validate_bug_with_dse(bug_info):
    """
    Run DSE validation on a single bug.
    Returns: {'validated': bool, 'concrete_trace': str or None, 'reason': str}
    """
    file_path = Path(bug_info['file'])
    bug_type = bug_info['bug_type']
    
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
    print("=" * 80)
    print("scikit-learn DSE Validation - Iteration 115")
    print("=" * 80)
    print(f"Total bugs to validate: {len(BUGS_TO_VALIDATE)}")
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    print()
    
    results = []
    validated_count = 0
    false_positive_count = 0
    
    for i, bug in enumerate(BUGS_TO_VALIDATE, 1):
        print(f"\n[{i}/{len(BUGS_TO_VALIDATE)}] Validating {Path(bug['file']).name}")
        print(f"  Bug type: {bug['bug_type']}")
        print(f"  File: {bug['file']}")
        
        validation_result = validate_bug_with_dse(bug)
        
        result_entry = {
            'bug_number': i,
            'file': bug['file'],
            'bug_type': bug['bug_type'],
            'expected': bug['expected'],
            'validated': validation_result['validated'],
            'reason': validation_result['reason'],
            'concrete_trace': validation_result['concrete_trace']
        }
        results.append(result_entry)
        
        if validation_result['validated']:
            validated_count += 1
            print(f"  ✓ VALIDATED: {validation_result['reason']}")
        else:
            false_positive_count += 1
            print(f"  ✗ FALSE POSITIVE: {validation_result['reason']}")
    
    # Summary
    print("\n" + "=" * 80)
    print("VALIDATION SUMMARY")
    print("=" * 80)
    print(f"Total bugs: {len(BUGS_TO_VALIDATE)}")
    print(f"Validated (TP): {validated_count} ({validated_count/len(BUGS_TO_VALIDATE)*100:.1f}%)")
    print(f"False positives: {false_positive_count} ({false_positive_count/len(BUGS_TO_VALIDATE)*100:.1f}%)")
    print()
    
    # Bug type breakdown
    from collections import Counter
    bug_type_validated = Counter()
    bug_type_total = Counter()
    
    for r in results:
        bug_type_total[r['bug_type']] += 1
        if r['validated']:
            bug_type_validated[r['bug_type']] += 1
    
    print("By bug type:")
    for bt in sorted(bug_type_total.keys()):
        val = bug_type_validated[bt]
        tot = bug_type_total[bt]
        print(f"  {bt}: {val}/{tot} validated ({val/tot*100:.0f}%)")
    
    # Save results
    output_file = Path('results') / 'sklearn_dse_validation_iter115.json'
    output_data = {
        'iteration': 115,
        'repo': 'scikit-learn',
        'scan_date': '2026-01-23T09:02:44',
        'validation_date': datetime.now(timezone.utc).isoformat(),
        'total_bugs': len(BUGS_TO_VALIDATE),
        'validated': validated_count,
        'false_positives': false_positive_count,
        'validation_rate': validated_count / len(BUGS_TO_VALIDATE),
        'false_positive_rate': false_positive_count / len(BUGS_TO_VALIDATE),
        'by_type': {
            bt: {
                'total': bug_type_total[bt],
                'validated': bug_type_validated[bt],
                'rate': bug_type_validated[bt] / bug_type_total[bt]
            }
            for bt in bug_type_total.keys()
        },
        'results': results
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    
    # Comparative analysis
    print("\n" + "=" * 80)
    print("COMPARATIVE ANALYSIS (Tier 2 DSE Validation)")
    print("=" * 80)
    print(f"numpy (iter 113):    9 bugs, 100% validated, 0% FP rate, 9% true bug rate")
    print(f"ansible (iter 114): 32 bugs, 100% validated, 0% FP rate, 32% true bug rate")
    print(f"scikit-learn (iter 115): {len(BUGS_TO_VALIDATE)} bugs, {validated_count/len(BUGS_TO_VALIDATE)*100:.0f}% validated, {false_positive_count/len(BUGS_TO_VALIDATE)*100:.0f}% FP rate, {validated_count/100*100:.0f}% true bug rate")
    print()
    
    return 0 if false_positive_count == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
