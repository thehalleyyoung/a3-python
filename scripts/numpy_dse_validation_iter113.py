#!/usr/bin/env python3
"""
NumPy DSE Validation - Iteration 113
Validate the 9 bugs found in numpy iteration 112 rescan.
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer

def load_numpy_bugs():
    """Load latest numpy scan results."""
    scan_file = Path('results/public_repos/scan_results/numpy_20260123_101147.json')
    with open(scan_file) as f:
        data = json.load(f)
    
    bugs = [f for f in data['findings'] if f['verdict'] == 'BUG']
    return bugs

def validate_bug(bug):
    """Validate a single bug with DSE."""
    file_path = Path(bug['file_path'])
    bug_type = bug['bug_type']
    witness_trace = bug.get('witness_trace', [])
    
    print(f"\nValidating {file_path.name} ({bug_type})...")
    print(f"  Witness trace length: {len(witness_trace)}")
    
    if not file_path.exists():
        print(f"  ✗ File not found: {file_path}")
        return False, "file_not_found"
    
    try:
        # Re-analyze with analyzer to get DSE validation
        analyzer = Analyzer(max_paths=200, max_depth=100, verbose=False)
        result = analyzer.analyze_file(file_path)
        
        # Check verdict matches
        if result.verdict != 'BUG':
            print(f"  ✗ Analyzer verdict: {result.verdict} (expected BUG)")
            return False, f"verdict_mismatch_{result.verdict}"
        
        if result.bug_type != bug_type:
            print(f"  ⚠ Bug type mismatch: {result.bug_type} vs {bug_type}")
        
        # Check DSE validation
        dse_validated = False
        if result.counterexample:
            dse_validated = result.counterexample.get('dse_validated', False)
            concrete_repro = result.counterexample.get('concrete_repro')
            
            if dse_validated:
                print(f"  ✓ DSE validated: {concrete_repro}")
                return True, "validated"
            else:
                print(f"  ✗ DSE could not validate within budget")
                return False, "dse_inconclusive"
        else:
            print(f"  ✗ No counterexample generated")
            return False, "no_counterexample"
    
    except Exception as e:
        print(f"  ✗ Exception: {str(e)[:100]}")
        import traceback
        traceback.print_exc()
        return False, f"exception_{type(e).__name__}"

def main():
    print("=" * 60)
    print("NumPy DSE Validation - Iteration 113")
    print("=" * 60)
    
    bugs = load_numpy_bugs()
    print(f"\nLoaded {len(bugs)} bugs from scan")
    
    results = {
        'total': len(bugs),
        'validated': 0,
        'false_positives': 0,
        'by_type': {},
        'by_reason': {},
        'details': []
    }
    
    for i, bug in enumerate(bugs, 1):
        file_name = Path(bug['file_path']).name
        bug_type = bug['bug_type']
        
        print(f"\n[{i}/{len(bugs)}] {file_name} ({bug_type})")
        
        validated, reason = validate_bug(bug)
        
        # Track by type
        if bug_type not in results['by_type']:
            results['by_type'][bug_type] = {'total': 0, 'validated': 0}
        results['by_type'][bug_type]['total'] += 1
        
        # Track by reason
        if reason not in results['by_reason']:
            results['by_reason'][reason] = 0
        results['by_reason'][reason] += 1
        
        if validated:
            results['validated'] += 1
            results['by_type'][bug_type]['validated'] += 1
        else:
            results['false_positives'] += 1
        
        results['details'].append({
            'file': file_name,
            'bug_type': bug_type,
            'validated': validated,
            'reason': reason
        })
    
    # Compute rates
    results['validation_rate'] = results['validated'] / results['total'] if results['total'] > 0 else 0
    results['false_positive_rate'] = results['false_positives'] / results['total'] if results['total'] > 0 else 0
    
    for bug_type, data in results['by_type'].items():
        data['rate'] = data['validated'] / data['total'] if data['total'] > 0 else 0
    
    # Print summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total bugs: {results['total']}")
    print(f"Validated: {results['validated']} ({results['validation_rate']:.1%})")
    print(f"False positives: {results['false_positives']} ({results['false_positive_rate']:.1%})")
    
    print("\nBy bug type:")
    for bug_type, data in sorted(results['by_type'].items()):
        print(f"  {bug_type}: {data['validated']}/{data['total']} ({data['rate']:.1%})")
    
    print("\nBy reason:")
    for reason, count in sorted(results['by_reason'].items(), key=lambda x: -x[1]):
        print(f"  {reason}: {count}")
    
    # Save results
    output_file = Path('results/numpy_dse_validation_iter113.json')
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {output_file}")
    
    return results

if __name__ == '__main__':
    main()
