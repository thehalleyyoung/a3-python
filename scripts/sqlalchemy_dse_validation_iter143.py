#!/usr/bin/env python3
"""
SQLAlchemy DSE Validation - Iteration 143
Validate the 4 bugs found in sqlalchemy tier 3 scan (iteration 142).
"""

import sys
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer

def load_sqlalchemy_bugs():
    """Load latest sqlalchemy scan results."""
    scan_file = Path('results/public_repos/scan_results/sqlalchemy_20260123_131448.json')
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
    print(f"  File: {file_path}")
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
    print("=" * 80)
    print("SQLAlchemy DSE Validation - Iteration 143 (Tier 3 First Evaluation)")
    print("=" * 80)
    
    bugs = load_sqlalchemy_bugs()
    print(f"\nLoaded {len(bugs)} bugs from scan (iteration 142)")
    print(f"Scan file: sqlalchemy_20260123_131448.json")
    print()
    
    results = {
        'total': len(bugs),
        'validated': 0,
        'false_positives': 0,
        'by_type': {}
    }
    
    for bug in bugs:
        bug_type = bug['bug_type']
        if bug_type not in results['by_type']:
            results['by_type'][bug_type] = {'total': 0, 'validated': 0}
        results['by_type'][bug_type]['total'] += 1
        
        validated, reason = validate_bug(bug)
        if validated:
            results['validated'] += 1
            results['by_type'][bug_type]['validated'] += 1
        else:
            results['false_positives'] += 1
    
    print("\n" + "=" * 80)
    print("VALIDATION SUMMARY")
    print("=" * 80)
    print(f"Total bugs: {results['total']}")
    print(f"Validated: {results['validated']} ({results['validated']/results['total']*100:.1f}%)")
    print(f"False positives: {results['false_positives']} ({results['false_positives']/results['total']*100:.1f}%)")
    print()
    print("By bug type:")
    for bug_type, stats in results['by_type'].items():
        rate = stats['validated'] / stats['total'] if stats['total'] > 0 else 0
        print(f"  {bug_type}: {stats['validated']}/{stats['total']} ({rate*100:.1f}%)")
    
    # Calculate estimated true bug rate
    scan_bug_rate = 4 / 100  # 4 bugs out of 100 files
    validation_rate = results['validated'] / results['total'] if results['total'] > 0 else 0
    estimated_true_bug_rate = scan_bug_rate * validation_rate
    
    print()
    print(f"Scan bug rate: {scan_bug_rate*100:.1f}%")
    print(f"Validation rate: {validation_rate*100:.1f}%")
    print(f"Estimated true bug rate: {estimated_true_bug_rate*100:.1f}%")
    
    # Save results
    output = {
        'iteration': 143,
        'scan_iteration': 142,
        'scan_date': '2026-01-23T13:14:48',
        'validation_date': datetime.utcnow().isoformat() + '+00:00',
        'repo': 'sqlalchemy',
        'tier': 3,
        'total_bugs': results['total'],
        'validated': results['validated'],
        'validation_rate': validation_rate,
        'false_positives': results['false_positives'],
        'false_positive_rate': results['false_positives'] / results['total'] if results['total'] > 0 else 0,
        'estimated_true_bug_rate': estimated_true_bug_rate,
        'scan_bug_rate': scan_bug_rate,
        'by_type': results['by_type']
    }
    
    output_file = Path('results/public_repos/sqlalchemy_dse_validation_iter143.json')
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")

if __name__ == '__main__':
    main()
