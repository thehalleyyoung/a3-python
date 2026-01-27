#!/usr/bin/env python3
"""
Ansible DSE Validation - Iteration 114
Rescan 100 ansible files and validate all bugs with DSE.
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer

def scan_ansible_files():
    """Scan 100 ansible files."""
    ansible_dir = Path('results/public_repos/clones/ansible/lib/ansible')
    py_files = sorted(ansible_dir.rglob('*.py'))[:100]
    
    print(f"Scanning {len(py_files)} ansible files...")
    
    analyzer = Analyzer(max_paths=200, max_depth=100, verbose=False)
    
    results = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'total_files': len(py_files),
        'bugs': [],
        'safe': [],
        'unknown': [],
        'errors': []
    }
    
    for i, file_path in enumerate(py_files, 1):
        if i % 20 == 0:
            print(f"  Progress: {i}/{len(py_files)}")
        
        try:
            result = analyzer.analyze_file(file_path)
            
            entry = {
                'file_path': str(file_path),
                'file_name': file_path.name,
                'verdict': result.verdict,
                'bug_type': result.bug_type,
                'function_name': getattr(result, 'function_name', 'unknown'),
                'is_module_init': getattr(result, 'is_module_init', False),
                'counterexample': result.counterexample if result.verdict == 'BUG' else None
            }
            
            if result.verdict == 'BUG':
                results['bugs'].append(entry)
            elif result.verdict == 'SAFE':
                results['safe'].append(entry)
            elif result.verdict == 'UNKNOWN':
                results['unknown'].append(entry)
        except Exception as e:
            results['errors'].append({
                'file_path': str(file_path),
                'error': str(e)
            })
    
    print(f"\nScan complete:")
    print(f"  BUG: {len(results['bugs'])}")
    print(f"  SAFE: {len(results['safe'])}")
    print(f"  UNKNOWN: {len(results['unknown'])}")
    print(f"  ERROR: {len(results['errors'])}")
    
    return results

def validate_bug(bug):
    """
    Validate a bug by checking DSE validation status.
    The analyzer already ran DSE during scan, so we check the counterexample.
    """
    file_path = Path(bug['file_path'])
    bug_type = bug['bug_type']
    counterexample = bug.get('counterexample')
    
    if not counterexample:
        return False, "no_counterexample"
    
    # Check if DSE validated this bug
    dse_validated = counterexample.get('dse_validated', False)
    
    if dse_validated:
        concrete_repro = counterexample.get('concrete_repro', 'N/A')
        return True, "validated"
    else:
        dse_reason = counterexample.get('dse_reason', 'unknown')
        return False, f"dse_inconclusive_{dse_reason}"

def main():
    print("=" * 60)
    print("Ansible DSE Validation - Iteration 114")
    print("=" * 60)
    
    # Scan ansible files
    scan_results = scan_ansible_files()
    
    # Save scan results
    scan_file = Path('results/ansible_scan_iter114.json')
    scan_file.parent.mkdir(parents=True, exist_ok=True)
    with open(scan_file, 'w') as f:
        json.dump(scan_results, f, indent=2)
    print(f"\nScan results saved to {scan_file}")
    
    # Validate bugs
    bugs = scan_results['bugs']
    print(f"\n{'=' * 60}")
    print(f"Validating {len(bugs)} bugs with DSE")
    print("=" * 60)
    
    validation_results = {
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
        if bug_type not in validation_results['by_type']:
            validation_results['by_type'][bug_type] = {'total': 0, 'validated': 0}
        validation_results['by_type'][bug_type]['total'] += 1
        
        # Track by reason
        if reason not in validation_results['by_reason']:
            validation_results['by_reason'][reason] = 0
        validation_results['by_reason'][reason] += 1
        
        if validated:
            validation_results['validated'] += 1
            validation_results['by_type'][bug_type]['validated'] += 1
            print(f"  ✓ DSE validated")
        else:
            validation_results['false_positives'] += 1
            print(f"  ✗ False positive: {reason}")
        
        validation_results['details'].append({
            'file': file_name,
            'bug_type': bug_type,
            'validated': validated,
            'reason': reason
        })
    
    # Calculate rates
    validation_results['validation_rate'] = (
        validation_results['validated'] / validation_results['total']
        if validation_results['total'] > 0 else 0.0
    )
    validation_results['false_positive_rate'] = (
        validation_results['false_positives'] / validation_results['total']
        if validation_results['total'] > 0 else 0.0
    )
    
    # Calculate true bug rate for ansible
    total_files = scan_results['total_files']
    true_bugs = validation_results['validated']
    validation_results['true_bug_rate'] = true_bugs / total_files if total_files > 0 else 0.0
    
    # Print summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total bugs found: {validation_results['total']}")
    print(f"DSE validated: {validation_results['validated']} ({validation_results['validation_rate']:.1%})")
    print(f"False positives: {validation_results['false_positives']} ({validation_results['false_positive_rate']:.1%})")
    print(f"True bug rate: {validation_results['true_bug_rate']:.1%} ({true_bugs}/{total_files} files)")
    
    print("\nBy bug type:")
    for bug_type, stats in sorted(validation_results['by_type'].items()):
        rate = stats['validated'] / stats['total'] if stats['total'] > 0 else 0.0
        print(f"  {bug_type}: {stats['validated']}/{stats['total']} ({rate:.1%})")
    
    print("\nBy validation reason:")
    for reason, count in sorted(validation_results['by_reason'].items(), key=lambda x: -x[1]):
        pct = count / validation_results['total'] * 100 if validation_results['total'] > 0 else 0
        print(f"  {reason}: {count} ({pct:.1f}%)")
    
    # Save validation results
    results_file = Path('results/ansible_dse_validation_iter114.json')
    with open(results_file, 'w') as f:
        json.dump(validation_results, f, indent=2)
    print(f"\nValidation results saved to {results_file}")
    
    return validation_results

if __name__ == '__main__':
    results = main()
