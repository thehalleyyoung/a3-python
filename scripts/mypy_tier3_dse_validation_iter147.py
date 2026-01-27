#!/usr/bin/env python3
"""
DSE validation for mypy tier 3 scan (iteration 147).

Analyzes the DSE validation results already embedded in the tier 3 scan
from iteration 146. The scan integrated DSE validation automatically.

Follows continuous refinement discipline from RustFromScratch workflow:
- Extract DSE validation status from scan output
- Track validation rate by bug type
- Record false positives and false negatives
- Compare with tier 3 baselines (sqlalchemy, pydantic)
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

def load_scan_results(scan_file):
    """Load bug reports from scan JSON."""
    with open(scan_file, 'r') as f:
        data = json.load(f)
    
    bugs = []
    for filepath, result in data.get('results', {}).items():
        if result.get('status') == 'BUG':
            bugs.append({
                'file': filepath,
                'result': result
            })
    
    return {
        'repo': data.get('repo', 'unknown'),
        'iteration': data.get('iteration', 0),
        'scan_date': data.get('scan_date', ''),
        'total_files': data.get('files_analyzed', 0),
        'bugs': bugs
    }

def extract_bug_info(bug_result):
    """Extract bug type and context from output."""
    output = bug_result['output']
    
    # Extract bug type
    bug_type = None
    if 'BUG: PANIC' in output:
        bug_type = 'PANIC'
    elif 'BUG: BOUNDS' in output:
        bug_type = 'BOUNDS'
    elif 'BUG: TYPE_CONFUSION' in output:
        bug_type = 'TYPE_CONFUSION'
    elif 'BUG: NULL_PTR' in output:
        bug_type = 'NULL_PTR'
    elif 'BUG: DIV_ZERO' in output:
        bug_type = 'DIV_ZERO'
    elif 'BUG: ASSERT_FAIL' in output:
        bug_type = 'ASSERT_FAIL'
    
    # Check if already DSE validated in scan
    dse_validated = '✓ DSE validated' in output
    
    # Check if module-init
    module_init = 'MODULE-INIT PHASE' in output
    
    # Extract exception info
    exception_type = None
    if 'UNHANDLED EXCEPTION: ImportError' in output:
        exception_type = 'ImportError'
    elif 'UNHANDLED EXCEPTION: NameError' in output:
        exception_type = 'NameError'
    elif 'UNHANDLED EXCEPTION: TypeError' in output:
        exception_type = 'TypeError'
    elif 'UNHANDLED EXCEPTION: AttributeError' in output:
        exception_type = 'AttributeError'
    elif 'UNHANDLED EXCEPTION: KeyError' in output:
        exception_type = 'KeyError'
    elif 'UNHANDLED EXCEPTION: IndexError' in output:
        exception_type = 'IndexError'
    elif 'UNHANDLED EXCEPTION: ValueError' in output:
        exception_type = 'ValueError'
    elif 'UNHANDLED EXCEPTION: ZeroDivisionError' in output:
        exception_type = 'ZeroDivisionError'
    
    return {
        'bug_type': bug_type,
        'dse_validated_in_scan': dse_validated,
        'module_init': module_init,
        'exception_type': exception_type
    }

def validate_all_bugs(scan_data):
    """Validate all bugs with DSE."""
    results = {
        'total': len(scan_data['bugs']),
        'validated': 0,
        'already_validated': 0,
        'validation_failed': 0,
        'by_type': {},
        'by_exception': {},
        'bugs': []
    }
    
    for i, bug in enumerate(scan_data['bugs']):
        print(f"\n[{i+1}/{results['total']}] Validating {bug['file']}")
        
        info = extract_bug_info(bug['result'])
        bug_type = info['bug_type']
        exception_type = info['exception_type']
        
        # Track by type
        if bug_type not in results['by_type']:
            results['by_type'][bug_type] = {
                'total': 0,
                'validated': 0,
                'already_validated': 0
            }
        results['by_type'][bug_type]['total'] += 1
        
        # Track by exception
        if exception_type:
            if exception_type not in results['by_exception']:
                results['by_exception'][exception_type] = {
                    'total': 0,
                    'validated': 0
                }
            results['by_exception'][exception_type]['total'] += 1
        
        # Check if already validated
        if info['dse_validated_in_scan']:
            print(f"  ✓ Already validated in scan (bug_type={bug_type}, exception={exception_type})")
            results['validated'] += 1
            results['already_validated'] += 1
            if bug_type:
                results['by_type'][bug_type]['validated'] += 1
                results['by_type'][bug_type]['already_validated'] += 1
            if exception_type:
                results['by_exception'][exception_type]['validated'] += 1
            
            results['bugs'].append({
                'file': bug['file'],
                'bug_type': bug_type,
                'exception_type': exception_type,
                'validated': True,
                'already_validated': True,
                'module_init': info['module_init']
            })
        else:
            # Need to validate - this shouldn't happen in current analyzer
            # (all bugs should have DSE validation embedded)
            print(f"  ⚠ Bug not DSE validated in scan - unexpected")
            results['validation_failed'] += 1
            results['bugs'].append({
                'file': bug['file'],
                'bug_type': bug_type,
                'exception_type': exception_type,
                'validated': False,
                'already_validated': False,
                'module_init': info['module_init']
            })
    
    # Calculate rates
    results['validation_rate'] = results['validated'] / results['total'] if results['total'] > 0 else 0
    results['false_positive_rate'] = results['validation_failed'] / results['total'] if results['total'] > 0 else 0
    
    for bug_type, stats in results['by_type'].items():
        stats['validation_rate'] = stats['validated'] / stats['total'] if stats['total'] > 0 else 0
    
    for exc_type, stats in results['by_exception'].items():
        stats['validation_rate'] = stats['validated'] / stats['total'] if stats['total'] > 0 else 0
    
    return results

def main():
    print("=" * 80)
    print("Mypy Tier 3 DSE Validation (Iteration 147)")
    print("=" * 80)
    
    # Load scan results from iteration 146
    scan_file = Path(__file__).parent.parent / 'results' / 'public_repos' / 'mypy_tier3_scan_iter146.json'
    
    if not scan_file.exists():
        print(f"ERROR: Scan file not found: {scan_file}")
        return 1
    
    print(f"\nLoading scan results from: {scan_file}")
    scan_data = load_scan_results(scan_file)
    
    print(f"  Repo: {scan_data['repo']}")
    print(f"  Scan iteration: {scan_data['iteration']}")
    print(f"  Scan date: {scan_data['scan_date']}")
    print(f"  Total files: {scan_data['total_files']}")
    print(f"  Total bugs: {len(scan_data['bugs'])}")
    
    # Validate all bugs
    print("\n" + "=" * 80)
    print("DSE Validation")
    print("=" * 80)
    
    validation_results = validate_all_bugs(scan_data)
    
    # Print summary
    print("\n" + "=" * 80)
    print("Summary")
    print("=" * 80)
    
    print(f"\nTotal bugs: {validation_results['total']}")
    print(f"Validated: {validation_results['validated']} ({validation_results['validation_rate']:.1%})")
    print(f"Already validated in scan: {validation_results['already_validated']}")
    print(f"Validation failed: {validation_results['validation_failed']} ({validation_results['false_positive_rate']:.1%})")
    
    print("\nBy bug type:")
    for bug_type, stats in sorted(validation_results['by_type'].items()):
        print(f"  {bug_type:20} {stats['validated']:3}/{stats['total']:3} ({stats['validation_rate']:5.1%})")
    
    print("\nBy exception type:")
    for exc_type, stats in sorted(validation_results['by_exception'].items()):
        print(f"  {exc_type:20} {stats['validated']:3}/{stats['total']:3} ({stats['validation_rate']:5.1%})")
    
    # Count module-init bugs
    module_init_bugs = sum(1 for b in validation_results['bugs'] if b.get('module_init', False))
    module_init_rate = module_init_bugs / validation_results['total'] if validation_results['total'] > 0 else 0
    print(f"\nModule-init bugs: {module_init_bugs}/{validation_results['total']} ({module_init_rate:.1%})")
    
    # Compare with tier 3 baselines
    print("\n" + "=" * 80)
    print("Tier 3 Comparison")
    print("=" * 80)
    
    # From State.json
    sqlalchemy_validation = 1.0
    sqlalchemy_bug_rate = 0.04
    pydantic_validation = 0.966
    pydantic_bug_rate = 0.58
    
    mypy_bug_rate = validation_results['total'] / scan_data['total_files']
    
    print(f"\nValidation rates:")
    print(f"  SQLAlchemy:  {sqlalchemy_validation:.1%} (iter 143)")
    print(f"  Pydantic:    {pydantic_validation:.1%} (iter 145)")
    print(f"  Mypy:        {validation_results['validation_rate']:.1%} (iter 147)")
    
    print(f"\nBug rates:")
    print(f"  SQLAlchemy:  {sqlalchemy_bug_rate:.1%} ({int(sqlalchemy_bug_rate * 100)} bugs/100 files)")
    print(f"  Pydantic:    {pydantic_bug_rate:.1%} ({int(pydantic_bug_rate * 100)} bugs/100 files)")
    print(f"  Mypy:        {mypy_bug_rate:.1%} ({validation_results['total']} bugs/100 files)")
    
    print(f"\nRanking (bug rate):")
    tiers = [
        ('SQLAlchemy', sqlalchemy_bug_rate),
        ('Mypy', mypy_bug_rate),
        ('Pydantic', pydantic_bug_rate)
    ]
    tiers.sort(key=lambda x: x[1])
    for i, (name, rate) in enumerate(tiers, 1):
        print(f"  {i}. {name:15} {rate:.1%}")
    
    # Save results
    output_file = Path(__file__).parent.parent / 'results' / 'public_repos' / 'mypy_tier3_dse_validation_iter147.json'
    
    output_data = {
        'repo': scan_data['repo'],
        'iteration': 147,
        'scan_iteration': scan_data['iteration'],
        'scan_date': scan_data['scan_date'],
        'validation_date': datetime.now(timezone.utc).isoformat(),
        'total_files': scan_data['total_files'],
        'total_bugs': validation_results['total'],
        'validated': validation_results['validated'],
        'validation_rate': validation_results['validation_rate'],
        'false_positives': validation_results['validation_failed'],
        'false_positive_rate': validation_results['false_positive_rate'],
        'true_bug_rate': (validation_results['validated'] / scan_data['total_files']) if scan_data['total_files'] > 0 else 0,
        'by_type': validation_results['by_type'],
        'by_exception': validation_results['by_exception'],
        'module_init_bugs': module_init_bugs,
        'module_init_rate': module_init_rate,
        'comparison': {
            'sqlalchemy': {
                'validation_rate': sqlalchemy_validation,
                'bug_rate': sqlalchemy_bug_rate
            },
            'pydantic': {
                'validation_rate': pydantic_validation,
                'bug_rate': pydantic_bug_rate
            },
            'mypy': {
                'validation_rate': validation_results['validation_rate'],
                'bug_rate': mypy_bug_rate
            }
        },
        'bugs': validation_results['bugs']
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n\nResults saved to: {output_file}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
