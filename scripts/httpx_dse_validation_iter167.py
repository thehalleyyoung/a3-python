#!/usr/bin/env python3
"""
DSE validation of httpx remaining 2 bugs (iteration 167).

After all semantic improvements (iterations 160-166), httpx has 2 remaining bugs:
- httpx/_multipart.py: PANIC (module-init)
- httpx/_status_codes.py: PANIC (module-init)

This script validates these bugs via DSE to confirm they are real or identify FPs.
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import analyze_file
from pyfromscratch.dse.concolic import DSEOracle

def validate_bug_with_dse(file_path: str, expected_bug_type: str) -> dict:
    """Run analyzer and DSE validation on a single file."""
    print(f"\n{'='*60}")
    print(f"File: {file_path}")
    print(f"Expected: {expected_bug_type}")
    print(f"{'='*60}")
    
    result = {
        'file': file_path,
        'expected_bug_type': expected_bug_type,
        'analyzer_result': None,
        'dse_validated': False,
        'dse_realizable': False,
        'validation_error': None
    }
    
    # Run analyzer
    try:
        analysis = analyze_file(file_path, max_paths=1000)
        result['analyzer_result'] = analysis['result']
        
        if analysis['result'] != 'BUG':
            print(f"⚠️  Analyzer result: {analysis['result']} (expected BUG)")
            result['validation_error'] = f"Analyzer result changed to {analysis['result']}"
            return result
        
        bug_type = analysis.get('bug_type', 'UNKNOWN')
        print(f"✓ Analyzer found BUG: {bug_type}")
        
        if bug_type != expected_bug_type:
            print(f"⚠️  Bug type mismatch: expected {expected_bug_type}, got {bug_type}")
            result['validation_error'] = f"Bug type changed from {expected_bug_type} to {bug_type}"
        
        # Extract trace and constraints for DSE
        trace = analysis.get('trace', '')
        constraints_data = analysis.get('constraints', [])
        
        # Run DSE validation
        print("\n--- DSE Validation ---")
        oracle = DSEOracle()
        
        try:
            validation_result = oracle.validate_counterexample(
                file_path,
                constraints_data,
                trace
            )
            
            result['dse_validated'] = True
            result['dse_realizable'] = validation_result.get('realizable', False)
            result['dse_inputs'] = validation_result.get('inputs', {})
            result['dse_error'] = validation_result.get('error')
            
            if result['dse_realizable']:
                print(f"✅ DSE VALIDATED: Bug is realizable")
                print(f"   Concrete inputs: {validation_result.get('inputs', {})}")
            else:
                print(f"❌ DSE FAILED: Could not realize bug")
                if validation_result.get('error'):
                    print(f"   Error: {validation_result['error']}")
                    
        except Exception as e:
            print(f"❌ DSE Exception: {e}")
            result['dse_validated'] = True
            result['dse_realizable'] = False
            result['dse_error'] = str(e)
            
    except Exception as e:
        print(f"❌ Analysis Exception: {e}")
        result['validation_error'] = str(e)
    
    return result


def main():
    print("="*70)
    print("httpx DSE Validation - Iteration 167")
    print("Validating 2 remaining bugs after all semantic improvements")
    print("="*70)
    
    # Base path for httpx clone
    base_path = Path("results/public_repos/clones/httpx")
    
    # Bugs to validate
    bugs_to_validate = [
        (str(base_path / "httpx/_multipart.py"), "PANIC"),
        (str(base_path / "httpx/_status_codes.py"), "PANIC"),
    ]
    
    results = []
    validated_count = 0
    false_positive_count = 0
    
    for file_path, expected_bug_type in bugs_to_validate:
        result = validate_bug_with_dse(file_path, expected_bug_type)
        results.append(result)
        
        if result['dse_validated']:
            if result['dse_realizable']:
                validated_count += 1
            else:
                false_positive_count += 1
    
    # Summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    print(f"Total bugs: {len(bugs_to_validate)}")
    print(f"Validated (realizable): {validated_count}")
    print(f"False positives: {false_positive_count}")
    print(f"Validation rate: {validated_count / len(bugs_to_validate) * 100:.1f}%")
    print(f"FP rate: {false_positive_count / len(bugs_to_validate) * 100:.1f}%")
    
    # Save results
    output = {
        'iteration': 167,
        'scan_iteration': 163,
        'validation_date': datetime.now(timezone.utc).isoformat(),
        'total_bugs': len(bugs_to_validate),
        'validated': validated_count,
        'false_positives': false_positive_count,
        'validation_rate': validated_count / len(bugs_to_validate),
        'false_positive_rate': false_positive_count / len(bugs_to_validate),
        'results': results,
        'by_type': {
            'PANIC': {
                'total': 2,
                'validated': validated_count,
                'rate': validated_count / 2
            }
        },
        'note': 'Final validation of httpx remaining 2 bugs after semantic improvements (iter 160-166)'
    }
    
    output_path = Path("results/httpx_dse_validation_iter167.json")
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
    
    return 0 if false_positive_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
