#!/usr/bin/env python3
"""
DSE validation of high-value production bugs.

This script takes bugs found by the symbolic analyzer and attempts to
validate them using DSE (dynamic symbolic execution).

Per the workflow rules:
- DSE success = concrete reproducer (attach to bug report)
- DSE failure = NO conclusion about feasibility (keep over-approximation)
- Use DSE to guide refinement, not to dismiss bugs
"""

import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import traceback
import dis
import types

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.dse.concolic import ConcreteInput, ConcreteExecutor, DSEResult


def load_scan_results(scan_file: Path) -> Dict[str, Any]:
    """Load scan results from JSON file."""
    with open(scan_file) as f:
        return json.load(f)


def select_high_value_bugs(scan_results: Dict[str, Any], max_bugs: int = 5) -> List[Dict[str, Any]]:
    """
    Select high-value bugs for DSE validation.
    
    Priority:
    1. Non-PANIC bugs (real semantic issues)
    2. Bugs in non-test files
    3. Bugs with complete witness traces
    """
    findings = scan_results.get('findings', [])
    bug_findings = [f for f in findings if f.get('verdict') == 'BUG']
    
    # Filter for high-value bugs
    high_value = []
    for bug in bug_findings:
        # Skip PANIC from unimplemented opcodes
        if bug.get('bug_type') == 'PANIC':
            # Check if it's due to unimplemented opcode
            trace = bug.get('witness_trace', [])
            if any('EXCEPTION: Opcode' in line for line in trace):
                continue
        
        # Prefer non-test files
        file_path = bug.get('file_path', '')
        is_test = '/test' in file_path or '/tests/' in file_path
        
        # Must have witness trace
        if not bug.get('witness_trace'):
            continue
        
        high_value.append({
            'bug': bug,
            'priority': 0 if not is_test else 1  # Non-test files first
        })
    
    # Sort by priority and limit
    high_value.sort(key=lambda x: x['priority'])
    return [item['bug'] for item in high_value[:max_bugs]]


def extract_function_from_bug(bug: Dict[str, Any]) -> Optional[types.CodeType]:
    """
    Extract the code object for the function containing the bug.
    
    Returns None if we can't load the code object.
    """
    file_path = bug.get('file_path')
    if not file_path or not os.path.exists(file_path):
        return None
    
    try:
        # Load and compile the file
        with open(file_path) as f:
            source = f.read()
        
        code = compile(source, file_path, 'exec')
        return code
    except Exception as e:
        print(f"  Failed to compile {file_path}: {e}")
        return None


def validate_bug_with_dse(bug: Dict[str, Any], repo_name: str) -> Dict[str, Any]:
    """
    Attempt to validate a bug using DSE.
    
    Returns a validation result dictionary.
    """
    result = {
        'repo': repo_name,
        'file': bug.get('file_path', 'unknown'),
        'bug_type': bug.get('bug_type'),
        'dse_status': 'not_attempted',
        'dse_message': '',
        'concrete_repro': None
    }
    
    print(f"\n  Validating {bug.get('bug_type')} in {Path(bug.get('file_path', 'unknown')).name}")
    
    # Extract witness trace
    witness_trace = bug.get('witness_trace', [])
    if not witness_trace:
        result['dse_status'] = 'no_trace'
        result['dse_message'] = 'No witness trace available'
        return result
    
    print(f"    Witness trace: {len(witness_trace)} steps")
    print(f"    Last 3 steps:")
    for line in witness_trace[-3:]:
        print(f"      {line}")
    
    # Extract code object
    code_obj = extract_function_from_bug(bug)
    if not code_obj:
        result['dse_status'] = 'code_load_failed'
        result['dse_message'] = 'Could not load code object'
        return result
    
    # Attempt concrete execution with empty inputs
    # In a full implementation, we would:
    # 1. Extract path constraints from symbolic trace
    # 2. Solve with Z3 to get concrete inputs
    # 3. Execute with those inputs
    # 
    # For now, we do a simpler check: can we execute the code at all?
    try:
        executor = ConcreteExecutor(max_steps=1000)
        
        # Build proper input with module context
        file_path = bug.get('file_path', 'unknown')
        
        # Try to infer module name from file path
        module_name = '__main__'
        if file_path and file_path != 'unknown':
            # Convert file path to module name (e.g., flask/views.py -> flask.views)
            parts = Path(file_path).with_suffix('').parts
            # Find the start of the package (after common prefixes)
            for i, part in enumerate(parts):
                if part not in ('src', 'lib', 'python', 'site-packages'):
                    module_name = '.'.join(parts[i:])
                    break
        
        concrete_input = ConcreteInput.for_module(
            module_name=module_name,
            file_path=file_path
        )
        
        # Note: This is a simplified validation. A full DSE implementation
        # would extract constraints from the symbolic trace and solve them.
        trace = executor.execute(code_obj, concrete_input)
        
        if trace.exception_raised:
            # Check if exception matches bug type
            exception_type = type(trace.exception_raised).__name__
            bug_type = bug.get('bug_type')
            
            # Map bug types to exception types
            bug_to_exception = {
                'BOUNDS': ['IndexError', 'KeyError'],
                'DIV_ZERO': ['ZeroDivisionError'],
                'TYPE_CONFUSION': ['TypeError'],
                'NULL_PTR': ['AttributeError', 'TypeError'],
                'ASSERT_FAIL': ['AssertionError'],
                'PANIC': [Exception],  # Any unhandled exception
            }
            
            expected_exceptions = bug_to_exception.get(bug_type, [])
            if any(exception_type == e if isinstance(e, str) else isinstance(trace.exception_raised, e) 
                   for e in expected_exceptions):
                result['dse_status'] = 'validated'
                result['dse_message'] = f'Concrete execution reproduced {exception_type}'
                result['concrete_repro'] = {
                    'exception': exception_type,
                    'message': str(trace.exception_raised),
                    'stdout': trace.stdout,
                    'stderr': trace.stderr
                }
                print(f"    ✓ VALIDATED: Reproduced {exception_type}")
            else:
                result['dse_status'] = 'different_exception'
                result['dse_message'] = f'Got {exception_type}, expected {bug_type}'
                print(f"    ✗ Different exception: {exception_type}")
        else:
            result['dse_status'] = 'no_exception'
            result['dse_message'] = 'Concrete execution succeeded without exception'
            print(f"    ? No exception raised (may need specific inputs)")
    
    except Exception as e:
        result['dse_status'] = 'execution_error'
        result['dse_message'] = f'DSE execution failed: {str(e)}'
        print(f"    ✗ Execution error: {e}")
    
    return result


def main():
    """Main validation workflow."""
    results_dir = Path(__file__).parent.parent / 'results' / 'public_repos'
    scan_dir = results_dir / 'scan_results'
    
    # Select repos and scan files
    repos = {
        'click': 'click_20260123_043148.json',
        'flask': 'flask_20260123_043154.json', 
        'requests': 'requests_20260123_043157.json',
    }
    
    all_validations = []
    
    print("=" * 80)
    print("DSE VALIDATION OF HIGH-VALUE PRODUCTION BUGS")
    print("=" * 80)
    
    for repo_name, scan_file_name in repos.items():
        scan_file = scan_dir / scan_file_name
        if not scan_file.exists():
            print(f"\n⚠ Scan file not found: {scan_file}")
            continue
        
        print(f"\n\n{'='*80}")
        print(f"REPO: {repo_name.upper()}")
        print(f"{'='*80}")
        
        # Load scan results
        scan_results = load_scan_results(scan_file)
        summary = scan_results.get('summary', {})
        print(f"\nScan summary:")
        print(f"  Total findings: {len(scan_results.get('findings', []))}")
        print(f"  BUG: {summary.get('BUG', 0)}")
        print(f"  SAFE: {summary.get('SAFE', 0)}")
        print(f"  UNKNOWN: {summary.get('UNKNOWN', 0)}")
        
        # Select high-value bugs
        high_value_bugs = select_high_value_bugs(scan_results, max_bugs=2)
        print(f"\nSelected {len(high_value_bugs)} high-value bugs for validation")
        
        # Validate each bug
        for bug in high_value_bugs:
            validation = validate_bug_with_dse(bug, repo_name)
            all_validations.append(validation)
    
    # Summary
    print("\n\n" + "=" * 80)
    print("VALIDATION SUMMARY")
    print("=" * 80)
    
    by_status = {}
    for v in all_validations:
        status = v['dse_status']
        by_status.setdefault(status, []).append(v)
    
    for status, validations in sorted(by_status.items()):
        print(f"\n{status.upper()}: {len(validations)} bugs")
        for v in validations:
            print(f"  - {v['repo']}: {v['bug_type']} in {Path(v['file']).name}")
    
    # Save results
    output_file = results_dir / 'dse_validation_results.json'
    with open(output_file, 'w') as f:
        json.dump({
            'validations': all_validations,
            'summary': {status: len(vals) for status, vals in by_status.items()},
            'total_validated': len([v for v in all_validations if v['dse_status'] == 'validated']),
            'total_attempted': len(all_validations)
        }, f, indent=2)
    
    print(f"\n\nResults saved to: {output_file}")
    
    # Report
    validated_count = len([v for v in all_validations if v['dse_status'] == 'validated'])
    print(f"\n{'='*80}")
    print(f"CONCLUSION: Validated {validated_count}/{len(all_validations)} bugs with concrete reproductions")
    print(f"{'='*80}")
    
    return 0 if validated_count > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
