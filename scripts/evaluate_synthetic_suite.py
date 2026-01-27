#!/usr/bin/env python3
"""
Comprehensive synthetic test suite evaluation.

This script runs the PythonFromScratch analyzer on all synthetic test files
and generates a detailed report of findings vs. ground truth.
"""

from pathlib import Path
from pyfromscratch.analyzer import Analyzer
import json

def main():
    test_files = [
        ("tests/fixtures/synthetic_sql_injection_multi.py", {
            "sql_bug_1": "SQL_INJECTION",
            "sql_bug_2": "SQL_INJECTION",
            "sql_safe_1": None,
            "sql_safe_2": None,
            "sql_bug_second_order": "SQL_INJECTION",
        }),
        ("tests/fixtures/synthetic_command_injection_multi.py", {
            "cmd_bug_1": "COMMAND_INJECTION",
            "cmd_bug_2": "COMMAND_INJECTION",
            "cmd_bug_3": "COMMAND_INJECTION",
            "cmd_safe_1": None,
            "cmd_safe_2": None,
            "cmd_bug_4": "COMMAND_INJECTION",
            "cmd_bug_5": "CODE_INJECTION",
        }),
        ("tests/fixtures/synthetic_path_injection_multi.py", {
            "path_bug_1": "PATH_INJECTION",
            "path_bug_2": "PATH_INJECTION",
            "path_safe_1": None,
            "path_safe_2": None,
            "path_bug_3": "PATH_INJECTION",
            "path_bug_4": "TAR_SLIP",
        }),
    ]
    
    analyzer = Analyzer(verbose=False, enable_interprocedural=True)
    
    results = {
        "total_tests": 0,
        "true_positives": 0,
        "true_negatives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "details": []
    }
    
    for file_path, ground_truth in test_files:
        print(f"\n{'='*60}")
        print(f"Analyzing: {file_path}")
        print(f"{'='*60}")
        
        result = analyzer.analyze_file(Path(file_path))
        
        # Extract all violations from SOTA engine
        violations_by_function = {}
        if result.counterexample and 'all_violations' in result.counterexample:
            for v in result.counterexample['all_violations']:
                func = v.get('function_name', 'unknown')
                bug_type = v.get('bug_type', 'UNKNOWN')
                if func not in violations_by_function:
                    violations_by_function[func] = []
                violations_by_function[func].append(bug_type)
        
        # Compare to ground truth
        for func_name, expected_bug in ground_truth.items():
            results["total_tests"] += 1
            found_bugs = violations_by_function.get(func_name, [])
            
            if expected_bug is None:
                # Should be safe
                if not found_bugs:
                    results["true_negatives"] += 1
                    status = "✓ TN"
                else:
                    results["false_positives"] += 1
                    status = f"✗ FP: Found {found_bugs}"
            else:
                # Should find bug
                if expected_bug in found_bugs:
                    results["true_positives"] += 1
                    status = "✓ TP"
                else:
                    results["false_negatives"] += 1
                    status = f"✗ FN: Expected {expected_bug}, found {found_bugs or 'nothing'}"
            
            print(f"  {func_name}: {status}")
            
            results["details"].append({
                "file": file_path,
                "function": func_name,
                "expected": expected_bug,
                "found": found_bugs,
                "status": status
            })
    
    # Print summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total tests: {results['total_tests']}")
    print(f"True positives: {results['true_positives']}")
    print(f"True negatives: {results['true_negatives']}")
    print(f"False positives: {results['false_positives']}")
    print(f"False negatives: {results['false_negatives']}")
    
    if results['total_tests'] > 0:
        precision = results['true_positives'] / (results['true_positives'] + results['false_positives']) if (results['true_positives'] + results['false_positives']) > 0 else 0
        recall = results['true_positives'] / (results['true_positives'] + results['false_negatives']) if (results['true_positives'] + results['false_negatives']) > 0 else 0
        accuracy = (results['true_positives'] + results['true_negatives']) / results['total_tests']
        
        print(f"\nPrecision: {precision:.2%}")
        print(f"Recall: {recall:.2%}")
        print(f"Accuracy: {accuracy:.2%}")
    
    # Save results
    with open("results/synthetic_suite_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed results saved to: results/synthetic_suite_results.json")

if __name__ == "__main__":
    main()
