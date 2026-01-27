#!/usr/bin/env python3
"""
Run analyzer on entire synthetic suite and save results.

Usage:
    python scripts/run_synthetic_suite.py [--output <path>] [--verbose]
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List
import traceback


def find_test_files(suite_dir: Path) -> List[Path]:
    """Find all Python test files in synthetic suite."""
    test_files = []
    for bug_type_dir in suite_dir.iterdir():
        if bug_type_dir.is_dir() and not bug_type_dir.name.startswith('.'):
            for py_file in bug_type_dir.glob("*.py"):
                test_files.append(py_file)
    return sorted(test_files)


def run_analyzer_on_file(file_path: Path, verbose: bool = False) -> Dict:
    """Run analyzer on a single file and return result."""
    try:
        # Import analyzer
        from pyfromscratch.analyzer import Analyzer
        
        if verbose:
            print(f"Analyzing: {file_path}")
        
        # Create analyzer and run
        analyzer = Analyzer(verbose=verbose)
        result = analyzer.analyze_file(file_path)
        
        return {
            "verdict": result.verdict,
            "bug_type": result.bug_type,
            "counterexample": result.counterexample,
            "barrier": str(result.barrier) if result.barrier else None,
            "paths_explored": result.paths_explored,
            "message": result.message,
            "error": None
        }
    
    except Exception as e:
        if verbose:
            print(f"Error analyzing {file_path}: {e}")
            traceback.print_exc()
        
        return {
            "verdict": "ERROR",
            "bug_type": None,
            "counterexample": None,
            "barrier": None,
            "paths_explored": 0,
            "message": f"Analysis error: {str(e)}",
            "error": str(e)
        }


def run_suite(suite_dir: Path, verbose: bool = False) -> Dict:
    """Run analyzer on all test files."""
    test_files = find_test_files(suite_dir)
    
    print(f"\n{'=' * 80}")
    print(f"Running analyzer on {len(test_files)} test files...")
    print(f"{'=' * 80}\n")
    
    results = {}
    errors = []
    
    for i, test_file in enumerate(test_files, 1):
        rel_path = str(test_file.relative_to(suite_dir.parent))
        
        if verbose or i % 10 == 0:
            print(f"[{i}/{len(test_files)}] {rel_path}")
        
        result = run_analyzer_on_file(test_file, verbose)
        results[rel_path] = result
        
        if result["verdict"] == "ERROR":
            errors.append(rel_path)
    
    print(f"\n{'=' * 80}")
    print(f"Analysis complete!")
    print(f"  Total: {len(test_files)}")
    print(f"  Errors: {len(errors)}")
    print(f"{'=' * 80}\n")
    
    if errors and verbose:
        print("Files with errors:")
        for err_file in errors:
            print(f"  - {err_file}")
        print()
    
    return results


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Run analyzer on synthetic test suite")
    parser.add_argument("--suite", type=Path, 
                        default=Path("tests/synthetic_suite"),
                        help="Path to synthetic suite directory")
    parser.add_argument("--output", type=Path, 
                        default=Path("results/synthetic_suite_results.json"),
                        help="Path to save results JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Check suite exists
    if not args.suite.exists():
        print(f"Error: Synthetic suite not found: {args.suite}", file=sys.stderr)
        sys.exit(1)
    
    # Run suite
    results = run_suite(args.suite, args.verbose)
    
    # Save results
    args.output.parent.mkdir(parents=True, exist_ok=True)
    
    output_data = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_files": len(results),
            "suite_directory": str(args.suite)
        },
        "results": results
    }
    
    with open(args.output, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"Results saved to: {args.output}")
    print(f"\nTo validate results, run:")
    print(f"  python scripts/validate_synthetic_suite.py --results {args.output}")


if __name__ == "__main__":
    main()
