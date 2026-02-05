#!/usr/bin/env python3
"""
CLI entrypoint for PythonFromScratch analyzer.

Usage:
    pyfromscratch <file.py> [--verbose] [--functions]
    
Returns:
    0: SAFE (verified with barrier certificate)
    1: BUG (counterexample found)
    2: UNKNOWN (neither proof nor counterexample)
    3: Error (file not found, etc.)
"""

import argparse
import sys
from pathlib import Path

from .analyzer import analyze, Analyzer
from .semantics.intent_detector import create_intent_aware_filter, IntentDetector
from .semantics.ast_guard_analysis import SafetyAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description="PythonFromScratch: Python semantics + barrier-certificate verifier"
    )
    parser.add_argument("file", type=Path, help="Python file to analyze")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--kitchensink",
        action="store_true",
        help="Enable staged portfolio analysis (kitchen-sink orchestrator)",
    )
    parser.add_argument(
        "--no-concolic",
        action="store_true",
        help="Disable all concrete execution (pure symbolic/static analysis)",
    )
    parser.add_argument(
        "--functions",
        action="store_true",
        help="Analyze function-level entry points with tainted parameters (for security bugs)",
    )
    parser.add_argument(
        "--all-functions",
        action="store_true",
        help="Analyze ALL functions as entry points with tainted parameters",
    )
    parser.add_argument(
        "--interprocedural",
        action="store_true",
        help="Enable interprocedural analysis with call graph and summaries (Phase 4)",
    )
    parser.add_argument(
        "--entry-points",
        type=str,
        help="Comma-separated list of entry point function names (for --interprocedural)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="Minimum confidence threshold for reporting bugs (0.0-1.0, default: 0.7 for high-confidence only)",
    )
    parser.add_argument(
        "--intent-filter",
        action="store_true",
        default=True,
        help="Enable intent-aware filtering to reduce false positives (default: enabled)",
    )
    parser.add_argument(
        "--no-intent-filter",
        action="store_true",
        help="Disable intent-aware filtering (report all bugs regardless of intent)",
    )
    parser.add_argument(
        "--deduplicate",
        action="store_true",
        help="Deduplicate findings by bug_type + location (reduces over-reporting)",
    )
    parser.add_argument(
        "--consolidate-variants",
        action="store_true",
        default=True,
        help="Consolidate bug type variants (e.g., SSRF×3 → SSRF×1)",
    )
    parser.add_argument(
        "--context-depth",
        type=int,
        default=0,
        help="k-CFA context depth for interprocedural analysis (0=context-insensitive, 1=1-CFA, 2=2-CFA, etc.)",
    )
    parser.add_argument(
        "--check-termination",
        action="store_true",
        help="Check loop termination with ranking function synthesis",
    )
    parser.add_argument(
        "--synthesize-invariants",
        action="store_true",
        help="Synthesize inductive loop invariants for safety proofs",
    )
    parser.add_argument(
        "--dse-verify",
        action="store_true",
        help="Verify bugs using DSE with Z3 (reduces false positives, more accurate)",
    )
    parser.add_argument(
        "--max-dse-steps",
        type=int,
        default=100,
        help="Maximum DSE steps per function for --dse-verify (default: 100)",
    )
    
    args = parser.parse_args()
    
    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        return 3
    
    print(f"Analyzing: {args.file}")
    print()
    
    # Run analysis
    # Determine if intent filtering is enabled
    use_intent_filter = args.intent_filter and not args.no_intent_filter
    
    if args.interprocedural:
        # Interprocedural analysis mode with call graph and summaries
        # Use InterproceduralBugTracker with intent filtering
        from .semantics.interprocedural_bugs import InterproceduralBugTracker
        
        root_path = args.file if args.file.is_dir() else args.file.parent
        
        print(f"Building interprocedural analysis...")
        tracker = InterproceduralBugTracker.from_project(root_path)
        print(f"Functions: {len(tracker.call_graph.functions)}")
        print(f"Entry points: {len(tracker.entry_points)}")
        
        # Find bugs with intent filtering enabled by default (high confidence only)
        bugs = tracker.find_all_bugs(
            apply_fp_reduction=True,
            apply_intent_filter=use_intent_filter,
            intent_confidence=args.min_confidence,
            root_path=root_path,
        )
        
        # Report results
        print(f"\n{'='*60}")
        print("INTERPROCEDURAL ANALYSIS RESULTS")
        if use_intent_filter:
            print(f"(High-confidence TPs only, threshold={args.min_confidence})")
        print(f"{'='*60}")
        print(f"Total bugs found: {len(bugs)}")
        
        # Group bugs by type
        bugs_by_type = {}
        for bug in bugs:
            if bug.bug_type not in bugs_by_type:
                bugs_by_type[bug.bug_type] = []
            bugs_by_type[bug.bug_type].append(bug)
        
        for bug_type, type_bugs in sorted(bugs_by_type.items()):
            print(f"\n{bug_type} ({len(type_bugs)})")
            for bug in type_bugs[:5]:  # Show first 5 of each type
                print(f"  - {bug.crash_function}")
                print(f"    {bug.crash_location}")
                print(f"    Confidence: {bug.confidence:.2f}")
            if len(type_bugs) > 5:
                print(f"  ... and {len(type_bugs) - 5} more")
        
        # Return exit code
        return 1 if bugs else 0
    
    elif args.all_functions:
        # Analyze ALL functions with tainted parameters
        analyzer = Analyzer(
            verbose=args.verbose, 
            enable_concolic=not args.no_concolic,
            check_termination=args.check_termination,
            synthesize_invariants=args.synthesize_invariants
        )
        results = analyzer.analyze_all_functions(args.file)
        
        # Print results
        print(f"Functions analyzed: {len(results['function_results'])}")
        for func_result in results['function_results']:
            func_name = func_result['function_name']
            result = func_result['result']
            print(f"  {func_name}: {result.verdict}")
            if result.verdict == 'BUG':
                print(f"    {result.bug_type}: {result.message}")
        
        print(f"\nTotal bugs found: {results['total_bugs']}")
        
        # Return exit code
        return 1 if results['total_bugs'] > 0 else 0
    
    elif args.functions:
        # Use function-level entry point analysis for security bugs
        analyzer = Analyzer(
            verbose=args.verbose, 
            enable_concolic=not args.no_concolic,
            context_depth=args.context_depth,
            check_termination=args.check_termination,
            synthesize_invariants=args.synthesize_invariants
        )
        func_results = analyzer.analyze_function_entry_points(args.file, skip_module_level=False)
        
        # Print results
        if func_results['module_result']:
            print(f"Module-level: {func_results['module_result'].verdict}")
            if func_results['module_result'].verdict == 'BUG':
                print(f"  {func_results['module_result'].bug_type}: {func_results['module_result'].message}")
        
        print(f"\nFunction-level entry points: {len(func_results['function_results'])}")
        for func_result in func_results['function_results']:
            ep = func_result['entry_point']
            result = func_result['result']
            print(f"  {ep.name}: {result.verdict}")
            if result.verdict == 'BUG':
                print(f"    {result.bug_type}: {result.message}")
        
        print(f"\nTotal bugs found: {func_results['total_bugs']}")
        
        # Return exit code based on whether bugs were found
        if func_results['total_bugs'] > 0:
            return 1
        else:
            # Check if any function was verified SAFE
            any_safe = any(fr['result'].verdict == 'SAFE' for fr in func_results['function_results'])
            return 0 if any_safe else 2
    else:
        # Regular module-level analysis
        if args.kitchensink:
            analyzer = Analyzer(
                verbose=args.verbose,
                enable_concolic=not args.no_concolic,
                check_termination=args.check_termination,
                synthesize_invariants=args.synthesize_invariants,
            )
            result = analyzer.analyze_file_kitchensink(args.file)
        else:
            result = analyze(
                args.file,
                verbose=args.verbose,
                enable_concolic=not args.no_concolic,
                check_termination=args.check_termination,
                synthesize_invariants=args.synthesize_invariants,
            )
        
        # Print result summary
        print(result.summary())
        
        # Return appropriate exit code
        if result.verdict == "SAFE":
            return 0
        elif result.verdict == "BUG":
            return 1
        else:  # UNKNOWN
            return 2


if __name__ == "__main__":
    sys.exit(main())
