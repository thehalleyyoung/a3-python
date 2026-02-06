#!/usr/bin/env python3
"""
CLI entrypoint for PythonFromScratch analyzer.

Usage:
    python -m pyfromscratch <target> [options]

    # Analyze a single file
    python -m pyfromscratch myfile.py

    # Full project analysis (crash summaries + barriers + DSE)
    python -m pyfromscratch path/to/project/

Returns:
    0: SAFE / no true positives found
    1: BUG / true positives found
    2: UNKNOWN
    3: Error
"""

import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="pyfromscratch",
        description="PythonFromScratch: Python semantics + barrier-certificate verifier",
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Python file or project directory to analyze",
    )
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
    parser.add_argument(
        "--save-results",
        type=Path,
        default=None,
        help="Save results to a pickle file (default: results/<project>_results.pkl)",
    )
    
    args = parser.parse_args()
    
    if not args.target.exists():
        print(f"Error: Target not found: {args.target}", file=sys.stderr)
        return 3

    # ── Directory target → full project analysis pipeline ──
    if args.target.is_dir():
        return _analyze_project(args)

    # ── Single file target → legacy per-file analysis ──
    return _analyze_file(args)


def _analyze_file(args):
    """Single-file analysis (original CLI behaviour)."""
    from .analyzer import analyze, Analyzer
    from .semantics.intent_detector import create_intent_aware_filter, IntentDetector
    from .semantics.ast_guard_analysis import SafetyAnalyzer

    print(f"Analyzing: {args.target}")
    print()
    
    # Run analysis
    # Determine if intent filtering is enabled
    use_intent_filter = args.intent_filter and not args.no_intent_filter
    
    if args.interprocedural:
        # Interprocedural analysis mode with call graph and summaries
        # Use InterproceduralBugTracker with intent filtering
        from .semantics.interprocedural_bugs import InterproceduralBugTracker
        
        root_path = args.target if args.target.is_dir() else args.target.parent
        
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
        results = analyzer.analyze_all_functions(args.target)
        
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
        func_results = analyzer.analyze_function_entry_points(args.target, skip_module_level=False)
        
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
            result = analyzer.analyze_file_kitchensink(args.target)
        else:
            result = analyze(
                args.target,
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


def _analyze_project(args):
    """
    Full project analysis pipeline.

    1. Build call graph from directory
    2. Compute crash summaries (bytecode-level)
    3. Build code objects for DSE
    4. Run enhanced barrier certificates (Patterns 1-10)
    5. DSE confirmation on surviving candidates
    6. Report results
    """
    import time
    import pickle
    import logging
    from collections import Counter

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    project_path = args.target.resolve()
    project_name = project_path.name

    print("=" * 70)
    print(f"  PythonFromScratch — Full Project Analysis")
    print(f"  Target: {project_path}")
    print("=" * 70)
    print()

    # ── Step 1: Build call graph ─────────────────────────────────────────
    print("=" * 70)
    print("STEP 1: BUILDING CALL GRAPH")
    print("=" * 70)

    from .cfg.call_graph import build_call_graph_from_directory

    t0 = time.time()
    call_graph = build_call_graph_from_directory(project_path)
    n_funcs = len(call_graph.functions)
    print(f"  Functions: {n_funcs}  ({time.time() - t0:.1f}s)")

    # ── Step 2: Crash summaries ──────────────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 2: COMPUTING CRASH SUMMARIES")
    print("=" * 70)

    from .semantics.crash_summaries import BytecodeCrashSummaryComputer

    t1 = time.time()
    computer = BytecodeCrashSummaryComputer(call_graph)
    summaries = computer.compute_all()
    print(f"  Summaries: {len(summaries)}  ({time.time() - t1:.1f}s)")

    # ── Step 3: Build code objects for DSE ───────────────────────────────
    print()
    print("=" * 70)
    print("STEP 3: BUILDING CODE OBJECTS FOR DSE")
    print("=" * 70)

    from .barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

    t2 = time.time()
    code_objects = EnhancedDeepBarrierTheoryEngine.build_code_objects_from_call_graph(call_graph)
    print(f"  Code objects: {len(code_objects)}  ({time.time() - t2:.1f}s)")

    # ── Step 4: Bug-type coverage ────────────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 4: BUG TYPE COVERAGE")
    print("=" * 70)

    trigger_types = Counter()
    for s in summaries.values():
        for bt in getattr(s, "may_trigger", set()):
            trigger_types[bt] += 1

    for bt, cnt in trigger_types.most_common():
        print(f"  {cnt:6d}  {bt}")

    # ── Step 5: Enhanced barriers + DSE ──────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 5: BARRIER CERTIFICATE + DSE ANALYSIS")
    print("=" * 70)

    engine = EnhancedDeepBarrierTheoryEngine(
        all_summaries=summaries,
        code_objects=code_objects,
    )

    total_bugs = 0
    fully_guarded = 0
    unguarded_bugs = []

    for func_name, summary in summaries.items():
        gc = getattr(summary, "guard_counts", {})
        gb = getattr(summary, "guarded_bugs", set())
        for bug_type, (guarded_count, total_count) in gc.items():
            total_bugs += 1
            if bug_type in gb:
                fully_guarded += 1
            else:
                unguarded_bugs.append((func_name, bug_type, summary))

    print(f"  Total bug instances:     {total_bugs}")
    print(f"  Fully guarded (guards):  {fully_guarded}")
    print(f"  Unguarded:               {len(unguarded_bugs)}")

    # Run barrier certificates on unguarded
    t3 = time.time()
    proven_fp = 0
    remaining = []
    barrier_counts = Counter()

    for func_name, bug_type, summary in unguarded_bugs:
        is_safe, cert = engine.verify_via_deep_barriers(bug_type, "<v>", summary)
        if is_safe:
            proven_fp += 1
            barrier_counts[cert.barrier_type.value] += 1
        else:
            remaining.append((func_name, bug_type, summary))

    grand_fp = fully_guarded + proven_fp
    elapsed = time.time() - t3

    print(f"\n  Barrier results ({elapsed:.1f}s):")
    print(f"    Proven FP:   {proven_fp}/{len(unguarded_bugs)}")
    print(f"    Remaining:   {len(remaining)}")
    print(f"\n  Barrier contributions:")
    for bt, cnt in sorted(barrier_counts.items(), key=lambda x: -x[1]):
        print(f"    {cnt:5d}  {bt}")

    # ── Step 6: DSE results ──────────────────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 6: DSE RESULTS")
    print("=" * 70)

    dse_results = engine.get_dse_results()
    dse_reachable = {k: v for k, v in dse_results.items() if v[0] == "reachable"}
    dse_unreachable = {k: v for k, v in dse_results.items() if v[0] == "unreachable"}
    dse_error = {k: v for k, v in dse_results.items() if v[0] == "error"}

    print(f"  DSE analysed:        {len(dse_results)}")
    print(f"  DSE confirmed FP:    {len(dse_unreachable)}")
    print(f"  DSE confirmed TP:    {len(dse_reachable)}")
    if dse_error:
        print(f"  DSE errors:          {len(dse_error)}")

    # ── Step 7: Categorise remaining ─────────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 7: TRUE POSITIVE CANDIDATES")
    print("=" * 70)

    remaining_types = Counter(bt for _, bt, _ in remaining)
    for bt, cnt in remaining_types.most_common():
        print(f"  {cnt:5d}  {bt}")

    # Separate production vs test code
    test_bugs = []
    prod_bugs = []
    for func_name, bug_type, summary in remaining:
        parts = func_name.split(".")
        is_test = (
            func_name.startswith("tests.")
            or "test_" in func_name
            or ".tests." in func_name
            or any(p.startswith("Test") for p in parts)
        )
        if is_test:
            test_bugs.append((func_name, bug_type, summary))
        else:
            prod_bugs.append((func_name, bug_type, summary))

    print(f"\n  Production code bugs:  {len(prod_bugs)}")
    print(f"  Test-only code bugs:   {len(test_bugs)}")

    if prod_bugs:
        print(f"\n  PRODUCTION BUGS TO INVESTIGATE:")
        for func_name, bug_type, summary in prod_bugs[:50]:
            gc = summary.guard_counts.get(bug_type, (0, 0))
            ug = gc[1] - gc[0]
            print(f"    {bug_type:15s} ({ug} unguarded) {func_name}")
        if len(prod_bugs) > 50:
            print(f"    ... and {len(prod_bugs) - 50} more")

    if dse_reachable:
        print(f"\n  TRUE POSITIVES (DSE-confirmed reachable):")
        for func_name, (status, bug_type, cex) in sorted(dse_reachable.items()):
            is_test = (
                func_name.startswith("tests.")
                or "test_" in func_name
                or ".tests." in func_name
            )
            marker = "  (test)" if is_test else "  ⚠️"
            print(f"   {marker} {bug_type} in {func_name}")

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Functions analysed:    {n_funcs}")
    print(f"  Total bug instances:   {total_bugs}")
    print(f"  Proven false positive: {grand_fp} ({100 * grand_fp / max(total_bugs, 1):.1f}%)")
    print(f"  DSE unreachable:       {len(dse_unreachable)}")
    print(f"  Remaining candidates:  {len(remaining)}")
    print(f"    Production:          {len(prod_bugs)}")
    print(f"    Test-only:           {len(test_bugs)}")
    print(f"  DSE-confirmed TPs:     {len(dse_reachable)}")
    print()

    # ── Save results ─────────────────────────────────────────────────────
    save_path = args.save_results
    if save_path is None:
        save_path = Path("results") / f"{project_name}_results.pkl"
    save_path.parent.mkdir(parents=True, exist_ok=True)

    results = {
        "project": str(project_path),
        "total_functions": n_funcs,
        "total_bugs": total_bugs,
        "fully_guarded": fully_guarded,
        "barrier_proven_fp": proven_fp,
        "grand_fp": grand_fp,
        "remaining_count": len(remaining),
        "remaining": [(fn, bt) for fn, bt, _ in remaining],
        "dse_reachable": {k: (v[0], v[1]) for k, v in dse_reachable.items()},
        "dse_unreachable": list(dse_unreachable.keys()),
        "prod_bugs": [(fn, bt) for fn, bt, _ in prod_bugs],
        "test_bugs": [(fn, bt) for fn, bt, _ in test_bugs],
    }
    with open(save_path, "wb") as f:
        pickle.dump(results, f)
    print(f"  Results saved to {save_path}")
    print()

    # Exit code: 1 if true positives found, 0 if clean
    return 1 if prod_bugs else 0


if __name__ == "__main__":
    sys.exit(main())

