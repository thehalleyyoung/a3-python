#!/usr/bin/env python3
"""
CLI entrypoint for A³ analyzer.

Usage:
    # Legacy / direct scan (backward-compatible)
    a3 <target> [options]
    a3 myfile.py
    a3 path/to/project/

    # Subcommands (new)
    a3 scan <target> [options]    # analyse with --output-sarif
    a3 init <repo>                # bootstrap CI workflows
    a3 triage --sarif <file>       # LLM-classify findings
    a3 baseline diff --sarif <f>   # ratchet check
    a3 baseline accept --sarif <f> # update baseline

Returns:
    0: SAFE / no true positives found
    1: BUG / true positives found
    2: UNKNOWN
    3: Error
"""

import argparse
import os
import sys
from pathlib import Path


# ── Shared scan arguments (used by both legacy mode and "scan" subcommand) ───

def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    """Add all analysis flags to a parser (shared between legacy & scan)."""
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--no-kitchensink",
        action="store_true",
        help="Disable staged portfolio analysis (enabled by default)",
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
        help="Save results to a JSON file (default: results/<project>_results.json)",
    )
    parser.add_argument(
        "--output-sarif",
        type=Path,
        default=None,
        help="Write results as SARIF 2.1.0 JSON (for GitHub Code Scanning)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to .a3.yml config file (default: auto-detect in target dir)",
    )
    # ── Integrated triage (scan + triage in one command) ──────────────
    parser.add_argument(
        "--triage",
        nargs="?",
        const="auto",
        default=None,
        metavar="PROVIDER",
        help="Run LLM triage after scan (provider: openai, anthropic, github; default: auto-detect from env)",
    )
    parser.add_argument(
        "--triage-model",
        default=None,
        help="LLM model for triage (default: provider-appropriate model)",
    )
    parser.add_argument(
        "--triage-api-key",
        default=None,
        help="API key for triage (default: from env var)",
    )


def _apply_config_defaults(args: argparse.Namespace) -> None:
    """
    If a .a3.yml exists and no explicit flags override it,
    apply the config-file defaults to the args namespace.
    """
    from .ci.config import A3Config

    target = args.target.resolve() if hasattr(args, "target") else Path.cwd()
    config_root = target if target.is_dir() else target.parent

    if args.config:
        config_root = args.config.parent
    
    cfg = A3Config.load(config_root)

    # Only apply config defaults for flags that weren't explicitly set on CLI
    # We detect this by checking if the value is still the argparse default
    if not args.interprocedural and cfg.analysis.interprocedural:
        args.interprocedural = True
    # Kitchensink is now enabled by default
    if hasattr(args, 'no_kitchensink'):
        args.kitchensink = not args.no_kitchensink
    else:
        args.kitchensink = True
    if not args.dse_verify and cfg.analysis.dse_verify:
        args.dse_verify = True
    if not args.deduplicate and cfg.analysis.deduplicate:
        args.deduplicate = True
    if not args.no_intent_filter and cfg.analysis.no_intent_filter:
        args.no_intent_filter = True
    if args.min_confidence == 0.7 and cfg.analysis.min_confidence != 0.7:
        args.min_confidence = cfg.analysis.min_confidence
    if args.max_dse_steps == 100 and cfg.analysis.max_dse_steps != 100:
        args.max_dse_steps = cfg.analysis.max_dse_steps


# ── Subcommand handlers ─────────────────────────────────────────────────────

def _handle_scan(args: argparse.Namespace) -> int:
    """Handle ``a3 scan <target>``."""
    _apply_config_defaults(args)

    if not args.target.exists():
        print(f"Error: Target not found: {args.target}", file=sys.stderr)
        return 3

    if args.target.is_dir():
        return _analyze_project(args)
    return _analyze_file(args)


def _handle_init(args: argparse.Namespace) -> int:
    """Handle ``a3 init <repo>``."""
    from .ci.init_cmd import cmd_init
    return cmd_init(
        args.repo.resolve(),
        overwrite=args.overwrite,
        llm_triage=args.llm_triage,
        copilot=args.copilot,
    )


def _handle_triage(args: argparse.Namespace) -> int:
    """Handle ``a3 triage``."""
    from .ci.triage import cmd_triage

    # Resolve API key based on the chosen provider so we don't send the
    # wrong provider's key (e.g. OPENAI_API_KEY to GitHub Models).
    if args.api_key:
        api_key = args.api_key
    elif args.provider == "github":
        api_key = os.environ.get("GITHUB_TOKEN", "")
    elif args.provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY", "")
    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    return cmd_triage(
        sarif_path=args.sarif,
        output_sarif_path=args.output_sarif,
        repo_root=Path(args.repo_root).resolve() if args.repo_root else Path.cwd(),
        model=args.model,
        api_key=api_key,
        provider=args.provider,
        min_confidence=args.min_confidence,
        verbose=args.verbose,
    )


def _handle_baseline(args: argparse.Namespace) -> int:
    """Handle ``a3 baseline {diff,accept}``."""
    from .ci.baseline import cmd_baseline_diff, cmd_baseline_accept

    repo_root = Path(args.repo_root).resolve() if args.repo_root else Path.cwd()

    if args.baseline_action == "diff":
        return cmd_baseline_diff(
            args.sarif,
            repo_root,
            baseline_path=args.baseline_file,
            auto_issue=args.auto_issue,
        )
    elif args.baseline_action == "accept":
        return cmd_baseline_accept(
            args.sarif,
            repo_root,
            baseline_path=args.baseline_file,
        )
    else:
        print("Usage: a3 baseline {diff,accept} --sarif <file>", file=sys.stderr)
        return 3


# ── Main entry point ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="a3",
        description="A³: Python semantics + barrier-certificate verifier",
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── scan subcommand ──────────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run static analysis on a file or project",
    )
    scan_parser.add_argument(
        "target", type=Path,
        help="Python file or project directory to analyze",
    )
    _add_scan_arguments(scan_parser)

    # ── init subcommand ──────────────────────────────────────────────────
    init_parser = subparsers.add_parser(
        "init",
        help="Bootstrap CI workflows in a repository",
    )
    init_parser.add_argument(
        "repo", type=Path, nargs="?", default=Path("."),
        help="Repository root to initialise (default: current directory)",
    )
    init_parser.add_argument(
        "--overwrite", action="store_true",
        help="Overwrite existing workflow files",
    )
    init_parser.add_argument(
        "--llm-triage", action="store_true",
        help="Enable LLM triage in the generated config",
    )
    init_parser.add_argument(
        "--copilot", action="store_true",
        help="Enable triage via GitHub Copilot (uses GITHUB_TOKEN, no extra API keys)",
    )

    # ── triage subcommand ────────────────────────────────────────────────
    triage_parser = subparsers.add_parser(
        "triage",
        help="Classify findings via LLM to filter false positives",
    )
    triage_parser.add_argument(
        "--sarif", required=True,
        help="Path to SARIF file to triage",
    )
    triage_parser.add_argument(
        "--output-sarif", default=None,
        help="Path to write filtered SARIF (default: stdout)",
    )
    triage_parser.add_argument(
        "--repo-root", default=None,
        help="Repository root for source context (default: cwd)",
    )
    triage_parser.add_argument(
        "--model", default="claude-sonnet-4-20250514",
        help="LLM model to use (default: claude-sonnet-4-20250514)",
    )
    triage_parser.add_argument(
        "--provider", default="anthropic", choices=["anthropic", "openai", "github"],
        help="LLM provider: 'github' uses GITHUB_TOKEN with GitHub Models (default: anthropic)",
    )
    triage_parser.add_argument(
        "--api-key", default="",
        help="API key (default: from ANTHROPIC_API_KEY / OPENAI_API_KEY / GITHUB_TOKEN env var)",
    )
    triage_parser.add_argument(
        "--min-confidence", type=float, default=0.6,
        help="Minimum confidence to keep a TP (default: 0.6)",
    )
    triage_parser.add_argument(
        "--verbose", action="store_true",
        help="Print classification details for each finding",
    )

    # ── baseline subcommand ──────────────────────────────────────────────
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Manage the findings baseline (ratchet)",
    )
    baseline_parser.add_argument(
        "baseline_action", choices=["diff", "accept"],
        help="'diff' to check for new findings, 'accept' to update baseline",
    )
    baseline_parser.add_argument(
        "--sarif", required=True,
        help="Path to SARIF file",
    )
    baseline_parser.add_argument(
        "--repo-root", default=None,
        help="Repository root (default: cwd)",
    )
    baseline_parser.add_argument(
        "--baseline-file", default=None,
        help="Path to baseline JSON file (default: .a3-baseline.json)",
    )
    baseline_parser.add_argument(
        "--auto-issue", action="store_true",
        help="Automatically create GitHub issues for new findings (requires gh CLI)",
    )

    # ── Parse ────────────────────────────────────────────────────────────
    # First, try to detect if the user is using legacy (no-subcommand) syntax.
    # Legacy: a3 /some/path [--flags]
    # New:    a3 scan /some/path [--flags]
    #
    # We detect legacy mode when argv[1] is not a known subcommand and
    # looks like a path.
    known_subcommands = {"scan", "init", "triage", "baseline"}
    argv = sys.argv[1:]

    if argv and argv[0] not in known_subcommands and not argv[0].startswith("-"):
        # Legacy mode: prepend "scan" so the subparser picks it up
        argv = ["scan"] + argv

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    # Dispatch
    if args.command == "scan":
        return _handle_scan(args)
    elif args.command == "init":
        return _handle_init(args)
    elif args.command == "triage":
        return _handle_triage(args)
    elif args.command == "baseline":
        return _handle_baseline(args)
    else:
        parser.print_help()
        return 0


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
        
        # Only scan the specific file or directory provided, not the parent
        if args.target.is_file():
            # For single file, build tracker from just that file
            from .cfg.call_graph import build_call_graph_from_file
            from .semantics.crash_summaries import BytecodeCrashSummaryComputer, compute_all_bug_summaries
            from .semantics.summaries import SummaryComputer
            from .contracts.security_lattice import init_security_contracts, get_source_contracts_for_summaries, get_sink_contracts_for_summaries, get_sanitizer_contracts_for_summaries
            
            print(f"Building interprocedural analysis...")
            call_graph = build_call_graph_from_file(args.target, args.target.stem)
            
            # Initialize security contracts
            init_security_contracts()
            
            # All functions in the file are entry points and reachable
            all_functions = set(call_graph.functions.keys())
            
            # Compute taint summaries
            print(f"Computing taint summaries...")
            source_contracts = get_source_contracts_for_summaries()
            sink_contracts = get_sink_contracts_for_summaries()
            sanitizer_contracts = get_sanitizer_contracts_for_summaries()
            taint_computer = SummaryComputer(
                call_graph,
                source_contracts=source_contracts,
                sink_contracts=sink_contracts,
                sanitizer_contracts=sanitizer_contracts,
            )
            taint_summaries = taint_computer.compute_all()
            
            # Compute crash summaries (bytecode-level)
            print(f"Computing crash summaries...")
            crash_computer = BytecodeCrashSummaryComputer(call_graph)
            crash_summaries = crash_computer.compute_all()
            
            # Combine summaries
            combined_summaries = compute_all_bug_summaries(call_graph, taint_summaries)
            
            # Build tracker with computed summaries
            tracker = InterproceduralBugTracker(
                call_graph=call_graph,
                entry_points=all_functions,
                reachable_functions=all_functions,
                root_path=args.target.parent,
                taint_summaries=taint_summaries,
                crash_summaries=crash_summaries,
                combined_summaries=combined_summaries,
            )
        else:
            # For directory, scan the whole directory
            tracker = InterproceduralBugTracker.from_project(args.target)
        
        print(f"Functions: {len(tracker.call_graph.functions)}")
        print(f"Entry points: {len(tracker.entry_points)}")
        
        # Find bugs with FP reduction to filter out low-confidence false positives
        # Apply a low confidence threshold (0.15) to keep real bugs while filtering noise
        bugs = tracker.find_all_bugs(
            apply_fp_reduction=True,
            apply_intent_filter=use_intent_filter,
            intent_confidence=args.min_confidence,
            root_path=tracker.root_path,
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
        # Regular module-level analysis (kitchensink enabled by default)
        if args.kitchensink:
            analyzer = Analyzer(
                verbose=args.verbose,
                enable_concolic=not args.no_concolic,
                check_termination=args.check_termination,
                synthesize_invariants=args.synthesize_invariants,
            )
            result = analyzer.analyze_file_kitchensink(args.target)
        else:
            # Fallback to basic analysis only when explicitly disabled
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
    import json
    import logging
    from collections import Counter

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        # Silence chatty third-party HTTP loggers even in verbose mode
        for _noisy in ("httpx", "httpcore", "openai", "anthropic", "urllib3"):
            logging.getLogger(_noisy).setLevel(logging.WARNING)
    else:
        logging.basicConfig(level=logging.WARNING)

    project_path = args.target.resolve()
    project_name = project_path.name

    print("=" * 70)
    print(f"  A³ — Full Project Analysis")
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
        save_path = Path("results") / f"{project_name}_results.json"
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
        "dse_reachable_full": {k: (v[0], v[1], v[2]) for k, v in dse_reachable.items()},
        "dse_unreachable": list(dse_unreachable.keys()),
        "prod_bugs": [(fn, bt) for fn, bt, _ in prod_bugs],
        "test_bugs": [(fn, bt) for fn, bt, _ in test_bugs],
        # Rich data for SARIF (not serialised to JSON, only used in-memory)
        "_call_graph": call_graph,
        "_summaries": summaries,
    }

    # Save JSON results (strip non-serializable internal data)
    json_results = {k: v for k, v in results.items()
                    if not k.startswith("_") and k != "dse_reachable_full"}
    with open(save_path, "w") as f:
        json.dump(json_results, f, indent=2)
    print(f"  Results saved to {save_path}")

    # ── SARIF output (optional) ──────────────────────────────────────────
    sarif_path = getattr(args, "output_sarif", None)
    triage_flag = getattr(args, "triage", None)

    # If --triage is used without --output-sarif, auto-generate a temp SARIF path
    if triage_flag and not sarif_path:
        import tempfile
        sarif_path = Path(tempfile.mktemp(suffix=".sarif", prefix="a3_"))

    if sarif_path:
        from .ci.sarif import results_to_sarif, write_sarif
        sarif = results_to_sarif(results, project_path)
        write_sarif(sarif, sarif_path)
        n_sarif = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
        print(f"  SARIF written to {sarif_path}  ({n_sarif} findings)")

    # ── Integrated triage (optional) ─────────────────────────────────────
    if triage_flag and sarif_path:
        from .ci.triage import cmd_triage

        # Resolve provider
        if triage_flag == "auto":
            # Auto-detect from available env vars
            if os.environ.get("GITHUB_TOKEN"):
                provider = "github"
            elif os.environ.get("OPENAI_API_KEY"):
                provider = "openai"
            elif os.environ.get("ANTHROPIC_API_KEY"):
                provider = "anthropic"
            else:
                print("⚠️  --triage: no API key found in env (OPENAI_API_KEY, ANTHROPIC_API_KEY, GITHUB_TOKEN)", file=sys.stderr)
                print("   Skipping triage. Set an API key or pass --triage openai/anthropic/github", file=sys.stderr)
                return 1 if prod_bugs else 0
        else:
            provider = triage_flag

        # Resolve API key
        triage_api_key = getattr(args, "triage_api_key", None) or ""
        if not triage_api_key:
            if provider == "github":
                triage_api_key = os.environ.get("GITHUB_TOKEN", "")
            elif provider == "openai":
                triage_api_key = os.environ.get("OPENAI_API_KEY", "")
            else:
                triage_api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        triage_model = getattr(args, "triage_model", None) or "claude-sonnet-4-20250514"

        # Output triaged SARIF alongside the original
        triaged_path = str(sarif_path).replace(".sarif", "_triaged.sarif")
        if triaged_path == str(sarif_path):
            triaged_path = str(sarif_path) + ".triaged"

        print()
        cmd_triage(
            sarif_path=str(sarif_path),
            output_sarif_path=triaged_path,
            repo_root=project_path,
            model=triage_model,
            api_key=triage_api_key,
            provider=provider,
            verbose=getattr(args, "verbose", False),
        )

        # Also write true_positives.md into the project's results/ directory
        tp_md_project = project_path / "results" / "true_positives.md"
        tp_md_temp = Path(triaged_path).with_suffix(".md")
        if tp_md_temp.exists():
            tp_md_project.parent.mkdir(parents=True, exist_ok=True)
            tp_md_project.write_text(tp_md_temp.read_text())
            print(f"📝  True positives report also saved to {tp_md_project}")

    print()

    # Exit code: 1 if true positives found, 0 if clean
    return 1 if prod_bugs else 0


if __name__ == "__main__":
    sys.exit(main())

