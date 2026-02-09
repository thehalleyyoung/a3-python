#!/usr/bin/env python3
"""
Analyze all external repos using the PythonFromScratch API directly (no subprocess).
Output is written to results/analysis_log.txt and results/all_repos_summary.txt.
"""

import sys
import time
import pickle
import io
import os
from pathlib import Path
from collections import Counter
from contextlib import redirect_stdout, redirect_stderr

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

EXTERNAL = ROOT / "external_tools"
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

LOG_FILE = RESULTS_DIR / "analysis_log.txt"

# Map of repo name → Python source directory (relative to external_tools/<repo>/)
REPOS = {
    "Counterfit":     "counterfit",
    "DebugPy":        "src/debugpy",
    "DeepSpeed":      "deepspeed",
    "FLAML":          "flaml",
    "GraphRAG":       "graphrag",
    "Guidance":       "guidance",
    "LightGBM":       "python-package/lightgbm",
    "MSTICPY":        "msticpy",
    "ONNXRuntime":    "onnxruntime/python",
    "Presidio":       "presidio-analyzer/presidio_analyzer",
    "PromptFlow":     "src/promptflow/promptflow",
    "Qlib":           "qlib",
    "RDAgent":        "rdagent",
    "RESTler":        "restler",
    "SemanticKernel": "python/semantic_kernel",
    "django":         "django",
    "pygoat":         "pygoat",
}


def log(msg, logf):
    """Print and log simultaneously."""
    print(msg, flush=True)
    logf.write(msg + "\n")
    logf.flush()


def analyze_one_repo(repo_name, src_subdir, logf):
    """
    Run the full PythonFromScratch analysis pipeline on a single repo.
    Returns a result dict.
    """
    import logging
    logging.basicConfig(level=logging.WARNING)
    
    target = EXTERNAL / repo_name / src_subdir
    if not target.exists():
        log(f"  SKIPPED: directory not found: {target}", logf)
        return {
            "repo": repo_name,
            "status": "SKIPPED",
            "reason": f"Directory not found: {target}",
            "elapsed": 0,
        }

    save_path = RESULTS_DIR / f"{repo_name.lower()}_results.pkl"

    log(f"\n{'='*70}", logf)
    log(f"  ANALYZING: {repo_name}", logf)
    log(f"  Target:    {target}", logf)
    log(f"{'='*70}\n", logf)

    t0 = time.time()

    try:
        # Step 1: Build call graph
        log("STEP 1: BUILDING CALL GRAPH", logf)
        from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
        
        t1 = time.time()
        call_graph = build_call_graph_from_directory(target)
        n_funcs = len(call_graph.functions)
        log(f"  Functions: {n_funcs}  ({time.time() - t1:.1f}s)", logf)

        # Step 2: Crash summaries
        log("\nSTEP 2: COMPUTING CRASH SUMMARIES", logf)
        from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer

        t2 = time.time()
        computer = BytecodeCrashSummaryComputer(call_graph)
        summaries = computer.compute_all()
        log(f"  Summaries: {len(summaries)}  ({time.time() - t2:.1f}s)", logf)

        # Step 3: Build code objects for DSE
        log("\nSTEP 3: BUILDING CODE OBJECTS FOR DSE", logf)
        from pyfromscratch.barriers.enhanced_barrier_theory import EnhancedDeepBarrierTheoryEngine

        t3 = time.time()
        code_objects = EnhancedDeepBarrierTheoryEngine.build_code_objects_from_call_graph(call_graph)
        log(f"  Code objects: {len(code_objects)}  ({time.time() - t3:.1f}s)", logf)

        # Step 4: Bug-type coverage
        log("\nSTEP 4: BUG TYPE COVERAGE", logf)
        trigger_types = Counter()
        for s in summaries.values():
            for bt in getattr(s, "may_trigger", set()):
                trigger_types[bt] += 1
        for bt, cnt in trigger_types.most_common():
            log(f"  {cnt:6d}  {bt}", logf)

        # Step 5: Enhanced barriers + DSE
        log("\nSTEP 5: BARRIER CERTIFICATE + DSE ANALYSIS", logf)
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

        log(f"  Total bug instances:     {total_bugs}", logf)
        log(f"  Fully guarded (guards):  {fully_guarded}", logf)
        log(f"  Unguarded:               {len(unguarded_bugs)}", logf)

        # Run barrier certificates
        t4 = time.time()
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
        elapsed_barriers = time.time() - t4

        log(f"\n  Barrier results ({elapsed_barriers:.1f}s):", logf)
        log(f"    Proven FP:   {proven_fp}/{len(unguarded_bugs)}", logf)
        log(f"    Remaining:   {len(remaining)}", logf)

        # Step 6: DSE results
        log("\nSTEP 6: DSE RESULTS", logf)
        dse_results = engine.get_dse_results()
        dse_reachable = {k: v for k, v in dse_results.items() if v[0] == "reachable"}
        dse_unreachable = {k: v for k, v in dse_results.items() if v[0] == "unreachable"}

        log(f"  DSE analysed:        {len(dse_results)}", logf)
        log(f"  DSE confirmed FP:    {len(dse_unreachable)}", logf)
        log(f"  DSE confirmed TP:    {len(dse_reachable)}", logf)

        # Step 7: Categorise
        log("\nSTEP 7: TRUE POSITIVE CANDIDATES", logf)
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

        log(f"  Production code bugs:  {len(prod_bugs)}", logf)
        log(f"  Test-only code bugs:   {len(test_bugs)}", logf)

        if dse_reachable:
            log(f"\n  TRUE POSITIVES (DSE-confirmed reachable):", logf)
            for func_name, (status, bug_type, cex) in sorted(dse_reachable.items()):
                is_test = (
                    func_name.startswith("tests.") or "test_" in func_name or ".tests." in func_name
                )
                marker = "  (test)" if is_test else "  ⚠️"
                log(f"   {marker} {bug_type} in {func_name}", logf)

        # Summary
        fp_pct = 100.0 * grand_fp / max(total_bugs, 1)
        log(f"\nSUMMARY", logf)
        log(f"  Functions analysed:    {n_funcs}", logf)
        log(f"  Total bug instances:   {total_bugs}", logf)
        log(f"  Proven false positive: {grand_fp} ({fp_pct:.1f}%)", logf)
        log(f"  Remaining candidates:  {len(remaining)}", logf)
        log(f"  DSE-confirmed TPs:     {len(dse_reachable)}", logf)

        elapsed = time.time() - t0
        log(f"  Time:                  {elapsed:.1f}s", logf)

        # Save pickle
        results = {
            "project": str(target),
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
        log(f"  Results saved to {save_path}", logf)

        return {
            "repo": repo_name,
            "status": "OK",
            "elapsed": elapsed,
            "functions": n_funcs,
            "total_bugs": total_bugs,
            "grand_fp": grand_fp,
            "fp_pct": fp_pct,
            "remaining": len(remaining),
            "prod_bugs": len(prod_bugs),
            "test_bugs": len(test_bugs),
            "dse_tps": len(dse_reachable),
        }

    except Exception as e:
        elapsed = time.time() - t0
        import traceback
        tb = traceback.format_exc()
        log(f"  ERROR: {e}", logf)
        log(tb, logf)
        return {
            "repo": repo_name,
            "status": "ERROR",
            "elapsed": elapsed,
            "error": str(e),
        }


def main():
    with open(LOG_FILE, "w") as logf:
        log("PythonFromScratch — External Repos Analysis", logf)
        log(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}", logf)
        log(f"Repos: {len(REPOS)}", logf)
        log("=" * 70, logf)

        all_results = []
        total_start = time.time()

        for repo_name, src_subdir in REPOS.items():
            result = analyze_one_repo(repo_name, src_subdir, logf)
            all_results.append(result)

        total_elapsed = time.time() - total_start

        # Grand summary
        log("\n" + "=" * 70, logf)
        log("  GRAND SUMMARY — ALL REPOS", logf)
        log("=" * 70, logf)

        header = f"{'Repo':<20s} {'Status':<8s} {'Time':>8s} {'Funcs':>7s} {'Bugs':>6s} {'FP%':>7s} {'Remain':>7s} {'TPs':>5s}"
        log(header, logf)
        log("-" * 70, logf)

        total_funcs = 0
        total_bugs_all = 0
        total_fp = 0
        total_remaining = 0
        total_tps = 0
        ok_count = 0

        for r in all_results:
            repo = r["repo"]
            status = r["status"]
            elapsed = f"{r['elapsed']:.1f}s"

            if status == "OK":
                ok_count += 1
                funcs = r["functions"]
                bugs = r["total_bugs"]
                fp_pct = f"{r['fp_pct']:.1f}%"
                remain = r["remaining"]
                tps = r["dse_tps"]

                total_funcs += funcs
                total_bugs_all += bugs
                total_fp += r["grand_fp"]
                total_remaining += remain
                total_tps += tps

                line = f"{repo:<20s} {status:<8s} {elapsed:>8s} {funcs:>7d} {bugs:>6d} {fp_pct:>7s} {remain:>7d} {tps:>5d}"
                log(line, logf)
            else:
                reason = r.get("error", r.get("reason", ""))[:30]
                line = f"{repo:<20s} {status:<8s} {elapsed:>8s} {'—':>7s} {'—':>6s} {'—':>7s} {'—':>7s} {'—':>5s}  {reason}"
                log(line, logf)

        log("-" * 70, logf)
        overall_fp_pct = 100.0 * total_fp / max(total_bugs_all, 1)
        log(f"{'TOTAL':<20s} {ok_count:>2d}/{len(REPOS):<4s} {total_elapsed:>7.0f}s {total_funcs:>7d} {total_bugs_all:>6d} {overall_fp_pct:>6.1f}% {total_remaining:>7d} {total_tps:>5d}", logf)
        log(f"\nTotal time: {total_elapsed:.1f}s ({total_elapsed/60:.1f} min)", logf)
        log(f"Results in: {RESULTS_DIR}/", logf)

        # Save structured summary
        summary_path = RESULTS_DIR / "all_repos_summary.txt"
        with open(summary_path, "w") as sf:
            sf.write("PythonFromScratch — External Repos Analysis Summary\n")
            sf.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            sf.write("=" * 70 + "\n\n")
            sf.write(header + "\n")
            sf.write("-" * 70 + "\n")
            for r in all_results:
                repo = r["repo"]
                status = r["status"]
                elapsed = f"{r['elapsed']:.1f}s"
                if status == "OK":
                    sf.write(f"{repo:<20s} {status:<8s} {elapsed:>8s} {r['functions']:>7d} {r['total_bugs']:>6d} {r['fp_pct']:>6.1f}% {r['remaining']:>7d} {r['dse_tps']:>5d}\n")
                else:
                    sf.write(f"{repo:<20s} {status:<8s} {elapsed:>8s}  {r.get('error', r.get('reason', ''))[:50]}\n")
            sf.write("-" * 70 + "\n")
            sf.write(f"TOTAL: {total_funcs} functions, {total_bugs_all} bugs, {overall_fp_pct:.1f}% FP, {total_remaining} remaining, {total_tps} DSE-TPs\n")
            sf.write(f"Time: {total_elapsed:.1f}s\n")

        log(f"\nSummary written to {summary_path}", logf)


if __name__ == "__main__":
    main()
