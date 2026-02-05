"""
Fast analysis of all repos using crash summaries (not full symbolic execution).

This uses the bytecode crash summary system which is much faster than
full symbolic execution but still provides interprocedural analysis.
"""

import sys
import time
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer


# Bug types to track
CRASH_TYPES = {
    'DIV_ZERO', 'NULL_PTR', 'BOUNDS', 'ASSERT_FAIL', 'TYPE_CONFUSION',
    'INTEGER_OVERFLOW', 'RECURSION_DEPTH', 'ITERATOR_INVALID',
    'VALUE_ERROR', 'RUNTIME_ERROR', 'FILE_NOT_FOUND', 'PERMISSION_ERROR',
    'NAME_ERROR', 'PANIC'
}

SECURITY_TYPES = {
    'SQL_INJECTION', 'COMMAND_INJECTION', 'CODE_INJECTION', 'PATH_INJECTION',
    'REFLECTED_XSS', 'SSRF', 'UNSAFE_DESERIALIZATION', 'XXE',
    'CLEARTEXT_LOGGING', 'CLEARTEXT_STORAGE'
}


@dataclass  
class RepoAnalysis:
    """Analysis result for a repo."""
    name: str
    num_functions: int = 0
    num_files: int = 0
    time_sec: float = 0.0
    
    # Intraprocedural bugs (may_trigger without considering guards)
    intra_bugs: Dict[str, int] = field(default_factory=Counter)
    intra_total: int = 0
    
    # Interprocedural bugs (may_trigger minus guarded_bugs)
    inter_bugs: Dict[str, int] = field(default_factory=Counter)
    inter_total: int = 0
    
    # Guarded bugs (FPs eliminated by interprocedural)
    guarded_bugs: Dict[str, int] = field(default_factory=Counter)
    guarded_total: int = 0
    
    # Sample locations
    samples: List[tuple] = field(default_factory=list)


def analyze_repo(repo_path: Path) -> RepoAnalysis:
    """Analyze a repo using crash summaries."""
    result = RepoAnalysis(name=repo_path.name)
    start = time.time()
    
    try:
        # Build call graph
        print(f"    Building call graph...", end="\r")
        cg = build_call_graph_from_directory(repo_path)
        result.num_functions = len(cg.functions)
        result.num_files = len(set(f.split(':')[0] for f in cg.functions.keys() if ':' in f))
        
        # Compute crash summaries
        print(f"    Computing summaries ({result.num_functions} functions)...", end="\r")
        computer = BytecodeCrashSummaryComputer(cg)
        summaries = computer.compute_all()
        
        # Analyze each function
        for func_name, summary in summaries.items():
            # Intraprocedural: all bugs the function may trigger
            for bug_type in summary.may_trigger:
                if bug_type in CRASH_TYPES or bug_type in SECURITY_TYPES:
                    result.intra_bugs[bug_type] += 1
                    result.intra_total += 1
            
            # Interprocedural: bugs minus guarded ones
            for bug_type in summary.may_trigger:
                if bug_type in CRASH_TYPES or bug_type in SECURITY_TYPES:
                    if bug_type not in summary.guarded_bugs:
                        result.inter_bugs[bug_type] += 1
                        result.inter_total += 1
                        
                        # Sample locations
                        if len(result.samples) < 20:
                            result.samples.append((func_name, bug_type))
            
            # Guarded bugs (FPs eliminated)
            for bug_type in summary.guarded_bugs:
                if bug_type in CRASH_TYPES or bug_type in SECURITY_TYPES:
                    result.guarded_bugs[bug_type] += 1
                    result.guarded_total += 1
        
    except Exception as e:
        print(f"    ERROR: {type(e).__name__}: {e}")
    
    result.time_sec = time.time() - start
    print(" " * 60, end="\r")
    return result


def main():
    base = Path("/Users/halleyyoung/Documents/PythonFromScratch/external_tools")
    
    repos = [
        "pygoat",       # Ground truth
        "Counterfit",
        "DebugPy",
        "FLAML",
        "GraphRAG", 
        "Guidance",
        "Presidio",
        "PromptFlow",
        "RDAgent",
        "RESTler",
        "DeepSpeed",
        "LightGBM",
        "MSTICPY",
        "ONNXRuntime",
        "Qlib",
        "SemanticKernel",
        "django",
        "Pyright",
    ]
    
    print("="*70)
    print("INTERPROCEDURAL vs INTRAPROCEDURAL - CRASH SUMMARY ANALYSIS")
    print("="*70)
    print(f"\nAnalyzing {len(repos)} repos using fast crash summaries\n")
    
    all_results = []
    
    for repo_name in repos:
        repo_path = base / repo_name
        if not repo_path.exists():
            print(f"⚠ {repo_name}: Not found")
            continue
        
        print(f"\n{'─'*50}")
        print(f"{repo_name}")
        print(f"{'─'*50}")
        
        result = analyze_repo(repo_path)
        all_results.append(result)
        
        print(f"  Functions: {result.num_functions}")
        print(f"  Time: {result.time_sec:.1f}s")
        print(f"  INTRA bugs: {result.intra_total}")
        print(f"  INTER bugs: {result.inter_total}")
        print(f"  Guarded (FP eliminated): {result.guarded_total}")
        
        if result.guarded_total > 0:
            reduction = 100 * result.guarded_total / max(result.intra_total, 1)
            print(f"  → FP Reduction: {reduction:.1f}%")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    total_intra = sum(r.intra_total for r in all_results)
    total_inter = sum(r.inter_total for r in all_results)
    total_guarded = sum(r.guarded_total for r in all_results)
    total_functions = sum(r.num_functions for r in all_results)
    total_time = sum(r.time_sec for r in all_results)
    
    print(f"\nTotal Functions Analyzed: {total_functions}")
    print(f"Total Analysis Time: {total_time:.1f}s")
    print(f"\nINTRA bugs (no cross-function context): {total_intra}")
    print(f"INTER bugs (with guarding analysis):    {total_inter}")
    print(f"Guarded/FP Eliminated:                  {total_guarded}")
    print(f"FP Reduction:                           {100*total_guarded/max(total_intra,1):.1f}%")
    
    # Bug types breakdown
    print("\n" + "-"*60)
    print("BUG TYPES BREAKDOWN")
    print("-"*60)
    
    intra_types = Counter()
    inter_types = Counter()
    guarded_types = Counter()
    
    for r in all_results:
        intra_types.update(r.intra_bugs)
        inter_types.update(r.inter_bugs)
        guarded_types.update(r.guarded_bugs)
    
    all_types = set(intra_types.keys()) | set(inter_types.keys())
    
    print(f"\n{'Bug Type':<30} {'INTRA':>8} {'INTER':>8} {'Guarded':>8} {'%FP':>6}")
    print("-"*65)
    
    for bt in sorted(all_types, key=lambda x: -intra_types.get(x, 0)):
        i = intra_types.get(bt, 0)
        j = inter_types.get(bt, 0)
        g = guarded_types.get(bt, 0)
        fp_pct = 100 * g / max(i, 1)
        print(f"{bt:<30} {i:>8} {j:>8} {g:>8} {fp_pct:>5.1f}%")
    
    # Per-repo breakdown
    print("\n" + "-"*60)
    print("PER-REPO BREAKDOWN")
    print("-"*60)
    
    print(f"\n{'Repo':<20} {'Funcs':>8} {'INTRA':>8} {'INTER':>8} {'%FP':>6} {'Time':>6}")
    print("-"*65)
    
    for r in sorted(all_results, key=lambda x: -x.intra_total):
        fp_pct = 100 * r.guarded_total / max(r.intra_total, 1)
        print(f"{r.name:<20} {r.num_functions:>8} {r.intra_total:>8} {r.inter_total:>8} {fp_pct:>5.1f}% {r.time_sec:>5.1f}s")
    
    # Sample bugs for manual inspection
    print("\n" + "="*70)
    print("SAMPLE BUGS FOR MANUAL INSPECTION")
    print("="*70)
    
    for r in all_results[:5]:
        if r.samples:
            print(f"\n{r.name} (INTER bugs - need manual review):")
            for func, bt in r.samples[:5]:
                # Shorten function name
                short = func if len(func) < 50 else func[:47] + "..."
                print(f"  [{bt}] {short}")


if __name__ == "__main__":
    main()
