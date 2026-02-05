"""
Compare Interprocedural vs Intraprocedural Analysis on External Python Repos.

This script runs both modes on each repo and compares:
- Total bugs found
- Bugs by type
- FP reduction from kitchensink proofs
- Per-bug-type verdicts

ITERATION 701: Testing the new semantic bug types (24 types) along with
the existing exception (17), security (47), and core (20) bug types.
"""

import sys
import time
import signal
from pathlib import Path
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
import traceback
from contextlib import contextmanager

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.analyzer import Analyzer


class TimeoutError(Exception):
    pass


@contextmanager
def timeout(seconds):
    """Context manager for timing out operations."""
    def signal_handler(signum, frame):
        raise TimeoutError(f"Timed out after {seconds}s")
    
    # Set the signal handler
    old_handler = signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


@dataclass
class RepoAnalysisResult:
    """Results from analyzing a repo in one mode."""
    repo_name: str
    mode: str  # "intra" or "inter"
    
    # Timing
    analysis_time_sec: float = 0.0
    
    # Bug counts
    total_bugs: int = 0
    bugs_by_type: Dict[str, int] = field(default_factory=Counter)
    
    # FP reduction
    proofs_found: int = 0
    proofs_by_source: Dict[str, int] = field(default_factory=Counter)
    
    # Per-file results
    files_analyzed: int = 0
    files_with_bugs: int = 0
    files_safe: int = 0
    files_error: int = 0
    
    # Detailed bug locations
    bug_locations: List[Tuple[str, str, int]] = field(default_factory=list)  # (file, bug_type, line)
    
    # Errors
    errors: List[str] = field(default_factory=list)


def analyze_repo_intra(repo_path: Path, max_files: int = 50, file_timeout: int = 10) -> RepoAnalysisResult:
    """Analyze repo in intraprocedural mode (per-file)."""
    result = RepoAnalysisResult(
        repo_name=repo_path.name,
        mode="intra"
    )
    
    start_time = time.time()
    analyzer = Analyzer(verbose=False)
    
    # Find Python files
    py_files = list(repo_path.rglob("*.py"))[:max_files]
    result.files_analyzed = len(py_files)
    
    for i, py_file in enumerate(py_files):
        try:
            # Skip test files and __pycache__
            if "__pycache__" in str(py_file) or "test" in py_file.name.lower():
                continue
            
            # Show progress
            if i % 5 == 0:
                print(f"      [{i+1}/{len(py_files)}] {py_file.name[:30]}...", end="\r")
            
            with timeout(file_timeout):
                analysis = analyzer.analyze_file(py_file)
            
            if analysis.verdict == "BUG":
                result.files_with_bugs += 1
                for bug in analysis.bugs:
                    bug_type = bug.get("bug_type", "UNKNOWN")
                    result.bugs_by_type[bug_type] += 1
                    result.total_bugs += 1
                    result.bug_locations.append((
                        str(py_file.relative_to(repo_path)),
                        bug_type,
                        bug.get("line", 0)
                    ))
            elif analysis.verdict == "SAFE":
                result.files_safe += 1
            
            # Count proofs if any
            if analysis.per_bug_type:
                for bug_type, info in analysis.per_bug_type.items():
                    if info.get("verdict") == "SAFE":
                        result.proofs_found += 1
                        source = info.get("source", "unknown")
                        result.proofs_by_source[source] += 1
        
        except TimeoutError:
            result.files_error += 1
            result.errors.append(f"{py_file.name}: Timeout")
        except Exception as e:
            result.files_error += 1
            result.errors.append(f"{py_file.name}: {type(e).__name__}")
    
    print(" " * 60, end="\r")  # Clear progress line
    result.analysis_time_sec = time.time() - start_time
    return result


def analyze_repo_inter(repo_path: Path, max_files: int = 50, file_timeout: int = 30) -> RepoAnalysisResult:
    """Analyze repo in interprocedural mode (kitchensink with cross-file analysis)."""
    result = RepoAnalysisResult(
        repo_name=repo_path.name,
        mode="inter"
    )
    
    start_time = time.time()
    analyzer = Analyzer(verbose=False)
    
    # Find Python files
    py_files = list(repo_path.rglob("*.py"))[:max_files]
    result.files_analyzed = len(py_files)
    
    for i, py_file in enumerate(py_files):
        try:
            # Skip test files and __pycache__
            if "__pycache__" in str(py_file) or "test" in py_file.name.lower():
                continue
            
            # Show progress
            if i % 3 == 0:
                print(f"      [{i+1}/{len(py_files)}] {py_file.name[:30]}...", end="\r")
            
            # Use kitchensink mode for interprocedural analysis with timeout
            with timeout(file_timeout):
                analysis = analyzer.analyze_file_kitchensink(py_file)
            
            if analysis.verdict == "BUG":
                result.files_with_bugs += 1
                for bug in analysis.bugs:
                    bug_type = bug.get("bug_type", "UNKNOWN")
                    result.bugs_by_type[bug_type] += 1
                    result.total_bugs += 1
                    result.bug_locations.append((
                        str(py_file.relative_to(repo_path)),
                        bug_type,
                        bug.get("line", 0)
                    ))
            elif analysis.verdict == "SAFE":
                result.files_safe += 1
            
            # Count proofs
            if analysis.per_bug_type:
                for bug_type, info in analysis.per_bug_type.items():
                    if info.get("verdict") == "SAFE":
                        result.proofs_found += 1
                        source = info.get("source", "unknown")
                        result.proofs_by_source[source] += 1
        
        except TimeoutError:
            result.files_error += 1
            result.errors.append(f"{py_file.name}: Timeout")
        except Exception as e:
            result.files_error += 1
            result.errors.append(f"{py_file.name}: {type(e).__name__}")
    
    print(" " * 60, end="\r")  # Clear progress line
    result.analysis_time_sec = time.time() - start_time
    return result


def compare_results(intra: RepoAnalysisResult, inter: RepoAnalysisResult) -> Dict:
    """Compare intra vs inter results."""
    comparison = {
        "repo": intra.repo_name,
        "intra_bugs": intra.total_bugs,
        "inter_bugs": inter.total_bugs,
        "bug_reduction": intra.total_bugs - inter.total_bugs,
        "intra_proofs": intra.proofs_found,
        "inter_proofs": inter.proofs_found,
        "proof_increase": inter.proofs_found - intra.proofs_found,
        "intra_time": intra.analysis_time_sec,
        "inter_time": inter.analysis_time_sec,
        "time_ratio": inter.analysis_time_sec / max(intra.analysis_time_sec, 0.001),
    }
    
    # Find bugs only in intra (FPs eliminated by inter)
    intra_only_bugs = set(intra.bugs_by_type.keys()) - set(inter.bugs_by_type.keys())
    comparison["fps_eliminated"] = list(intra_only_bugs)
    
    # Find bugs only in inter (TPs found by inter)
    inter_only_bugs = set(inter.bugs_by_type.keys()) - set(intra.bugs_by_type.keys())
    comparison["tps_found"] = list(inter_only_bugs)
    
    return comparison


def print_result(result: RepoAnalysisResult):
    """Print analysis result summary."""
    print(f"\n{'='*60}")
    print(f"{result.repo_name} - {result.mode.upper()} MODE")
    print(f"{'='*60}")
    print(f"Files: {result.files_analyzed} analyzed, {result.files_with_bugs} with bugs, {result.files_safe} safe, {result.files_error} errors")
    print(f"Time: {result.analysis_time_sec:.2f}s")
    print(f"\nBugs Found: {result.total_bugs}")
    
    if result.bugs_by_type:
        print("\n  By Type:")
        for bug_type, count in sorted(result.bugs_by_type.items(), key=lambda x: -x[1])[:10]:
            print(f"    {bug_type}: {count}")
    
    print(f"\nProofs Found: {result.proofs_found}")
    if result.proofs_by_source:
        print("\n  By Source:")
        for source, count in sorted(result.proofs_by_source.items(), key=lambda x: -x[1])[:5]:
            print(f"    {source}: {count}")
    
    if result.errors:
        print(f"\nErrors ({len(result.errors)}):")
        for err in result.errors[:5]:
            print(f"    {err}")


def main():
    base_path = Path("/Users/halleyyoung/Documents/PythonFromScratch/external_tools")
    
    # All repos to analyze
    repos = [
        "pygoat",      # Known vulnerable (ground truth)
        "Counterfit",
        "DebugPy",
        "DeepSpeed",
        "FLAML",
        "GraphRAG",
        "Guidance",
        "LightGBM",
        "MSTICPY",
        "ONNXRuntime",
        "Presidio",
        "PromptFlow",
        "Pyright",
        "Qlib",
        "RDAgent",
        "RESTler",
        "SemanticKernel",
        "django",
    ]
    
    max_files = 500  # Analyze all files (high limit)
    
    all_comparisons = []
    all_intra = []
    all_inter = []
    
    print("="*70)
    print("INTERPROCEDURAL vs INTRAPROCEDURAL ANALYSIS COMPARISON")
    print("="*70)
    print(f"\nAnalyzing {len(repos)} repos COMPLETELY (max {max_files} files each)...")
    print(f"Timeouts: INTRA=10s/file, INTER=30s/file\n")
    
    for repo_name in repos:
        repo_path = base_path / repo_name
        if not repo_path.exists():
            print(f"⚠ {repo_name}: Not found, skipping")
            continue
        
        print(f"\n{'─'*60}")
        print(f"Analyzing {repo_name}...")
        print(f"{'─'*60}")
        
        try:
            # Run intraprocedural
            print("  Running INTRA mode...")
            intra = analyze_repo_intra(repo_path, max_files)
            all_intra.append(intra)
            print(f"    Found {intra.total_bugs} bugs, {intra.proofs_found} proofs in {intra.analysis_time_sec:.1f}s")
            
            # Run interprocedural
            print("  Running INTER mode...")
            inter = analyze_repo_inter(repo_path, max_files)
            all_inter.append(inter)
            print(f"    Found {inter.total_bugs} bugs, {inter.proofs_found} proofs in {inter.analysis_time_sec:.1f}s")
            
            # Compare
            comparison = compare_results(intra, inter)
            all_comparisons.append(comparison)
            
            if comparison["bug_reduction"] > 0:
                print(f"  ✓ FP REDUCTION: {comparison['bug_reduction']} fewer bugs with interprocedural")
            if comparison["proof_increase"] > 0:
                print(f"  ✓ MORE PROOFS: {comparison['proof_increase']} more proofs with interprocedural")
            if comparison["fps_eliminated"]:
                print(f"  ✓ FPs eliminated: {comparison['fps_eliminated']}")
            if comparison["tps_found"]:
                print(f"  ✓ TPs found: {comparison['tps_found']}")
                
        except Exception as e:
            print(f"  ✗ Error: {type(e).__name__}: {e}")
            traceback.print_exc()
    
    # Print summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    total_intra_bugs = sum(r.total_bugs for r in all_intra)
    total_inter_bugs = sum(r.total_bugs for r in all_inter)
    total_intra_proofs = sum(r.proofs_found for r in all_intra)
    total_inter_proofs = sum(r.proofs_found for r in all_inter)
    total_intra_time = sum(r.analysis_time_sec for r in all_intra)
    total_inter_time = sum(r.analysis_time_sec for r in all_inter)
    
    print(f"\nTotal Bugs:")
    print(f"  INTRA: {total_intra_bugs}")
    print(f"  INTER: {total_inter_bugs}")
    print(f"  REDUCTION: {total_intra_bugs - total_inter_bugs} ({100*(total_intra_bugs - total_inter_bugs)/max(total_intra_bugs,1):.1f}%)")
    
    print(f"\nTotal Proofs:")
    print(f"  INTRA: {total_intra_proofs}")
    print(f"  INTER: {total_inter_proofs}")
    print(f"  INCREASE: {total_inter_proofs - total_intra_proofs}")
    
    print(f"\nTotal Time:")
    print(f"  INTRA: {total_intra_time:.1f}s")
    print(f"  INTER: {total_inter_time:.1f}s")
    print(f"  RATIO: {total_inter_time/max(total_intra_time,0.001):.1f}x")
    
    # Aggregate bug types
    print("\n" + "-"*50)
    print("BUG TYPES COMPARISON")
    print("-"*50)
    
    intra_bug_types = Counter()
    inter_bug_types = Counter()
    for r in all_intra:
        intra_bug_types.update(r.bugs_by_type)
    for r in all_inter:
        inter_bug_types.update(r.bugs_by_type)
    
    all_types = set(intra_bug_types.keys()) | set(inter_bug_types.keys())
    print(f"\n{'Bug Type':<40} {'INTRA':>8} {'INTER':>8} {'DELTA':>8}")
    print("-"*70)
    for bug_type in sorted(all_types):
        intra_count = intra_bug_types.get(bug_type, 0)
        inter_count = inter_bug_types.get(bug_type, 0)
        delta = intra_count - inter_count
        delta_str = f"+{-delta}" if delta < 0 else f"-{delta}" if delta > 0 else "0"
        print(f"{bug_type:<40} {intra_count:>8} {inter_count:>8} {delta_str:>8}")
    
    # Print detailed bug locations for manual inspection
    print("\n" + "="*70)
    print("SAMPLE BUGS FOR MANUAL INSPECTION")
    print("="*70)
    
    for result in all_inter[:3]:  # First 3 repos
        if result.bug_locations:
            print(f"\n{result.repo_name}:")
            for file, bug_type, line in result.bug_locations[:5]:
                print(f"  [{bug_type}] {file}:{line}")


if __name__ == "__main__":
    main()
