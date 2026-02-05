"""
Analyze all external Python repos - Simple version without complex timeouts.

Compares INTRA (analyze_file) vs INTER (analyze_file_kitchensink) modes.
"""

import sys
import time
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import traceback

sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.analyzer import Analyzer


@dataclass
class RepoResult:
    """Results from analyzing a repo."""
    repo_name: str
    mode: str
    time_sec: float = 0.0
    total_bugs: int = 0
    bugs_by_type: Dict[str, int] = field(default_factory=Counter)
    proofs_found: int = 0
    files_analyzed: int = 0
    files_with_bugs: int = 0
    files_error: int = 0
    bug_locations: List[Tuple[str, str, int]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def analyze_single_file_intra(analyzer: Analyzer, py_file: Path, repo_path: Path) -> dict:
    """Analyze a single file in intraprocedural mode."""
    result = {"bugs": [], "proofs": 0, "error": None}
    try:
        analysis = analyzer.analyze_file(py_file)
        if analysis.verdict == "BUG":
            for bug in analysis.bugs:
                result["bugs"].append({
                    "file": str(py_file.relative_to(repo_path)),
                    "bug_type": bug.get("bug_type", "UNKNOWN"),
                    "line": bug.get("line", 0)
                })
        if analysis.per_bug_type:
            for info in analysis.per_bug_type.values():
                if info.get("verdict") == "SAFE":
                    result["proofs"] += 1
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:50]}"
    return result


def analyze_single_file_inter(analyzer: Analyzer, py_file: Path, repo_path: Path) -> dict:
    """Analyze a single file in interprocedural mode."""
    result = {"bugs": [], "proofs": 0, "error": None}
    try:
        analysis = analyzer.analyze_file_kitchensink(py_file)
        if analysis.verdict == "BUG":
            for bug in analysis.bugs:
                result["bugs"].append({
                    "file": str(py_file.relative_to(repo_path)),
                    "bug_type": bug.get("bug_type", "UNKNOWN"),
                    "line": bug.get("line", 0)
                })
        if analysis.per_bug_type:
            for info in analysis.per_bug_type.values():
                if info.get("verdict") == "SAFE":
                    result["proofs"] += 1
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:50]}"
    return result


def analyze_repo(repo_path: Path, mode: str, max_files: int = 100) -> RepoResult:
    """Analyze a repo in the given mode."""
    result = RepoResult(repo_name=repo_path.name, mode=mode)
    start = time.time()
    analyzer = Analyzer(verbose=False)
    
    # Get Python files, skip tests and pycache
    py_files = []
    for f in repo_path.rglob("*.py"):
        if "__pycache__" not in str(f) and "test" not in f.name.lower():
            py_files.append(f)
        if len(py_files) >= max_files:
            break
    
    result.files_analyzed = len(py_files)
    
    for i, py_file in enumerate(py_files):
        if i % 10 == 0:
            print(f"    [{i+1}/{len(py_files)}] {py_file.name[:25]}...", end="\r", flush=True)
        
        if mode == "intra":
            file_result = analyze_single_file_intra(analyzer, py_file, repo_path)
        else:
            file_result = analyze_single_file_inter(analyzer, py_file, repo_path)
        
        if file_result["error"]:
            result.files_error += 1
            result.errors.append(f"{py_file.name}: {file_result['error']}")
        elif file_result["bugs"]:
            result.files_with_bugs += 1
            for bug in file_result["bugs"]:
                result.bugs_by_type[bug["bug_type"]] += 1
                result.total_bugs += 1
                result.bug_locations.append((bug["file"], bug["bug_type"], bug["line"]))
        
        result.proofs_found += file_result["proofs"]
    
    print(" " * 60, end="\r")
    result.time_sec = time.time() - start
    return result


def main():
    base = Path("/Users/halleyyoung/Documents/PythonFromScratch/external_tools")
    
    repos = [
        "pygoat",       # Ground truth - known vulnerabilities
        "Counterfit",
        "DebugPy", 
        "FLAML",
        "GraphRAG",
        "Guidance",
        "Presidio",
        "PromptFlow",
        "RDAgent",
        "RESTler",
    ]
    
    max_files = 20  # Per repo - reduced for speed with full symbolic execution
    
    print("="*70)
    print("INTER vs INTRA ANALYSIS - ALL REPOS")
    print("="*70)
    print(f"\nAnalyzing {len(repos)} repos, {max_files} files each\n")
    
    all_intra = []
    all_inter = []
    
    for repo_name in repos:
        repo_path = base / repo_name
        if not repo_path.exists():
            print(f"⚠ {repo_name}: Not found")
            continue
        
        print(f"\n{'─'*50}")
        print(f"{repo_name}")
        print(f"{'─'*50}")
        
        # INTRA mode
        print("  INTRA mode...")
        try:
            intra = analyze_repo(repo_path, "intra", max_files)
            all_intra.append(intra)
            print(f"    Bugs: {intra.total_bugs}, Proofs: {intra.proofs_found}, Time: {intra.time_sec:.1f}s")
        except Exception as e:
            print(f"    ERROR: {e}")
            traceback.print_exc()
        
        # INTER mode  
        print("  INTER mode...")
        try:
            inter = analyze_repo(repo_path, "inter", max_files)
            all_inter.append(inter)
            print(f"    Bugs: {inter.total_bugs}, Proofs: {inter.proofs_found}, Time: {inter.time_sec:.1f}s")
        except Exception as e:
            print(f"    ERROR: {e}")
            traceback.print_exc()
        
        # Quick comparison
        if all_intra and all_inter and all_intra[-1].repo_name == all_inter[-1].repo_name:
            diff = all_intra[-1].total_bugs - all_inter[-1].total_bugs
            if diff > 0:
                print(f"  → FP reduction: {diff} fewer bugs with INTER")
            elif diff < 0:
                print(f"  → More bugs with INTER: {-diff}")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    total_intra_bugs = sum(r.total_bugs for r in all_intra)
    total_inter_bugs = sum(r.total_bugs for r in all_inter)
    total_intra_proofs = sum(r.proofs_found for r in all_intra)
    total_inter_proofs = sum(r.proofs_found for r in all_inter)
    
    print(f"\nTotal Bugs:   INTRA={total_intra_bugs}  INTER={total_inter_bugs}  Δ={total_intra_bugs - total_inter_bugs}")
    print(f"Total Proofs: INTRA={total_intra_proofs}  INTER={total_inter_proofs}  Δ={total_inter_proofs - total_intra_proofs}")
    
    # Bug types breakdown
    print("\n" + "-"*50)
    print("BUG TYPES")
    print("-"*50)
    
    intra_types = Counter()
    inter_types = Counter()
    for r in all_intra:
        intra_types.update(r.bugs_by_type)
    for r in all_inter:
        inter_types.update(r.bugs_by_type)
    
    all_types = set(intra_types.keys()) | set(inter_types.keys())
    print(f"\n{'Type':<35} {'INTRA':>6} {'INTER':>6} {'Δ':>6}")
    print("-"*55)
    for bt in sorted(all_types):
        i, j = intra_types.get(bt, 0), inter_types.get(bt, 0)
        print(f"{bt:<35} {i:>6} {j:>6} {i-j:>+6}")
    
    # Sample bugs for manual inspection
    print("\n" + "="*70)
    print("SAMPLE BUGS FOR MANUAL INSPECTION")
    print("="*70)
    
    for result in all_inter[:5]:
        if result.bug_locations:
            print(f"\n{result.repo_name}:")
            for file, bt, line in result.bug_locations[:5]:
                print(f"  [{bt}] {file}:{line}")


if __name__ == "__main__":
    main()
