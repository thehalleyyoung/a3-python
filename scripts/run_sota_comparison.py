#!/usr/bin/env python3
"""
Run SOTA/Kitchensink comparison on PyGoat and other repos.

This script compares:
1. Previous analysis results (baseline)
2. New SOTA-integrated analysis with unified synthesis engine

The goal is to see if the layered SOTA architecture improves:
- True positive detection
- False positive reduction  
- Verification confidence (SAFE proofs with barrier certificates)
"""

import json
import sys
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.analyzer import Analyzer, AnalysisResult
from pyfromscratch.semantics.interprocedural_bugs import analyze_file_for_bugs, InterproceduralBug


@dataclass
class ScanResult:
    """Result of scanning a file."""
    file: str
    bugs: List[Dict[str, Any]]
    safe_proofs: List[Dict[str, Any]]
    analysis_time_ms: float
    error: Optional[str] = None


def scan_file(filepath: Path, analyzer: Analyzer) -> ScanResult:
    """Scan a single file and return results."""
    start = time.time()
    bugs = []
    safe_proofs = []
    error = None
    
    try:
        # Run intraprocedural analysis
        result = analyzer.analyze_file(filepath)
        
        if result.verdict == "BUG":
            bugs.append({
                "bug_type": result.bug_type,
                "location": str(result.counterexample.get("location")) if result.counterexample else None,
                "message": result.message,
            })
        elif result.verdict == "SAFE":
            safe_proofs.append({
                "barrier": str(result.barrier) if result.barrier else None,
                "message": result.message,
            })
        
        # Run interprocedural security analysis
        try:
            interproc_bugs = analyze_file_for_bugs(filepath)
            for bug in interproc_bugs:
                bugs.append({
                    "bug_type": bug.bug_type,
                    "location": bug.crash_location,
                    "confidence": bug.confidence,
                    "call_chain": bug.call_chain,
                    "reason": bug.reason,
                })
        except Exception as e:
            pass  # Interprocedural is optional enhancement
            
    except Exception as e:
        error = str(e)
    
    elapsed_ms = (time.time() - start) * 1000
    
    return ScanResult(
        file=str(filepath),
        bugs=bugs,
        safe_proofs=safe_proofs,
        analysis_time_ms=elapsed_ms,
        error=error,
    )


def scan_project(project_dir: Path, file_patterns: List[str] = None) -> Dict[str, Any]:
    """Scan a project directory and return aggregated results."""
    
    # Find Python files
    python_files = list(project_dir.rglob("*.py"))
    
    # Filter out migrations, tests, __pycache__
    python_files = [
        f for f in python_files 
        if "migration" not in str(f) 
        and "__pycache__" not in str(f)
        and "test" not in f.stem.lower()
    ]
    
    # If specific patterns provided, filter further
    if file_patterns:
        filtered = []
        for pattern in file_patterns:
            filtered.extend([f for f in python_files if pattern in str(f)])
        python_files = list(set(filtered))
    
    print(f"Found {len(python_files)} Python files to analyze")
    
    # Create analyzer with SOTA integration
    analyzer = Analyzer(verbose=False)
    
    all_results = []
    all_bugs = []
    all_safe_proofs = []
    bug_type_counts = defaultdict(int)
    
    for i, filepath in enumerate(python_files):
        rel_path = filepath.relative_to(project_dir) if filepath.is_relative_to(project_dir) else filepath
        print(f"[{i+1}/{len(python_files)}] Analyzing {rel_path}...", end=" ", flush=True)
        
        result = scan_file(filepath, analyzer)
        all_results.append(result)
        
        if result.bugs:
            print(f"Found {len(result.bugs)} bugs")
            for bug in result.bugs:
                all_bugs.append({**bug, "file": str(rel_path)})
                bug_type_counts[bug.get("bug_type", "UNKNOWN")] += 1
        elif result.safe_proofs:
            print(f"SAFE ({len(result.safe_proofs)} proofs)")
            all_safe_proofs.extend(result.safe_proofs)
        elif result.error:
            print(f"Error: {result.error[:50]}...")
        else:
            print("No findings")
    
    return {
        "project": str(project_dir),
        "files_analyzed": len(python_files),
        "total_bugs": len(all_bugs),
        "total_safe_proofs": len(all_safe_proofs),
        "bug_type_counts": dict(bug_type_counts),
        "bugs": all_bugs,
        "safe_proofs": all_safe_proofs,
        "file_results": [asdict(r) for r in all_results],
    }


def compare_with_baseline(new_results: Dict, baseline_path: Path) -> Dict[str, Any]:
    """Compare new results with baseline and report differences."""
    
    if not baseline_path.exists():
        return {"error": f"Baseline not found: {baseline_path}"}
    
    with open(baseline_path) as f:
        baseline = json.load(f)
    
    # Extract bug sets for comparison
    new_bugs = set()
    for bug in new_results.get("bugs", []):
        key = (bug.get("bug_type"), bug.get("file"), bug.get("location"))
        new_bugs.add(key)
    
    baseline_bugs = set()
    for bug in baseline.get("bugs", []):
        key = (bug.get("bug_type"), bug.get("file"), bug.get("location"))
        baseline_bugs.add(key)
    
    new_only = new_bugs - baseline_bugs
    baseline_only = baseline_bugs - new_bugs
    common = new_bugs & baseline_bugs
    
    return {
        "baseline_total": len(baseline_bugs),
        "new_total": len(new_bugs),
        "common": len(common),
        "new_only": len(new_only),
        "baseline_only": len(baseline_only),
        "new_findings": [{"bug_type": k[0], "file": k[1], "location": k[2]} for k in new_only],
        "removed_findings": [{"bug_type": k[0], "file": k[1], "location": k[2]} for k in baseline_only],
    }


def main():
    """Main entry point."""
    
    print("=" * 70)
    print("SOTA/Kitchensink Architecture Comparison")
    print("=" * 70)
    print()
    
    # PyGoat - intentionally vulnerable Django app
    pygoat_dir = Path("external_tools/pygoat")
    
    if pygoat_dir.exists():
        print("### Scanning PyGoat (OWASP Vulnerable App) ###")
        print()
        
        # Scan key vulnerable files
        key_patterns = [
            "views.py",
            "utility.py",
            "mitre.py",
        ]
        
        start_time = time.time()
        results = scan_project(pygoat_dir, key_patterns)
        elapsed = time.time() - start_time
        
        print()
        print(f"### PyGoat Results ###")
        print(f"Files analyzed: {results['files_analyzed']}")
        print(f"Total bugs found: {results['total_bugs']}")
        print(f"Safe proofs: {results['total_safe_proofs']}")
        print(f"Analysis time: {elapsed:.1f}s")
        print()
        
        print("Bug type breakdown:")
        for bug_type, count in sorted(results["bug_type_counts"].items(), key=lambda x: -x[1]):
            print(f"  {bug_type}: {count}")
        
        # Save results
        output_path = Path("results/pygoat_sota_comparison.json")
        output_path.parent.mkdir(exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to: {output_path}")
        
        # Compare with baseline if available
        baseline_path = Path("results/pygoat-our-results-iter528.json")
        if baseline_path.exists():
            print("\n### Comparison with Iteration 528 Baseline ###")
            comparison = compare_with_baseline(results, baseline_path)
            print(f"Baseline bugs: {comparison.get('baseline_total', 'N/A')}")
            print(f"New bugs: {comparison.get('new_total', 'N/A')}")
            print(f"Common findings: {comparison.get('common', 'N/A')}")
            print(f"New only: {comparison.get('new_only', 'N/A')}")
            print(f"Removed (potential FP reduction): {comparison.get('baseline_only', 'N/A')}")
            
            if comparison.get("new_findings"):
                print("\nNew findings (potential new TPs):")
                for f in comparison["new_findings"][:10]:
                    print(f"  {f['bug_type']} in {f['file']}")
    else:
        print(f"PyGoat not found at {pygoat_dir}")
    
    print()
    print("=" * 70)
    print("Scan complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
