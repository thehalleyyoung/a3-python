#!/usr/bin/env python3
"""
httpx Rescan - Iteration 163: POP_JUMP_IF_NOT_NONE + POP_JUMP_IF_NONE Fix

Rescan httpx after implementing Python 3.14 opcodes:
- POP_JUMP_IF_NOT_NONE (used in httpx/_decoders.py)
- POP_JUMP_IF_NONE (symmetric implementation)

Expected impact:
- httpx/_decoders.py: ERROR -> analyzed (BUG or SAFE)
- Iteration 155 baseline: 10 bugs (43.5% rate)
- Iteration 162 baseline: 4 bugs (17.4% rate) post stdlib contracts
- Expected: Stable or further reduction if _decoders.py was in sample
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REPOS_DIR = Path("results/public_repos/clones")
RESULTS_DIR = Path("results/public_repos")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def scan_repo(repo_name: str, max_files: int = None):
    """Run scanner on a repository."""
    repo_path = REPOS_DIR / repo_name
    
    # Get all Python files
    py_files = sorted(repo_path.rglob("*.py"))
    
    # Filter out test/example files
    main_files = [
        f for f in py_files
        if not any(part in f.parts for part in ["test", "tests", "example", "examples", "benchmark"])
    ]
    
    if max_files:
        main_files = main_files[:max_files]
    
    results = {
        "repo": repo_name,
        "scan_date": datetime.now().isoformat(),
        "iteration": 163,
        "total_files": len(main_files),
        "results": {},
        "bug_count": 0,
        "safe_count": 0,
        "unknown_count": 0,
        "error_count": 0,
    }
    
    for i, file_path in enumerate(main_files, 1):
        rel_path = file_path.relative_to(repo_path)
        print(f"  [{i}/{len(main_files)}] {rel_path}", file=sys.stderr)
        
        try:
            result = subprocess.run(
                ["python3", "-m", "pyfromscratch.cli", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if "BUG:" in result.stdout:
                status = "BUG"
                results["bug_count"] += 1
            elif "SAFE:" in result.stdout:
                status = "SAFE"
                results["safe_count"] += 1
            elif "UNKNOWN:" in result.stdout:
                status = "UNKNOWN"
                results["unknown_count"] += 1
            else:
                status = "ERROR"
                results["error_count"] += 1
            
            results["results"][str(rel_path)] = {
                "status": status,
                "stdout": result.stdout[:500],
                "stderr": result.stderr[:500] if result.stderr else "",
            }
            
        except subprocess.TimeoutExpired:
            print("    TIMEOUT", file=sys.stderr)
            results["results"][str(rel_path)] = {
                "status": "TIMEOUT",
                "stdout": "",
                "stderr": "Timeout after 30s",
            }
            results["error_count"] += 1
        except Exception as e:
            print(f"    ERROR: {e}", file=sys.stderr)
            results["results"][str(rel_path)] = {
                "status": "ERROR",
                "stdout": "",
                "stderr": str(e),
            }
            results["error_count"] += 1
    
    return results

def main():
    print("=== httpx Rescan - Iteration 163: POP_JUMP_IF_NOT_NONE Fix ===", file=sys.stderr)
    print(f"Scan started: {datetime.now().isoformat()}", file=sys.stderr)
    print("", file=sys.stderr)
    
    # Scan httpx (same 23 files as iteration 155)
    print("Scanning httpx (23 files)...", file=sys.stderr)
    httpx_results = scan_repo("httpx", max_files=23)
    
    # Save results
    output_file = RESULTS_DIR / "httpx_rescan_iter163_pop_jump_fix.json"
    with open(output_file, "w") as f:
        json.dump(httpx_results, f, indent=2)
    
    print("", file=sys.stderr)
    print("=== Summary ===", file=sys.stderr)
    print(f"httpx: {httpx_results['bug_count']} BUG, {httpx_results['safe_count']} SAFE, "
          f"{httpx_results['unknown_count']} UNKNOWN, {httpx_results['error_count']} ERROR", file=sys.stderr)
    
    # Comparison with iteration 162
    print("", file=sys.stderr)
    print("=== Comparison ===", file=sys.stderr)
    print("Iteration 155 (pre stdlib contracts): 10 bugs (43.5%)", file=sys.stderr)
    print("Iteration 162 (post stdlib contracts): 4 bugs (17.4%)", file=sys.stderr)
    print(f"Iteration 163 (post POP_JUMP_IF_NOT_NONE): {httpx_results['bug_count']} bugs ({httpx_results['bug_count']/httpx_results['total_files']*100:.1f}%)", file=sys.stderr)
    
    bug_delta_162 = httpx_results['bug_count'] - 4
    print(f"Delta from iter 162: {bug_delta_162:+d} bugs", file=sys.stderr)
    
    print("", file=sys.stderr)
    print(f"Results saved to: {output_file}", file=sys.stderr)
    
    # Print summary JSON
    summary = {
        "iteration": 163,
        "scan_date": httpx_results["scan_date"],
        "httpx": {
            "files": httpx_results["total_files"],
            "bug": httpx_results["bug_count"],
            "safe": httpx_results["safe_count"],
            "unknown": httpx_results["unknown_count"],
            "error": httpx_results["error_count"],
            "bug_rate": httpx_results["bug_count"] / httpx_results["total_files"],
        },
        "comparison_with_iter162": {
            "iter162_bugs": 4,
            "iter163_bugs": httpx_results["bug_count"],
            "bug_delta": bug_delta_162,
        }
    }
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
