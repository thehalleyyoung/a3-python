#!/usr/bin/env python3
"""
Tier 3 Stdlib Contract Expansion Rescan - Iteration 162

Rescan httpx and uvicorn after adding:
- typing.MutableMapping
- types.TracebackType
- contextlib.asynccontextmanager
- locals() builtin

Expected impact:
- httpx: -5 bugs (locals, asynccontextmanager, MutableMapping, 2x TracebackType)
- uvicorn: -2 bugs (2x TracebackType)
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
    
    # Filter out test/example files if needed
    main_files = [
        f for f in py_files
        if not any(part in f.parts for part in ["test", "tests", "example", "examples", "benchmark"])
    ]
    
    if max_files:
        main_files = main_files[:max_files]
    
    results = {
        "repo": repo_name,
        "scan_date": datetime.now().isoformat(),
        "iteration": 162,
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
                "output": result.stdout[:500],
            }
            
        except subprocess.TimeoutExpired:
            results["results"][str(rel_path)] = {
                "status": "TIMEOUT",
                "output": "Analysis timed out after 30s"
            }
        except Exception as e:
            results["results"][str(rel_path)] = {
                "status": "ERROR",
                "output": str(e)
            }
    
    # Calculate rates
    total = results["total_files"]
    results["bug_rate"] = results["bug_count"] / total if total > 0 else 0
    results["safe_rate"] = results["safe_count"] / total if total > 0 else 0
    
    return results

def main():
    print("Tier 3 Stdlib Contract Expansion Rescan - Iteration 162", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    
    # Scan httpx (23 files)
    print("\nScanning httpx...", file=sys.stderr)
    httpx_results = scan_repo("httpx", max_files=23)
    
    output_file = RESULTS_DIR / "httpx_iter162_rescan.json"
    with open(output_file, "w") as f:
        json.dump(httpx_results, f, indent=2)
    
    print(f"\nhttpx results:", file=sys.stderr)
    print(f"  Files: {httpx_results['total_files']}", file=sys.stderr)
    print(f"  BUG: {httpx_results['bug_count']} ({httpx_results['bug_rate']:.1%})", file=sys.stderr)
    print(f"  SAFE: {httpx_results['safe_count']} ({httpx_results['safe_rate']:.1%})", file=sys.stderr)
    
    # Scan uvicorn (41 files)
    print("\nScanning uvicorn...", file=sys.stderr)
    uvicorn_results = scan_repo("uvicorn", max_files=41)
    
    output_file = RESULTS_DIR / "uvicorn_iter162_rescan.json"
    with open(output_file, "w") as f:
        json.dump(uvicorn_results, f, indent=2)
    
    print(f"\nuvicorn results:", file=sys.stderr)
    print(f"  Files: {uvicorn_results['total_files']}", file=sys.stderr)
    print(f"  BUG: {uvicorn_results['bug_count']} ({uvicorn_results['bug_rate']:.1%})", file=sys.stderr)
    print(f"  SAFE: {uvicorn_results['safe_count']} ({uvicorn_results['safe_rate']:.1%})", file=sys.stderr)
    
    # Summary
    print("\n" + "=" * 60, file=sys.stderr)
    print("Summary:", file=sys.stderr)
    print(f"  httpx: {httpx_results['bug_count']} bugs (was 10 in iter 155)", file=sys.stderr)
    print(f"  uvicorn: {uvicorn_results['bug_count']} bugs (was 17 in iter 155)", file=sys.stderr)
    
    total_delta = (httpx_results['bug_count'] - 10) + (uvicorn_results['bug_count'] - 17)
    print(f"  Total delta: {total_delta}", file=sys.stderr)

if __name__ == "__main__":
    main()
