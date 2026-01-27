#!/usr/bin/env python3
"""
Iteration 168: Rescan httpx after adding chr and setattr builtins.

Goal: Verify the 2 remaining bugs from iteration 167 are eliminated.

Previous state (iter 167):
- Total bugs: 2
- Bug rate: 8.7%
- Both are PANIC (NameError on chr, setattr)
- 100% validation rate

Expected after adding chr and setattr:
- Total bugs: 0
- Bug rate: 0%
- SAFE rate: 100%
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
        "iteration": 168,
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
                "output": "Analysis timed out after 30s",
            }
            results["error_count"] += 1
        except Exception as e:
            results["results"][str(rel_path)] = {
                "status": "ERROR",
                "output": str(e),
            }
            results["error_count"] += 1
    
    return results

def main():
    print("="*80, file=sys.stderr)
    print("Iteration 168: httpx rescan after chr/setattr builtin addition", file=sys.stderr)
    print("="*80, file=sys.stderr)
    
    results = scan_repo("httpx", max_files=23)
    
    # Save results
    output_file = RESULTS_DIR / "httpx_iter168_chr_setattr.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_file}", file=sys.stderr)
    
    # Print summary
    print("\n" + "="*80, file=sys.stderr)
    print("SUMMARY", file=sys.stderr)
    print("="*80, file=sys.stderr)
    
    total = results["total_files"]
    bugs = results["bug_count"]
    safe = results["safe_count"]
    unknown = results["unknown_count"]
    errors = results["error_count"]
    
    print(f"Total files: {total}", file=sys.stderr)
    print(f"BUG: {bugs} ({bugs/total*100:.1f}%)", file=sys.stderr)
    print(f"SAFE: {safe} ({safe/total*100:.1f}%)", file=sys.stderr)
    print(f"UNKNOWN: {unknown} ({unknown/total*100:.1f}%)", file=sys.stderr)
    print(f"ERROR: {errors} ({errors/total*100:.1f}%)", file=sys.stderr)
    
    print("\n" + "="*80, file=sys.stderr)
    print("COMPARISON WITH ITERATION 167", file=sys.stderr)
    print("="*80, file=sys.stderr)
    print("Iteration 167: 2 bugs (8.7%), 21 SAFE (91.3%)", file=sys.stderr)
    print(f"Iteration 168: {bugs} bugs ({bugs/23*100:.1f}%), {safe} SAFE ({safe/23*100:.1f}%)", file=sys.stderr)
    print(f"Bug reduction: {2 - bugs} ({(2-bugs)/2*100:.1f}%)", file=sys.stderr)
    
    if bugs == 0:
        print("\n✓ SUCCESS: All bugs eliminated via chr/setattr builtin addition!", file=sys.stderr)
        print("✓ httpx now 100% SAFE - semantic completeness improvement validated", file=sys.stderr)
    elif bugs < 2:
        print(f"\n✓ PARTIAL SUCCESS: {2-bugs}/2 bugs eliminated", file=sys.stderr)
        print("⚠ Remaining bugs need investigation", file=sys.stderr)
    else:
        print("\n⚠ UNEXPECTED: Bug count did not decrease", file=sys.stderr)
        print("⚠ Manual investigation required", file=sys.stderr)
    
    # Print to stdout for capture
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
