#!/usr/bin/env python3
"""
Iteration 126: Investigate UNKNOWN results from Phase 2 tier 2 scan.

According to State.json iteration 124 rescan:
- black: 1 UNKNOWN file
- scikit-learn: 1 UNKNOWN file

Goal: Identify which files returned UNKNOWN and why (unimplemented opcode, recursion, size limit, etc.)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyfromscratch.analyzer import analyze
import json
from pathlib import Path

def scan_repo_for_unknown(repo_name, max_files=100):
    """Scan repo and return only UNKNOWN results with details."""
    repo_path = Path(f"results/public_repos/clones/{repo_name}")
    
    if not repo_path.exists():
        print(f"Repository {repo_name} not found at {repo_path}")
        return []
    
    py_files = sorted(repo_path.rglob("*.py"))[:max_files]
    print(f"Scanning {len(py_files)} files in {repo_name}...")
    
    unknown_results = []
    
    for i, file_path in enumerate(py_files, 1):
        try:
            result = analyze(file_path, verbose=False)
            
            if result.verdict == "UNKNOWN":
                unknown_results.append({
                    "file": str(file_path),
                    "verdict": result.verdict,
                    "summary": result.bugs if hasattr(result, 'bugs') else str(result),
                    "details": result.__dict__
                })
                print(f"[{i}/{len(py_files)}] UNKNOWN: {file_path}")
                print(f"  Summary: {result}")
            elif i % 10 == 0:
                print(f"[{i}/{len(py_files)}] Processed...")
                
        except Exception as e:
            print(f"[{i}/{len(py_files)}] ERROR in {file_path}: {e}")
    
    return unknown_results

def main():
    results = {
        "black": [],
        "scikit-learn": []
    }
    
    print("=" * 80)
    print("ITERATION 126: Investigating UNKNOWN results from Phase 2 tier 2 scan")
    print("=" * 80)
    print()
    
    for repo in ["black", "scikit-learn"]:
        print(f"\n{'=' * 80}")
        print(f"Repository: {repo}")
        print('=' * 80)
        
        unknown_files = scan_repo_for_unknown(repo, max_files=100)
        results[repo] = unknown_files
        
        print(f"\nSummary for {repo}:")
        print(f"  UNKNOWN files: {len(unknown_files)}")
        
        if unknown_files:
            print("\n  Files:")
            for item in unknown_files:
                print(f"    - {item['file']}")
                print(f"      Summary: {item.get('summary', 'N/A')}")
    
    # Save results
    output_file = "results/unknown_investigation_iter126.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n\nResults saved to: {output_file}")
    
    # Analysis summary
    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)
    
    total_unknown = sum(len(results[repo]) for repo in results)
    print(f"Total UNKNOWN files: {total_unknown}")
    
    if total_unknown == 0:
        print("\nNote: No UNKNOWN files found. Possible reasons:")
        print("  1. Phase 2 improvements eliminated the UNKNOWN results")
        print("  2. Files may have been filtered by module-init detection")
        print("  3. Repository structure changed")
    else:
        print("\nTrigger Analysis:")
        for repo, unknown_list in results.items():
            if unknown_list:
                print(f"\n{repo}:")
                for item in unknown_list:
                    details = item.get("details", {})
                    print(f"  {Path(item['file']).name}:")
                    
                    # Extract trigger reason from result
                    if "hit_path_limit" in str(details):
                        print("    Trigger: Path limit exceeded")
                    if "recursion" in str(details).lower():
                        print("    Trigger: Recursion detected")
                    if "unimplemented" in str(details).lower():
                        print("    Trigger: Unimplemented opcode")
                    if "too_large" in str(details).lower() or "size" in str(details).lower():
                        print("    Trigger: Function size limit")
                    
                    print(f"    Verdict: {item.get('verdict')}")
                    print(f"    Details keys: {list(details.keys()) if isinstance(details, dict) else 'N/A'}")

if __name__ == "__main__":
    main()
