#!/usr/bin/env python3
"""
Script to run public repository evaluation.

Usage:
    python scripts/run_public_eval.py tier <1|2|3> [max_files] [--include-tests]
    python scripts/run_public_eval.py repo <repo_name> [max_files] [--include-tests]
    python scripts/run_public_eval.py list
"""

import sys
from pathlib import Path

# Add parent dir to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.evaluation.scanner import RepoScanner
from pyfromscratch.evaluation.repo_list import get_all_repos, get_tier


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "list":
        print("Available repositories:")
        print("\nTier 1 (Small to medium):")
        for repo in get_tier(1):
            print(f"  - {repo.name:20} {repo.description}")
        print("\nTier 2 (Larger, complex):")
        for repo in get_tier(2):
            print(f"  - {repo.name:20} {repo.description}")
        print("\nTier 3 (Specialist):")
        for repo in get_tier(3):
            print(f"  - {repo.name:20} {repo.description}")
        return
    
    # Parse exclude_tests flag (default: exclude tests)
    exclude_tests = "--include-tests" not in sys.argv
    
    if command == "tier":
        if len(sys.argv) < 3:
            print("Error: tier number required (1, 2, or 3)")
            sys.exit(1)
        
        tier = int(sys.argv[2])
        max_files = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "--include-tests" else 50
        
        print(f"Scanning tier {tier} repositories (max {max_files} files per repo)...")
        test_status = "excluding" if exclude_tests else "including"
        print(f"Test filtering: {test_status} test directories and files")
        scanner = RepoScanner()
        results = scanner.scan_tier(tier, max_files_per_repo=max_files, exclude_tests=exclude_tests)
        
        print("\n" + "="*60)
        print("TIER SCAN SUMMARY")
        print("="*60)
        for result in results:
            print(f"\n{result.repo_name}:")
            print(f"  Files analyzed: {result.analyzed_files}/{result.total_files}")
            print(f"  Findings: {result.summary}")
    
    elif command == "repo":
        if len(sys.argv) < 3:
            print("Error: repo name required")
            sys.exit(1)
        
        repo_name = sys.argv[2]
        max_files = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "--include-tests" else 50
        
        all_repos = get_all_repos()
        repo = next((r for r in all_repos if r.name == repo_name), None)
        if not repo:
            print(f"Unknown repository: {repo_name}")
            print(f"Available repos: {[r.name for r in all_repos]}")
            sys.exit(1)
        
        test_status = "excluding" if exclude_tests else "including"
        print(f"Scanning {repo.name} (max {max_files} files, {test_status} tests)...")
        scanner = RepoScanner()
        result = scanner.scan_repo(repo, max_files=max_files, exclude_tests=exclude_tests)
        
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Repository: {result.repo_name}")
        print(f"Files analyzed: {result.analyzed_files}/{result.total_files}")
        print(f"Findings: {result.summary}")
        print(f"\nDetailed results saved to: results/public_repos/scan_results/")
    
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
