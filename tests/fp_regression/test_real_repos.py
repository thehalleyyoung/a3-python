#!/usr/bin/env python3
"""
Test FP reduction on real Microsoft RISE repos.

This script analyzes repos with and without FP reduction,
showing the impact on finding counts and precision.
"""
import sys
import os
from pathlib import Path
from collections import Counter
import time

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker


REPOS_TO_TEST = [
    'py_synthetic/prog01_calculator',
    'py_synthetic/prog02_usermgmt',
    'py_synthetic/prog03_dataproc',
]

# Add real repos if available
REAL_REPOS = [
    'external_tools/FLAML',
    'external_tools/qlib',
    'external_tools/graphrag',
]


def analyze_repo(repo_path: Path, apply_fp_reduction: bool, timeout: int = 60) -> dict:
    """Analyze a repo and return results."""
    import signal
    
    class TimeoutError(Exception):
        pass
    
    def handler(signum, frame):
        raise TimeoutError("Analysis timed out")
    
    # Set timeout
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(timeout)
    
    try:
        tracker = InterproceduralBugTracker.from_project(repo_path)
        bugs = tracker.find_all_bugs(apply_fp_reduction=apply_fp_reduction)
        
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)  # Cancel timeout
        
        return {
            'bug_count': len(bugs),
            'types': dict(Counter(b.bug_type for b in bugs)),
            'bugs': bugs,
        }
    except TimeoutError:
        return {'bug_count': -1, 'types': {}, 'bugs': [], 'timeout': True}
    except Exception as e:
        return {'bug_count': -1, 'types': {}, 'bugs': [], 'error': str(e)}
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)


def main():
    print("=" * 70)
    print("FP Reduction Impact Test on Real Repos")
    print("=" * 70)
    
    all_repos = REPOS_TO_TEST + [r for r in REAL_REPOS if Path(r).exists()]
    
    print(f"\nRepos to test: {len(all_repos)}")
    
    for repo_rel in all_repos:
        repo_path = Path(repo_rel)
        if not repo_path.exists():
            continue
        
        print(f"\n{'=' * 50}")
        print(f"Repository: {repo_rel}")
        print(f"{'=' * 50}")
        
        # Without FP reduction
        print("\nAnalyzing without FP reduction...")
        start = time.time()
        result_raw = analyze_repo(repo_path, apply_fp_reduction=False, timeout=30)
        time_raw = time.time() - start
        
        if result_raw.get('timeout'):
            print(f"  TIMEOUT after {time_raw:.1f}s")
            continue
        elif result_raw.get('error'):
            print(f"  ERROR: {result_raw['error']}")
            continue
        
        print(f"  Found {result_raw['bug_count']} bugs in {time_raw:.1f}s")
        print(f"  Types: {result_raw['types']}")
        
        # With FP reduction
        print("\nAnalyzing with FP reduction...")
        start = time.time()
        result_fp = analyze_repo(repo_path, apply_fp_reduction=True, timeout=30)
        time_fp = time.time() - start
        
        if result_fp.get('timeout'):
            print(f"  TIMEOUT after {time_fp:.1f}s")
            continue
        elif result_fp.get('error'):
            print(f"  ERROR: {result_fp['error']}")
            continue
        
        print(f"  Found {result_fp['bug_count']} bugs in {time_fp:.1f}s")
        print(f"  Types: {result_fp['types']}")
        
        # Reduction summary
        if result_raw['bug_count'] > 0:
            reduction = 100 * (1 - result_fp['bug_count'] / result_raw['bug_count'])
            print(f"\n  FP Reduction: {result_raw['bug_count']} -> {result_fp['bug_count']} ({reduction:.1f}% reduction)")
        else:
            print(f"\n  No bugs found in raw analysis")
    
    print("\n" + "=" * 70)
    print("Done!")
    print("=" * 70)


if __name__ == "__main__":
    main()
