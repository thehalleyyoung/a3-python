#!/usr/bin/env python3
"""
Analyze all external repos for non-security bugs using interprocedural barrier analysis.

Non-security bug types:
- DIV_ZERO: Division by zero
- NULL_PTR: None/null dereference  
- BOUNDS: Array/index out of bounds
- TYPE_CONFUSION: Type errors
- PANIC: Unhandled exceptions
"""

import os
import sys
from pathlib import Path
from collections import defaultdict
import traceback

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.semantics.crash_summaries import CrashSummary, PreconditionType
from pyfromscratch.semantics.interprocedural_barriers import FunctionBarrierSynthesizer

NON_SECURITY_BUGS = {'DIV_ZERO', 'NULL_PTR', 'BOUNDS', 'TYPE_CONFUSION', 'PANIC'}

REPOS = [
    'Qlib',
    'LightGBM', 
    'DeepSpeed',
    'FLAML',
    'GraphRAG',
    'Guidance',
    'ONNXRuntime',
    'PromptFlow',
    'RDAgent',
    'Pyright',
    'MSTICPY',
    'Counterfit',
    'DebugPy',
    'RESTler',
    'SemanticKernel',
    'Presidio',
]

def find_python_dirs(repo_path: Path) -> list[Path]:
    """Find directories with Python files worth analyzing."""
    dirs = []
    # Look for common source directories
    for pattern in ['**/src', '**/lib', '**/core', '**/utils', '**/common', 
                    '**/backtest', '**/data', '**/model', '**/ops', '**/runtime']:
        for d in repo_path.glob(pattern):
            if d.is_dir() and any(d.glob('*.py')):
                dirs.append(d)
    
    # If no specific dirs found, try the root python files
    if not dirs:
        if any(repo_path.glob('*.py')):
            dirs.append(repo_path)
        # Try first-level subdirs
        for d in repo_path.iterdir():
            if d.is_dir() and not d.name.startswith('.') and d.name not in ['tests', 'test', 'docs', 'examples']:
                if any(d.glob('*.py')) or any(d.glob('**/*.py')):
                    dirs.append(d)
    
    return dirs[:5]  # Limit to 5 dirs per repo for speed

def analyze_directory(dir_path: Path) -> dict:
    """Analyze a directory using interprocedural barrier analysis."""
    results = {
        'total_functions': 0,
        'functions_with_bugs': defaultdict(list),
        'barriers_synthesized': 0,
        'barriers_verified': 0,
        'bugs': [],
        'errors': []
    }
    
    try:
        tracker = InterproceduralBugTracker.from_project(dir_path)
        results['total_functions'] = len(tracker.crash_summaries)
        
        synthesizer = FunctionBarrierSynthesizer()
        
        for func_name, summary in tracker.crash_summaries.items():
            # Check for non-security bugs
            relevant_bugs = summary.may_trigger & NON_SECURITY_BUGS
            if not relevant_bugs:
                continue
                
            for bug_type in relevant_bugs:
                results['functions_with_bugs'][bug_type].append(func_name)
                
                # Synthesize barrier if we have divisor params
                if bug_type == 'DIV_ZERO' and summary.divisor_params:
                    for param_idx in summary.divisor_params:
                        barrier = synthesizer.synthesize_div_zero_barrier(
                            f'param_{param_idx}',
                            summary.preconditions
                        )
                        if barrier:
                            results['barriers_synthesized'] += 1
                            if barrier.verified:
                                results['barriers_verified'] += 1
                            results['bugs'].append({
                                'function': func_name,
                                'bug_type': bug_type,
                                'param_idx': param_idx,
                                'barrier': str(barrier.expression) if barrier else None,
                                'verified': barrier.verified if barrier else False
                            })
                elif bug_type in {'NULL_PTR', 'BOUNDS', 'TYPE_CONFUSION'}:
                    results['bugs'].append({
                        'function': func_name,
                        'bug_type': bug_type,
                        'param_idx': None,
                        'barrier': None,
                        'verified': False
                    })
                    
    except Exception as e:
        results['errors'].append(f"{dir_path}: {str(e)}")
        
    return results

def main():
    base_path = Path(__file__).parent / 'external_tools'
    
    all_results = {}
    
    print("=" * 80)
    print("INTERPROCEDURAL BARRIER ANALYSIS: ALL REPOS - NON-SECURITY BUGS")
    print("=" * 80)
    print()
    
    for repo in REPOS:
        repo_path = base_path / repo
        if not repo_path.exists():
            print(f"⚠️  {repo}: Not found")
            continue
            
        print(f"\n{'='*60}")
        print(f"ANALYZING: {repo}")
        print(f"{'='*60}")
        
        repo_results = {
            'dirs_analyzed': 0,
            'total_functions': 0,
            'bugs_by_type': defaultdict(int),
            'all_bugs': [],
            'barriers_synthesized': 0,
            'barriers_verified': 0,
            'errors': []
        }
        
        dirs = find_python_dirs(repo_path)
        if not dirs:
            print(f"  No Python directories found")
            continue
            
        for dir_path in dirs:
            print(f"\n  Analyzing: {dir_path.relative_to(repo_path)}")
            try:
                dir_results = analyze_directory(dir_path)
                repo_results['dirs_analyzed'] += 1
                repo_results['total_functions'] += dir_results['total_functions']
                repo_results['barriers_synthesized'] += dir_results['barriers_synthesized']
                repo_results['barriers_verified'] += dir_results['barriers_verified']
                repo_results['errors'].extend(dir_results['errors'])
                
                for bug_type, funcs in dir_results['functions_with_bugs'].items():
                    repo_results['bugs_by_type'][bug_type] += len(funcs)
                    
                repo_results['all_bugs'].extend(dir_results['bugs'])
                
                # Print summary for this dir
                print(f"    Functions: {dir_results['total_functions']}")
                for bug_type, funcs in dir_results['functions_with_bugs'].items():
                    print(f"    {bug_type}: {len(funcs)} functions")
                    
            except Exception as e:
                print(f"    ERROR: {e}")
                repo_results['errors'].append(str(e))
                
        all_results[repo] = repo_results
        
        # Print repo summary
        print(f"\n  REPO SUMMARY:")
        print(f"    Dirs analyzed: {repo_results['dirs_analyzed']}")
        print(f"    Total functions: {repo_results['total_functions']}")
        print(f"    Barriers: {repo_results['barriers_synthesized']} synthesized, {repo_results['barriers_verified']} verified")
        for bug_type, count in sorted(repo_results['bugs_by_type'].items()):
            print(f"    {bug_type}: {count}")
    
    # Final summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY ACROSS ALL REPOS")
    print("=" * 80)
    
    total_functions = 0
    total_bugs = defaultdict(int)
    total_barriers = 0
    total_verified = 0
    
    for repo, results in all_results.items():
        total_functions += results['total_functions']
        total_barriers += results['barriers_synthesized']
        total_verified += results['barriers_verified']
        for bug_type, count in results['bugs_by_type'].items():
            total_bugs[bug_type] += count
            
    print(f"\nTotal functions analyzed: {total_functions}")
    print(f"Total barriers synthesized: {total_barriers}")
    print(f"Total barriers verified: {total_verified}")
    print(f"\nBugs by type:")
    for bug_type, count in sorted(total_bugs.items()):
        print(f"  {bug_type}: {count}")
        
    # Sample of specific bugs for manual review
    print("\n" + "=" * 80)
    print("SAMPLE BUGS FOR MANUAL REVIEW (potential FPs/FNs)")
    print("=" * 80)
    
    sample_count = 0
    for repo, results in all_results.items():
        for bug in results['all_bugs'][:3]:  # First 3 from each repo
            if sample_count >= 20:
                break
            print(f"\n[{repo}] {bug['function']}")
            print(f"  Bug: {bug['bug_type']}")
            if bug['param_idx'] is not None:
                print(f"  Divisor param: {bug['param_idx']}")
            if bug['barrier']:
                print(f"  Barrier: {bug['barrier']}")
                print(f"  Verified: {bug['verified']}")
            sample_count += 1

if __name__ == '__main__':
    main()
