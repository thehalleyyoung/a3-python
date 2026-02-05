#!/usr/bin/env python3
"""
Analyze non-security bugs only using DSE.
Manually inspect results for TP/FP/FN.
"""

from pathlib import Path
from collections import defaultdict
from pyfromscratch.semantics.symbolic_vm import SymbolicVM
from pyfromscratch.unsafe.registry import check_unsafe_regions, SECURITY_BUG_TYPES
import ast
import types

# Non-security bug types (the 20 core bugs minus security)
NON_SECURITY_BUGS = {
    'DIV_ZERO', 'NULL_PTR', 'BOUNDS', 'TYPE_CONFUSION',
    'ASSERT_FAIL', 'INTEGER_OVERFLOW', 'FP_DOMAIN',
    'STACK_OVERFLOW', 'MEMORY_LEAK', 'NON_TERMINATION',
    'ITERATOR_INVALID', 'USE_AFTER_FREE', 'DOUBLE_FREE',
    'UNINIT_MEMORY', 'DATA_RACE', 'DEADLOCK', 'SEND_SYNC',
    'INFO_LEAK', 'TIMING_CHANNEL', 'PANIC'
}

def find_code_objects(module_code, results=None, depth=0):
    """Recursively find all code objects in a module."""
    if results is None:
        results = []
    
    for const in module_code.co_consts:
        if isinstance(const, types.CodeType):
            results.append((const, depth))
            find_code_objects(const, results, depth + 1)
    
    return results

def analyze_file_dse(file_path: Path, max_steps: int = 50):
    """Analyze a single file using DSE for non-security bugs."""
    bugs = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        
        module_code = compile(source, str(file_path), 'exec')
        code_objects = find_code_objects(module_code)
        
        for code_obj, depth in code_objects:
            func_name = code_obj.co_name
            line_no = code_obj.co_firstlineno
            
            # Skip lambdas and comprehensions
            if func_name in ('<lambda>', '<listcomp>', '<dictcomp>', '<setcomp>', '<genexpr>'):
                continue
            
            try:
                vm = SymbolicVM()
                paths = vm.explore_bounded(code_obj, max_steps=max_steps)
                
                for path in paths:
                    result = check_unsafe_regions(path.state, path.trace)
                    if result and result.get('bug_type') in NON_SECURITY_BUGS:
                        bugs.append({
                            'bug_type': result['bug_type'],
                            'file': str(file_path),
                            'function': func_name,
                            'line': line_no,
                            'context': result.get('context', {}),
                        })
            except Exception as e:
                pass
    except Exception as e:
        pass
    
    return bugs

def analyze_repo(repo_path: Path, max_files: int = 50, max_steps: int = 30):
    """Analyze a repo for non-security bugs."""
    all_bugs = []
    
    python_files = list(repo_path.rglob('*.py'))
    python_files = [f for f in python_files 
                   if '__pycache__' not in str(f)
                   and 'test' not in f.name.lower()
                   and not f.name.startswith('test_')]
    
    files_processed = 0
    for file_path in python_files:
        if files_processed >= max_files:
            break
        
        bugs = analyze_file_dse(file_path, max_steps=max_steps)
        all_bugs.extend(bugs)
        files_processed += 1
        
        if files_processed % 10 == 0:
            print(f"  Processed {files_processed} files, found {len(all_bugs)} bugs so far")
    
    return all_bugs

def main():
    base_path = Path('external_tools')
    repos = ['Qlib', 'LightGBM', 'DeepSpeed', 'FLAML', 'ONNXRuntime']
    
    print("=" * 70)
    print("NON-SECURITY BUG ANALYSIS (DSE-verified)")
    print("=" * 70)
    print()
    
    all_results = {}
    
    for repo in repos:
        repo_path = base_path / repo
        if not repo_path.exists():
            print(f"Skipping {repo} (not found)")
            continue
        
        print(f"Analyzing {repo}...")
        bugs = analyze_repo(repo_path, max_files=30, max_steps=30)
        all_results[repo] = bugs
        
        # Count by type
        by_type = defaultdict(list)
        for bug in bugs:
            by_type[bug['bug_type']].append(bug)
        
        print(f"  Found {len(bugs)} bugs:")
        for bug_type, bug_list in sorted(by_type.items()):
            print(f"    {bug_type}: {len(bug_list)}")
        print()
    
    # Aggregate
    print("=" * 70)
    print("AGGREGATE RESULTS")
    print("=" * 70)
    
    total_by_type = defaultdict(list)
    for repo, bugs in all_results.items():
        for bug in bugs:
            total_by_type[bug['bug_type']].append((repo, bug))
    
    for bug_type in sorted(total_by_type.keys()):
        bugs = total_by_type[bug_type]
        print(f"\n{bug_type}: {len(bugs)} total")
        
        # Show first 5 examples for manual inspection
        print(f"  Examples (first 5):")
        for repo, bug in bugs[:5]:
            file_short = bug['file'].split('/')[-1]
            print(f"    [{repo}] {file_short}:{bug['line']} in {bug['function']}")
    
    # Save detailed results for inspection
    print()
    print("=" * 70)
    print("DETAILED RESULTS FOR MANUAL INSPECTION")
    print("=" * 70)
    
    for bug_type in sorted(total_by_type.keys()):
        bugs = total_by_type[bug_type]
        print(f"\n### {bug_type} ({len(bugs)} bugs)")
        
        for i, (repo, bug) in enumerate(bugs[:10]):
            print(f"\n{i+1}. [{repo}] {bug['file']}")
            print(f"   Function: {bug['function']} (line {bug['line']})")
            if bug.get('context'):
                print(f"   Context: {bug['context']}")

if __name__ == '__main__':
    main()
