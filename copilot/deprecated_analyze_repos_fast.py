#!/usr/bin/env python3
"""
Fast analysis of all external repos for non-security bugs.
Focuses on key directories to reduce analysis time.
"""

import os
import sys
from pathlib import Path
from collections import defaultdict
import ast
import traceback

sys.path.insert(0, str(Path(__file__).parent))

NON_SECURITY_BUGS = {'DIV_ZERO', 'NULL_PTR', 'BOUNDS', 'TYPE_CONFUSION', 'PANIC'}

# Map repos to their most important directories
REPO_DIRS = {
    'Qlib': ['qlib/backtest', 'qlib/utils', 'qlib/data'],
    'LightGBM': ['python-package/lightgbm'],
    'DeepSpeed': ['deepspeed/ops', 'deepspeed/runtime', 'deepspeed/utils'],
    'FLAML': ['flaml/automl', 'flaml/tune'],
    'GraphRAG': ['graphrag/index', 'graphrag/query'],
    'Guidance': ['guidance/models', 'guidance/library'],
    'ONNXRuntime': ['onnxruntime/python', 'onnxruntime/transformers'],
    'PromptFlow': ['src/promptflow-core/promptflow'],
    'RDAgent': ['rdagent/core', 'rdagent/components'],
    'Pyright': ['packages/pyright-internal/src'],  # TypeScript but may have Python wrappers
    'MSTICPY': ['msticpy/analysis', 'msticpy/data'],
    'Counterfit': ['counterfit/core'],
    'DebugPy': ['src/debugpy'],
    'RESTler': ['restler/engine'],
    'SemanticKernel': ['python/semantic_kernel'],
    'Presidio': ['presidio-analyzer/presidio_analyzer'],
}

def analyze_file_for_bugs(filepath: Path) -> dict:
    """Analyze a single Python file for potential bugs using AST analysis."""
    results = {
        'div_zero': [],
        'null_ptr': [],
        'bounds': [],
        'type_confusion': [],
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source)
    except:
        return results
    
    for node in ast.walk(tree):
        # DIV_ZERO: Look for division operations
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                # Check if divisor could be zero (heuristic: variable or complex expr)
                divisor = node.right
                if not isinstance(divisor, ast.Constant) or divisor.value == 0:
                    results['div_zero'].append({
                        'line': node.lineno,
                        'col': node.col_offset,
                        'divisor': ast.dump(divisor)[:50]
                    })
        
        # NULL_PTR: Look for attribute access on potentially None values
        if isinstance(node, ast.Attribute):
            # Check for common patterns like x.value where x could be None
            if isinstance(node.value, ast.Name):
                # Heuristic: names ending in _result, _response, found, item often could be None
                name = node.value.id
                if any(pat in name.lower() for pat in ['result', 'response', 'found', 'item', 'match', 'get']):
                    results['null_ptr'].append({
                        'line': node.lineno,
                        'col': node.col_offset,
                        'name': name,
                        'attr': node.attr
                    })
        
        # BOUNDS: Look for subscript access
        if isinstance(node, ast.Subscript):
            # Heuristic: check for common OOB patterns
            if isinstance(node.slice, ast.BinOp):
                # x[len(x)] or x[i + 1] patterns
                results['bounds'].append({
                    'line': node.lineno,
                    'col': node.col_offset,
                    'slice': ast.dump(node.slice)[:50]
                })
            elif isinstance(node.slice, ast.Constant):
                # x[-1], x[0] - usually safe but can be OOB on empty
                if node.slice.value in (-1, 0):
                    results['bounds'].append({
                        'line': node.lineno,
                        'col': node.col_offset,
                        'slice': str(node.slice.value),
                        'risk': 'empty_container'
                    })
    
    return results

def analyze_directory_fast(dir_path: Path) -> dict:
    """Fast AST-based analysis of a directory."""
    results = {
        'files_analyzed': 0,
        'bugs': defaultdict(list),
    }
    
    py_files = list(dir_path.rglob('*.py'))[:50]  # Limit files per dir
    
    for pyfile in py_files:
        if 'test' in str(pyfile).lower():
            continue
        try:
            file_results = analyze_file_for_bugs(pyfile)
            results['files_analyzed'] += 1
            
            for bug_type, bugs in file_results.items():
                for bug in bugs[:5]:  # Limit bugs per file
                    bug['file'] = str(pyfile.relative_to(dir_path.parent.parent))
                    results['bugs'][bug_type].append(bug)
        except Exception as e:
            pass
    
    return results

def main():
    base_path = Path(__file__).parent / 'external_tools'
    
    print("=" * 80)
    print("FAST NON-SECURITY BUG ANALYSIS: ALL REPOS")
    print("=" * 80)
    
    all_results = {}
    
    for repo, dirs in REPO_DIRS.items():
        repo_path = base_path / repo
        if not repo_path.exists():
            print(f"\n⚠️  {repo}: Not found")
            continue
        
        print(f"\n{'='*60}")
        print(f"REPO: {repo}")
        print(f"{'='*60}")
        
        repo_results = {
            'total_files': 0,
            'bugs_by_type': defaultdict(list),
        }
        
        for subdir in dirs:
            dir_path = repo_path / subdir
            if not dir_path.exists():
                # Try glob patterns
                matches = list(repo_path.glob(subdir))
                if matches:
                    dir_path = matches[0]
                else:
                    continue
            
            print(f"\n  {subdir}:")
            dir_results = analyze_directory_fast(dir_path)
            repo_results['total_files'] += dir_results['files_analyzed']
            
            for bug_type, bugs in dir_results['bugs'].items():
                repo_results['bugs_by_type'][bug_type].extend(bugs)
                print(f"    {bug_type}: {len(bugs)} potential issues")
        
        all_results[repo] = repo_results
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY: POTENTIAL BUGS BY TYPE ACROSS ALL REPOS")
    print("=" * 80)
    
    total_by_type = defaultdict(int)
    for repo, results in all_results.items():
        for bug_type, bugs in results['bugs_by_type'].items():
            total_by_type[bug_type] += len(bugs)
    
    for bug_type, count in sorted(total_by_type.items()):
        print(f"  {bug_type.upper()}: {count}")
    
    # Sample bugs for review
    print("\n" + "=" * 80)
    print("SAMPLE BUGS FOR REVIEW (to identify FPs/FNs)")
    print("=" * 80)
    
    for bug_type in ['div_zero', 'null_ptr', 'bounds']:
        print(f"\n{bug_type.upper()} SAMPLES:")
        count = 0
        for repo, results in all_results.items():
            for bug in results['bugs_by_type'][bug_type]:
                if count >= 10:
                    break
                print(f"  [{repo}] {bug['file']}:{bug['line']}")
                if 'divisor' in bug:
                    print(f"    Divisor: {bug['divisor']}")
                elif 'name' in bug:
                    print(f"    Access: {bug['name']}.{bug['attr']}")
                elif 'slice' in bug:
                    print(f"    Slice: {bug['slice']}")
                count += 1
            if count >= 10:
                break

if __name__ == '__main__':
    main()
