#!/usr/bin/env python3
"""Quick scan of all external repos for non-security bugs."""

import ast
from pathlib import Path
from collections import defaultdict

REPO_DIRS = {
    'Qlib': ['qlib/backtest', 'qlib/utils', 'qlib/data'],
    'LightGBM': ['python-package/lightgbm'],
    'DeepSpeed': ['deepspeed/runtime', 'deepspeed/utils'],
    'FLAML': ['flaml/automl', 'flaml/tune'],
    'GraphRAG': ['graphrag/index', 'graphrag/query'],
    'PromptFlow': ['src/promptflow-core/promptflow'],
    'MSTICPY': ['msticpy/analysis', 'msticpy/data'],
    'Presidio': ['presidio-analyzer/presidio_analyzer'],
    'Guidance': ['guidance/models', 'guidance/library'],
    'ONNXRuntime': ['onnxruntime/python'],
    'RDAgent': ['rdagent/core'],
    'SemanticKernel': ['python/semantic_kernel'],
}

def analyze_file(filepath):
    """Analyze a single Python file for potential bugs."""
    results = {'div_zero': [], 'null_ptr': [], 'bounds': [], 'type_confusion': []}
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source)
    except:
        return results
    
    for node in ast.walk(tree):
        # DIV_ZERO: Division operations
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            divisor = node.right
            # Variable divisors or complex expressions could be zero
            if not isinstance(divisor, ast.Constant) or divisor.value == 0:
                results['div_zero'].append({
                    'line': node.lineno,
                    'col': node.col_offset,
                })
        
        # BOUNDS: Subscript with computed index
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.BinOp):
                # x[i + 1], x[len(x) - 1], etc.
                results['bounds'].append({
                    'line': node.lineno,
                    'col': node.col_offset,
                })
            elif isinstance(node.slice, ast.UnaryOp) and isinstance(node.slice.op, ast.USub):
                # x[-n] where n is variable
                if not isinstance(node.slice.operand, ast.Constant):
                    results['bounds'].append({
                        'line': node.lineno,
                        'col': node.col_offset,
                    })
        
        # NULL_PTR: Attribute access on potentially None values
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            name = node.value.id
            # Common patterns for values that could be None
            if any(p in name.lower() for p in ['result', 'response', 'found', 'item', 'match', 'get', 'fetch']):
                results['null_ptr'].append({
                    'line': node.lineno,
                    'name': name,
                    'attr': node.attr,
                })
        
        # TYPE_CONFUSION: Calling something that might not be callable
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # Check for getattr patterns that could return non-callable
            if isinstance(node.func.value, ast.Call):
                func_call = node.func.value
                if isinstance(func_call.func, ast.Name) and func_call.func.id == 'getattr':
                    results['type_confusion'].append({
                        'line': node.lineno,
                        'pattern': 'getattr_call',
                    })
    
    return results

def main():
    base_path = Path(__file__).parent / 'external_tools'
    all_results = {}
    
    print('=' * 80)
    print('NON-SECURITY BUG SCAN: ALL EXTERNAL REPOS')
    print('=' * 80)
    
    for repo, dirs in REPO_DIRS.items():
        repo_path = base_path / repo
        if not repo_path.exists():
            continue
        
        repo_results = defaultdict(list)
        files_analyzed = 0
        
        for subdir in dirs:
            dir_path = repo_path / subdir
            if not dir_path.exists():
                continue
            
            for pyfile in list(dir_path.rglob('*.py'))[:50]:
                if 'test' in str(pyfile).lower():
                    continue
                res = analyze_file(pyfile)
                files_analyzed += 1
                for bug_type, bugs in res.items():
                    for bug in bugs:
                        bug['file'] = str(pyfile.relative_to(repo_path))
                        repo_results[bug_type].append(bug)
        
        all_results[repo] = dict(repo_results)
        
        # Print summary for this repo
        total = sum(len(bugs) for bugs in repo_results.values())
        if total > 0:
            print(f'\n{repo} ({files_analyzed} files):')
            for bug_type in ['div_zero', 'null_ptr', 'bounds', 'type_confusion']:
                count = len(repo_results.get(bug_type, []))
                if count > 0:
                    print(f'  {bug_type.upper()}: {count}')
    
    # Summary totals
    print('\n' + '=' * 80)
    print('TOTALS BY BUG TYPE')
    print('=' * 80)
    
    total_by_type = defaultdict(int)
    for repo, results in all_results.items():
        for bug_type, bugs in results.items():
            total_by_type[bug_type] += len(bugs)
    
    for bug_type in ['div_zero', 'null_ptr', 'bounds', 'type_confusion']:
        print(f'  {bug_type.upper()}: {total_by_type[bug_type]}')
    
    print(f'\n  TOTAL: {sum(total_by_type.values())}')
    
    # Sample of specific bugs for manual review (to identify FPs/FNs)
    print('\n' + '=' * 80)
    print('SAMPLE BUGS FOR FP/FN ANALYSIS')
    print('=' * 80)
    
    for bug_type in ['div_zero', 'null_ptr', 'bounds']:
        print(f'\n{bug_type.upper()} SAMPLES:')
        count = 0
        for repo, results in all_results.items():
            for bug in results.get(bug_type, [])[:3]:
                if count >= 8:
                    break
                print(f'  [{repo}] {bug["file"]}:{bug["line"]}')
                count += 1
            if count >= 8:
                break

if __name__ == '__main__':
    main()
