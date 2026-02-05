#!/usr/bin/env python3
"""Analyze false positive rates in non-security bug detection."""

import ast
from pathlib import Path
from collections import defaultdict

def analyze_div_zero_fps(filepath):
    """Analyze a file for DIV_ZERO and classify as path-division (FP) vs numeric."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source)
    except:
        return {'path_div': 0, 'numeric_div': 0, 'guarded': 0}
    
    results = {'path_div': 0, 'numeric_div': 0, 'guarded': 0, 'examples': []}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            # Get left operand type hints
            left_str = ast.unparse(node.left) if hasattr(ast, 'unparse') else str(node.left)
            right_str = ast.unparse(node.right) if hasattr(ast, 'unparse') else str(node.right)
            
            # Check if it's likely a path operation
            is_path = any(p in left_str.lower() for p in ['path', 'dir', 'folder', 'file', 'self.path', '.path'])
            
            # Check if divisor is guarded (if x != 0: ... x)
            is_constant_nonzero = isinstance(node.right, ast.Constant) and node.right.value != 0
            
            if is_path:
                results['path_div'] += 1
            elif is_constant_nonzero:
                results['guarded'] += 1
            else:
                results['numeric_div'] += 1
                if len(results['examples']) < 3:
                    results['examples'].append({
                        'line': node.lineno,
                        'expr': f'{left_str} / {right_str}'[:60]
                    })
    
    return results

def analyze_null_ptr_fps(filepath):
    """Analyze NULL_PTR reports for false positives."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source)
    except:
        return {'likely_fp': 0, 'potential_bug': 0}
    
    results = {'likely_fp': 0, 'potential_bug': 0, 'examples': []}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            name = node.value.id
            # Check for common patterns that are likely FPs
            # - 'self' is rarely None
            # - 'cls' is rarely None
            # - Common safe names
            if name in ['self', 'cls', 'np', 'pd', 'os', 'sys', 'math', 'json', 're']:
                results['likely_fp'] += 1
            elif any(p in name.lower() for p in ['result', 'response', 'found', 'item', 'match', 'get', 'fetch']):
                results['potential_bug'] += 1
                if len(results['examples']) < 3:
                    results['examples'].append({
                        'line': node.lineno,
                        'access': f'{name}.{node.attr}'
                    })
    
    return results

def analyze_bounds_fps(filepath):
    """Analyze BOUNDS reports for false positives."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source)
    except:
        return {'likely_safe': 0, 'potential_bug': 0}
    
    results = {'likely_safe': 0, 'potential_bug': 0, 'examples': []}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            slice_str = ast.unparse(node.slice) if hasattr(ast, 'unparse') else str(node.slice)
            
            # Check for common safe patterns
            # - x[i] where i is from enumerate/range is usually safe
            # - x[0], x[-1] are mostly safe except on empty
            # - x[len(x)-1] is safe if len(x) > 0
            
            if isinstance(node.slice, ast.Constant):
                # Constant index - likely safe unless empty check missing
                results['likely_safe'] += 1
            elif isinstance(node.slice, ast.BinOp):
                # Computed index - check for len-based patterns
                if 'len(' in slice_str:
                    # Check for off-by-one patterns
                    if 'len(' in slice_str and '-' not in slice_str and '+' not in slice_str:
                        # x[len(x)] is always OOB!
                        results['potential_bug'] += 1
                        if len(results['examples']) < 3:
                            results['examples'].append({
                                'line': node.lineno,
                                'access': slice_str[:60]
                            })
                    else:
                        results['likely_safe'] += 1
                else:
                    results['potential_bug'] += 1
            else:
                results['likely_safe'] += 1
    
    return results

def main():
    base_path = Path(__file__).parent / 'external_tools'
    
    repos = {
        'Qlib': ['qlib/backtest', 'qlib/utils'],
        'DeepSpeed': ['deepspeed/runtime'],
        'FLAML': ['flaml/automl'],
        'GraphRAG': ['graphrag/index'],
        'PromptFlow': ['src/promptflow-core/promptflow'],
    }
    
    print('=' * 80)
    print('FALSE POSITIVE ANALYSIS')
    print('=' * 80)
    
    total_div = {'path_div': 0, 'numeric_div': 0, 'guarded': 0}
    total_null = {'likely_fp': 0, 'potential_bug': 0}
    total_bounds = {'likely_safe': 0, 'potential_bug': 0}
    
    for repo, dirs in repos.items():
        repo_path = base_path / repo
        if not repo_path.exists():
            continue
        
        print(f'\n{repo}:')
        
        for subdir in dirs:
            dir_path = repo_path / subdir
            if not dir_path.exists():
                continue
            
            for pyfile in list(dir_path.rglob('*.py'))[:30]:
                if 'test' in str(pyfile).lower():
                    continue
                
                div_res = analyze_div_zero_fps(pyfile)
                null_res = analyze_null_ptr_fps(pyfile)
                bounds_res = analyze_bounds_fps(pyfile)
                
                for k in total_div:
                    total_div[k] += div_res.get(k, 0)
                for k in total_null:
                    total_null[k] += null_res.get(k, 0)
                for k in total_bounds:
                    total_bounds[k] += bounds_res.get(k, 0)
    
    print('\n' + '=' * 80)
    print('FALSE POSITIVE SUMMARY')
    print('=' * 80)
    
    print('\nDIV_ZERO:')
    print(f'  Path divisions (FP): {total_div["path_div"]}')
    print(f'  Constant non-zero divisor (FP): {total_div["guarded"]}')
    print(f'  Potential real bugs: {total_div["numeric_div"]}')
    total_div_all = sum(total_div.values())
    if total_div_all > 0:
        fp_rate = (total_div["path_div"] + total_div["guarded"]) / total_div_all * 100
        print(f'  FP Rate: {fp_rate:.1f}%')
    
    print('\nNULL_PTR:')
    print(f'  Likely FP (self, cls, etc.): {total_null["likely_fp"]}')
    print(f'  Potential real bugs: {total_null["potential_bug"]}')
    total_null_all = sum(total_null.values())
    if total_null_all > 0:
        fp_rate = total_null["likely_fp"] / total_null_all * 100
        print(f'  FP Rate: {fp_rate:.1f}%')
    
    print('\nBOUNDS:')
    print(f'  Likely safe patterns: {total_bounds["likely_safe"]}')
    print(f'  Potential real bugs: {total_bounds["potential_bug"]}')
    total_bounds_all = sum(total_bounds.values())
    if total_bounds_all > 0:
        fp_rate = total_bounds["likely_safe"] / total_bounds_all * 100
        print(f'  FP Rate: {fp_rate:.1f}%')

if __name__ == '__main__':
    main()
