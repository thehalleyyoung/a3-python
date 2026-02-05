#!/usr/bin/env python3
"""
Analyze all external repos with pyfromscratch and save results to JSON.
"""

from pathlib import Path
import sys
import time
import json
from collections import Counter
import traceback

sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.analyzer import Analyzer


def analyze_single_file(analyzer, py_file, repo_path):
    """Analyze a single file and return bugs/proofs."""
    result = {'bugs': [], 'proofs': 0, 'error': None}
    try:
        analysis = analyzer.analyze_file_kitchensink(py_file)
        rel_file = str(py_file.relative_to(repo_path))
        
        if analysis.verdict == 'BUG':
            # Handle interprocedural bugs (multiple bugs)
            if analysis.interprocedural_bugs:
                for bug in analysis.interprocedural_bugs:
                    result['bugs'].append({
                        'file': rel_file,
                        'bug_type': getattr(bug, 'bug_type', 'UNKNOWN'),
                        'line': getattr(bug, 'line', 0),
                        'message': getattr(bug, 'message', ''),
                        'confidence': getattr(bug, 'confidence', 1.0)
                    })
            # Handle single bug from counterexample
            elif analysis.counterexample:
                cx = analysis.counterexample
                result['bugs'].append({
                    'file': rel_file,
                    'bug_type': cx.get('bug_type', analysis.bug_type or 'UNKNOWN'),
                    'line': cx.get('line', 0),
                    'message': cx.get('message', analysis.message or ''),
                    'confidence': cx.get('confidence', 1.0)
                })
            # Fallback: just bug_type
            elif analysis.bug_type:
                result['bugs'].append({
                    'file': rel_file,
                    'bug_type': analysis.bug_type,
                    'line': 0,
                    'message': analysis.message or '',
                    'confidence': 1.0
                })
        
        if analysis.per_bug_type:
            for info in analysis.per_bug_type.values():
                if info.get('verdict') == 'SAFE':
                    result['proofs'] += 1
    except Exception as e:
        result['error'] = f'{type(e).__name__}: {str(e)[:100]}'
    return result


def analyze_repo(repo_path, max_files=50, file_timeout=60):
    """Analyze a repo and return structured results."""
    import signal
    
    result = {
        'repo_name': repo_path.name,
        'time_sec': 0.0,
        'total_bugs': 0,
        'bugs_by_type': {},
        'proofs_found': 0,
        'files_analyzed': 0,
        'files_with_bugs': 0,
        'files_error': 0,
        'bugs': [],
        'errors': []
    }
    start = time.time()
    analyzer = Analyzer(verbose=False)
    
    # Collect Python files, skip tests, pycache, and build scripts
    py_files = []
    skip_patterns = ['__pycache__', 'test', 'build', 'versioneer', 'setup.py', 'conftest']
    for f in repo_path.rglob('*.py'):
        skip = False
        f_str = str(f).lower()
        for pat in skip_patterns:
            if pat in f_str:
                skip = True
                break
        if not skip:
            py_files.append(f)
        if len(py_files) >= max_files:
            break
    
    result['files_analyzed'] = len(py_files)
    
    for i, py_file in enumerate(py_files):
        print(f'  [{i+1}/{len(py_files)}] {py_file.name[:30]}...', end='\r', flush=True)
        
        # Per-file try-except to prevent single file from crashing whole analysis
        try:
            file_result = analyze_single_file(analyzer, py_file, repo_path)
        except Exception as e:
            file_result = {'bugs': [], 'proofs': 0, 'error': f'{type(e).__name__}: {str(e)[:80]}'}
        
        if file_result['error']:
            result['files_error'] += 1
            result['errors'].append({
                'file': str(py_file.relative_to(repo_path)), 
                'error': file_result['error']
            })
        elif file_result['bugs']:
            result['files_with_bugs'] += 1
            for bug in file_result['bugs']:
                bt = bug['bug_type']
                result['bugs_by_type'][bt] = result['bugs_by_type'].get(bt, 0) + 1
                result['total_bugs'] += 1
                result['bugs'].append(bug)
        
        result['proofs_found'] += file_result['proofs']
    
    print(' ' * 60, end='\r')
    result['time_sec'] = round(time.time() - start, 2)
    return result


def main():
    base = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools')
    output_path = Path('/Users/halleyyoung/Documents/PythonFromScratch/results/all_repos_analysis.json')
    output_path.parent.mkdir(exist_ok=True)
    
    # Get all repos, skip only codeql (not Python code)
    skip_repos = {'codeql'}  
    repos = sorted([d.name for d in base.iterdir() if d.is_dir() and not d.name.startswith('.') and d.name not in skip_repos])
    
    print('=' * 70)
    print('PYFROMSCRATCH ANALYSIS - ALL EXTERNAL REPOS')
    print('=' * 70)
    print(f'Repos: {repos}')
    print(f'Total: {len(repos)} repos (skipping: {skip_repos})')
    print()
    
    # Load existing results if any (to resume)
    all_results = {'repos': [], 'summary': {}}
    done_repos = set()
    if output_path.exists():
        try:
            with open(output_path) as f:
                existing = json.load(f)
                all_results = existing
                done_repos = {r['repo_name'] for r in existing.get('repos', []) if 'total_bugs' in r}
                print(f'Resuming: {len(done_repos)} repos already done')
        except:
            pass
    
    for repo_name in repos:
        if repo_name in done_repos:
            print(f'{repo_name}... SKIPPED (already done)')
            continue
            
        repo_path = base / repo_name
        print(f'{repo_name}...')
        try:
            result = analyze_repo(repo_path, max_files=30)
            all_results['repos'].append(result)
            print(f'  Files: {result["files_analyzed"]}, Bugs: {result["total_bugs"]}, Proofs: {result["proofs_found"]}, Time: {result["time_sec"]}s')
            
            # Save intermediate results after each repo
            with open(output_path, 'w') as f:
                json.dump(all_results, f, indent=2)
                
        except Exception as e:
            print(f'  ERROR: {e}')
            traceback.print_exc()
            all_results['repos'].append({'repo_name': repo_name, 'error': str(e)})
    
    # Calculate summary
    total_bugs = sum(r.get('total_bugs', 0) for r in all_results['repos'])
    total_proofs = sum(r.get('proofs_found', 0) for r in all_results['repos'])
    total_files = sum(r.get('files_analyzed', 0) for r in all_results['repos'])
    
    all_types = Counter()
    for r in all_results['repos']:
        if 'bugs_by_type' in r:
            for bt, cnt in r['bugs_by_type'].items():
                all_types[bt] += cnt
    
    all_results['summary'] = {
        'total_repos': len(repos),
        'total_files': total_files,
        'total_bugs': total_bugs,
        'total_proofs': total_proofs,
        'bugs_by_type': dict(all_types)
    }
    
    # Write final results
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print()
    print('=' * 70)
    print(f'Results saved to: {output_path}')
    print(f'Total: {total_files} files, {total_bugs} bugs, {total_proofs} proofs')
    print('=' * 70)
    
    # Print bug type breakdown
    print('\nBug Types:')
    for bt, count in sorted(all_types.items(), key=lambda x: -x[1]):
        print(f'  {bt}: {count}')
    
    print('\nPer-Repo Summary:')
    for r in all_results['repos']:
        if 'error' in r and 'total_bugs' not in r:
            print(f'  {r["repo_name"]}: ERROR')
        else:
            status = 'CLEAN' if r.get('total_bugs', 0) == 0 else f'{r["total_bugs"]} bugs'
            print(f'  {r["repo_name"]}: {r.get("files_analyzed", 0)} files, {status}')


if __name__ == '__main__':
    main()
