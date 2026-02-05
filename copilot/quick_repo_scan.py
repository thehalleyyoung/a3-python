#!/usr/bin/env python3
"""
Fast analysis of all external repos - samples just a few files per repo.
Designed to complete quickly and save results incrementally.
"""

import sys
import json
import time
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.analyzer import Analyzer


def analyze_file_quick(analyzer, py_file, repo_path):
    """Analyze a single file, return bugs found."""
    result = {'bugs': [], 'error': None}
    try:
        analysis = analyzer.analyze_file(py_file)
        rel = str(py_file.relative_to(repo_path))
        
        if analysis.verdict == 'BUG':
            if analysis.interprocedural_bugs:
                for bug in analysis.interprocedural_bugs:
                    result['bugs'].append({
                        'file': rel,
                        'bug_type': getattr(bug, 'bug_type', 'UNKNOWN'),
                        'line': getattr(bug, 'line', 0),
                    })
            elif analysis.counterexample:
                cx = analysis.counterexample
                result['bugs'].append({
                    'file': rel,
                    'bug_type': cx.get('bug_type', analysis.bug_type or 'UNKNOWN'),
                    'line': cx.get('line', 0),
                })
            elif analysis.bug_type:
                result['bugs'].append({
                    'file': rel,
                    'bug_type': analysis.bug_type,
                    'line': 0,
                })
    except Exception as e:
        result['error'] = f'{type(e).__name__}: {str(e)[:60]}'
    return result


def main():
    base = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools')
    output_path = Path('/Users/halleyyoung/Documents/PythonFromScratch/results/all_repos_analysis.json')
    
    # Get all repos except codeql
    repos = sorted([d.name for d in base.iterdir() if d.is_dir() and d.name not in {'.', 'codeql'}])
    
    print(f'Analyzing {len(repos)} repos: {repos}')
    
    # Load existing or start fresh
    all_results = {'repos': [], 'summary': {}}
    done = set()
    if output_path.exists():
        try:
            with open(output_path) as f:
                all_results = json.load(f)
                done = {r['repo_name'] for r in all_results.get('repos', []) if 'bugs' in r}
                print(f'Resuming: {len(done)} done')
        except:
            pass
    
    max_files = 10  # Only analyze 10 files per repo for speed
    
    for repo in repos:
        if repo in done:
            print(f'{repo}: skip (done)')
            continue
        
        print(f'{repo}...', end=' ', flush=True)
        start = time.time()
        
        repo_result = {
            'repo_name': repo,
            'bugs': [],
            'bugs_by_type': {},
            'total_bugs': 0,
            'files_analyzed': 0,
            'errors': [],
            'time_sec': 0
        }
        
        try:
            analyzer = Analyzer(verbose=False)
            repo_path = base / repo
            
            # Get files, skip test/build/setup
            skip = ['test', 'build', 'setup', '__pycache__', 'versioneer', 'conftest']
            py_files = []
            for f in repo_path.rglob('*.py'):
                if not any(s in str(f).lower() for s in skip):
                    py_files.append(f)
                    if len(py_files) >= max_files:
                        break
            
            repo_result['files_analyzed'] = len(py_files)
            
            for pf in py_files:
                try:
                    res = analyze_file_quick(analyzer, pf, repo_path)
                    if res['error']:
                        repo_result['errors'].append(res['error'])
                    for bug in res['bugs']:
                        repo_result['bugs'].append(bug)
                        bt = bug['bug_type']
                        repo_result['bugs_by_type'][bt] = repo_result['bugs_by_type'].get(bt, 0) + 1
                        repo_result['total_bugs'] += 1
                except Exception as e:
                    repo_result['errors'].append(str(e)[:50])
        
        except Exception as e:
            repo_result['errors'].append(f'REPO ERROR: {str(e)[:50]}')
        
        repo_result['time_sec'] = round(time.time() - start, 2)
        all_results['repos'].append(repo_result)
        
        print(f'{repo_result["total_bugs"]} bugs, {repo_result["files_analyzed"]} files, {repo_result["time_sec"]}s')
        
        # Save after each repo
        with open(output_path, 'w') as f:
            json.dump(all_results, f, indent=2)
    
    # Summary
    total_bugs = sum(r.get('total_bugs', 0) for r in all_results['repos'])
    total_files = sum(r.get('files_analyzed', 0) for r in all_results['repos'])
    
    all_types = Counter()
    for r in all_results['repos']:
        for bt, cnt in r.get('bugs_by_type', {}).items():
            all_types[bt] += cnt
    
    all_results['summary'] = {
        'total_repos': len(repos),
        'total_files': total_files,
        'total_bugs': total_bugs,
        'bugs_by_type': dict(all_types)
    }
    
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print()
    print('=' * 50)
    print(f'DONE: {total_files} files, {total_bugs} bugs')
    print(f'Types: {dict(all_types)}')
    print(f'Saved: {output_path}')


if __name__ == '__main__':
    main()
