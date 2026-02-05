#!/usr/bin/env python3
"""
Analyze all external repos with pyfromscratch - simple sequential version.
"""

import os
import sys
import json
import time
import signal
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.analyzer import Analyzer


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException("Analysis timed out")


def analyze_file_safe(analyzer, py_file, repo_path, timeout=30):
    """Analyze a single file with timeout."""
    result = {'bugs': [], 'proofs': 0, 'error': None}
    
    # Set timeout
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    
    try:
        analysis = analyzer.analyze_file(py_file)  # Use faster analyze_file instead of kitchensink
        rel_file = str(py_file.relative_to(repo_path))
        
        if analysis.verdict == 'BUG':
            if analysis.interprocedural_bugs:
                for bug in analysis.interprocedural_bugs:
                    result['bugs'].append({
                        'file': rel_file,
                        'bug_type': getattr(bug, 'bug_type', 'UNKNOWN'),
                        'line': getattr(bug, 'line', 0),
                        'confidence': getattr(bug, 'confidence', 1.0)
                    })
            elif analysis.counterexample:
                cx = analysis.counterexample
                result['bugs'].append({
                    'file': rel_file,
                    'bug_type': cx.get('bug_type', analysis.bug_type or 'UNKNOWN'),
                    'line': cx.get('line', 0),
                    'confidence': cx.get('confidence', 1.0)
                })
            elif analysis.bug_type:
                result['bugs'].append({
                    'file': rel_file,
                    'bug_type': analysis.bug_type,
                    'line': 0,
                    'confidence': 1.0
                })
        
        if analysis.per_bug_type:
            for info in analysis.per_bug_type.values():
                if info.get('verdict') == 'SAFE':
                    result['proofs'] += 1
                    
    except TimeoutException:
        result['error'] = 'TIMEOUT'
    except Exception as e:
        result['error'] = f'{type(e).__name__}: {str(e)[:60]}'
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
    
    return result


def analyze_repo(repo_name, base_path, max_files=25):
    """Analyze a single repo."""
    repo_path = base_path / repo_name
    result = {
        'repo_name': repo_name,
        'time_sec': 0.0,
        'total_bugs': 0,
        'bugs_by_type': {},
        'proofs_found': 0,
        'files_analyzed': 0,
        'bugs': [],
        'errors': []
    }
    
    start = time.time()
    
    try:
        analyzer = Analyzer(verbose=False)
        
        # Collect Python files
        py_files = []
        skip_patterns = ['__pycache__', 'test', 'build', 'setup.py', 'conftest', 'versioneer']
        for f in repo_path.rglob('*.py'):
            if any(pat in str(f).lower() for pat in skip_patterns):
                continue
            py_files.append(f)
            if len(py_files) >= max_files:
                break
        
        result['files_analyzed'] = len(py_files)
        
        for i, py_file in enumerate(py_files):
            print(f'  [{i+1}/{len(py_files)}] {py_file.name[:25]}...', end='\r', flush=True)
            
            file_result = analyze_file_safe(analyzer, py_file, repo_path, timeout=30)
            
            if file_result['error']:
                result['errors'].append({
                    'file': str(py_file.relative_to(repo_path)),
                    'error': file_result['error']
                })
            
            for bug in file_result['bugs']:
                bt = bug['bug_type']
                result['bugs_by_type'][bt] = result['bugs_by_type'].get(bt, 0) + 1
                result['total_bugs'] += 1
                result['bugs'].append(bug)
            
            result['proofs_found'] += file_result['proofs']
        
        print(' ' * 50, end='\r')
        
    except Exception as e:
        result['errors'].append({'file': 'REPO', 'error': str(e)[:100]})
    
    result['time_sec'] = round(time.time() - start, 2)
    return result


def main():
    base = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools')
    output_path = Path('/Users/halleyyoung/Documents/PythonFromScratch/results/all_repos_analysis.json')
    
    # Skip codeql (not Python)
    repos = sorted([d.name for d in base.iterdir() if d.is_dir() and not d.name.startswith('.') and d.name != 'codeql'])
    
    print('=' * 70)
    print('PYFROMSCRATCH - EXTERNAL REPOS ANALYSIS')
    print('=' * 70)
    print(f'Repos: {repos}')
    print(f'Total: {len(repos)}')
    print()
    
    # Load existing
    all_results = {'repos': [], 'summary': {}}
    done_repos = set()
    if output_path.exists():
        try:
            with open(output_path) as f:
                existing = json.load(f)
                all_results = existing
                done_repos = {r['repo_name'] for r in existing.get('repos', []) if 'total_bugs' in r}
                print(f'Resuming: {len(done_repos)} already done')
        except:
            pass
    
    for repo_name in repos:
        if repo_name in done_repos:
            print(f'{repo_name}: SKIPPED')
            continue
        
        print(f'{repo_name}...')
        result = analyze_repo(repo_name, base)
        all_results['repos'].append(result)
        
        print(f'  Bugs: {result["total_bugs"]}, Files: {result["files_analyzed"]}, Time: {result["time_sec"]}s')
        if result['bugs_by_type']:
            print(f'  Types: {dict(result["bugs_by_type"])}')
        
        # Save after each repo
        with open(output_path, 'w') as f:
            json.dump(all_results, f, indent=2)
    
    # Summary
    total_bugs = sum(r.get('total_bugs', 0) for r in all_results['repos'])
    total_files = sum(r.get('files_analyzed', 0) for r in all_results['repos'])
    total_proofs = sum(r.get('proofs_found', 0) for r in all_results['repos'])
    
    all_types = Counter()
    for r in all_results['repos']:
        for bt, cnt in r.get('bugs_by_type', {}).items():
            all_types[bt] += cnt
    
    all_results['summary'] = {
        'total_repos': len(repos),
        'total_files': total_files,
        'total_bugs': total_bugs,
        'total_proofs': total_proofs,
        'bugs_by_type': dict(all_types)
    }
    
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print()
    print('=' * 70)
    print('SUMMARY')
    print('=' * 70)
    print(f'Files: {total_files}, Bugs: {total_bugs}, Proofs: {total_proofs}')
    print(f'Bug types: {dict(all_types)}')
    print(f'Saved to: {output_path}')


if __name__ == '__main__':
    main()
