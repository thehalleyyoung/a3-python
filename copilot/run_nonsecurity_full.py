#!/usr/bin/env python3
"""
Analyze all external repos with pyfromscratch for NON-SECURITY bugs only.
Runs on FULL repo contents (no file limit).
Uses subprocess isolation per-file with timeout to prevent hangs.
"""

import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

BASE_DIR = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools')
OUTPUT_PATH = Path('/Users/halleyyoung/Documents/PythonFromScratch/results/all_repos_nonsecurity_full.json')
PYTHON = '/Users/halleyyoung/Documents/PythonFromScratch/test_venv/bin/python'
TIMEOUT_PER_FILE = 15  # seconds per file (reduced to avoid long hangs)

# Non-security bug types (crash/error bugs)
NON_SECURITY_BUG_TYPES = {
    'NULL_PTR', 'BOUNDS', 'DIV_ZERO', 'TYPE_CONFUSION', 'ASSERT_FAIL', 'PANIC',
    'STACK_OVERFLOW', 'INTEGER_OVERFLOW', 'FP_DOMAIN', 'MEMORY_LEAK',
    'USE_AFTER_FREE', 'DOUBLE_FREE', 'UNINIT_MEMORY', 'DATA_RACE', 'DEADLOCK',
    'ITERATOR_INVALID', 'NON_TERMINATION', 'SEND_SYNC', 'INFO_LEAK', 'TIMING_CHANNEL',
    'INDEX_ERROR', 'KEY_ERROR', 'ATTRIBUTE_ERROR', 'VALUE_ERROR', 'RUNTIME_ERROR',
}

SKIP_PATTERNS = [
    '__pycache__', 'test_', '_test.py', 'tests/', '/test/', 'testing/',
    'conftest.py', 'setup.py', 'versioneer.py', '.git/', 'build/', 'dist/',
    'node_modules/', 'vendor/', 'migrations/', 'fixtures/', '_version.py',
]

# Single-file analysis script (inline)
ANALYZE_SINGLE_FILE_SCRIPT = '''
import sys
import json
from pathlib import Path

sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')
from pyfromscratch.analyzer import Analyzer

NON_SECURITY_BUG_TYPES = {
    'NULL_PTR', 'BOUNDS', 'DIV_ZERO', 'TYPE_CONFUSION', 'ASSERT_FAIL', 'PANIC',
    'STACK_OVERFLOW', 'INTEGER_OVERFLOW', 'FP_DOMAIN', 'MEMORY_LEAK',
    'USE_AFTER_FREE', 'DOUBLE_FREE', 'UNINIT_MEMORY', 'DATA_RACE', 'DEADLOCK',
    'ITERATOR_INVALID', 'NON_TERMINATION', 'SEND_SYNC', 'INFO_LEAK', 'TIMING_CHANNEL',
    'INDEX_ERROR', 'KEY_ERROR', 'ATTRIBUTE_ERROR', 'VALUE_ERROR', 'RUNTIME_ERROR',
}

filepath = Path(sys.argv[1])
repo_path = Path(sys.argv[2])
result = {'bugs': [], 'error': None}

try:
    analyzer = Analyzer(verbose=False)
    analysis = analyzer.analyze_file_kitchensink(filepath)
    rel_file = str(filepath.relative_to(repo_path))
    
    if analysis.verdict == 'BUG':
        if analysis.interprocedural_bugs:
            for bug in analysis.interprocedural_bugs:
                bt = getattr(bug, 'bug_type', 'UNKNOWN')
                if bt in NON_SECURITY_BUG_TYPES:
                    result['bugs'].append({
                        'file': rel_file,
                        'bug_type': bt,
                        'line': getattr(bug, 'line', 0),
                        'message': str(getattr(bug, 'message', ''))[:200],
                    })
        elif analysis.counterexample:
            cx = analysis.counterexample
            bt = cx.get('bug_type', analysis.bug_type or 'UNKNOWN')
            if bt in NON_SECURITY_BUG_TYPES:
                result['bugs'].append({
                    'file': rel_file,
                    'bug_type': bt,
                    'line': cx.get('line', 0),
                    'message': str(cx.get('message', ''))[:200],
                })
        elif analysis.bug_type and analysis.bug_type in NON_SECURITY_BUG_TYPES:
            result['bugs'].append({
                'file': rel_file,
                'bug_type': analysis.bug_type,
                'line': 0,
                'message': str(getattr(analysis, 'message', ''))[:200] if hasattr(analysis, 'message') else '',
            })
except Exception as e:
    result['error'] = f'{type(e).__name__}: {str(e)[:100]}'

print(json.dumps(result))
'''


def should_skip_file(filepath: Path) -> bool:
    """Check if file should be skipped based on patterns."""
    path_str = str(filepath).lower()
    return any(pat in path_str for pat in SKIP_PATTERNS)


def get_python_files(repo_path: Path) -> list:
    """Get all Python files in repo, excluding test/build files."""
    files = []
    for f in repo_path.rglob('*.py'):
        if not should_skip_file(f):
            files.append(f)
    return sorted(files)


def analyze_file_subprocess(py_file: Path, repo_path: Path) -> dict:
    """Analyze a single file in a subprocess with timeout."""
    try:
        result = subprocess.run(
            [PYTHON, '-c', ANALYZE_SINGLE_FILE_SCRIPT, str(py_file), str(repo_path)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_PER_FILE,
            cwd=str(repo_path),
        )
        if result.returncode == 0 and result.stdout.strip():
            # Find the JSON line (last line that starts with {)
            for line in reversed(result.stdout.strip().split('\n')):
                line = line.strip()
                if line.startswith('{'):
                    return json.loads(line)
            return {'bugs': [], 'error': 'No JSON output'}
        else:
            return {'bugs': [], 'error': f'Exit {result.returncode}: {result.stderr[:100]}'}
    except subprocess.TimeoutExpired:
        return {'bugs': [], 'error': 'TIMEOUT'}
    except json.JSONDecodeError as e:
        return {'bugs': [], 'error': f'JSON error: {e}'}
    except Exception as e:
        return {'bugs': [], 'error': f'{type(e).__name__}: {str(e)[:80]}'}


def analyze_repo(repo_path: Path) -> dict:
    """Analyze all Python files in a repo."""
    result = {
        'repo_name': repo_path.name,
        'bugs': [],
        'bugs_by_type': {},
        'total_bugs': 0,
        'files_analyzed': 0,
        'files_with_bugs': 0,
        'files_error': 0,
        'files_timeout': 0,
        'errors': [],
        'time_sec': 0.0,
    }
    
    start = time.time()
    py_files = get_python_files(repo_path)
    total_files = len(py_files)
    result['files_analyzed'] = total_files
    
    print(f'  Found {total_files} Python files to analyze')
    
    for i, py_file in enumerate(py_files):
        if (i + 1) % 20 == 0 or i == 0:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (total_files - i - 1) / rate if rate > 0 else 0
            print(f'  [{i+1}/{total_files}] {py_file.name[:35]}... ({rate:.1f} files/s, ETA {eta:.0f}s)', flush=True)
        
        # Print each file for debugging (less frequent)
        if i > 0 and i % 10 == 0:
            sys.stdout.flush()
        
        file_result = analyze_file_subprocess(py_file, repo_path)
        
        if file_result.get('error'):
            result['files_error'] += 1
            if 'TIMEOUT' in file_result['error']:
                result['files_timeout'] += 1
            # Only log first 20 errors
            if len(result['errors']) < 20:
                result['errors'].append({
                    'file': str(py_file.relative_to(repo_path)),
                    'error': file_result['error']
                })
        
        if file_result.get('bugs'):
            result['files_with_bugs'] += 1
            for bug in file_result['bugs']:
                bt = bug['bug_type']
                result['bugs_by_type'][bt] = result['bugs_by_type'].get(bt, 0) + 1
                result['total_bugs'] += 1
                result['bugs'].append(bug)
    
    result['time_sec'] = round(time.time() - start, 2)
    return result


def main():
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    
    # Get all repos, skip codeql (not Python)
    skip_repos = {'codeql'}
    repos = sorted([
        d.name for d in BASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith('.') and d.name not in skip_repos
    ])
    
    print('=' * 70)
    print('PYFROMSCRATCH ANALYSIS - NON-SECURITY BUGS ONLY (FULL REPOS)')
    print('=' * 70)
    print(f'Repos to analyze: {len(repos)}')
    print(f'Output: {OUTPUT_PATH}')
    print()
    
    # Load existing results to resume
    all_results = {'repos': [], 'summary': {}}
    done_repos = set()
    if OUTPUT_PATH.exists():
        try:
            with open(OUTPUT_PATH) as f:
                existing = json.load(f)
                all_results = existing
                done_repos = {r['repo_name'] for r in existing.get('repos', []) if 'total_bugs' in r}
                print(f'Resuming: {len(done_repos)} repos already done')
        except:
            pass
    
    for repo_name in repos:
        if repo_name in done_repos:
            print(f'{repo_name}: SKIPPED (already done)')
            continue
            
        repo_path = BASE_DIR / repo_name
        print(f'\n{repo_name}:')
        
        try:
            result = analyze_repo(repo_path)
            all_results['repos'].append(result)
            
            print(f'  -> Files: {result["files_analyzed"]}, Bugs: {result["total_bugs"]}, '
                  f'Errors: {result["files_error"]} ({result["files_timeout"]} timeouts), Time: {result["time_sec"]}s')
            
            # Save intermediate results
            with open(OUTPUT_PATH, 'w') as f:
                json.dump(all_results, f, indent=2)
                
        except Exception as e:
            print(f'  -> ERROR: {e}')
            all_results['repos'].append({'repo_name': repo_name, 'error': str(e)})
    
    # Calculate summary
    total_bugs = sum(r.get('total_bugs', 0) for r in all_results['repos'])
    total_files = sum(r.get('files_analyzed', 0) for r in all_results['repos'])
    total_errors = sum(r.get('files_error', 0) for r in all_results['repos'])
    total_timeouts = sum(r.get('files_timeout', 0) for r in all_results['repos'])
    
    all_types = Counter()
    for r in all_results['repos']:
        for bt, cnt in r.get('bugs_by_type', {}).items():
            all_types[bt] += cnt
    
    all_results['summary'] = {
        'total_repos': len(repos),
        'total_files': total_files,
        'total_bugs': total_bugs,
        'total_errors': total_errors,
        'total_timeouts': total_timeouts,
        'bugs_by_type': dict(all_types),
    }
    
    # Write final results
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print()
    print('=' * 70)
    print(f'Results saved to: {OUTPUT_PATH}')
    print(f'Total: {total_files} files analyzed, {total_bugs} non-security bugs found')
    print(f'Errors: {total_errors} ({total_timeouts} timeouts)')
    print('=' * 70)
    
    if all_types:
        print('\nBug Types Found:')
        for bt, count in sorted(all_types.items(), key=lambda x: -x[1]):
            print(f'  {bt}: {count}')
    else:
        print('\nNo non-security bugs found!')
    
    print('\nPer-Repo Summary:')
    for r in all_results['repos']:
        if 'error' in r and 'total_bugs' not in r:
            print(f'  {r["repo_name"]}: ERROR')
        else:
            bugs = r.get('total_bugs', 0)
            files = r.get('files_analyzed', 0)
            status = 'CLEAN' if bugs == 0 else f'{bugs} bugs'
            print(f'  {r["repo_name"]}: {files} files, {status}')


if __name__ == '__main__':
    main()
