#!/usr/bin/env python3
"""
Analyze all external repos using subprocess with timeout per repo.
This ensures we get results even if some repos take too long.
"""

import subprocess
import sys
import json
import time
from pathlib import Path
from collections import Counter

def analyze_repo_subprocess(repo_path, max_files=10, timeout=120):
    """Analyze a repo using subprocess with timeout."""
    
    script = f'''
import sys
import json
sys.path.insert(0, "{Path(__file__).parent}")
from pathlib import Path
from pyfromscratch.analyzer import Analyzer

def main():
    repo_path = Path("{repo_path}")
    analyzer = Analyzer(verbose=False)
    
    skip = ['test', 'build', 'setup', '__pycache__', 'versioneer', 'conftest']
    py_files = []
    for f in repo_path.rglob('*.py'):
        if not any(s in str(f).lower() for s in skip):
            py_files.append(f)
            if len(py_files) >= {max_files}:
                break
    
    results = {{"bugs": [], "files": len(py_files), "errors": []}}
    
    for pf in py_files:
        try:
            analysis = analyzer.analyze_file(pf)
            if analysis.verdict == "BUG":
                if analysis.interprocedural_bugs:
                    for bug in analysis.interprocedural_bugs:
                        results["bugs"].append({{
                            "file": str(pf.relative_to(repo_path)),
                            "bug_type": getattr(bug, "bug_type", "UNKNOWN"),
                            "line": getattr(bug, "line", 0),
                        }})
                elif analysis.counterexample:
                    cx = analysis.counterexample
                    results["bugs"].append({{
                        "file": str(pf.relative_to(repo_path)),
                        "bug_type": cx.get("bug_type", analysis.bug_type or "UNKNOWN"),
                        "line": cx.get("line", 0),
                    }})
                elif analysis.bug_type:
                    results["bugs"].append({{
                        "file": str(pf.relative_to(repo_path)),
                        "bug_type": analysis.bug_type,
                        "line": 0,
                    }})
        except Exception as e:
            results["errors"].append(str(e)[:50])
    
    print(json.dumps(results))

main()
'''
    
    try:
        result = subprocess.run(
            [sys.executable, '-c', script],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(Path(__file__).parent)
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
        else:
            return {"bugs": [], "files": 0, "errors": [result.stderr[:100] if result.stderr else "Unknown error"]}
    
    except subprocess.TimeoutExpired:
        return {"bugs": [], "files": 0, "errors": ["TIMEOUT"]}
    except Exception as e:
        return {"bugs": [], "files": 0, "errors": [str(e)[:50]]}


def main():
    base = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools')
    output_path = Path('/Users/halleyyoung/Documents/PythonFromScratch/results/all_repos_analysis.json')
    
    repos = sorted([d.name for d in base.iterdir() if d.is_dir() and d.name not in {'.', 'codeql'}])
    
    print(f'Analyzing {len(repos)} repos with subprocess timeout...')
    
    all_results = {'repos': [], 'summary': {}}
    
    # Create empty file first to confirm we can write
    with open(output_path, 'w') as f:
        json.dump(all_results, f)
    print(f'Created: {output_path}')
    
    for repo in repos:
        print(f'{repo}...', end=' ', flush=True)
        start = time.time()
        
        repo_path = base / repo
        res = analyze_repo_subprocess(repo_path, max_files=5, timeout=60)
        
        elapsed = round(time.time() - start, 2)
        
        # Build result
        bugs_by_type = Counter(b['bug_type'] for b in res['bugs'])
        
        repo_result = {
            'repo_name': repo,
            'bugs': res['bugs'],
            'bugs_by_type': dict(bugs_by_type),
            'total_bugs': len(res['bugs']),
            'files_analyzed': res['files'],
            'errors': res['errors'],
            'time_sec': elapsed
        }
        
        all_results['repos'].append(repo_result)
        
        print(f'{repo_result["total_bugs"]} bugs, {repo_result["files_analyzed"]} files, {elapsed}s')
        if res['errors']:
            print(f'  Errors: {res["errors"]}')
        
        # Save after each repo
        with open(output_path, 'w') as f:
            json.dump(all_results, f, indent=2)
    
    # Summary
    total_bugs = sum(r['total_bugs'] for r in all_results['repos'])
    total_files = sum(r['files_analyzed'] for r in all_results['repos'])
    
    all_types = Counter()
    for r in all_results['repos']:
        for bt, cnt in r['bugs_by_type'].items():
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
    print(f'Bug types: {dict(all_types)}')
    print(f'Saved: {output_path}')


if __name__ == '__main__':
    main()
