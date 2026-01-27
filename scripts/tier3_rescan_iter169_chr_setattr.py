#!/usr/bin/env python3
"""Tier 3 rescan after chr/setattr builtins (iteration 169)."""

import subprocess
import json
from pathlib import Path
from datetime import datetime

REPOS = {
    'pydantic': 'results/public_repos/clones/pydantic',
    'sqlalchemy': 'results/public_repos/clones/sqlalchemy',
    'mypy': 'results/public_repos/clones/mypy',
}

def scan_repo(repo_name, repo_path, max_files=100):
    """Scan a repo and return results."""
    print(f"\n{'='*80}")
    print(f"Scanning {repo_name}...")
    print(f"{'='*80}")
    
    # Use same filtering as previous scans - exclude tests, examples, __pycache__
    py_files = []
    for f in Path(repo_path).rglob('*.py'):
        path_str = str(f).lower()
        if any(x in path_str for x in ['test', '__pycache__', 'example']):
            continue
        py_files.append(f)
    
    py_files = py_files[:max_files]
    
    results = {'BUG': 0, 'SAFE': 0, 'UNKNOWN': 0, 'ERROR': 0}
    bug_details = []
    
    for py_file in py_files:
        try:
            result = subprocess.run(
                ['python3', '-m', 'pyfromscratch.cli', str(py_file)],
                capture_output=True,
                text=True,
                timeout=30,
                cwd='/Users/halleyyoung/Documents/PythonFromScratch'
            )
            
            output = result.stdout
            
            # More robust result parsing - output format is "BUG: TYPE", "SAFE", "UNKNOWN"
            if result.returncode == 0 or 'BUG:' in output:
                if 'BUG:' in output:
                    results['BUG'] += 1
                    # Extract bug type from "BUG: TYPE_CONFUSION" format
                    bug_type = 'UNKNOWN'
                    for line in output.split('\n'):
                        line = line.strip()
                        if line.startswith('BUG:'):
                            bug_type = line.split(':', 1)[1].strip()
                            break
                    bug_details.append({
                        'file': str(py_file.relative_to(repo_path)),
                        'type': bug_type
                    })
                elif 'SAFE' in output and 'BUG' not in output:
                    results['SAFE'] += 1
                elif 'UNKNOWN' in output:
                    results['UNKNOWN'] += 1
                else:
                    results['ERROR'] += 1
            else:
                results['ERROR'] += 1
                
        except subprocess.TimeoutExpired:
            results['ERROR'] += 1
        except Exception as e:
            results['ERROR'] += 1
            
    total = sum(results.values())
    print(f"\nResults for {repo_name}:")
    print(f"  Files: {len(py_files)}")
    print(f"  BUG: {results['BUG']} ({results['BUG']/total*100:.1f}%)")
    print(f"  SAFE: {results['SAFE']} ({results['SAFE']/total*100:.1f}%)")
    print(f"  UNKNOWN: {results['UNKNOWN']} ({results['UNKNOWN']/total*100:.1f}%)")
    print(f"  ERROR: {results['ERROR']} ({results['ERROR']/total*100:.1f}%)")
    
    if bug_details:
        print(f"\nBug breakdown:")
        bug_types = {}
        for bug in bug_details:
            bug_types[bug['type']] = bug_types.get(bug['type'], 0) + 1
        for bt, count in sorted(bug_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {bt}: {count}")
    
    return {
        'files': len(py_files),
        'results': results,
        'bugs': bug_details
    }

def main():
    print("Tier 3 Rescan - chr/setattr Impact (Iteration 169)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    all_results = {}
    
    for repo_name, repo_path in REPOS.items():
        if not Path(repo_path).exists():
            print(f"\nSkipping {repo_name} - not found at {repo_path}")
            continue
        
        all_results[repo_name] = scan_repo(repo_name, repo_path)
    
    # Summary
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    
    total_files = sum(r['files'] for r in all_results.values())
    total_bugs = sum(r['results']['BUG'] for r in all_results.values())
    total_safe = sum(r['results']['SAFE'] for r in all_results.values())
    
    print(f"Total files: {total_files}")
    if total_files > 0:
        print(f"Total BUG: {total_bugs} ({total_bugs/total_files*100:.1f}%)")
        print(f"Total SAFE: {total_safe} ({total_safe/total_files*100:.1f}%)")
    else:
        print("No files scanned")
    
    # Compare with previous iteration (168)
    print("\nComparison with previous scans:")
    previous = {
        'pydantic': {'iteration': 144, 'bugs': 58, 'rate': 0.58},
        'sqlalchemy': {'iteration': 142, 'bugs': 4, 'rate': 0.04},
        'mypy': {'iteration': 146, 'bugs': 43, 'rate': 0.43},
    }
    
    for repo_name in all_results:
        if repo_name in previous:
            prev = previous[repo_name]
            curr_bugs = all_results[repo_name]['results']['BUG']
            curr_rate = curr_bugs / all_results[repo_name]['files']
            delta = curr_bugs - prev['bugs']
            rate_delta = curr_rate - prev['rate']
            
            print(f"\n{repo_name}:")
            print(f"  Previous (iter {prev['iteration']}): {prev['bugs']} bugs ({prev['rate']*100:.1f}%)")
            print(f"  Current (iter 169): {curr_bugs} bugs ({curr_rate*100:.1f}%)")
            print(f"  Delta: {delta:+d} bugs ({rate_delta*100:+.1f}pp)")
    
    # Save results
    output_file = Path('results/tier3_rescan_iter169.json')
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump({
            'iteration': 169,
            'timestamp': datetime.now().isoformat(),
            'repos': all_results,
            'summary': {
                'total_files': total_files,
                'total_bugs': total_bugs,
                'total_safe': total_safe,
                'bug_rate': total_bugs / total_files if total_files > 0 else 0,
            }
        }, f, indent=2)
    
    print(f"\nResults saved to {output_file}")

if __name__ == '__main__':
    main()
