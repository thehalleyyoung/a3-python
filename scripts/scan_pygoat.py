#!/usr/bin/env python3
"""
Scan PyGoat with our checker and collect results for comparison with CodeQL.
"""
import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone

def find_python_files(root_dir):
    """Find all Python files in PyGoat, excluding venv/cache dirs."""
    py_files = []
    for root, dirs, files in os.walk(root_dir):
        # Skip venv, .git, __pycache__, etc.
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', '__pycache__', 'node_modules', 'migrations')]
        for f in files:
            if f.endswith('.py') and not f.startswith('__'):
                py_files.append(os.path.join(root, f))
    return sorted(py_files)

def run_analyzer(file_path):
    """Run our analyzer on a file and capture results."""
    try:
        result = subprocess.run(
            ['python3', '-m', 'pyfromscratch.cli', file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            'file': file_path,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            'file': file_path,
            'stdout': '',
            'stderr': 'TIMEOUT',
            'returncode': -1
        }
    except Exception as e:
        return {
            'file': file_path,
            'stdout': '',
            'stderr': str(e),
            'returncode': -2
        }

def parse_result(result):
    """Parse analyzer output to extract verdict and bugs."""
    stdout = result['stdout']
    file_path = result['file']
    
    # Extract verdict
    if 'BUG:' in stdout:
        verdict = 'BUG'
        # Extract bug types
        bugs = []
        for line in stdout.split('\n'):
            if line.strip().startswith('BUG:'):
                bugs.append(line.strip())
        return {'verdict': verdict, 'bugs': bugs, 'file': file_path}
    elif 'SAFE:' in stdout:
        return {'verdict': 'SAFE', 'bugs': [], 'file': file_path}
    elif 'UNKNOWN:' in stdout:
        return {'verdict': 'UNKNOWN', 'bugs': [], 'file': file_path}
    elif 'ERROR:' in stdout or result['returncode'] != 0:
        return {'verdict': 'ERROR', 'bugs': [], 'file': file_path, 'error': result['stderr']}
    else:
        return {'verdict': 'UNKNOWN', 'bugs': [], 'file': file_path}

def main():
    pygoat_dir = 'external_tools/pygoat'
    output_file = 'results/pygoat-our-results.json'
    
    print(f"Scanning PyGoat at {pygoat_dir}...")
    
    py_files = find_python_files(pygoat_dir)
    print(f"Found {len(py_files)} Python files")
    
    results = []
    for i, file_path in enumerate(py_files, 1):
        print(f"[{i}/{len(py_files)}] Analyzing {os.path.relpath(file_path, pygoat_dir)}...", end='', flush=True)
        result = run_analyzer(file_path)
        parsed = parse_result(result)
        results.append(parsed)
        print(f" {parsed['verdict']}")
    
    # Summarize
    verdicts = {}
    for r in results:
        v = r['verdict']
        verdicts[v] = verdicts.get(v, 0) + 1
    
    summary = {
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'total_files': len(py_files),
        'verdicts': verdicts,
        'results': results
    }
    
    # Save results
    os.makedirs('results', exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nResults saved to {output_file}")
    print(f"\nSummary:")
    print(f"  Total files: {len(py_files)}")
    for verdict, count in sorted(verdicts.items()):
        print(f"  {verdict}: {count} ({100*count/len(py_files):.1f}%)")

if __name__ == '__main__':
    main()
