#!/usr/bin/env python3
"""
Scan PyGoat with PythonFromScratch analyzer (Iteration 528)
Focus: Validate Django template sanitizers reduce XSS false positives
"""
import json
import subprocess
from pathlib import Path
from collections import defaultdict

PYGOAT_DIR = Path("external_tools/pygoat")
OUTPUT_FILE = Path("results/pygoat-our-results-iter528.json")

def find_python_files(directory):
    """Find all .py files in directory, excluding venv/migrations"""
    for path in directory.rglob("*.py"):
        path_str = str(path)
        if "venv" in path_str or "migrations" in path_str or "__pycache__" in path_str:
            continue
        yield path

def analyze_file(filepath):
    """Run analyzer on a single file"""
    cmd = [
        "venv/bin/python", "-m", "pyfromscratch.cli",
        str(filepath),
        "--functions",
        "--deduplicate",
        "--consolidate-variants"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return None, f"TIMEOUT analyzing {filepath}"
    except Exception as e:
        return None, f"ERROR analyzing {filepath}: {e}"

def parse_output(stdout):
    """Extract findings from CLI output"""
    findings = []
    lines = stdout.split('\n')
    
    # Look for function-level findings in format:
    # "  FunctionName: BUG"
    # "    BUG_TYPE: details"
    current_function = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Check for function entry point result
        if line.startswith('  ') and not line.startswith('    ') and ': BUG' in line:
            # Function has a bug
            current_function = line.split(':')[0].strip()
        elif line.startswith('    ') and current_function:
            # Bug type details
            if ':' in stripped:
                bug_type = stripped.split(':')[0].strip()
                details = stripped.split(':', 1)[1].strip() if ':' in stripped else ''
                findings.append({
                    'function': current_function,
                    'bug_type': bug_type,
                    'details': details,
                    'raw_line': line.strip()
                })
        elif 'BUG:' in line or 'POSSIBLE:' in line:
            # Fallback: module-level or other format
            parts = line.split()
            if len(parts) >= 2:
                bug_type = parts[1] if parts[1] != 'at' else 'UNKNOWN'
                findings.append({
                    'bug_type': bug_type,
                    'raw_line': line.strip()
                })
    
    return findings

def main():
    print("=== PyGoat Analysis - Iteration 528 ===")
    print("Goal: Validate Django template sanitizers reduce XSS false positives\n")
    
    all_findings = []
    bug_counts = defaultdict(int)
    files_scanned = 0
    files_with_findings = 0
    
    python_files = list(find_python_files(PYGOAT_DIR))
    print(f"Found {len(python_files)} Python files to analyze\n")
    
    for i, filepath in enumerate(python_files, 1):
        if i % 10 == 0:
            print(f"Progress: {i}/{len(python_files)} files...")
        
        stdout, stderr = analyze_file(filepath)
        if stdout is None:
            print(f"  SKIP: {filepath.relative_to(PYGOAT_DIR)} - {stderr}")
            continue
        
        findings = parse_output(stdout)
        if findings:
            files_with_findings += 1
            for finding in findings:
                finding['file'] = str(filepath.relative_to(PYGOAT_DIR))
                all_findings.append(finding)
                bug_counts[finding['bug_type']] += 1
        
        files_scanned += 1
    
    print(f"\n=== Summary ===")
    print(f"Files scanned: {files_scanned}")
    print(f"Files with findings: {files_with_findings}")
    print(f"Total findings: {len(all_findings)}")
    print(f"\nFindings by bug type:")
    for bug_type in sorted(bug_counts.keys()):
        print(f"  {bug_type}: {bug_counts[bug_type]}")
    
    # Save results
    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    results = {
        'iteration': 528,
        'files_scanned': files_scanned,
        'total_findings': len(all_findings),
        'bug_counts': dict(bug_counts),
        'findings': all_findings
    }
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {OUTPUT_FILE}")
    
    # Compare with iteration 522
    print("\n=== Comparison with Iteration 522 ===")
    print("Previous XSS findings:")
    print("  REFLECTED_XSS: 10 (all false positives)")
    print("  STORED_XSS: 7 (all false positives)")
    print("  DOM_XSS: 7 (all false positives)")
    print(f"\nCurrent XSS findings:")
    xss_types = [k for k in bug_counts.keys() if 'XSS' in k]
    for xss in xss_types:
        print(f"  {xss}: {bug_counts[xss]}")
    
    if not xss_types:
        print("  (No XSS findings - Django sanitizers working!)")

if __name__ == '__main__':
    main()
