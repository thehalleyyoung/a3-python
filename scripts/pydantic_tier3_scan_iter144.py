#!/usr/bin/env python3
"""
Iteration 144: Pydantic Tier 3 Scan
Scan pydantic (popular validation library) as second tier 3 repo.
Continue evaluation of specialized libraries after sqlalchemy.
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import sys

REPO_PATH = Path("results/public_repos/clones/pydantic")
OUTPUT_FILE = Path("results/public_repos/pydantic_tier3_scan_iter144.json")
MAX_FILES = 100

def find_python_files():
    """Find Python files excluding tests."""
    result = subprocess.run(
        ["find", str(REPO_PATH), "-name", "*.py", "-type", "f"],
        capture_output=True,
        text=True
    )
    
    files = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        # Exclude tests, __pycache__, examples
        if any(x in line.lower() for x in ['test', '__pycache__', 'example']):
            continue
        files.append(line)
    
    return files[:MAX_FILES]

def analyze_file(filepath):
    """Analyze a single Python file."""
    try:
        result = subprocess.run(
            ["python3", "-m", "pyfromscratch.cli", filepath],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=Path.cwd()
        )
        
        output = result.stdout.strip()
        
        # Parse result
        if "BUG:" in output:
            # Extract bug type
            bug_line = [l for l in output.split('\n') if l.startswith('BUG:')][0]
            bug_type = bug_line.split(':')[1].strip().split()[0]
            return {"result": "BUG", "bug_type": bug_type, "output": output}
        elif "SAFE" in output:
            return {"result": "SAFE", "output": output}
        elif "UNKNOWN" in output:
            return {"result": "UNKNOWN", "output": output}
        elif "ERROR" in output or result.returncode != 0:
            return {"result": "ERROR", "output": output, "stderr": result.stderr}
        else:
            return {"result": "UNKNOWN", "output": output}
            
    except subprocess.TimeoutExpired:
        return {"result": "ERROR", "output": "Timeout (30s)"}
    except Exception as e:
        return {"result": "ERROR", "output": f"Exception: {str(e)}"}

def main():
    print("=" * 80)
    print("Iteration 144: Pydantic Tier 3 Scan")
    print("=" * 80)
    
    files = find_python_files()
    print(f"\nFound {len(files)} Python files (excluding tests)")
    print(f"Analyzing first {MAX_FILES} files...\n")
    
    results = {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "iteration": 144,
        "repo": "pydantic",
        "tier": 3,
        "files_analyzed": len(files),
        "max_files": MAX_FILES,
        "files": {},
        "summary": {
            "BUG": 0,
            "SAFE": 0,
            "UNKNOWN": 0,
            "ERROR": 0
        },
        "bug_types": {}
    }
    
    for i, filepath in enumerate(files, 1):
        rel_path = Path(filepath).relative_to(REPO_PATH)
        print(f"[{i}/{len(files)}] {rel_path}...", end=' ', flush=True)
        
        file_result = analyze_file(filepath)
        result_type = file_result["result"]
        
        print(result_type)
        
        results["files"][str(rel_path)] = file_result
        results["summary"][result_type] += 1
        
        if result_type == "BUG":
            bug_type = file_result.get("bug_type", "UNKNOWN")
            results["bug_types"][bug_type] = results["bug_types"].get(bug_type, 0) + 1
    
    # Calculate rates
    total = len(files)
    results["summary"]["bug_rate"] = results["summary"]["BUG"] / total if total > 0 else 0
    results["summary"]["safe_rate"] = results["summary"]["SAFE"] / total if total > 0 else 0
    results["summary"]["unknown_rate"] = results["summary"]["UNKNOWN"] / total if total > 0 else 0
    results["summary"]["error_rate"] = results["summary"]["ERROR"] / total if total > 0 else 0
    
    # Save results
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total files: {total}")
    print(f"BUG:     {results['summary']['BUG']:3d} ({results['summary']['bug_rate']:.1%})")
    print(f"SAFE:    {results['summary']['SAFE']:3d} ({results['summary']['safe_rate']:.1%})")
    print(f"UNKNOWN: {results['summary']['UNKNOWN']:3d} ({results['summary']['unknown_rate']:.1%})")
    print(f"ERROR:   {results['summary']['ERROR']:3d} ({results['summary']['error_rate']:.1%})")
    
    if results["bug_types"]:
        print("\nBug types:")
        for bug_type, count in sorted(results["bug_types"].items(), key=lambda x: -x[1]):
            print(f"  {bug_type}: {count}")
    
    print(f"\nResults saved to: {OUTPUT_FILE}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
