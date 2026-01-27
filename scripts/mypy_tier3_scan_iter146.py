#!/usr/bin/env python3
"""
Iteration 146: Mypy Tier 3 Scan
Scan mypy (Python static type checker) as third tier 3 repo.
Continue evaluation of specialized libraries after sqlalchemy and pydantic.
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import sys

REPO_PATH = Path("results/public_repos/clones/mypy")
OUTPUT_FILE = Path("results/public_repos/mypy_tier3_scan_iter146.json")
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
            return {"status": "BUG", "output": output}
        elif "SAFE:" in output:
            return {"status": "SAFE", "output": output}
        elif "UNKNOWN:" in output:
            return {"status": "UNKNOWN", "output": output}
        elif "ERROR:" in output:
            return {"status": "ERROR", "output": output}
        else:
            return {"status": "ERROR", "output": f"Unparseable: {output}"}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "output": "Timeout"}
    except Exception as e:
        return {"status": "ERROR", "output": str(e)}

def main():
    print("Finding Python files in mypy...")
    files = find_python_files()
    print(f"Found {len(files)} files to analyze")
    
    results = {
        "repo": "mypy",
        "iteration": 146,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "files_analyzed": len(files),
        "results": {}
    }
    
    bug_count = 0
    safe_count = 0
    unknown_count = 0
    error_count = 0
    
    for i, filepath in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {filepath}")
        result = analyze_file(filepath)
        results["results"][filepath] = result
        
        if result["status"] == "BUG":
            bug_count += 1
        elif result["status"] == "SAFE":
            safe_count += 1
        elif result["status"] == "UNKNOWN":
            unknown_count += 1
        else:
            error_count += 1
    
    results["summary"] = {
        "bug": bug_count,
        "safe": safe_count,
        "unknown": unknown_count,
        "error": error_count,
        "bug_rate": bug_count / len(files) if files else 0,
        "safe_rate": safe_count / len(files) if files else 0
    }
    
    print("\n" + "="*60)
    print(f"Mypy Tier 3 Scan Results:")
    print(f"  BUG:     {bug_count:3d} ({results['summary']['bug_rate']:.1%})")
    print(f"  SAFE:    {safe_count:3d} ({results['summary']['safe_rate']:.1%})")
    print(f"  UNKNOWN: {unknown_count:3d}")
    print(f"  ERROR:   {error_count:3d}")
    print("="*60)
    
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {OUTPUT_FILE}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
