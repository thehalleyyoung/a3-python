#!/usr/bin/env python3
"""
Iteration 155: httpx and uvicorn Tier 3 Scan
Scan httpx (HTTP client) and uvicorn (ASGI server) to expand tier 3 diversity.
Continue diversity expansion alongside existing tier 3 repos.
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import sys

MAX_FILES_PER_REPO = 100

REPOS = [
    {
        "name": "httpx",
        "path": Path("results/public_repos/clones/httpx"),
        "output": Path("results/public_repos/httpx_tier3_scan_iter155.json"),
        "description": "HTTP client library with HTTP/2 support"
    },
    {
        "name": "uvicorn",
        "path": Path("results/public_repos/clones/uvicorn"),
        "output": Path("results/public_repos/uvicorn_tier3_scan_iter155.json"),
        "description": "Lightning-fast ASGI server implementation"
    }
]

def find_python_files(repo_path):
    """Find Python files excluding tests."""
    result = subprocess.run(
        ["find", str(repo_path), "-name", "*.py", "-type", "f"],
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
    
    return files[:MAX_FILES_PER_REPO]

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

def scan_repo(repo_info):
    """Scan a single repository."""
    print(f"\n{'='*60}")
    print(f"Scanning {repo_info['name']}: {repo_info['description']}")
    print(f"{'='*60}")
    
    print(f"Finding Python files in {repo_info['name']}...")
    files = find_python_files(repo_info['path'])
    print(f"Found {len(files)} files to analyze")
    
    results = {
        "repo": repo_info['name'],
        "description": repo_info['description'],
        "iteration": 155,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "files_analyzed": len(files),
        "results": {}
    }
    
    bug_count = 0
    safe_count = 0
    unknown_count = 0
    error_count = 0
    
    for i, filepath in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {filepath}", end=' ... ')
        result = analyze_file(filepath)
        results["results"][filepath] = result
        
        status = result["status"]
        print(status)
        
        if status == "BUG":
            bug_count += 1
        elif status == "SAFE":
            safe_count += 1
        elif status == "UNKNOWN":
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
    print(f"{repo_info['name']} Results:")
    print(f"  BUG:     {bug_count:3d} ({results['summary']['bug_rate']:.1%})")
    print(f"  SAFE:    {safe_count:3d} ({results['summary']['safe_rate']:.1%})")
    print(f"  UNKNOWN: {unknown_count:3d}")
    print(f"  ERROR:   {error_count:3d}")
    print("="*60)
    
    repo_info['output'].parent.mkdir(parents=True, exist_ok=True)
    with open(repo_info['output'], 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to {repo_info['output']}")
    
    return results["summary"]

def main():
    print("Iteration 155: httpx and uvicorn Tier 3 Scan")
    print("Expanding tier 3 diversity with HTTP client and ASGI server repos")
    
    summaries = {}
    
    for repo_info in REPOS:
        summaries[repo_info['name']] = scan_repo(repo_info)
    
    print("\n" + "="*60)
    print("Combined Tier 3 Summary:")
    print("="*60)
    for repo_name, summary in summaries.items():
        print(f"\n{repo_name}:")
        print(f"  BUG:  {summary['bug']:3d} ({summary['bug_rate']:.1%})")
        print(f"  SAFE: {summary['safe']:3d} ({summary['safe_rate']:.1%})")
    
    print("\n" + "="*60)
    print("Comparison with existing Tier 3:")
    print("  sqlalchemy: 4% BUG (100% validation)")
    print("  poetry:     5% BUG (80% validation)")
    print("  fastapi:   34% BUG (100% validation)")
    print("  mypy:      43% BUG (100% validation)")
    print("  pydantic:  58% BUG (96.6% validation)")
    print("  Overall:    97.9% validation rate (141/144)")
    print("="*60)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
