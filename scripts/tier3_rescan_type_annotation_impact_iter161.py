#!/usr/bin/env python3
"""
Iteration 161: Tier 3 Rescan for Type Annotation Fix Impact
Rescan mypy, httpx, uvicorn to measure impact of iteration 160 type annotation semantics fix.
Iteration 160 fixed BINARY_OP subscript on OBJ-tagged values (type parameterization) to avoid false BOUNDS bugs.
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import sys

MAX_FILES_PER_REPO = 100

REPOS = [
    {
        "name": "mypy",
        "path": Path("results/public_repos/clones/mypy"),
        "output": Path("results/public_repos/mypy_tier3_rescan_iter161.json"),
        "description": "Type checker - BOUNDS-heavy (33%), previous scan: 43 bugs",
        "previous_scan": {
            "iteration": 146,
            "bugs": 43,
            "bug_rate": 0.43,
            "bounds": 14,
            "type_confusion": 12,
            "panic": 15
        }
    },
    {
        "name": "httpx",
        "path": Path("results/public_repos/clones/httpx"),
        "output": Path("results/public_repos/httpx_tier3_rescan_iter161.json"),
        "description": "HTTP client - previous scan: 10 bugs (43.5% rate)",
        "previous_scan": {
            "iteration": 155,
            "bugs": 10,
            "bug_rate": 0.435,
            "bounds": 2,
            "panic": 7,
            "null_ptr": 1
        }
    },
    {
        "name": "uvicorn",
        "path": Path("results/public_repos/clones/uvicorn"),
        "output": Path("results/public_repos/uvicorn_tier3_rescan_iter161.json"),
        "description": "ASGI server - previous scan: 17 bugs (41.5% rate)",
        "previous_scan": {
            "iteration": 155,
            "bugs": 17,
            "bug_rate": 0.415,
            "panic": 11,
            "type_confusion": 4,
            "null_ptr": 2
        }
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
    """Analyze a single file."""
    try:
        result = subprocess.run(
            ["python3", "-m", "pyfromscratch.cli", filepath],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout.strip()
        if not output:
            return {"status": "UNKNOWN", "error": "no_output"}
        
        # Parse result
        if "BUG:" in output:
            # Extract bug type and details
            lines = output.split('\n')
            bug_type = None
            function = None
            exception = None
            
            for line in lines:
                if "BUG:" in line:
                    parts = line.split()
                    if len(parts) > 1:
                        bug_type = parts[1]
                if "Function:" in line:
                    function = line.split("Function:", 1)[1].strip()
                if "Exception:" in line:
                    exception = line.split("Exception:", 1)[1].strip()
            
            return {
                "status": "BUG",
                "bug_type": bug_type,
                "function": function,
                "exception": exception,
                "raw": output
            }
        elif "SAFE" in output:
            return {"status": "SAFE", "raw": output}
        elif "UNKNOWN" in output:
            return {"status": "UNKNOWN", "raw": output}
        else:
            return {"status": "ERROR", "error": "unparsed_output", "raw": output}
            
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "error": "timeout"}
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

def scan_repo(repo):
    """Scan a repository."""
    print(f"\n{'='*80}")
    print(f"Scanning {repo['name']}: {repo['description']}")
    print(f"Previous scan (iter {repo['previous_scan']['iteration']}): {repo['previous_scan']['bugs']} bugs")
    print(f"{'='*80}\n")
    
    if not repo["path"].exists():
        print(f"ERROR: Repository not found at {repo['path']}")
        return None
    
    files = find_python_files(repo["path"])
    print(f"Found {len(files)} Python files to analyze")
    
    results = {
        "repo": repo["name"],
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "iteration": 161,
        "previous_scan": repo["previous_scan"],
        "files_analyzed": len(files),
        "results": {}
    }
    
    bug_count = 0
    safe_count = 0
    unknown_count = 0
    error_count = 0
    bug_types = {}
    
    for i, filepath in enumerate(files, 1):
        rel_path = str(Path(filepath).relative_to(repo["path"]))
        print(f"[{i}/{len(files)}] {rel_path}...", end=' ', flush=True)
        
        result = analyze_file(filepath)
        results["results"][rel_path] = result
        
        status = result["status"]
        if status == "BUG":
            bug_count += 1
            bug_type = result.get("bug_type", "UNKNOWN")
            bug_types[bug_type] = bug_types.get(bug_type, 0) + 1
            print(f"BUG ({bug_type})")
        elif status == "SAFE":
            safe_count += 1
            print("SAFE")
        elif status == "UNKNOWN":
            unknown_count += 1
            print("UNKNOWN")
        else:
            error_count += 1
            print(f"ERROR ({result.get('error', 'unknown')})")
    
    results["summary"] = {
        "bug": bug_count,
        "safe": safe_count,
        "unknown": unknown_count,
        "error": error_count,
        "bug_rate": bug_count / len(files) if files else 0,
        "safe_rate": safe_count / len(files) if files else 0,
        "bug_types": bug_types
    }
    
    # Save results
    repo["output"].parent.mkdir(parents=True, exist_ok=True)
    with open(repo["output"], 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {repo['output']}")
    
    return results

def main():
    print("Iteration 161: Type Annotation Fix Impact Rescan")
    print("Iteration 160 fix: OBJ-tagged BINARY_OP subscript treated as type parameterization")
    print("Expected impact: Reduction in false BOUNDS bugs from type annotations like Mapping[K,V]\n")
    
    all_results = {}
    
    for repo in REPOS:
        result = scan_repo(repo)
        if result:
            all_results[repo["name"]] = result
    
    # Summary comparison
    print(f"\n{'='*80}")
    print("SUMMARY COMPARISON")
    print(f"{'='*80}\n")
    
    total_previous_bugs = 0
    total_current_bugs = 0
    total_previous_files = 0
    total_current_files = 0
    
    for repo_name, result in all_results.items():
        prev = result["previous_scan"]
        curr = result["summary"]
        
        total_previous_bugs += prev["bugs"]
        total_current_bugs += curr["bug"]
        total_previous_files += result["files_analyzed"]
        total_current_files += result["files_analyzed"]
        
        bug_delta = curr["bug"] - prev["bugs"]
        rate_delta = curr["bug_rate"] - prev["bug_rate"]
        
        print(f"{repo_name}:")
        print(f"  Previous (iter {prev['iteration']}): {prev['bugs']} bugs ({prev['bug_rate']:.1%})")
        print(f"  Current (iter 161): {curr['bug']} bugs ({curr['bug_rate']:.1%})")
        print(f"  Delta: {bug_delta:+d} bugs ({rate_delta:+.1%})")
        if bug_delta < 0:
            improvement_pct = abs(bug_delta) / prev["bugs"] * 100 if prev["bugs"] > 0 else 0
            print(f"  Improvement: {improvement_pct:.1f}% reduction")
        print(f"  Bug types: {curr['bug_types']}")
        print()
    
    overall_bug_delta = total_current_bugs - total_previous_bugs
    overall_rate_prev = total_previous_bugs / total_previous_files if total_previous_files > 0 else 0
    overall_rate_curr = total_current_bugs / total_current_files if total_current_files > 0 else 0
    overall_rate_delta = overall_rate_curr - overall_rate_prev
    
    print(f"Overall (3 repos, {total_current_files} files):")
    print(f"  Previous: {total_previous_bugs} bugs ({overall_rate_prev:.1%})")
    print(f"  Current: {total_current_bugs} bugs ({overall_rate_curr:.1%})")
    print(f"  Delta: {overall_bug_delta:+d} bugs ({overall_rate_delta:+.1%})")
    if overall_bug_delta < 0:
        improvement_pct = abs(overall_bug_delta) / total_previous_bugs * 100 if total_previous_bugs > 0 else 0
        print(f"  Improvement: {improvement_pct:.1f}% reduction")

if __name__ == "__main__":
    main()
