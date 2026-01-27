#!/usr/bin/env python3
"""
Iteration 224: PyGoat Function-Level Security Analysis
Rescan PyGoat with function-level entry points to detect security bugs.
Previous scan (iter 217) only found 15 PANIC bugs.
This scan should detect CODE_INJECTION, SQL_INJECTION, etc.
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import sys

REPO_PATH = Path("external_tools/pygoat")
OUTPUT_FILE = Path("results/pygoat-our-results-iter224.json")

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
        # Exclude __pycache__, migrations
        if any(x in line.lower() for x in ['__pycache__', 'migration']):
            continue
        files.append(line)
    
    return sorted(files)

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
            
            # Extract function info if present
            function_info = None
            for line in output.split('\n'):
                if "Function:" in line:
                    function_info = line.split("Function:")[1].strip()
                    break
            
            return {
                "result": "BUG", 
                "bug_type": bug_type, 
                "function": function_info,
                "output": output
            }
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
    print("Iteration 224: PyGoat Function-Level Security Scan")
    print("=" * 80)
    
    files = find_python_files()
    print(f"\nFound {len(files)} Python files")
    print(f"Analyzing all files...\n")
    
    results = {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "iteration": 224,
        "repo": "pygoat",
        "files_analyzed": len(files),
        "files": {}
    }
    
    bug_count = 0
    safe_count = 0
    unknown_count = 0
    error_count = 0
    
    bug_types = {}
    security_bugs = []
    
    for i, filepath in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {filepath}...", end=" ", flush=True)
        
        file_result = analyze_file(filepath)
        results["files"][filepath] = file_result
        
        if file_result["result"] == "BUG":
            bug_count += 1
            bug_type = file_result["bug_type"]
            bug_types[bug_type] = bug_types.get(bug_type, 0) + 1
            
            # Track security bugs separately
            if bug_type in ["CODE_INJECTION", "SQL_INJECTION", "COMMAND_INJECTION", 
                           "UNSAFE_DESERIALIZATION", "PATH_INJECTION", "FULL_SSRF",
                           "XXE", "XML_BOMB", "CLEARTEXT_LOGGING", "CLEARTEXT_STORAGE",
                           "WEAK_CRYPTO_ALGORITHM", "INSECURE_COOKIE", "FLASK_DEBUG",
                           "COOKIE_INJECTION"]:
                security_bugs.append({
                    "file": filepath,
                    "bug_type": bug_type,
                    "function": file_result.get("function")
                })
            
            print(f"BUG ({bug_type})")
        elif file_result["result"] == "SAFE":
            safe_count += 1
            print("SAFE")
        elif file_result["result"] == "UNKNOWN":
            unknown_count += 1
            print("UNKNOWN")
        else:
            error_count += 1
            print("ERROR")
    
    # Summary
    results["summary"] = {
        "total": len(files),
        "bug": bug_count,
        "safe": safe_count,
        "unknown": unknown_count,
        "error": error_count,
        "bug_rate": bug_count / len(files) if len(files) > 0 else 0,
        "safe_rate": safe_count / len(files) if len(files) > 0 else 0,
    }
    
    results["bug_types"] = bug_types
    results["security_bugs"] = security_bugs
    results["security_bug_count"] = len(security_bugs)
    
    # Write results
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)
    print(f"Total files:      {len(files)}")
    print(f"BUG:              {bug_count} ({results['summary']['bug_rate']:.1%})")
    print(f"SAFE:             {safe_count} ({results['summary']['safe_rate']:.1%})")
    print(f"UNKNOWN:          {unknown_count}")
    print(f"ERROR:            {error_count}")
    print(f"\nSecurity bugs:    {len(security_bugs)}")
    print("\nBug type breakdown:")
    for bug_type, count in sorted(bug_types.items(), key=lambda x: x[1], reverse=True):
        print(f"  {bug_type}: {count}")
    
    if security_bugs:
        print("\nSecurity bug details:")
        for sb in security_bugs:
            print(f"  {sb['file']}")
            print(f"    Type: {sb['bug_type']}")
            if sb['function']:
                print(f"    Function: {sb['function']}")
    
    print(f"\nResults saved to: {OUTPUT_FILE}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
