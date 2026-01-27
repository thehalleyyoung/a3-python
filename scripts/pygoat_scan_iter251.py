#!/usr/bin/env python3
"""Scan all PyGoat Python files with function-level entry points."""

import sys
from pathlib import Path
from pyfromscratch.analyzer import analyze_file

pygoat_dir = Path("external_tools/pygoat")

# Find all Python files
py_files = sorted(pygoat_dir.rglob("*.py"))
print(f"Found {len(py_files)} Python files in PyGoat")

results = {"BUG": [], "SAFE": [], "UNKNOWN": [], "ERROR": []}
security_bugs = []

for py_file in py_files:
    print(f"Scanning {py_file}...")
    try:
        result = analyze_file(str(py_file), enable_concolic=True, analyze_functions=True, max_paths=100)
        
        # Aggregate results
        overall_result = result.get("overall", "UNKNOWN")
        results[overall_result].append(str(py_file))
        
        # Check for security bugs in function-level results
        function_results = result.get("function_results", {})
        for func_name, func_result in function_results.items():
            if func_result.get("verdict") == "BUG":
                bug_types = func_result.get("bug_types", [])
                # Security bug types from the lattice
                security_bug_types = ["CODE_INJECTION", "SQL_INJECTION", "COMMAND_INJECTION", 
                                      "PATH_INJECTION", "FULL_SSRF", "PARTIAL_SSRF",
                                      "UNSAFE_DESERIALIZATION", "XXE", "XML_BOMB",
                                      "CLEARTEXT_LOGGING", "CLEARTEXT_STORAGE", 
                                      "WEAK_CRYPTO_ALGORITHM", "INSECURE_COOKIE", 
                                      "FLASK_DEBUG", "COOKIE_INJECTION", "REFLECTED_XSS",
                                      "HEADER_INJECTION", "URL_REDIRECT", "CSRF_PROTECTION_DISABLED"]
                
                for bug_type in bug_types:
                    if bug_type in security_bug_types:
                        security_bugs.append({
                            "file": str(py_file),
                            "function": func_name,
                            "bug_type": bug_type
                        })
                        print(f"  SECURITY BUG FOUND: {bug_type} in {func_name}")
        
    except Exception as e:
        print(f"  ERROR: {e}")
        results["ERROR"].append(str(py_file))

# Print summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"BUG: {len(results['BUG'])}")
print(f"SAFE: {len(results['SAFE'])}")
print(f"UNKNOWN: {len(results['UNKNOWN'])}")
print(f"ERROR: {len(results['ERROR'])}")
print(f"\nSECURITY BUGS FOUND: {len(security_bugs)}")
if security_bugs:
    print("\nSecurity bugs by type:")
    by_type = {}
    for bug in security_bugs:
        bt = bug["bug_type"]
        by_type[bt] = by_type.get(bt, 0) + 1
    for bug_type, count in sorted(by_type.items()):
        print(f"  {bug_type}: {count}")
    
    print("\nAll security bug locations:")
    for bug in security_bugs:
        print(f"  {bug['file']}:{bug['function']} - {bug['bug_type']}")
