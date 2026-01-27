#!/usr/bin/env python3
"""
Quick evaluation of new synthetic test cases
"""

import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.cli import analyze_file

# Test programs to evaluate
NEW_TESTS = [
    "sql_injection_001.py",
    "sql_injection_002.py",
    "sql_injection_safe_001.py",
    "command_injection_001.py",
    "command_injection_002.py",
    "command_injection_safe_001.py",
    "path_injection_001.py",
    "path_injection_002.py",
    "cleartext_logging_001.py",
    "cleartext_logging_safe_001.py",
    "cleartext_storage_001.py",
    "cleartext_storage_safe_001.py",
    "weak_crypto_001.py",
    "weak_crypto_safe_001.py",
]

results = {
    "total": 0,
    "bugs_detected": 0,
    "safe_detected": 0,
    "unknown": 0,
    "details": []
}

standalone_dir = Path("py_synthetic/standalone")

for test_file in NEW_TESTS:
    test_path = standalone_dir / test_file
    if not test_path.exists():
        print(f"SKIP: {test_file} not found")
        continue
    
    print(f"\nAnalyzing {test_file}...")
    try:
        result = analyze_file(str(test_path), timeout=30)
        verdict = "BUG" if result.get("bugs") else "SAFE" if result.get("safe") else "UNKNOWN"
        
        results["total"] += 1
        if verdict == "BUG":
            results["bugs_detected"] += 1
            bug_types = [b["bug_type"] for b in result.get("bugs", [])]
            print(f"  → BUG: {bug_types}")
        elif verdict == "SAFE":
            results["safe_detected"] += 1
            print(f"  → SAFE")
        else:
            results["unknown"] += 1
            print(f"  → UNKNOWN")
        
        results["details"].append({
            "file": test_file,
            "verdict": verdict,
            "bugs": result.get("bugs", [])
        })
    except Exception as e:
        print(f"  → ERROR: {e}")
        results["unknown"] += 1

print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"Total analyzed: {results['total']}")
print(f"Bugs detected: {results['bugs_detected']}")
print(f"Safe detected: {results['safe_detected']}")
print(f"Unknown: {results['unknown']}")

# Save results
with open("py_synthetic/new_tests_results.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\nResults saved to py_synthetic/new_tests_results.json")
