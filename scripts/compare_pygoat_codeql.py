#!/usr/bin/env python3
"""Compare our findings to CodeQL on PyGoat."""

from pathlib import Path
from pyfromscratch.semantics.sota_interprocedural import analyze_file_interprocedural

# Analyze PyGoat views.py
filepath = Path('external_tools/pygoat/introduction/views.py')
violations = analyze_file_interprocedural(filepath, verbose=False)

print("=== Our SOTA Analyzer Results ===")
print(f"Total: {len(violations)}")
print()

by_type = {}
for v in violations:
    by_type.setdefault(v.bug_type, []).append(v)

for bug_type, vs in sorted(by_type.items()):
    print(f"{bug_type}: {len(vs)}")
    for v in vs[:5]:  # Show first 5
        print(f"  Line {v.line_number}: {v.function_name} [{v.sink_type.name}]")

print()
print("=== Sink type breakdown ===")
by_sink = {}
for v in violations:
    by_sink.setdefault(v.sink_type.name, []).append(v)

for sink_type, vs in sorted(by_sink.items()):
    print(f"{sink_type}: {len(vs)}")

print()
print("=== CodeQL Results (from CODEQL_RESULTS_SUMMARY.md) ===")
codeql_counts = {
    'Code Injection (CWE-094)': 2,
    'SQL Injection (CWE-089)': 2,
    'Command Injection (CWE-078)': 2,
    'Unsafe Deserialization (CWE-502)': 3,
    'SSRF (CWE-918)': 1,
    'Path Injection (CWE-022)': 1,
    'XXE (CWE-611)': 1,
    'Cleartext Logging (CWE-312)': 5,
}
for k, v in codeql_counts.items():
    print(f"{k}: {v}")
