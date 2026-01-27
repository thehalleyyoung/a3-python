#!/usr/bin/env python
"""Test the SOTA security scan integration."""

from pathlib import Path
import tempfile

from pyfromscratch.analyzer import Analyzer

# Create a test file with security vulnerabilities
test_code = '''
def vulnerable_sql(user_id):
    """SQL injection vulnerability."""
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)

def vulnerable_command(cmd):
    """Command injection vulnerability."""
    import os
    os.system(cmd)

def vulnerable_eval(code_input):
    """Code injection vulnerability."""
    eval(code_input)

def safe_function(count):
    """Safe function - no security issues."""
    return count + 1
'''

# Write to temp file
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write(test_code)
    test_path = Path(f.name)

print(f"Testing SOTA security scan on: {test_path}")
print()

# Run SOTA security scan
analyzer = Analyzer(verbose=True)
result = analyzer.sota_security_scan(test_path)

print()
print("=" * 60)
print(f"Verdict: {result.verdict}")
print(f"Bug type: {result.bug_type}")
print(f"Message: {result.message}")

if result.counterexample:
    print()
    print("Violations found:")
    for v in result.counterexample.get('all_violations', []):
        print(f"  - {v['bug_type']} at {v['file_path']}:{v['line_number']}")
        print(f"    Reason: {v['reason']}")

# Cleanup
test_path.unlink()
