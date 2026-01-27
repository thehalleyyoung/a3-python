#!/usr/bin/env python3
"""Compare our findings with CodeQL findings on PyGoat."""
import csv
from collections import defaultdict

# Parse CodeQL results
codeql_findings = []
with open('external_tools/codeql/pygoat-codeql-results.csv', 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        if len(row) >= 8:
            codeql_findings.append({
                'type': row[0],
                'message': row[1],
                'severity': row[2],
                'details': row[3],
                'file': row[4],
                'start_line': row[5],
                'end_line': row[7] if len(row) > 7 else row[5],
            })

print("=" * 80)
print("CodeQL Findings Summary")
print("=" * 80)

# Group by type
by_type = defaultdict(list)
for finding in codeql_findings:
    by_type[finding['type']].append(finding)

for bug_type, findings in sorted(by_type.items()):
    print(f"\n{bug_type}: {len(findings)}")
    for f in findings:
        print(f"  {f['file']}:{f['start_line']}")

print(f"\nTotal CodeQL findings: {len(codeql_findings)}")
print(f"Bug types: {len(by_type)}")

# Map CodeQL types to our types
codeql_to_ours = {
    'Code injection': 'CODE_INJECTION',
    'Use of a broken or weak cryptographic hashing algorithm on sensitive data': 'WEAK_CRYPTO',
    'Full server-side request forgery': 'SSRF',
    'Failure to use secure cookies': 'INSECURE_COOKIE',
    'SQL query built from user-controlled sources': 'SQL_INJECTION',
    'Construction of a cookie using user-supplied input': 'COOKIE_INJECTION',
    'Flask app is run in debug mode': 'FLASK_DEBUG',
    'XML internal entity expansion': 'XML_BOMB',
    'Clear-text storage of sensitive information': 'CLEARTEXT_STORAGE',
    'Clear-text logging of sensitive information': 'CLEARTEXT_LOGGING',
    'Deserialization of user-controlled data': 'UNSAFE_DESERIALIZATION',
    'Uncontrolled data used in path expression': 'PATH_INJECTION',
    'XML external entity expansion': 'XXE',
    'Uncontrolled command line': 'COMMAND_INJECTION',
}

print("\n" + "=" * 80)
print("CodeQL Bug Types Mapped to Our Types")
print("=" * 80)
for codeql_type, our_type in codeql_to_ours.items():
    count = len(by_type.get(codeql_type, []))
    print(f"  {our_type}: {count} ({codeql_type})")

# What we implement (including subtypes)
our_bug_types = {
    'SQL_INJECTION', 'COMMAND_INJECTION', 'CODE_INJECTION', 'PATH_INJECTION',
    'CLEARTEXT_LOGGING', 'CLEARTEXT_STORAGE', 'WEAK_CRYPTO', 
    'INSECURE_COOKIE', 'COOKIE_INJECTION', 'FLASK_DEBUG',
    'XXE', 'XML_BOMB', 'REGEX_INJECTION', 'TARSLIP', 'ZIPSLIP',
    'NULL_PTR', 'BOUNDS', 'TYPE_CONFUSION', 'PANIC', 'DIV_ZERO',
    # SSRF variants
    'SSRF', 'FULL_SSRF', 'PARTIAL_SSRF',
    # Deserialization variants
    'UNSAFE_DESERIALIZATION', 'PICKLE_INJECTION', 'YAML_INJECTION',
}

print("\n" + "=" * 80)
print("Coverage Analysis")
print("=" * 80)

codeql_types_covered = set(codeql_to_ours.values())
our_types_matched = codeql_types_covered & our_bug_types
our_unique = our_bug_types - codeql_types_covered
codeql_we_miss = codeql_types_covered - our_bug_types

print(f"\nCodeQL bug types we implement: {len(our_types_matched)}/{len(codeql_types_covered)}")
print(f"  {sorted(our_types_matched)}")

print(f"\nOur unique bug types (CodeQL doesn't check): {len(our_unique)}")
print(f"  {sorted(our_unique)}")

print(f"\nCodeQL types we don't implement: {len(codeql_we_miss)}")
print(f"  {sorted(codeql_we_miss)}")
