#!/usr/bin/env python3
"""Analyze SOTA-only findings to determine true vs false positives."""

from pathlib import Path
from pyfromscratch.semantics.sota_interprocedural import analyze_file_interprocedural

# Get our findings
views = Path('external_tools/pygoat/introduction/views.py')
mitre = Path('external_tools/pygoat/introduction/mitre.py')

all_violations = []
for f in [views, mitre]:
    all_violations.extend(analyze_file_interprocedural(f, verbose=False))

# CodeQL findings (from CSV)
codeql_lines = {
    ('views.py', 159, 'CLEARTEXT_LOGGING'),
    ('views.py', 162, 'SQL_INJECTION'),
    ('views.py', 214, 'UNSAFE_DESERIALIZATION'),
    ('views.py', 255, 'XXE'),
    ('views.py', 286, 'INSECURE_COOKIE'),
    ('views.py', 300, 'INSECURE_COOKIE'),
    ('views.py', 309, 'CLEARTEXT_LOGGING'),
    ('views.py', 314, 'INSECURE_COOKIE'),
    ('views.py', 425, 'COMMAND_INJECTION'),
    ('views.py', 454, 'CODE_INJECTION'),
    ('views.py', 554, 'UNSAFE_DESERIALIZATION'),
    ('views.py', 749, 'CLEARTEXT_LOGGING'),
    ('views.py', 855, 'CLEARTEXT_LOGGING'),
    ('views.py', 869, 'CLEARTEXT_LOGGING'),
    ('views.py', 872, 'SQL_INJECTION'),
    ('views.py', 921, 'PATH_INJECTION'),
    ('views.py', 957, 'SSRF'),
    ('views.py', 1020, 'WEAK_CRYPTO'),
    ('views.py', 1188, 'WEAK_CRYPTO'),
    ('mitre.py', 161, 'WEAK_CRYPTO'),
    ('mitre.py', 218, 'CODE_INJECTION'),
    ('mitre.py', 233, 'COMMAND_INJECTION'),
}

# Find SOTA-only findings
print('=== SOTA-only Findings (not in CodeQL) ===')
print()

sota_only = []
for v in sorted(all_violations, key=lambda x: (x.bug_type, x.line_number)):
    filename = 'views.py' if 'views' in v.file_path else 'mitre.py'
    
    # Check if this is in CodeQL (with some tolerance)
    matched = False
    for cq_file, cq_line, cq_type in codeql_lines:
        if cq_file == filename and abs(v.line_number - cq_line) <= 3:
            matched = True
            break
    
    if not matched:
        sota_only.append((v, filename))

# Group by bug type
by_type = {}
for v, filename in sota_only:
    by_type.setdefault(v.bug_type, []).append((v, filename))

for bug_type, findings in sorted(by_type.items()):
    print(f'### {bug_type} ({len(findings)} findings)')
    print()
    for v, filename in findings:
        print(f'  Line {v.line_number}: {v.function_name}')
        print(f'    Sink: {v.sink_type.name}')
        reason = v.reason[:80] + '...' if len(v.reason) > 80 else v.reason
        print(f'    Reason: {reason}')
    print()
