#!/usr/bin/env python3
"""Detailed line-by-line comparison of our findings vs CodeQL on PyGoat."""
import sys
import csv
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, '.')
# Use intraprocedural analysis directly for more comprehensive results
from pyfromscratch.semantics.intraprocedural_taint import analyze_file_intraprocedural

# Parse CodeQL results
codeql_by_file = defaultdict(list)
with open('external_tools/codeql/pygoat-codeql-results.csv', 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        if len(row) >= 8:
            file_path = row[4]
            line = int(row[5])
            bug_type = row[0]
            codeql_by_file[file_path].append({
                'line': line,
                'type': bug_type,
                'message': row[1],
                'severity': row[2],
            })

# Map CodeQL types to our types
codeql_to_ours = {
    'Code injection': 'CODE_INJECTION',
    'Use of a broken or weak cryptographic hashing algorithm on sensitive data': 'WEAK_CRYPTO',
    'Full server-side request forgery': 'FULL_SSRF',
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

# Files to analyze (key PyGoat files)
files_to_analyze = [
    'external_tools/pygoat/introduction/views.py',
    'external_tools/pygoat/introduction/mitre.py',
    # 'external_tools/pygoat/dockerized_labs/broken_auth_lab/app.py',  # Flask, may need different handling
    # 'external_tools/pygoat/dockerized_labs/insec_des_lab/main.py',
]

print("=" * 80)
print("Line-by-Line Comparison: Our Analyzer vs CodeQL")
print("=" * 80)

for file_path in files_to_analyze:
    p = Path(file_path)
    if not p.exists():
        print(f"\n⚠️ {file_path} not found")
        continue
    
    # Get CodeQL findings for this file
    codeql_key = '/' + '/'.join(file_path.split('/')[-2:])  # e.g., /introduction/views.py
    codeql_findings = codeql_by_file.get(codeql_key, [])
    
    print(f"\n{'='*80}")
    print(f"File: {file_path}")
    print(f"CodeQL findings: {len(codeql_findings)}")
    print(f"{'='*80}")
    
    # Run our analyzer (use intraprocedural analysis for comprehensive coverage)
    try:
        our_findings_raw = analyze_file_intraprocedural(p)
        print(f"Our findings (raw): {len(our_findings_raw)}")
        
        # Filter and deduplicate our findings:
        # 1. Only security bugs (not crash bugs like NULL_PTR, BOUNDS)
        # 2. Skip line 0 (missing source location)
        # 3. Deduplicate by (line, bug_type)
        # 4. Merge similar types (JINJA2_INJECTION → TEMPLATE_INJECTION)
        
        security_bug_types = {
            'SQL_INJECTION', 'COMMAND_INJECTION', 'CODE_INJECTION', 'PATH_INJECTION',
            'CLEARTEXT_LOGGING', 'CLEARTEXT_STORAGE', 'WEAK_CRYPTO',
            'INSECURE_COOKIE', 'COOKIE_INJECTION', 'FLASK_DEBUG',
            'XXE', 'XML_BOMB', 'REGEX_INJECTION', 'REFLECTED_XSS',
            'FULL_SSRF', 'PARTIAL_SSRF', 'SSRF', 'PICKLE_INJECTION', 'YAML_INJECTION',
            'UNSAFE_DESERIALIZATION', 'TEMPLATE_INJECTION', 'JINJA2_INJECTION',
            'EVAL_INJECTION', 'EXEC_INJECTION', 'TARSLIP', 'ZIPSLIP',
            'HEADER_INJECTION', 'URL_REDIRECT', 'LOG_INJECTION',
        }
        
        # Normalize bug types (merge duplicates)
        def normalize_type(t):
            if t == 'JINJA2_INJECTION':
                return 'TEMPLATE_INJECTION'
            if t in ('EVAL_INJECTION', 'EXEC_INJECTION'):
                return 'CODE_INJECTION'
            return t
        
        seen = set()
        our_findings = []
        for b in our_findings_raw:
            if b.line_number == 0:
                continue  # Skip bugs without proper location
            if b.bug_type not in security_bug_types:
                continue  # Skip crash bugs
            
            normalized = normalize_type(b.bug_type)
            key = (b.line_number, normalized)
            if key not in seen:
                seen.add(key)
                our_findings.append(b)
        
        print(f"Our findings (filtered/deduped): {len(our_findings)}")
        
        # Create lookup by line number
        our_by_line = defaultdict(list)
        for b in our_findings:
            our_by_line[b.line_number].append(b)
        
        codeql_lines = {f['line'] for f in codeql_findings}
        our_lines = set(our_by_line.keys())
        
        # Find matches (with ±1 line tolerance for different reporting conventions)
        matches = set()
        for codeql_line in codeql_lines:
            if codeql_line in our_lines:
                matches.add(codeql_line)
            elif codeql_line - 1 in our_lines:
                matches.add(codeql_line)  # We found it 1 line earlier
            elif codeql_line + 1 in our_lines:
                matches.add(codeql_line)  # We found it 1 line later
        
        only_codeql = codeql_lines - matches
        only_ours = {l for l in our_lines if not any(abs(l - cl) <= 1 for cl in codeql_lines)}
        
        print(f"\nMatches (both found, ±1 line tolerance): {len(matches)}")
        print(f"Only CodeQL found: {len(only_codeql)}")
        print(f"Only we found: {len(only_ours)}")
        
        # Details for each category
        print("\n--- MATCHES (Both Found) ---")
        for line in sorted(matches):
            codeql_at_line = [f for f in codeql_findings if f['line'] == line]
            # Check ±1 line tolerance for our findings
            ours_at_line = our_by_line.get(line, [])
            if not ours_at_line:
                ours_at_line = our_by_line.get(line - 1, [])
            if not ours_at_line:
                ours_at_line = our_by_line.get(line + 1, [])
            for cf in codeql_at_line:
                our_type = codeql_to_ours.get(cf['type'], cf['type'])
                our_match = [b for b in ours_at_line if b.bug_type == our_type]
                if our_match:
                    print(f"  ✓ Line {line}: {cf['type']} - EXACT TYPE MATCH")
                else:
                    print(f"  ~ Line {line}: {cf['type']} - Different type (we have: {[b.bug_type for b in ours_at_line]})")
        
        print("\n--- ONLY CodeQL FOUND ---")
        for line in sorted(only_codeql):
            codeql_at_line = [f for f in codeql_findings if f['line'] == line]
            for cf in codeql_at_line:
                print(f"  ✗ Line {line}: {cf['type']}")
        
        print("\n--- ONLY WE FOUND (potential unique value) ---")
        for line in sorted(only_ours)[:20]:  # Limit to first 20
            ours_at_line = our_by_line[line]
            for b in ours_at_line:
                print(f"  + Line {line}: {b.bug_type}")
        if len(only_ours) > 20:
            print(f"  ... and {len(only_ours) - 20} more")
        
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        import traceback
        traceback.print_exc()

print("\n" + "=" * 80)
print("Analysis Complete")
print("=" * 80)
