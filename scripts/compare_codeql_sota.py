#!/usr/bin/env python3
"""Compare SOTA analyzer findings against CodeQL baseline."""

import csv
import sys
from pathlib import Path
from dataclasses import dataclass

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer


@dataclass
class Finding:
    """Normalized finding for comparison."""
    file: str
    line: int
    bug_type: str
    severity: str


def parse_codeql_results(csv_path: str) -> list[Finding]:
    """Parse CodeQL CSV results into normalized findings."""
    findings = []
    
    # Map CodeQL names to our types
    type_map = {
        'Code injection': 'CODE_INJECTION',
        'SQL query built from user-controlled sources': 'SQL_INJECTION',
        'Uncontrolled command line': 'COMMAND_INJECTION',
        'Deserialization of user-controlled data': 'UNSAFE_DESERIALIZATION',
        'Uncontrolled data used in path expression': 'PATH_INJECTION',
        'Full server-side request forgery': 'SSRF',
        'Clear-text logging of sensitive information': 'CLEARTEXT_LOGGING',
        'Clear-text storage of sensitive information': 'CLEARTEXT_STORAGE',
        'Failure to use secure cookies': 'INSECURE_COOKIE',
        'Construction of a cookie using user-supplied input': 'COOKIE_INJECTION',
        'Use of a broken or weak cryptographic hashing algorithm on sensitive data': 'WEAK_CRYPTO',
        'Flask app is run in debug mode': 'DEBUG_MODE',
        'XML external entity expansion': 'XXE',
        'XML internal entity expansion': 'XXE',
    }
    
    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 6:
                continue
            bug_name, desc, severity, msg, file_path, line = row[:6]
            
            # Normalize file path
            if file_path.startswith('/'):
                file_path = file_path[1:]  # Remove leading slash
            
            # Map to our types
            bug_type = type_map.get(bug_name, bug_name.upper().replace(' ', '_'))
            
            findings.append(Finding(
                file=file_path,
                line=int(line) if line.isdigit() else 0,
                bug_type=bug_type,
                severity=severity,
            ))
    
    return findings


def run_sota_scan(pygoat_path: str) -> list[Finding]:
    """Run SOTA analyzer on PyGoat and return normalized findings."""
    findings = []
    
    a = Analyzer()
    
    # Scan key files
    files_to_scan = [
        'introduction/views.py',
        'introduction/mitre.py',
        # 'introduction/playground/A9/archive.py',
        # 'dockerized_labs/broken_auth_lab/app.py',
        # 'dockerized_labs/insec_des_lab/main.py',
    ]
    
    for rel_path in files_to_scan:
        full_path = Path(pygoat_path) / rel_path
        if not full_path.exists():
            print(f"Warning: {full_path} not found")
            continue
        
        print(f"Scanning {rel_path}...")
        try:
            result = a.sota_interprocedural_scan(full_path)
            violations = result.counterexample.get('all_violations', []) if result.counterexample else []
            
            for v in violations:
                findings.append(Finding(
                    file=rel_path,
                    line=v.get('line_number', 0),
                    bug_type=v.get('bug_type', 'UNKNOWN'),
                    severity='error',
                ))
        except Exception as e:
            print(f"  Error: {e}")
    
    return findings


def compare_findings(codeql: list[Finding], ours: list[Finding]) -> dict:
    """Compare findings and produce a report."""
    # Create lookup keys
    def key(f: Finding) -> tuple:
        return (f.file, f.line, f.bug_type)
    
    # Related type mappings (our type -> CodeQL type)
    related_types = {
        'LOG_INJECTION': ['CLEARTEXT_LOGGING'],
        'REFLECTED_XSS': [],
        'REGEX_INJECTION': [],
    }
    
    codeql_set = {key(f) for f in codeql}
    our_set = {key(f) for f in ours}
    
    # Filter to just views.py and mitre.py for fair comparison
    codeql_filtered = {k for k in codeql_set if k[0] in ('introduction/views.py', 'introduction/mitre.py')}
    our_filtered = our_set
    
    agreement = codeql_filtered & our_filtered
    codeql_only = codeql_filtered - our_filtered
    our_only = our_filtered - codeql_filtered
    
    # Looser matching (same file, line ±3, and compatible bug types)
    def compatible_types(t1, t2):
        if t1 == t2:
            return True
        # Check related types (our type is t2, codeql type is t1)
        for our_type, codeql_types in related_types.items():
            if t2 == our_type and t1 in codeql_types:
                return True
        return False
    
    def loose_match(ck, ok):
        return ck[0] == ok[0] and abs(ck[1] - ok[1]) <= 3 and compatible_types(ck[2], ok[2])
    
    codeql_matched_loose = set()
    our_matched_loose = set()
    for ck in codeql_only:
        for ok in our_only:
            if loose_match(ck, ok):
                codeql_matched_loose.add(ck)
                our_matched_loose.add(ok)
                break
    
    return {
        'codeql_total': len(codeql_filtered),
        'our_total': len(our_filtered),
        'exact_agreement': len(agreement),
        'codeql_only': sorted(codeql_only - codeql_matched_loose),
        'our_only': sorted(our_only - our_matched_loose),
        'loose_matches': len(codeql_matched_loose),
        'codeql_loose_matched': sorted(codeql_matched_loose),
    }


def main():
    pygoat_path = 'external_tools/pygoat'
    codeql_csv = 'results/pygoat_codeql/pygoat-codeql-results.csv'
    
    print("=== Parsing CodeQL results ===")
    codeql_findings = parse_codeql_results(codeql_csv)
    print(f"  Total CodeQL findings: {len(codeql_findings)}")
    
    # Group by type
    by_type = {}
    for f in codeql_findings:
        by_type[f.bug_type] = by_type.get(f.bug_type, 0) + 1
    print("  By type:")
    for t, c in sorted(by_type.items()):
        print(f"    {t}: {c}")
    
    print("\n=== Running SOTA analysis ===")
    our_findings = run_sota_scan(pygoat_path)
    print(f"  Total SOTA findings: {len(our_findings)}")
    
    # Group by type
    by_type = {}
    for f in our_findings:
        by_type[f.bug_type] = by_type.get(f.bug_type, 0) + 1
    print("  By type:")
    for t, c in sorted(by_type.items()):
        print(f"    {t}: {c}")
    
    print("\n=== Comparison ===")
    comparison = compare_findings(codeql_findings, our_findings)
    
    print(f"  CodeQL findings (filtered): {comparison['codeql_total']}")
    print(f"  SOTA findings: {comparison['our_total']}")
    print(f"  Exact agreement: {comparison['exact_agreement']}")
    print(f"  Loose matches (+/-3 lines): {comparison['loose_matches']}")
    
    print(f"\n  CodeQL-only ({len(comparison['codeql_only'])}):")
    for k in comparison['codeql_only'][:10]:
        print(f"    {k[0]}:{k[1]} {k[2]}")
    if len(comparison['codeql_only']) > 10:
        print(f"    ... and {len(comparison['codeql_only']) - 10} more")
    
    print(f"\n  SOTA-only ({len(comparison['our_only'])}):")
    for k in comparison['our_only'][:10]:
        print(f"    {k[0]}:{k[1]} {k[2]}")
    if len(comparison['our_only']) > 10:
        print(f"    ... and {len(comparison['our_only']) - 10} more")


if __name__ == '__main__':
    main()
