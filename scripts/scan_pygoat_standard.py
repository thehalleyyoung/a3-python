#!/usr/bin/env python3
"""
Standardized PyGoat Security Scanner
=====================================

This is the CANONICAL script for scanning PyGoat with PythonFromScratch.
All future PyGoat evaluations MUST use this script for consistency.

Purpose:
- Scan OWASP PyGoat vulnerable app for security bugs
- Compare findings with CodeQL baseline (31 bugs)
- Track progress across iterations

Architecture:
- Uses Analyzer.analyze_function_entry_points() for function-level security analysis
- Focuses on introduction/ directory (contains intentional vulnerabilities)
- Detects entry points: @app.route, Django views, HTTP handlers
- Reports security bugs only (filters out error bugs like PANIC, DIV_ZERO)

Usage:
    python scripts/scan_pygoat_standard.py [--verbose] [--output results.json]
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer
from pyfromscratch.contracts.security_lattice import init_security_contracts


# Security bug types we care about (from CodeQL comparison)
SECURITY_BUG_TYPES = {
    # Injection
    'SQL_INJECTION', 'COMMAND_INJECTION', 'CODE_INJECTION', 
    'LDAP_INJECTION', 'XPATH_INJECTION', 'NOSQL_INJECTION',
    'LOG_INJECTION', 'REGEX_INJECTION',
    
    # Path/File
    'PATH_INJECTION', 'TAR_SLIP', 'INSECURE_TEMPORARY_FILE',
    
    # Web/XSS
    'REFLECTED_XSS', 'JINJA2_AUTOESCAPE_FALSE', 'HEADER_INJECTION',
    'URL_REDIRECT', 'COOKIE_INJECTION', 'INSECURE_COOKIE',
    
    # SSRF/Network
    'FULL_SSRF', 'PARTIAL_SSRF', 'SSRF',
    
    # Serialization/XML
    'UNSAFE_DESERIALIZATION', 'XXE', 'XML_BOMB',
    
    # Crypto/Secrets
    'CLEARTEXT_STORAGE', 'CLEARTEXT_LOGGING', 'HARDCODED_CREDENTIALS',
    'WEAK_CRYPTO_KEY', 'BROKEN_CRYPTO_ALGORITHM', 
    'WEAK_SENSITIVE_DATA_HASHING', 'INSECURE_PROTOCOL',
    
    # Certificate Validation
    'MISSING_HOST_KEY_VALIDATION', 'REQUEST_WITHOUT_CERT_VALIDATION',
    
    # Regex DoS
    'REDOS', 'POLYNOMIAL_REDOS',
    
    # Validation
    'BAD_TAG_FILTER', 'INCOMPLETE_HOSTNAME_REGEXP',
    'INCOMPLETE_URL_SUBSTRING_SANITIZATION',
    
    # Other
    'PAM_AUTHORIZATION_BYPASS', 'UNTRUSTED_DATA_TO_EXTERNAL_API',
    'FLASK_DEBUG', 'CSRF_PROTECTION_DISABLED', 'STACK_TRACE_EXPOSURE',
}


def scan_pygoat(verbose: bool = False, output_file: Path = None) -> Dict[str, Any]:
    """
    Scan PyGoat introduction directory for security bugs.
    
    Returns:
        Dictionary with scan results:
        {
            'timestamp': ISO timestamp,
            'files_scanned': int,
            'total_bugs': int,
            'security_bugs': int,
            'bugs_by_type': {...},
            'bugs_by_file': {...},
            'detailed_bugs': [...]
        }
    """
    pygoat_dir = Path("external_tools/pygoat/introduction/")
    
    if not pygoat_dir.exists():
        print(f"Error: PyGoat directory not found: {pygoat_dir}")
        sys.exit(1)
    
    # Initialize security contracts (CRITICAL!)
    init_security_contracts()
    
    # Find all Python files
    py_files = sorted(pygoat_dir.rglob("*.py"))
    py_files = [f for f in py_files if '__pycache__' not in str(f)]
    
    print(f"PyGoat Security Scanner")
    print(f"=" * 60)
    print(f"Target: {pygoat_dir}")
    print(f"Files: {len(py_files)} Python files")
    print(f"Mode: Function-level entry point analysis")
    print(f"Concolic: Disabled (pure symbolic)")
    print(f"=" * 60)
    print()
    
    # Create analyzer
    analyzer = Analyzer(verbose=verbose, enable_concolic=False)
    
    # Results tracking
    results = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'files_scanned': 0,
        'total_bugs': 0,
        'security_bugs': 0,
        'bugs_by_type': {},
        'bugs_by_file': {},
        'detailed_bugs': []
    }
    
    # Scan each file
    for i, py_file in enumerate(py_files, 1):
        rel_path = py_file.relative_to("external_tools/pygoat")
        
        print(f"[{i}/{len(py_files)}] {rel_path}", end=" ", flush=True)
        
        try:
            # Run function-level entry point analysis
            func_results = analyzer.analyze_function_entry_points(
                py_file, 
                skip_module_level=False  # Include module-level for completeness
            )
            
            results['files_scanned'] += 1
            file_bugs = []
            
            # Check module-level result
            if func_results.get('module_result'):
                result = func_results['module_result']
                if result.verdict == 'BUG':
                    bug_type = result.bug_type
                    
                    # Only count security bugs
                    if bug_type in SECURITY_BUG_TYPES:
                        bug_info = {
                            'file': str(rel_path),
                            'function': '<module>',
                            'bug_type': bug_type,
                            'message': result.message,
                            'entry_point_type': 'module'
                        }
                        file_bugs.append(bug_info)
                        results['security_bugs'] += 1
                    
                    results['total_bugs'] += 1
            
            # Check function-level results
            for func_result in func_results.get('function_results', []):
                result = func_result['result']
                if result.verdict == 'BUG':
                    bug_type = result.bug_type
                    entry_point = func_result['entry_point']
                    
                    # Only count security bugs
                    if bug_type in SECURITY_BUG_TYPES:
                        bug_info = {
                            'file': str(rel_path),
                            'function': entry_point.name,
                            'bug_type': bug_type,
                            'message': result.message,
                            'entry_point_type': entry_point.entry_type,
                            'line': entry_point.line_number
                        }
                        file_bugs.append(bug_info)
                        results['security_bugs'] += 1
                    
                    results['total_bugs'] += 1
            
            # Update results
            if file_bugs:
                results['detailed_bugs'].extend(file_bugs)
                results['bugs_by_file'][str(rel_path)] = file_bugs
                
                for bug in file_bugs:
                    bug_type = bug['bug_type']
                    results['bugs_by_type'][bug_type] = results['bugs_by_type'].get(bug_type, 0) + 1
                
                print(f"✓ {len(file_bugs)} security bugs")
            else:
                print("✓")
        
        except Exception as e:
            print(f"✗ Error: {e}")
            continue
    
    print()
    print(f"=" * 60)
    print(f"Scan Complete")
    print(f"=" * 60)
    print(f"Files scanned: {results['files_scanned']}")
    print(f"Total bugs found: {results['total_bugs']}")
    print(f"Security bugs: {results['security_bugs']}")
    print()
    
    if results['security_bugs'] > 0:
        print("Security bugs by type:")
        for bug_type, count in sorted(results['bugs_by_type'].items()):
            print(f"  {bug_type}: {count}")
        print()
        
        print("Security bugs by file:")
        for file_path, bugs in sorted(results['bugs_by_file'].items()):
            print(f"  {file_path}: {len(bugs)} bugs")
            for bug in bugs:
                print(f"    - {bug['bug_type']} in {bug['function']}")
    
    # Write output file
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults written to: {output_file}")
    
    return results


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Standardized PyGoat security scanner"
    )
    parser.add_argument(
        '--verbose', 
        action='store_true', 
        help="Verbose analyzer output"
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('results/pygoat_scan_latest.json'),
        help="Output JSON file (default: results/pygoat_scan_latest.json)"
    )
    
    args = parser.parse_args()
    
    results = scan_pygoat(verbose=args.verbose, output_file=args.output)
    
    # Exit with code based on results
    # 0 = scan completed successfully
    # 1 = scan failed
    sys.exit(0)


if __name__ == '__main__':
    main()
