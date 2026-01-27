#!/usr/bin/env python3
"""
Triage tier 1 scan results with improved DSE context.

Categorizes findings into:
- Real bugs: DSE validated or trivially valid (assert False, div by zero with concrete values)
- Context issues: Missing imports/external dependencies
- Analyzer gaps: Missing opcode support
- Unknown: Needs further investigation
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

def load_latest_scan_results():
    """Load the most recent scan results for tier 1 repos."""
    results_dir = Path('results/public_repos/scan_results')
    results = {}
    
    tier1_repos = ['click', 'flask', 'requests', 'pytest', 'rich']
    
    for repo in tier1_repos:
        # Find most recent scan for this repo
        pattern = f"{repo}_*.json"
        files = sorted(results_dir.glob(pattern), reverse=True)
        if files:
            with open(files[0]) as f:
                results[repo] = json.load(f)
    
    return results

def categorize_finding(finding):
    """Categorize a BUG finding into one of several categories."""
    
    # Check witness trace for patterns
    witness = finding.get('witness_trace', [])
    witness_str = '\n'.join(witness) if isinstance(witness, list) else str(witness)
    
    # Missing opcode support
    missing_opcodes = [
        'UNPACK_SEQUENCE', 'STORE_SUBSCR', 'DELETE_SUBSCR', 
        'BINARY_SUBSCR', 'LIST_APPEND', 'DICT_UPDATE',
        'SET_ADD', 'SET_UPDATE', 'BUILD_SLICE', 'BUILD_SET',
        'BUILD_STRING', 'FORMAT_VALUE', 'EXTENDED_ARG',
        'LOAD_ASSERTION_ERROR', 'STORE_ATTR', 'DELETE_ATTR',
        'DELETE_FAST', 'DELETE_NAME', 'DELETE_GLOBAL', 'DELETE_DEREF'
    ]
    
    for opcode in missing_opcodes:
        if f'EXCEPTION: Opcode {opcode}' in witness_str:
            return 'analyzer_gap_opcode', opcode
    
    # Missing import (external dependency not available)
    if 'IMPORT_NAME' in witness_str and 'EXCEPTION' in witness_str:
        # Extract import name
        for line in witness:
            if 'IMPORT_NAME' in line:
                parts = line.split()
                if len(parts) >= 2:
                    import_name = parts[-1]
                    return 'context_missing_import', import_name
        return 'context_missing_import', 'unknown'
    
    # Check for DSE validation
    dse_repro = finding.get('dse_repro')
    if dse_repro:
        dse_status = dse_repro.get('status')
        if dse_status == 'validated':
            return 'real_bug_dse_validated', None
        elif dse_status == 'failed':
            # DSE failed to validate - could be spurious
            return 'unknown_dse_failed', None
    
    # Check for trivially valid bugs (concrete counterexamples)
    bug_type = finding.get('bug_type')
    
    if bug_type == 'ASSERT_FAIL':
        # Check if it's a concrete assert False (no symbolic conditions)
        if 'assert False' in witness_str.lower() or 'AssertionError' in witness_str:
            return 'real_bug_trivial', 'assert False'
    
    if bug_type == 'DIV_ZERO':
        # Check for concrete division by zero
        if 'BINARY_OP' in witness_str and any(c in witness_str for c in ['/ 0', '% 0']):
            return 'real_bug_trivial', 'div by zero'
    
    # Unknown external calls causing exceptions
    if 'havoc_unknown_call' in witness_str or 'external module' in witness_str.lower():
        return 'context_unknown_external', None
    
    # Default: needs investigation
    return 'unknown_needs_investigation', None

def triage_results(scan_results):
    """Triage all findings from scan results."""
    
    report = {
        'real_bugs': defaultdict(list),
        'context_issues': defaultdict(list),
        'analyzer_gaps': defaultdict(list),
        'unknown': defaultdict(list),
        'stats': defaultdict(lambda: defaultdict(int))
    }
    
    for repo_name, repo_data in scan_results.items():
        findings = repo_data.get('findings', [])
        
        for finding in findings:
            if finding['verdict'] != 'BUG':
                continue
            
            category, detail = categorize_finding(finding)
            
            entry = {
                'file': finding['file_path'],
                'bug_type': finding.get('bug_type'),
                'location': finding.get('location'),
                'detail': detail,
                'witness_preview': finding.get('witness_trace', [])[-5:] if finding.get('witness_trace') else []
            }
            
            # Categorize into main groups
            if category.startswith('real_bug'):
                report['real_bugs'][repo_name].append(entry)
                report['stats'][repo_name]['real_bugs'] += 1
            elif category.startswith('context'):
                report['context_issues'][repo_name].append(entry)
                report['stats'][repo_name]['context_issues'] += 1
            elif category.startswith('analyzer_gap'):
                report['analyzer_gaps'][repo_name].append(entry)
                report['stats'][repo_name]['analyzer_gaps'] += 1
            else:
                report['unknown'][repo_name].append(entry)
                report['stats'][repo_name]['unknown'] += 1
    
    return report

def print_report(report):
    """Print a human-readable triage report."""
    
    print("=" * 70)
    print("TIER 1 PUBLIC REPO EVALUATION - TRIAGE REPORT")
    print("=" * 70)
    print()
    
    # Summary stats
    print("SUMMARY STATISTICS")
    print("-" * 70)
    total_real = sum(stats['real_bugs'] for stats in report['stats'].values())
    total_context = sum(stats['context_issues'] for stats in report['stats'].values())
    total_gaps = sum(stats['analyzer_gaps'] for stats in report['stats'].values())
    total_unknown = sum(stats['unknown'] for stats in report['stats'].values())
    
    for repo_name, stats in sorted(report['stats'].items()):
        print(f"{repo_name:15} Real: {stats['real_bugs']:3d}  Context: {stats['context_issues']:3d}  "
              f"Gaps: {stats['analyzer_gaps']:3d}  Unknown: {stats['unknown']:3d}")
    
    print(f"{'TOTAL':15} Real: {total_real:3d}  Context: {total_context:3d}  "
          f"Gaps: {total_gaps:3d}  Unknown: {total_unknown:3d}")
    print()
    
    # Real bugs section
    if any(report['real_bugs'].values()):
        print("=" * 70)
        print("REAL BUGS (validated or trivially valid)")
        print("=" * 70)
        for repo_name, bugs in sorted(report['real_bugs'].items()):
            if bugs:
                print(f"\n{repo_name.upper()}:")
                for bug in bugs:
                    print(f"  [{bug['bug_type']}] {Path(bug['file']).name}")
                    if bug['detail']:
                        print(f"    Detail: {bug['detail']}")
                    if bug['location']:
                        print(f"    Location: {bug['location']}")
        print()
    
    # Context issues section
    if any(report['context_issues'].values()):
        print("=" * 70)
        print("CONTEXT ISSUES (missing imports/external dependencies)")
        print("=" * 70)
        for repo_name, issues in sorted(report['context_issues'].items()):
            if issues:
                print(f"\n{repo_name.upper()}:")
                import_issues = defaultdict(int)
                for issue in issues:
                    if issue['detail']:
                        import_issues[issue['detail']] += 1
                for import_name, count in sorted(import_issues.items(), key=lambda x: -x[1]):
                    print(f"  Missing import '{import_name}': {count} file(s)")
        print()
    
    # Analyzer gaps section
    if any(report['analyzer_gaps'].values()):
        print("=" * 70)
        print("ANALYZER GAPS (missing opcode support)")
        print("=" * 70)
        opcode_counts = defaultdict(int)
        for repo_name, gaps in report['analyzer_gaps'].items():
            for gap in gaps:
                if gap['detail']:
                    opcode_counts[gap['detail']] += 1
        
        for opcode, count in sorted(opcode_counts.items(), key=lambda x: -x[1]):
            print(f"  {opcode:25s}: {count:3d} occurrence(s)")
        print()
    
    # Unknown section
    if any(report['unknown'].values()):
        print("=" * 70)
        print("UNKNOWN (needs further investigation)")
        print("=" * 70)
        for repo_name, unknowns in sorted(report['unknown'].items()):
            if unknowns:
                print(f"\n{repo_name.upper()}: {len(unknowns)} finding(s)")
                for unk in unknowns[:3]:  # Show first 3
                    print(f"  [{unk['bug_type']}] {Path(unk['file']).name}")
                    if len(unk['witness_preview']) > 0:
                        print(f"    Last trace: {unk['witness_preview'][-1][:80]}")
                if len(unknowns) > 3:
                    print(f"  ... and {len(unknowns) - 3} more")
        print()

def main():
    results = load_latest_scan_results()
    
    if not results:
        print("No scan results found. Run tier 1 scan first.")
        sys.exit(1)
    
    report = triage_results(results)
    print_report(report)
    
    # Save report to file
    output_path = Path('results/public_repos/triage_report_tier1.json')
    with open(output_path, 'w') as f:
        json.dump({
            'stats': dict(report['stats']),
            'real_bugs': {k: v for k, v in report['real_bugs'].items()},
            'context_issues': {k: v for k, v in report['context_issues'].items()},
            'analyzer_gaps': {k: v for k, v in report['analyzer_gaps'].items()},
            'unknown': {k: v for k, v in report['unknown'].items()}
        }, f, indent=2)
    
    print(f"Full triage report saved to: {output_path}")

if __name__ == '__main__':
    main()
