#!/usr/bin/env python3
"""
Iteration 117: Rescan scikit-learn after TYPE_CONFUSION UNPACK_SEQUENCE fix

Purpose: Measure impact of sound over-approximation fix from iteration 117
- Fixed false positives in UNPACK_SEQUENCE by using "definitely not unpackable" check
- Should eliminate TYPE_CONFUSION FPs like doc/api_reference.py
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.evaluation.scanner import RepoScanner
from pyfromscratch.evaluation.repo_list import get_all_repos


def main():
    print("="*60)
    print("ITERATION 117: Scikit-learn Rescan (TYPE_CONFUSION Fix)")
    print("="*60)
    print("Purpose: Measure TYPE_CONFUSION FP elimination after UNPACK_SEQUENCE fix")
    print()
    
    # Get scikit-learn repo
    repo = next(r for r in get_all_repos() if r.name == "scikit-learn")
    
    # Scan with current analyzer
    print("Scanning scikit-learn with current analyzer (iteration 117)...")
    scanner = RepoScanner()
    result = scanner.scan_repo(repo, max_files=100, exclude_tests=True)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Files analyzed: {result.analyzed_files}/{result.total_files}")
    print(f"Findings: {result.summary}")
    print()
    
    # Load file-level results - find the most recent scan file
    results_dir = Path("results/public_repos/scan_results")
    scan_files = sorted(results_dir.glob(f"{repo.name}_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    
    if not scan_files:
        print(f"Error: No scan results found for {repo.name}")
        return
    
    result_file = scan_files[0]
    print(f"Loading results from: {result_file.name}")
    
    with open(result_file, 'r') as f:
        scan_data = json.load(f)
    
    # Count by verdict
    verdicts = {'BUG': 0, 'SAFE': 0, 'UNKNOWN': 0, 'ERROR': 0}
    bug_types = {}
    bug_files = []
    
    for file_result in scan_data['findings']:
        verdict = file_result['verdict']
        verdicts[verdict] += 1
        
        if verdict == 'BUG':
            bug_files.append({
                'file': file_result['file_path'],
                'bug_type': file_result.get('bug_type', 'UNKNOWN'),
                'location': file_result.get('location', 'unknown')
            })
            bug_type = file_result.get('bug_type', 'UNKNOWN')
            bug_types[bug_type] = bug_types.get(bug_type, 0) + 1
    
    total = verdicts['BUG'] + verdicts['SAFE'] + verdicts['UNKNOWN'] + verdicts['ERROR']
    
    print("\nDETAILED BREAKDOWN:")
    print(f"  BUG:     {verdicts['BUG']:3d} ({verdicts['BUG']/total*100:.1f}%)")
    print(f"  SAFE:    {verdicts['SAFE']:3d} ({verdicts['SAFE']/total*100:.1f}%)")
    print(f"  UNKNOWN: {verdicts['UNKNOWN']:3d} ({verdicts['UNKNOWN']/total*100:.1f}%)")
    print(f"  ERROR:   {verdicts['ERROR']:3d} ({verdicts['ERROR']/total*100:.1f}%)")
    print()
    
    print("BUG TYPES:")
    for bug_type, count in sorted(bug_types.items(), key=lambda x: x[1], reverse=True):
        print(f"  {bug_type}: {count}")
    print()
    
    # Compare with iteration 116 results
    print("="*60)
    print("COMPARISON WITH ITERATION 116 (pre-TYPE_CONFUSION fix)")
    print("="*60)
    old_bugs = 6
    old_type_confusion = 2
    old_panic = 4
    old_bug_rate = 0.06
    new_bugs = verdicts['BUG']
    new_bug_rate = verdicts['BUG'] / total
    new_type_confusion = bug_types.get('TYPE_CONFUSION', 0)
    new_panic = bug_types.get('PANIC', 0)
    
    print(f"Iteration 116 (pre-fix):  {old_bugs} bugs ({old_type_confusion} TYPE_CONFUSION, {old_panic} PANIC)")
    print(f"Iteration 117 (post-fix): {new_bugs} bugs ({new_type_confusion} TYPE_CONFUSION, {new_panic} PANIC)")
    print()
    
    delta = new_bugs - old_bugs
    tc_delta = new_type_confusion - old_type_confusion
    delta_sign = "+" if delta > 0 else ""
    tc_delta_sign = "+" if tc_delta > 0 else ""
    
    print(f"Total change: {delta_sign}{delta} bugs ({(new_bug_rate - old_bug_rate)*100:+.1f}pp)")
    print(f"TYPE_CONFUSION change: {tc_delta_sign}{tc_delta} bugs")
    print()
    
    print("Analysis:")
    if tc_delta < 0:
        print(f"  ✓ Eliminated {abs(tc_delta)} TYPE_CONFUSION false positives")
        print(f"  ✓ Sound over-approximation fix working as intended")
        print(f"  ✓ UNPACK_SEQUENCE now accepts generic OBJ values (dict.items() etc)")
        if delta == tc_delta:
            print(f"  ✓ All {abs(delta)} bugs eliminated were TYPE_CONFUSION (expected)")
        else:
            print(f"  - Other bug types changed: investigate difference")
    elif tc_delta > 0:
        print(f"  ⚠ UNEXPECTED: TYPE_CONFUSION increased by {tc_delta}")
        print(f"  - May indicate regression or new detection capability")
        print(f"  - Requires investigation")
    else:
        print(f"  - TYPE_CONFUSION count unchanged: no FPs eliminated")
        print(f"  - Fix may not have affected sklearn's specific patterns")
    print()
    
    # Check if doc/api_reference.py fixed
    doc_api_fixed = None
    for bug in bug_files:
        if 'doc/api_reference.py' in bug['file']:
            doc_api_fixed = False
            break
    else:
        doc_api_fixed = True
    
    if doc_api_fixed is not None:
        print("TARGET FILE CHECK:")
        print(f"  doc/api_reference.py: {'✓ FIXED (→SAFE)' if doc_api_fixed else '✗ STILL FLAGGED'}")
        print()
    
    # Save results
    output = {
        'iteration': 117,
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'repo': 'scikit-learn',
        'files_analyzed': total,
        'verdicts': verdicts,
        'bug_types': bug_types,
        'bug_rate': new_bug_rate,
        'comparison': {
            'previous_iteration': 116,
            'semantic_fix': 'TYPE_CONFUSION UNPACK_SEQUENCE over-approximation',
            'old_bugs': old_bugs,
            'new_bugs': new_bugs,
            'delta': delta,
            'old_bug_rate': old_bug_rate,
            'new_bug_rate': new_bug_rate,
            'rate_delta': new_bug_rate - old_bug_rate,
            'type_confusion_old': old_type_confusion,
            'type_confusion_new': new_type_confusion,
            'type_confusion_delta': tc_delta,
            'doc_api_reference_fixed': doc_api_fixed
        },
        'bug_files': bug_files
    }
    
    output_file = Path("results/sklearn_rescan_iter117.json")
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Results saved to: {output_file}")
    print()
    
    # Next step recommendation
    print("="*60)
    print("NEXT STEPS")
    print("="*60)
    if tc_delta < 0:
        print("1. Check other repos (numpy, pandas, ansible) for similar FP elimination")
        print("2. Document successful soundness-preserving false positive reduction")
        print("3. Consider similar over-approximation refinements for other opcodes")
    else:
        print("1. Investigate why TYPE_CONFUSION count unchanged/increased")
        print("2. Check if fix applies to sklearn's specific code patterns")
        print("3. Consider additional UNPACK_SEQUENCE patterns needing refinement")
    print()


if __name__ == "__main__":
    main()
