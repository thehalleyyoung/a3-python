#!/usr/bin/env python3
"""
Iteration 131: Rescan scikit-learn after string concatenation fix

Purpose: Measure impact of string concatenation support fix from iteration 130
- Fixed TYPE_CONFUSION FP in doc/api_reference.py (user function returning string used in +)
- Added string concatenation support to binary_op_add in z3model/values.py
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
    print("ITERATION 131: Scikit-learn Rescan (String Concat Fix)")
    print("="*60)
    print("Purpose: Confirm TYPE_CONFUSION FP elimination after string concatenation support")
    print()
    
    # Get scikit-learn repo
    repo = next(r for r in get_all_repos() if r.name == "scikit-learn")
    
    # Scan with current analyzer
    print("Scanning scikit-learn with current analyzer (iteration 131)...")
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
    
    # Extract findings list from dict structure
    findings = scan_data['findings'] if isinstance(scan_data, dict) else scan_data
    
    # Count by verdict
    verdicts = {'BUG': 0, 'SAFE': 0, 'UNKNOWN': 0, 'ERROR': 0}
    bug_types = {}
    bug_files = []
    
    for file_result in findings:
        verdict = file_result['verdict']
        verdicts[verdict] += 1
        
        if verdict == 'BUG':
            bug_type = file_result['bug_type']
            bug_types[bug_type] = bug_types.get(bug_type, 0) + 1
            bug_files.append({
                'file': file_result['file_path'],
                'bug_type': bug_type,
                'message': file_result.get('message', '')
            })
    
    print("\nVerdict distribution:")
    for verdict, count in verdicts.items():
        pct = 100.0 * count / len(findings) if findings else 0
        print(f"  {verdict:10s}: {count:3d} ({pct:.1f}%)")
    
    if bug_types:
        print("\nBug types:")
        for bug_type, count in sorted(bug_types.items(), key=lambda x: -x[1]):
            print(f"  {bug_type:20s}: {count:3d}")
    
    # Check for the specific FP we fixed
    api_ref_file = "sklearn/doc/api_reference.py"
    api_ref_bugs = [b for b in bug_files if api_ref_file in b['file']]
    
    print(f"\n{'='*60}")
    print("TARGET FP CHECK: sklearn/doc/api_reference.py")
    print(f"{'='*60}")
    if api_ref_bugs:
        print(f"❌ STILL BUGGY: Found {len(api_ref_bugs)} bug(s)")
        for b in api_ref_bugs:
            print(f"   {b['bug_type']}: {b['message']}")
    else:
        api_ref_result = next((f for f in findings if api_ref_file in f['file_path']), None)
        if api_ref_result:
            print(f"✅ FP ELIMINATED: Now {api_ref_result['verdict']}")
        else:
            print("⚠️  File not found in scan results")
    
    # Compare with iteration 116 (most recent sklearn scan)
    print(f"\n{'='*60}")
    print("COMPARISON WITH ITERATION 116")
    print(f"{'='*60}")
    iter116_bugs = 6
    iter116_type_confusion = 2
    iter116_panic = 4
    
    current_bugs = verdicts['BUG']
    current_type_confusion = bug_types.get('TYPE_CONFUSION', 0)
    current_panic = bug_types.get('PANIC', 0)
    
    print(f"Total bugs:        {iter116_bugs:3d} → {current_bugs:3d} (Δ {current_bugs - iter116_bugs:+d})")
    print(f"TYPE_CONFUSION:    {iter116_type_confusion:3d} → {current_type_confusion:3d} (Δ {current_type_confusion - iter116_type_confusion:+d})")
    print(f"PANIC:             {iter116_panic:3d} → {current_panic:3d} (Δ {current_panic - iter116_panic:+d})")
    
    if current_type_confusion < iter116_type_confusion:
        print(f"\n✅ TYPE_CONFUSION reduction: {iter116_type_confusion - current_type_confusion} FP(s) eliminated")
    elif current_type_confusion == iter116_type_confusion:
        print(f"\n⚠️  TYPE_CONFUSION unchanged (expected -1)")
    else:
        print(f"\n❌ TYPE_CONFUSION increased (unexpected)")
    
    # Save summary
    summary = {
        "iteration": 131,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "repo": repo.name,
        "files_analyzed": len(findings),
        "verdicts": verdicts,
        "bug_types": bug_types,
        "bug_files": bug_files,
        "comparison_with_iter116": {
            "iter116_bugs": iter116_bugs,
            "current_bugs": current_bugs,
            "bug_delta": current_bugs - iter116_bugs,
            "iter116_type_confusion": iter116_type_confusion,
            "current_type_confusion": current_type_confusion,
            "type_confusion_delta": current_type_confusion - iter116_type_confusion,
            "api_reference_eliminated": len(api_ref_bugs) == 0
        }
    }
    
    summary_file = Path("results") / "sklearn_rescan_iter131_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to: {summary_file}")


if __name__ == "__main__":
    main()
