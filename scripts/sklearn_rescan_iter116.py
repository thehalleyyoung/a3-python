#!/usr/bin/env python3
"""
Iteration 116: Rescan scikit-learn with current analyzer (27 iterations newer than iter 88 scan)

Purpose: Get accurate current bug rate and compare with old scan to measure continuous refinement impact
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
    print("ITERATION 116: Scikit-learn Rescan")
    print("="*60)
    print("Purpose: Measure continuous refinement impact over 27 iterations")
    print()
    
    # Get scikit-learn repo
    repo = next(r for r in get_all_repos() if r.name == "scikit-learn")
    
    # Scan with current analyzer
    print("Scanning scikit-learn with current analyzer (iteration 116)...")
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
    
    # Compare with iteration 88 results
    print("="*60)
    print("COMPARISON WITH ITERATION 88 (27 iterations old)")
    print("="*60)
    old_bugs = 7
    old_bug_rate = 0.07
    new_bugs = verdicts['BUG']
    new_bug_rate = verdicts['BUG'] / total
    
    print(f"Iteration 88 (old scan):  {old_bugs} bugs, {old_bug_rate*100:.1f}% bug rate")
    print(f"Iteration 116 (new scan): {new_bugs} bugs, {new_bug_rate*100:.1f}% bug rate")
    print()
    
    delta = new_bugs - old_bugs
    delta_sign = "+" if delta > 0 else ""
    print(f"Change: {delta_sign}{delta} bugs ({(new_bug_rate - old_bug_rate)*100:+.1f}pp)")
    print()
    
    if delta != 0:
        print("Analysis:")
        if delta > 0:
            print(f"  - Detected {delta} additional potential bugs")
            print(f"  - This could indicate improved detection OR new false positives")
            print(f"  - Requires DSE validation to determine true/false positives")
        else:
            print(f"  - Eliminated {abs(delta)} previous bug reports")
            print(f"  - This indicates continuous refinement reduced false positives")
            print(f"  - From iteration 115 DSE validation: 3/7 (43%) were FPs in old scan")
    else:
        print("Analysis:")
        print(f"  - Bug count stable over 27 iterations")
        print(f"  - Indicates detection consistency despite semantic enhancements")
    print()
    
    # Save results
    output = {
        'iteration': 116,
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'repo': 'scikit-learn',
        'files_analyzed': total,
        'verdicts': verdicts,
        'bug_types': bug_types,
        'bug_rate': new_bug_rate,
        'comparison': {
            'previous_iteration': 88,
            'iterations_elapsed': 27,
            'old_bugs': old_bugs,
            'new_bugs': new_bugs,
            'delta': delta,
            'old_bug_rate': old_bug_rate,
            'new_bug_rate': new_bug_rate,
            'rate_delta': new_bug_rate - old_bug_rate
        },
        'bug_files': bug_files
    }
    
    output_file = Path("results/sklearn_rescan_iter116.json")
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Results saved to: {output_file}")
    print()
    
    # Next step recommendation
    print("="*60)
    print("NEXT STEPS")
    print("="*60)
    if delta != 0:
        print("1. Run DSE validation on new scan results")
        print("2. Compare DSE validation rate with iter 115 (57% validated, 43% FP)")
        print("3. Determine if continuous refinement improved precision")
    else:
        print("1. Document stability over 27 iterations")
        print("2. Consider this as baseline for future refinements")
    print()


if __name__ == "__main__":
    main()
