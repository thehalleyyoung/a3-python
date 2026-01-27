#!/usr/bin/env python3
"""
Deep-dive DSE validation of tier 2 BUG findings.
Validates whether symbolic counterexamples are concretely realizable.
"""

import json
import sys
from pathlib import Path

# Add pyfromscratch to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer


def validate_finding(repo, finding, bug_type):
    """Attempt DSE validation of a single BUG finding."""
    file_path = finding['file_path']
    witness_trace = finding.get('witness_trace', [])
    
    print(f"\n{'='*80}")
    print(f"Validating: {repo}/{Path(file_path).name}")
    print(f"Bug type: {bug_type}")
    print(f"Location: {finding.get('location', 'unknown')}")
    print(f"Witness trace length: {len(witness_trace)}")
    print(f"{'='*80}\n")
    
    if not Path(file_path).exists():
        print(f"ERROR: File not found: {file_path}")
        return {
            'status': 'file_not_found',
            'repo': repo,
            'file': file_path,
            'bug_type': bug_type
        }
    
    # Attempt to analyze with DSE validation
    try:
        analyzer = Analyzer(max_paths=200, max_depth=100, verbose=True)
        result = analyzer.analyze_file(Path(file_path))
        
        # Check if DSE confirmed the bug
        dse_validated = False
        concrete_repro = None
        
        if result.verdict == 'BUG':
            if result.counterexample:
                dse_validated = result.counterexample.get('dse_validated', False)
                concrete_repro = result.counterexample.get('concrete_repro')
        
        validation_result = {
            'status': 'analyzed',
            'repo': repo,
            'file': file_path,
            'bug_type': bug_type,
            'analyzer_verdict': result.verdict,
            'analyzer_bug_type': result.bug_type,
            'dse_validated': dse_validated,
            'has_concrete_repro': concrete_repro is not None,
            'witness_trace_length': len(witness_trace),
            'paths_explored': result.paths_explored
        }
        
        if dse_validated:
            print("✓ DSE VALIDATED: Counterexample is concretely realizable")
            if concrete_repro:
                print(f"  Concrete inputs: {concrete_repro}")
        else:
            print("? DSE NOT VALIDATED: Could not concretely realize within budget")
            print("  (This does not mean the finding is spurious - DSE is under-approximate)")
        
        # Check if analyzer agrees with original finding
        if result.verdict == 'BUG' and result.bug_type == bug_type:
            print(f"✓ Analyzer confirms: {bug_type}")
        elif result.verdict == 'BUG' and result.bug_type != bug_type:
            print(f"⚠ Analyzer found different bug: {result.bug_type} (expected {bug_type})")
        elif result.verdict != 'BUG':
            print(f"⚠ Analyzer verdict: {result.verdict} (expected BUG:{bug_type})")
        
        # Print first few steps of witness trace
        print(f"\nWitness trace excerpt (first 10 steps):")
        for line in witness_trace[:10]:
            print(f"  {line}")
        if len(witness_trace) > 10:
            print(f"  ... ({len(witness_trace) - 10} more steps)")
        
        return validation_result
        
    except Exception as e:
        print(f"ERROR during analysis: {e}")
        import traceback
        traceback.print_exc()
        return {
            'status': 'error',
            'repo': repo,
            'file': file_path,
            'bug_type': bug_type,
            'error': str(e)
        }


def main():
    # Load selected targets
    targets_file = Path(__file__).parent.parent / 'results' / 'tier2_dse_targets.json'
    with open(targets_file, 'r') as f:
        targets = json.load(f)
    
    print(f"Loaded {len(targets)} targets for DSE validation")
    
    validation_results = []
    
    for i, target in enumerate(targets, 1):
        print(f"\n\n{'#'*80}")
        print(f"# Target {i}/{len(targets)}")
        print(f"{'#'*80}")
        
        result = validate_finding(
            target['repo'],
            target['finding'],
            target['bug_type']
        )
        validation_results.append(result)
    
    # Summary
    print(f"\n\n{'='*80}")
    print("VALIDATION SUMMARY")
    print(f"{'='*80}\n")
    
    analyzed = [r for r in validation_results if r['status'] == 'analyzed']
    validated = [r for r in analyzed if r.get('dse_validated')]
    errors = [r for r in validation_results if r['status'] == 'error']
    
    print(f"Total targets: {len(targets)}")
    print(f"Successfully analyzed: {len(analyzed)}")
    print(f"DSE validated (concrete repro): {len(validated)}")
    print(f"Not validated (within budget): {len(analyzed) - len(validated)}")
    print(f"Errors: {len(errors)}")
    
    if validated:
        print(f"\nDSE validation rate: {len(validated)/len(analyzed)*100:.1f}%")
    
    print(f"\nBy bug type:")
    bug_types = {}
    for r in analyzed:
        bt = r['bug_type']
        if bt not in bug_types:
            bug_types[bt] = {'total': 0, 'validated': 0}
        bug_types[bt]['total'] += 1
        if r.get('dse_validated'):
            bug_types[bt]['validated'] += 1
    
    for bt, counts in sorted(bug_types.items()):
        rate = counts['validated'] / counts['total'] * 100 if counts['total'] > 0 else 0
        print(f"  {bt}: {counts['validated']}/{counts['total']} ({rate:.1f}%)")
    
    # Save results
    output_file = Path(__file__).parent.parent / 'results' / 'tier2_dse_validation_results.json'
    with open(output_file, 'w') as f:
        json.dump({
            'targets': targets,
            'validation_results': validation_results,
            'summary': {
                'total': len(targets),
                'analyzed': len(analyzed),
                'validated': len(validated),
                'errors': len(errors),
                'by_bug_type': bug_types
            }
        }, f, indent=2)
    
    print(f"\nDetailed results saved to: {output_file}")


if __name__ == '__main__':
    main()
