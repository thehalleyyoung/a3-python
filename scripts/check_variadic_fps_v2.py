#!/usr/bin/env python3
"""
Iteration 136: Check for variadic function FP patterns in tier 2 repos

Check numpy, pandas, ansible for similar user-function FPs caused by
variadic functions (*args, **kwargs) not being inlined.
"""

import json
from pathlib import Path

def analyze_scan(scan_file):
    """Analyze a scan file for potential variadic function FPs"""
    
    with open(scan_file) as f:
        data = json.load(f)
    
    # Get repo name from filename
    repo_name = Path(scan_file).stem.split('_')[0]
    
    print(f"\n{'='*70}")
    print(f"Analyzing: {repo_name} ({Path(scan_file).name})")
    print(f"{'='*70}")
    
    results = data.get('results', [])
    bug_files = [r for r in results if r['result'] == 'BUG']
    
    if not bug_files:
        print(f"No bugs found")
        return {
            'repo': repo_name,
            'total_bugs': 0,
            'type_confusion': 0,
            'potential_variadic_fps': []
        }
    
    # Count bugs by type
    bug_types = {}
    for bug in bug_files:
        bt = bug.get('bug_type', 'UNKNOWN')
        bug_types[bt] = bug_types.get(bt, 0) + 1
    
    print(f"Total bugs: {len(bug_files)}")
    print(f"Bug types: {bug_types}")
    
    type_confusion_bugs = [
        b for b in bug_files 
        if b.get('bug_type') == 'TYPE_CONFUSION'
    ]
    
    # Analyze TYPE_CONFUSION bugs for potential variadic patterns
    potential_variadic = []
    
    for bug in type_confusion_bugs:
        file_path = bug['file']
        bug_info = bug.get('bug_info', {})
        context = bug_info.get('context', {})
        
        # Look for patterns that might indicate variadic function issues:
        # 1. Binary operations (especially + for string concat)
        # 2. In files with function definitions
        # 3. Module init context
        
        instruction = context.get('instruction', '')
        is_binary_op = 'BINARY_OP' in instruction
        offset = context.get('offset', 999999)
        
        potential_variadic.append({
            'file': file_path,
            'offset': offset,
            'instruction': instruction,
            'message': bug_info.get('message', ''),
            'is_binary_op': is_binary_op
        })
    
    if type_confusion_bugs:
        print(f"\nTYPE_CONFUSION bugs: {len(type_confusion_bugs)}")
        for i, pv in enumerate(potential_variadic, 1):
            print(f"  {i}. {Path(pv['file']).name} @ offset {pv['offset']}")
            print(f"     {pv['instruction']}")
            if pv['is_binary_op']:
                print(f"     ⚠️  BINARY_OP - potential variadic FP candidate")
    
    return {
        'repo': repo_name,
        'scan_file': str(scan_file),
        'total_bugs': len(bug_files),
        'bug_types': bug_types,
        'type_confusion': len(type_confusion_bugs),
        'potential_variadic_fps': potential_variadic
    }

def main():
    # Use most recent scans from iteration 124 (Phase 2)
    scan_files = [
        'results/public_repos/scan_results/numpy_20260123_111454.json',
        'results/public_repos/scan_results/pandas_20260123_091009.json',
        'results/public_repos/scan_results/ansible_20260123_111406.json'
    ]
    
    all_results = {}
    for scan_file in scan_files:
        if Path(scan_file).exists():
            result = analyze_scan(scan_file)
            all_results[result['repo']] = result
        else:
            print(f"Warning: {scan_file} not found")
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    
    total_bugs = sum(r['total_bugs'] for r in all_results.values())
    total_type_confusion = sum(r['type_confusion'] for r in all_results.values())
    total_potential = sum(len(r['potential_variadic_fps']) for r in all_results.values())
    
    print(f"\nTotal bugs across repos: {total_bugs}")
    print(f"Total TYPE_CONFUSION bugs: {total_type_confusion}")
    print(f"Potential variadic function FPs (BINARY_OP + TYPE_CONFUSION): {sum(1 for r in all_results.values() for p in r['potential_variadic_fps'] if p['is_binary_op'])}")
    
    if total_type_confusion == 0:
        print("\n✅ No TYPE_CONFUSION bugs in numpy, pandas, ansible")
        print("   The sklearn variadic FP appears to be an isolated case")
    elif total_potential == 0:
        print("\n✅ TYPE_CONFUSION bugs present but not BINARY_OP pattern")
        print("   Different root cause than sklearn variadic FP")
    else:
        print(f"\n⚠️  Found TYPE_CONFUSION bugs with similar patterns")
        print("   Consider prioritizing Phase 4 implementation")
    
    # Save results
    output_file = Path('results/variadic_fp_check_iter136.json')
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to: {output_file}")
    
    return all_results

if __name__ == '__main__':
    main()
