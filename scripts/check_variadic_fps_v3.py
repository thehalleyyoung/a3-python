#!/usr/bin/env python3
"""
Iteration 136: Check for variadic function FP patterns in tier 2 repos
"""

import json
from pathlib import Path
from collections import defaultdict

def analyze_scan(scan_file):
    """Analyze a scan file for potential variadic function FPs"""
    
    with open(scan_file) as f:
        data = json.load(f)
    
    repo_name = Path(scan_file).stem.split('_')[0]
    
    print(f"\n{'='*70}")
    print(f"Analyzing: {repo_name} ({Path(scan_file).name})")
    print(f"{'='*70}")
    
    findings = data.get('findings', [])
    summary = data.get('summary', {})
    
    print(f"Summary: {summary}")
    
    # Filter to actual bugs (verdict == BUG)
    bugs = [f for f in findings if f.get('verdict') == 'BUG']
    
    if not bugs:
        print(f"No bugs found")
        return {
            'repo': repo_name,
            'total_bugs': 0,
            'type_confusion': 0,
            'potential_variadic_fps': []
        }
    
    # Count bugs by type
    bug_types = defaultdict(int)
    for bug in bugs:
        bt = bug.get('bug_type', 'UNKNOWN')
        bug_types[bt] += 1
    
    print(f"\nBug breakdown:")
    for bt, count in sorted(bug_types.items()):
        print(f"  {bt}: {count}")
    
    # Focus on TYPE_CONFUSION bugs
    type_confusion_bugs = [b for b in bugs if b.get('bug_type') == 'TYPE_CONFUSION']
    
    potential_variadic = []
    
    for bug in type_confusion_bugs:
        file_path = bug.get('file_path', '')
        location = bug.get('location', {})
        message = bug.get('message', '')
        
        # Extract context
        offset = location.get('offset') if location else None
        instruction = location.get('instruction') if location else None
        
        is_binary_op = instruction and 'BINARY_OP' in instruction
        
        potential_variadic.append({
            'file': Path(file_path).name if file_path else 'unknown',
            'full_path': file_path,
            'offset': offset,
            'instruction': instruction,
            'message': message,
            'is_binary_op': is_binary_op
        })
    
    if type_confusion_bugs:
        print(f"\nTYPE_CONFUSION bugs: {len(type_confusion_bugs)}")
        for i, pv in enumerate(potential_variadic, 1):
            print(f"  {i}. {pv['file']}")
            if pv['instruction']:
                print(f"     Instruction: {pv['instruction']}")
            if pv['is_binary_op']:
                print(f"     ⚠️  BINARY_OP - potential variadic FP candidate")
            print(f"     Message: {pv['message'][:100]}...")
    
    return {
        'repo': repo_name,
        'scan_file': str(scan_file),
        'total_bugs': len(bugs),
        'bug_types': dict(bug_types),
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
    
    binary_op_fps = []
    for repo, result in all_results.items():
        for fp in result['potential_variadic_fps']:
            if fp['is_binary_op']:
                binary_op_fps.append((repo, fp))
    
    print(f"\nTotal bugs across repos: {total_bugs}")
    print(f"Total TYPE_CONFUSION bugs: {total_type_confusion}")
    print(f"BINARY_OP + TYPE_CONFUSION (variadic FP pattern): {len(binary_op_fps)}")
    
    if total_type_confusion == 0:
        print("\n✅ No TYPE_CONFUSION bugs in numpy, pandas, ansible")
        print("   The sklearn variadic FP appears to be an isolated case")
    elif len(binary_op_fps) == 0:
        print("\n✅ TYPE_CONFUSION bugs present but NOT BINARY_OP pattern")
        print("   Different root cause than sklearn variadic FP")
    else:
        print(f"\n⚠️  Found {len(binary_op_fps)} TYPE_CONFUSION bugs with BINARY_OP pattern")
        print("   These may be similar variadic FPs:")
        for repo, fp in binary_op_fps:
            print(f"   - {repo}: {fp['file']}")
    
    # Save results
    output_file = Path('results/variadic_fp_check_iter136.json')
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to: {output_file}")
    
    return all_results

if __name__ == '__main__':
    main()
