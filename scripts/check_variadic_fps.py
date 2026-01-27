#!/usr/bin/env python3
"""
Iteration 136: Check for variadic function FP patterns in tier 2 repos

Check numpy, pandas, ansible for similar user-function FPs caused by
variadic functions (*args, **kwargs) not being inlined.
"""

import json
import os
from pathlib import Path

def analyze_repo(repo_name, results_dir):
    """Analyze a repo's scan results for potential variadic function FPs"""
    
    # Find most recent scan results
    pattern = f"{repo_name}_scan_*.json"
    scan_files = sorted(results_dir.glob(pattern), reverse=True)
    
    if not scan_files:
        print(f"No scan results found for {repo_name}")
        return None
    
    scan_file = scan_files[0]
    print(f"\n{'='*70}")
    print(f"Analyzing: {repo_name} ({scan_file.name})")
    print(f"{'='*70}")
    
    with open(scan_file) as f:
        data = json.load(f)
    
    # Count bugs by type
    bug_files = [r for r in data.get('results', []) if r['result'] == 'BUG']
    
    if not bug_files:
        print(f"No bugs found in {repo_name}")
        return {
            'repo': repo_name,
            'total_bugs': 0,
            'type_confusion': 0,
            'potential_variadic_fps': []
        }
    
    type_confusion_bugs = [
        b for b in bug_files 
        if b.get('bug_type') == 'TYPE_CONFUSION'
    ]
    
    print(f"Total bugs: {len(bug_files)}")
    print(f"TYPE_CONFUSION bugs: {len(type_confusion_bugs)}")
    
    # Analyze TYPE_CONFUSION bugs for potential variadic patterns
    potential_variadic = []
    
    for bug in type_confusion_bugs:
        file_path = bug['file']
        bug_info = bug.get('bug_info', {})
        context = bug_info.get('context', {})
        
        # Look for patterns that might indicate variadic function issues:
        # 1. Binary operations (especially + for string concat)
        # 2. In files with function definitions
        # 3. Low offset (module init)
        
        is_binary_op = 'BINARY_OP' in context.get('instruction', '')
        offset = context.get('offset', 999999)
        in_module_init = offset < 2000  # Heuristic for module init
        
        if is_binary_op and in_module_init:
            potential_variadic.append({
                'file': file_path,
                'offset': offset,
                'instruction': context.get('instruction', ''),
                'message': bug_info.get('message', '')
            })
    
    print(f"Potential variadic FPs (BINARY_OP in module init): {len(potential_variadic)}")
    
    if potential_variadic:
        print("\nDetails:")
        for i, pv in enumerate(potential_variadic[:5], 1):  # Show up to 5
            print(f"  {i}. {Path(pv['file']).name} @ offset {pv['offset']}")
            print(f"     {pv['instruction']}")
    
    return {
        'repo': repo_name,
        'total_bugs': len(bug_files),
        'type_confusion': len(type_confusion_bugs),
        'potential_variadic_fps': potential_variadic
    }

def main():
    results_dir = Path('results')
    
    # Check the three repos mentioned in queue
    repos = ['numpy', 'pandas', 'ansible']
    
    all_results = {}
    for repo in repos:
        result = analyze_repo(repo, results_dir)
        if result:
            all_results[repo] = result
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    
    total_potential = sum(
        len(r['potential_variadic_fps']) 
        for r in all_results.values()
    )
    
    total_type_confusion = sum(
        r['type_confusion'] 
        for r in all_results.values()
    )
    
    print(f"\nTotal TYPE_CONFUSION bugs across repos: {total_type_confusion}")
    print(f"Potential variadic function FPs: {total_potential}")
    
    if total_potential == 0:
        print("\n✅ No variadic function FP patterns detected in numpy, pandas, ansible")
        print("   This FP pattern appears to be sklearn-specific")
    else:
        print(f"\n⚠️  Found {total_potential} potential variadic FPs")
        print("   Consider prioritizing Phase 4 implementation")
    
    # Save results
    output_file = results_dir / 'variadic_fp_check_iter136.json'
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to: {output_file}")

if __name__ == '__main__':
    main()
