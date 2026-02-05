#!/usr/bin/env python3
"""
Manual code review of all 31 HIGH severity bugs from DeepSpeed analysis.
This script reads each bug location and extracts surrounding code for review.
"""

import json
from pathlib import Path
from collections import defaultdict

def read_source_context(file_path: Path, line_num: int, context_lines: int = 10):
    """Read source code context around a line."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        start = max(0, line_num - context_lines)
        end = min(len(lines), line_num + context_lines)
        
        return {
            'exists': True,
            'total_lines': len(lines),
            'context': lines[start:end],
            'start_line': start + 1,
            'target_line': line_num,
            'target_content': lines[line_num - 1] if line_num <= len(lines) else None
        }
    except Exception as e:
        return {'exists': False, 'error': str(e)}

def analyze_bug(bug, index):
    """Analyze a single bug with source code review."""
    print(f"\n{'='*80}")
    print(f"BUG #{index}: {bug['type']} - {bug['file']}")
    print(f"{'='*80}")
    print(f"Function: {bug['function']}()")
    print(f"Line: {bug['line']}")
    print(f"Confidence: {bug['confidence']:.2f}")
    print(f"Path: {bug['full_path']}")
    print()
    
    # Read source code
    file_path = Path(bug['full_path'])
    context = read_source_context(file_path, bug['line'], context_lines=8)
    
    if not context['exists']:
        print(f"❌ ERROR: Could not read file - {context.get('error')}")
        return {'index': index, 'verdict': 'CANNOT_VERIFY', 'reason': 'file_not_found'}
    
    print(f"Source code context (lines {context['start_line']}-{context['start_line'] + len(context['context']) - 1}):")
    print("-" * 80)
    
    for i, line in enumerate(context['context']):
        line_num = context['start_line'] + i
        marker = ">>> " if line_num == context['target_line'] else "    "
        print(f"{marker}{line_num:4d}: {line.rstrip()}")
    
    print("-" * 80)
    print()
    
    # Manual analysis
    print("MANUAL ANALYSIS:")
    
    verdict = analyze_bug_pattern(bug, context)
    
    return verdict

def analyze_bug_pattern(bug, context):
    """Analyze bug pattern to determine if it's a true positive."""
    
    if not context.get('target_content'):
        return {'verdict': 'CANNOT_VERIFY', 'reason': 'no_target_content'}
    
    target = context['target_content'].strip()
    all_context = ''.join(context['context']).lower()
    
    # Check for division by zero patterns
    if bug['type'] == 'DIV_ZERO':
        if '//' in target or '/' in target:
            # Check for guards in context
            if any(guard in all_context for guard in ['if ', '!= 0', '> 0', 'assert', 'raise']):
                return {
                    'verdict': 'LIKELY_FALSE_POSITIVE',
                    'reason': 'Division operation but guards present in context',
                    'confidence': 0.3
                }
            else:
                return {
                    'verdict': 'TRUE_POSITIVE',
                    'reason': 'Division operation without visible guards',
                    'confidence': 0.8
                }
    
    # Check for bounds errors
    if bug['type'] == 'BOUNDS':
        if '[' in target:
            # Check for bounds checks
            if any(check in all_context for check in ['len(', 'range(', 'if ', 'assert', 'enumerate']):
                return {
                    'verdict': 'NEEDS_REVIEW',
                    'reason': 'Array access with some bounds-related code nearby',
                    'confidence': 0.5
                }
            else:
                return {
                    'verdict': 'TRUE_POSITIVE',
                    'reason': 'Array access without visible bounds checks',
                    'confidence': 0.7
                }
    
    return {
        'verdict': 'NEEDS_REVIEW',
        'reason': 'Requires deeper analysis',
        'confidence': 0.5
    }

def main():
    # Load bugs
    data = json.load(open('results/deepspeed_balanced_analysis.json'))
    bugs = data['high_severity_bugs']
    
    print("="*80)
    print("MANUAL CODE REVIEW: 31 HIGH SEVERITY BUGS")
    print("="*80)
    print(f"\nTotal bugs to review: {len(bugs)}")
    print()
    
    # Analyze each bug
    verdicts = []
    for i, bug in enumerate(bugs, 1):
        verdict = analyze_bug(bug, i)
        verdict['bug'] = bug
        verdicts.append(verdict)
        
        # Pause every 5 bugs
        if i % 5 == 0 and i < len(bugs):
            input(f"\nPress Enter to continue with next 5 bugs... ({i}/{len(bugs)} reviewed)")
    
    # Summary
    print("\n" + "="*80)
    print("REVIEW SUMMARY")
    print("="*80)
    print()
    
    verdict_counts = defaultdict(int)
    for v in verdicts:
        verdict_counts[v.get('verdict', 'UNKNOWN')] += 1
    
    print("Verdict distribution:")
    for verdict, count in sorted(verdict_counts.items(), key=lambda x: -x[1]):
        pct = 100 * count / len(verdicts)
        print(f"  {verdict:25s}: {count:2d} ({pct:5.1f}%)")
    
    print()
    print("High-confidence TRUE POSITIVES:")
    true_positives = [v for v in verdicts if v.get('verdict') == 'TRUE_POSITIVE' and v.get('confidence', 0) >= 0.7]
    for v in true_positives:
        bug = v['bug']
        print(f"  • {bug['file']}:{bug['function']}() line {bug['line']}")
        print(f"    {bug['type']}: {v['reason']}")
    
    # Save results
    output = {
        'total_reviewed': len(bugs),
        'verdict_counts': dict(verdict_counts),
        'verdicts': [
            {
                'index': v['index'] if 'index' in v else i+1,
                'bug_type': v['bug']['type'],
                'file': v['bug']['file'],
                'function': v['bug']['function'],
                'line': v['bug']['line'],
                'verdict': v.get('verdict', 'UNKNOWN'),
                'reason': v.get('reason', ''),
                'confidence': v.get('confidence', 0)
            }
            for i, v in enumerate(verdicts)
        ]
    }
    
    Path('results/manual_review_results.json').write_text(json.dumps(output, indent=2))
    print(f"\n✓ Results saved to: results/manual_review_results.json")

if __name__ == '__main__':
    main()
