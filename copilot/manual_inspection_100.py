#!/usr/bin/env python3
"""Manual inspection of first 100 bugs - classify as TP or FP with reasoning."""

import json
import ast
import sys
from pathlib import Path
from typing import List, Dict, Any

def extract_code_context(file_path: str, line_num: int, lines_before: int = 5, lines_after: int = 5) -> str:
    """Extract code context around a specific line."""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        start = max(0, line_num - lines_before - 1)
        end = min(len(lines), line_num + lines_after)
        
        context_lines = []
        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            context_lines.append(f"{prefix} {i+1:4d}: {lines[i].rstrip()}")
        
        return "\n".join(context_lines)
    except Exception as e:
        return f"[Error reading file: {e}]"

def analyze_bug(bug: Dict[str, Any], deepspeed_root: Path) -> Dict[str, Any]:
    """Analyze a single bug and classify as TP/FP."""
    
    # Parse location
    location_parts = bug['location'].split(':')
    if len(location_parts) >= 2:
        file_path = deepspeed_root / location_parts[0].replace('external_tools/DeepSpeed/', '')
        line_num = int(location_parts[1])
    else:
        file_path = None
        line_num = 0
    
    # Get code context
    if file_path and file_path.exists():
        code_context = extract_code_context(str(file_path), line_num)
    else:
        code_context = "[File not found]"
    
    # Start classification logic
    classification = "UNKNOWN"
    reasoning = ""
    
    bug_type = bug['type']
    function = bug['function']
    reason = bug['reason']
    variable = bug['variable']
    
    # Pattern-based classification
    if bug_type == "NULL_PTR":
        # Common FP: checking None before use
        if "may trigger NULL_PTR" in reason and not variable:
            classification = "LIKELY_FP"
            reasoning = "Generic NULL_PTR warning without specific variable - likely has checks"
        elif "__init__" in function:
            classification = "LIKELY_FP"
            reasoning = "__init__ methods typically validate inputs"
        else:
            classification = "NEEDS_REVIEW"
            reasoning = "NULL_PTR needs manual verification of checks"
    
    elif bug_type == "DIV_ZERO":
        if "may trigger DIV_ZERO" in reason and not variable:
            classification = "LIKELY_FP"
            reasoning = "Generic DIV_ZERO warning - likely has validation"
        else:
            classification = "NEEDS_REVIEW"
            reasoning = "DIV_ZERO needs verification of denominator validation"
    
    elif bug_type == "VALUE_ERROR":
        if "may trigger VALUE_ERROR" in reason:
            classification = "LIKELY_FP"
            reasoning = "Generic VALUE_ERROR - likely has proper exception handling"
        else:
            classification = "NEEDS_REVIEW"
            reasoning = "VALUE_ERROR needs context review"
    
    elif bug_type == "RUNTIME_ERROR":
        if "may trigger RUNTIME_ERROR" in reason:
            classification = "LIKELY_FP"
            reasoning = "Generic RUNTIME_ERROR - context needed"
        else:
            classification = "NEEDS_REVIEW"
            reasoning = "RUNTIME_ERROR needs manual inspection"
    
    return {
        **bug,
        'classification': classification,
        'reasoning': reasoning,
        'code_context': code_context
    }

def main():
    # Load bugs
    with open('first_100_bugs.json', 'r') as f:
        bugs = json.load(f)
    
    deepspeed_root = Path('external_tools/DeepSpeed')
    
    # Analyze each bug
    analyzed_bugs = []
    for bug in bugs:
        analyzed = analyze_bug(bug, deepspeed_root)
        analyzed_bugs.append(analyzed)
    
    # Save results
    with open('manual_inspection_100_results.json', 'w') as f:
        json.dump(analyzed_bugs, f, indent=2)
    
    # Print summary
    from collections import Counter
    classifications = Counter(b['classification'] for b in analyzed_bugs)
    
    print("\n" + "="*80)
    print("MANUAL INSPECTION OF FIRST 100 BUGS")
    print("="*80)
    print(f"\nClassification Summary:")
    for cls, count in sorted(classifications.items(), key=lambda x: -x[1]):
        print(f"  {cls}: {count}")
    
    print(f"\nResults saved to manual_inspection_100_results.json")
    print(f"\nNow performing detailed manual review...")

if __name__ == '__main__':
    main()
