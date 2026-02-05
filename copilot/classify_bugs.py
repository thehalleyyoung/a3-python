#!/usr/bin/env python3
"""
Classify bugs as True Positive (TP) or False Positive (FP).

For each bug found by the interprocedural analysis, this script:
1. Reads the source code at the bug location
2. Applies heuristic rules to classify as TP or FP
3. Updates the markdown file with classifications

Classification Rules:
- FP: Bug in test file (test_*.py, *_test.py)
- FP: Bug in __init__.py (usually import-time, handled)
- FP: Bug in code protected by try/except
- FP: Bug with guarded variable (None check, bounds check)
- TP: Bug in core code with no visible guard
- UNCERTAIN: Needs manual review
"""

import sys
import os
import re
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple

# Add project root
sys.path.insert(0, str(Path(__file__).parent))

# Results directory
RESULTS_DIR = Path(__file__).parent / 'results' / 'non_security_bugs'


def read_source_context(file_path: str, line_number: int, context: int = 5) -> Optional[str]:
    """Read source code context around a line."""
    try:
        path = Path(file_path)
        if not path.exists():
            return None
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        
        context_lines = []
        for i in range(start, end):
            marker = ">>>" if i == line_number - 1 else "   "
            context_lines.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")
        
        return '\n'.join(context_lines)
    except Exception as e:
        return f"Error reading file: {e}"


def classify_bug(bug: Dict[str, Any]) -> Tuple[str, str]:
    """
    Classify a bug as TP, FP, or UNCERTAIN.
    
    Returns: (classification, reason)
    """
    location = bug.get('location', '')
    func = bug.get('function', '')
    bug_type = bug.get('bug_type', '')
    reason = bug.get('reason', '')
    confidence = bug.get('confidence', 1.0)
    call_chain = bug.get('call_chain', [])
    
    # Extract file path and line from location
    file_path = ''
    line_num = 0
    if ':' in location:
        parts = location.rsplit(':', 1)
        file_path = parts[0]
        try:
            line_num = int(parts[1])
        except ValueError:
            pass
    
    # Rule 1: Test files are usually FP (tests exercise error paths)
    if file_path:
        file_name = Path(file_path).name
        if file_name.startswith('test_') or file_name.endswith('_test.py') or '/tests/' in file_path:
            return ('FP', 'Test file - intentional error path testing')
    
    # Rule 2: Very low confidence suggests already guarded
    if confidence < 0.25:
        return ('FP', f'Low confidence ({confidence:.2f}) - likely guarded')
    
    # Rule 3: __init__.py imports are usually handled
    if file_path and Path(file_path).name == '__init__.py' and bug_type == 'IMPORT_ERROR':
        return ('FP', '__init__.py import - typically handled at module level')
    
    # Rule 4: Check for guard patterns in reason
    if 'interprocedural guard' in reason.lower():
        return ('FP', 'Interprocedural guard detected')
    
    # Rule 5: Read source context and look for guards
    if file_path and line_num > 0:
        context = read_source_context(file_path, line_num, context=10)
        if context:
            # Check for try/except pattern
            if 'try:' in context and ('except' in context or 'finally:' in context):
                return ('FP', 'Protected by try/except block')
            
            # Check for None guards
            if bug_type == 'NULL_PTR':
                if 'is not None' in context or 'is None' in context:
                    return ('FP', 'None check in nearby code')
                if '!= None' in context or '== None' in context:
                    return ('FP', 'None comparison in nearby code')
            
            # Check for bounds guards
            if bug_type == 'BOUNDS':
                if 'len(' in context and ('<' in context or '>' in context or 'if ' in context):
                    return ('FP', 'Length check in nearby code')
                if 'range(len(' in context:
                    return ('FP', 'Bounded by range(len(...))')
            
            # Check for div guards
            if bug_type == 'DIV_ZERO':
                if '!= 0' in context or '> 0' in context or '< 0' in context:
                    return ('FP', 'Non-zero check in nearby code')
    
    # Rule 6: Long call chains with low-confidence intermediate calls
    if len(call_chain) >= 3 and confidence < 0.5:
        return ('UNCERTAIN', f'Long call chain ({len(call_chain)} calls) - may be context-dependent')
    
    # Rule 7: Configuration/setup code is often FP
    if file_path:
        file_name = Path(file_path).name
        if file_name in ('setup.py', 'conftest.py', 'config.py', 'settings.py'):
            return ('UNCERTAIN', 'Configuration file - typically guarded by environment')
    
    # Default: likely true positive, needs review
    if confidence >= 0.7:
        return ('TP', f'High confidence ({confidence:.2f}) - likely real bug')
    elif confidence >= 0.4:
        return ('UNCERTAIN', f'Medium confidence ({confidence:.2f}) - needs review')
    else:
        return ('UNCERTAIN', f'Low-medium confidence ({confidence:.2f}) - needs review')


def classify_repo_bugs(repo_name: str) -> Dict[str, Any]:
    """Classify all bugs for a repo."""
    json_path = RESULTS_DIR / 'combined_results.json'
    
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    # Find the repo data
    repo_data = None
    for repo in data.get('repos', []):
        if repo.get('repo_name') == repo_name:
            repo_data = repo
            break
    
    if not repo_data:
        return {'error': f'Repo {repo_name} not found'}
    
    bugs = repo_data.get('bugs', [])
    
    # Classify each bug
    classifications = {'TP': [], 'FP': [], 'UNCERTAIN': []}
    
    for bug in bugs:
        classification, reason = classify_bug(bug)
        bug['classification'] = classification
        bug['classification_reason'] = reason
        classifications[classification].append(bug)
    
    return {
        'repo_name': repo_name,
        'total_bugs': len(bugs),
        'true_positives': len(classifications['TP']),
        'false_positives': len(classifications['FP']),
        'uncertain': len(classifications['UNCERTAIN']),
        'classifications': classifications,
    }


def generate_classified_markdown(repo_name: str, result: Dict[str, Any]) -> str:
    """Generate markdown with classified bugs."""
    lines = [
        f"# {repo_name} - Non-Security Bug Analysis (Classified)",
        "",
        "## Classification Summary",
        "",
        f"- **Total Bugs Analyzed**: {result['total_bugs']}",
        f"- **True Positives (TP)**: {result['true_positives']} ({result['true_positives']/result['total_bugs']*100:.1f}%)" if result['total_bugs'] > 0 else "- **True Positives (TP)**: 0",
        f"- **False Positives (FP)**: {result['false_positives']} ({result['false_positives']/result['total_bugs']*100:.1f}%)" if result['total_bugs'] > 0 else "- **False Positives (FP)**: 0",
        f"- **Uncertain**: {result['uncertain']} ({result['uncertain']/result['total_bugs']*100:.1f}%)" if result['total_bugs'] > 0 else "- **Uncertain**: 0",
        "",
    ]
    
    # True Positives
    lines.extend([
        "## ✅ True Positives (Likely Real Bugs)",
        "",
    ])
    
    tp_by_type = defaultdict(list)
    for bug in result['classifications']['TP']:
        tp_by_type[bug['bug_type']].append(bug)
    
    for bug_type, bugs in sorted(tp_by_type.items()):
        lines.append(f"### {bug_type} ({len(bugs)})")
        lines.append("")
        for i, bug in enumerate(bugs[:10]):  # Limit to 10 per type
            lines.append(f"{i+1}. **`{bug['function']}`**")
            if bug.get('location'):
                lines.append(f"   - Location: {bug['location']}")
            lines.append(f"   - Reason: {bug.get('reason', 'N/A')[:80]}")
            lines.append(f"   - Classification: {bug['classification_reason']}")
            lines.append("")
        if len(bugs) > 10:
            lines.append(f"*... and {len(bugs) - 10} more*")
            lines.append("")
    
    # False Positives
    lines.extend([
        "## ❌ False Positives (Filtered)",
        "",
    ])
    
    fp_by_reason = defaultdict(list)
    for bug in result['classifications']['FP']:
        fp_by_reason[bug['classification_reason']].append(bug)
    
    for reason, bugs in sorted(fp_by_reason.items(), key=lambda x: -len(x[1])):
        lines.append(f"### {reason} ({len(bugs)})")
        lines.append("")
        for bug in bugs[:5]:
            lines.append(f"- `{bug['function']}` ({bug['bug_type']})")
        if len(bugs) > 5:
            lines.append(f"*... and {len(bugs) - 5} more*")
        lines.append("")
    
    # Uncertain
    lines.extend([
        "## ❓ Uncertain (Needs Manual Review)",
        "",
    ])
    
    uncertain_by_type = defaultdict(list)
    for bug in result['classifications']['UNCERTAIN']:
        uncertain_by_type[bug['bug_type']].append(bug)
    
    for bug_type, bugs in sorted(uncertain_by_type.items()):
        lines.append(f"### {bug_type} ({len(bugs)})")
        lines.append("")
        for i, bug in enumerate(bugs[:10]):
            lines.append(f"{i+1}. **`{bug['function']}`**")
            if bug.get('location'):
                lines.append(f"   - Location: {bug['location']}")
            lines.append(f"   - Reason: {bug.get('reason', 'N/A')[:80]}")
            lines.append(f"   - Why uncertain: {bug['classification_reason']}")
            lines.append("")
        if len(bugs) > 10:
            lines.append(f"*... and {len(bugs) - 10} more*")
            lines.append("")
    
    return '\n'.join(lines)


def main():
    """Main entry point."""
    # Get repos from combined results
    json_path = RESULTS_DIR / 'combined_results.json'
    
    if not json_path.exists():
        print(f"No combined results found at {json_path}")
        print("Run evaluate_repos_non_security.py first")
        sys.exit(1)
    
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    repos = [r['repo_name'] for r in data.get('repos', []) if 'error' not in r]
    
    if len(sys.argv) > 1:
        repos = [r for r in sys.argv[1:] if r in repos]
    
    print("="*60)
    print("BUG CLASSIFICATION")
    print("="*60)
    
    all_results = []
    
    for repo_name in repos:
        print(f"\nClassifying {repo_name}...")
        result = classify_repo_bugs(repo_name)
        
        if 'error' in result:
            print(f"  Error: {result['error']}")
            continue
        
        all_results.append(result)
        
        print(f"  Total: {result['total_bugs']}")
        print(f"  TP: {result['true_positives']}")
        print(f"  FP: {result['false_positives']}")
        print(f"  Uncertain: {result['uncertain']}")
        
        # Generate classified markdown
        markdown = generate_classified_markdown(repo_name, result)
        output_path = RESULTS_DIR / f"{repo_name}_classified.md"
        output_path.write_text(markdown)
        print(f"  Saved: {output_path}")
    
    # Summary
    print("\n" + "="*60)
    print("OVERALL SUMMARY")
    print("="*60)
    
    total_bugs = sum(r['total_bugs'] for r in all_results)
    total_tp = sum(r['true_positives'] for r in all_results)
    total_fp = sum(r['false_positives'] for r in all_results)
    total_uncertain = sum(r['uncertain'] for r in all_results)
    
    print(f"\nTotal bugs: {total_bugs}")
    print(f"True Positives: {total_tp} ({total_tp/total_bugs*100:.1f}%)" if total_bugs > 0 else "True Positives: 0")
    print(f"False Positives: {total_fp} ({total_fp/total_bugs*100:.1f}%)" if total_bugs > 0 else "False Positives: 0")
    print(f"Uncertain: {total_uncertain} ({total_uncertain/total_bugs*100:.1f}%)" if total_bugs > 0 else "Uncertain: 0")
    
    # Save summary
    summary = {
        'repos': [{'repo_name': r['repo_name'], 
                   'total': r['total_bugs'],
                   'tp': r['true_positives'],
                   'fp': r['false_positives'],
                   'uncertain': r['uncertain']} for r in all_results],
        'totals': {
            'total_bugs': total_bugs,
            'true_positives': total_tp,
            'false_positives': total_fp,
            'uncertain': total_uncertain,
        }
    }
    
    summary_path = RESULTS_DIR / 'classification_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to: {summary_path}")


if __name__ == '__main__':
    main()
