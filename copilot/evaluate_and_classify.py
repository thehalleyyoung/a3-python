#!/usr/bin/env python3
"""
Evaluate all repos and generate MD files with TP/FP classification.
True positives are listed first, then false positives.
"""

import sys
import os
import json
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

# Repos to analyze
REPOS = ['pygoat', 'Counterfit', 'Presidio', 'GraphRAG']

# Output directory
OUTPUT_DIR = Path(__file__).parent / 'results' / 'classified_bugs'

# Non-security bug types
NON_SECURITY_BUG_TYPES = {
    'NULL_PTR', 'DIV_ZERO', 'BOUNDS', 'TYPE_CONFUSION', 'ASSERT_FAIL',
    'INTEGER_OVERFLOW', 'ITERATOR_INVALID', 'USE_AFTER_FREE', 'DOUBLE_FREE',
    'MEMORY_LEAK', 'STACK_OVERFLOW', 'HEAP_OVERFLOW', 'FORMAT_STRING',
    'RACE_CONDITION', 'DEADLOCK', 'UNINITIALIZED_VAR', 'DANGLING_PTR',
    'BUFFER_OVERREAD', 'BUFFER_OVERWRITE', 'UNCHECKED_RETURN',
    'VALUE_ERROR', 'RUNTIME_ERROR', 'FILE_NOT_FOUND', 'PERMISSION_ERROR',
    'OS_ERROR', 'IO_ERROR', 'IMPORT_ERROR', 'NAME_ERROR', 'UNBOUND_LOCAL',
    'TIMEOUT_ERROR', 'INDEX_ERROR', 'KEY_ERROR', 'ATTRIBUTE_ERROR'
}

# FP classification rules
FP_PATTERNS = [
    # Test files (crash_location is file:line format)
    (lambda b: 'test' in b.crash_location.lower(), "Test file"),
    (lambda b: 'tests/' in b.crash_location.lower(), "Test directory"),
    (lambda b: '_test.py' in b.crash_location.lower(), "Test file suffix"),
    (lambda b: 'test_' in b.crash_location.lower().split('/')[-1], "Test file prefix"),
    
    # Self/cls on NULL_PTR
    (lambda b: b.bug_type == 'NULL_PTR' and b.bug_variable and 
               b.bug_variable.split('.')[0].split('[')[0] in ('self', 'cls'), 
     "self/cls never None"),
    
    # Guarded bugs
    (lambda b: hasattr(b, 'is_guarded') and b.is_guarded, "Guarded by check"),
    
    # Low confidence
    (lambda b: hasattr(b, 'confidence') and b.confidence < 0.3, "Low confidence"),
    
    # Exception handlers
    (lambda b: 'except' in str(getattr(b, 'context', '')).lower(), "In exception handler"),
    
    # __init__.py IMPORT_ERROR
    (lambda b: b.bug_type == 'IMPORT_ERROR' and '__init__.py' in b.crash_location, 
     "Import in __init__.py"),
    
    # Config/settings files
    (lambda b: 'config' in b.crash_location.lower() or 'settings' in b.crash_location.lower(),
     "Config file"),
    
    # Migration files
    (lambda b: 'migration' in b.crash_location.lower(), "Migration file"),
]

# TP patterns (bugs that are likely real)
TP_PATTERNS = [
    # Division by user input
    (lambda b: b.bug_type == 'DIV_ZERO' and 'request' in str(b.call_chain).lower(),
     "Division with user input"),
    
    # Bounds with external data
    (lambda b: b.bug_type == 'BOUNDS' and any(x in str(b.call_chain).lower() 
               for x in ['request', 'input', 'file', 'read']),
     "Bounds with external data"),
    
    # NULL_PTR on return values
    (lambda b: b.bug_type == 'NULL_PTR' and 'get' in b.crash_function.lower(),
     "NULL_PTR on get() return"),
]


def classify_bug(bug) -> Tuple[bool, str]:
    """
    Classify a bug as TP or FP.
    Returns (is_tp, reason).
    """
    # Check FP patterns first
    for pattern, reason in FP_PATTERNS:
        try:
            if pattern(bug):
                return (False, reason)
        except:
            pass
    
    # Check TP patterns
    for pattern, reason in TP_PATTERNS:
        try:
            if pattern(bug):
                return (True, reason)
        except:
            pass
    
    # Default: treat as potential TP (conservative)
    return (True, "No FP pattern matched")


def get_repo_path(repo_name: str) -> Path:
    """Get the path to a repository."""
    base = Path(__file__).parent / 'external_tools'
    return base / repo_name


def analyze_repo(repo_name: str) -> Dict:
    """Analyze a repository and return classified bugs."""
    repo_path = get_repo_path(repo_name)
    
    if not repo_path.exists():
        print(f"  Warning: {repo_path} does not exist")
        return {'tp': [], 'fp': [], 'stats': {}}
    
    print(f"  Building interprocedural analysis...")
    try:
        # Pass Path object, not string
        tracker = InterproceduralBugTracker.from_project(repo_path)
    except Exception as e:
        print(f"  Error building tracker: {e}")
        import traceback
        traceback.print_exc()
        return {'tp': [], 'fp': [], 'stats': {}}
    
    print(f"  Functions: {len(tracker.call_graph.functions)}")
    print(f"  Running analysis...")
    
    all_bugs = tracker.find_all_bugs()
    
    # Filter to non-security bugs
    non_security = [b for b in all_bugs if b.bug_type in NON_SECURITY_BUG_TYPES]
    print(f"  Total bugs: {len(all_bugs)}, Non-security: {len(non_security)}")
    
    # Classify each bug
    tp_bugs = []
    fp_bugs = []
    
    for bug in non_security:
        is_tp, reason = classify_bug(bug)
        # crash_location is "file:line" format
        location_parts = bug.crash_location.split(':')
        crash_file = ':'.join(location_parts[:-1]) if len(location_parts) > 1 else bug.crash_location
        crash_line = location_parts[-1] if len(location_parts) > 1 else None
        
        bug_info = {
            'type': bug.bug_type,
            'file': crash_file,
            'function': bug.crash_function,
            'line': crash_line,
            'variable': bug.bug_variable,
            'call_chain': bug.call_chain[:3] if len(bug.call_chain) > 3 else bug.call_chain,
            'confidence': getattr(bug, 'confidence', 1.0),
            'reason': reason,
        }
        
        if is_tp:
            tp_bugs.append(bug_info)
        else:
            fp_bugs.append(bug_info)
    
    # Stats by type
    stats = defaultdict(lambda: {'tp': 0, 'fp': 0})
    for b in tp_bugs:
        stats[b['type']]['tp'] += 1
    for b in fp_bugs:
        stats[b['type']]['fp'] += 1
    
    print(f"  Classified: {len(tp_bugs)} TP, {len(fp_bugs)} FP")
    
    return {
        'tp': tp_bugs,
        'fp': fp_bugs,
        'stats': dict(stats),
    }


def generate_markdown(repo_name: str, results: Dict) -> str:
    """Generate markdown report for a repository."""
    tp_bugs = results['tp']
    fp_bugs = results['fp']
    stats = results['stats']
    
    lines = []
    lines.append(f"# {repo_name} - Non-Security Bug Analysis")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **True Positives**: {len(tp_bugs)}")
    lines.append(f"- **False Positives**: {len(fp_bugs)}")
    lines.append(f"- **Total**: {len(tp_bugs) + len(fp_bugs)}")
    lines.append(f"- **FP Rate**: {len(fp_bugs) / max(1, len(tp_bugs) + len(fp_bugs)) * 100:.1f}%")
    lines.append("")
    
    # Stats by type
    lines.append("## By Bug Type")
    lines.append("")
    lines.append("| Type | TP | FP | Total |")
    lines.append("|------|----|----|-------|")
    for bug_type in sorted(stats.keys()):
        s = stats[bug_type]
        lines.append(f"| {bug_type} | {s['tp']} | {s['fp']} | {s['tp'] + s['fp']} |")
    lines.append("")
    
    # TRUE POSITIVES FIRST
    lines.append("---")
    lines.append("")
    lines.append("## TRUE POSITIVES")
    lines.append("")
    
    if tp_bugs:
        # Group by type
        by_type = defaultdict(list)
        for b in tp_bugs:
            by_type[b['type']].append(b)
        
        for bug_type in sorted(by_type.keys()):
            bugs = by_type[bug_type]
            lines.append(f"### {bug_type} ({len(bugs)})")
            lines.append("")
            
            for i, b in enumerate(bugs[:20], 1):  # Limit to 20 per type
                file_rel = b['file'].split('external_tools/')[-1] if 'external_tools/' in b['file'] else b['file']
                line_info = f" (line {b['line']})" if b['line'] else ""
                var_info = f" on `{b['variable']}`" if b['variable'] else ""
                
                lines.append(f"{i}. **{b['function']}**{var_info}")
                lines.append(f"   - File: `{file_rel}`{line_info}")
                lines.append(f"   - Reason: {b['reason']}")
                if b['call_chain'] and len(b['call_chain']) > 1:
                    chain = ' → '.join(b['call_chain'][:3])
                    lines.append(f"   - Call chain: `{chain}`")
                lines.append("")
            
            if len(bugs) > 20:
                lines.append(f"*... and {len(bugs) - 20} more*")
                lines.append("")
    else:
        lines.append("*No true positives found*")
        lines.append("")
    
    # FALSE POSITIVES
    lines.append("---")
    lines.append("")
    lines.append("## FALSE POSITIVES")
    lines.append("")
    
    if fp_bugs:
        # Group by reason
        by_reason = defaultdict(list)
        for b in fp_bugs:
            by_reason[b['reason']].append(b)
        
        for reason in sorted(by_reason.keys()):
            bugs = by_reason[reason]
            lines.append(f"### {reason} ({len(bugs)})")
            lines.append("")
            
            for i, b in enumerate(bugs[:10], 1):  # Limit to 10 per reason
                file_rel = b['file'].split('external_tools/')[-1] if 'external_tools/' in b['file'] else b['file']
                lines.append(f"{i}. `{b['type']}` in **{b['function']}** - `{file_rel}`")
            
            if len(bugs) > 10:
                lines.append(f"   *... and {len(bugs) - 10} more*")
            lines.append("")
    else:
        lines.append("*No false positives identified*")
        lines.append("")
    
    return '\n'.join(lines)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    all_stats = {}
    
    for repo in REPOS:
        print(f"\n{'='*60}")
        print(f"Analyzing {repo}...")
        print('='*60)
        
        results = analyze_repo(repo)
        all_stats[repo] = {
            'tp': len(results['tp']),
            'fp': len(results['fp']),
        }
        
        # Generate and save markdown
        md_content = generate_markdown(repo, results)
        md_path = OUTPUT_DIR / f"{repo}_bugs.md"
        md_path.write_text(md_content)
        print(f"  Saved: {md_path}")
    
    # Print summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    total_tp = sum(s['tp'] for s in all_stats.values())
    total_fp = sum(s['fp'] for s in all_stats.values())
    
    print(f"\n{'Repo':<15} {'TP':>6} {'FP':>6} {'Total':>7} {'FP Rate':>8}")
    print("-" * 45)
    for repo, stats in all_stats.items():
        total = stats['tp'] + stats['fp']
        fp_rate = stats['fp'] / max(1, total) * 100
        print(f"{repo:<15} {stats['tp']:>6} {stats['fp']:>6} {total:>7} {fp_rate:>7.1f}%")
    
    print("-" * 45)
    total = total_tp + total_fp
    fp_rate = total_fp / max(1, total) * 100
    print(f"{'TOTAL':<15} {total_tp:>6} {total_fp:>6} {total:>7} {fp_rate:>7.1f}%")
    
    print(f"\nResults saved to: {OUTPUT_DIR}/")


if __name__ == '__main__':
    main()
