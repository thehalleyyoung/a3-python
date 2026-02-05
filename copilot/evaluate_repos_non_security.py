#!/usr/bin/env python3
"""
Evaluate all external repos for non-security bugs using INTERPROCEDURAL analysis.

Uses the full interprocedural bug tracker with Z3-backed guard verification to find
bugs across function and file boundaries, while eliminating false positives through
interprocedural guard propagation.

Non-security bug types (from registry.py):
- NULL_PTR: NoneType attribute access
- DIV_ZERO: Division by zero
- BOUNDS: Index out of bounds
- TYPE_CONFUSION: Type mismatch
- ASSERT_FAIL: Failed assertions
- INTEGER_OVERFLOW: Integer overflow
- FP_DOMAIN: Floating point domain errors
- STACK_OVERFLOW: Recursion depth exceeded
- MEMORY_LEAK: Resource not released
- NON_TERMINATION: Infinite loops
- ITERATOR_INVALID: Iterator modification during iteration
- USE_AFTER_FREE: Use after resource closed
- DOUBLE_FREE: Double close/release
- UNINIT_MEMORY: Use of uninitialized variable
- DATA_RACE: Concurrent modification
- DEADLOCK: Lock ordering issues

Plus exception-based bugs:
- VALUE_ERROR, RUNTIME_ERROR, FILE_NOT_FOUND, etc.

INTERPROCEDURAL ANALYSIS:
- Builds call graph across all files
- Computes crash summaries with guard facts
- Propagates guards interprocedurally (caller guards protect callee bugs)
- Uses Z3 to verify guard implications
"""

import sys
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Any, Optional
import json

# Add the project root to path
sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker, InterproceduralBug
from pyfromscratch.semantics.interprocedural_guards import check_bug_guarded_by_z3
from pyfromscratch.unsafe.registry import SECURITY_BUG_TYPES


# Non-security bug types to check (core error bugs)
NON_SECURITY_BUG_TYPES = {
    # Core error types
    'NULL_PTR', 'DIV_ZERO', 'BOUNDS', 'TYPE_CONFUSION',
    'ASSERT_FAIL', 'INTEGER_OVERFLOW', 'FP_DOMAIN',
    'STACK_OVERFLOW', 'MEMORY_LEAK', 'NON_TERMINATION',
    'ITERATOR_INVALID', 'USE_AFTER_FREE', 'DOUBLE_FREE',
    'UNINIT_MEMORY', 'DATA_RACE', 'DEADLOCK', 'SEND_SYNC',
    'INFO_LEAK', 'TIMING_CHANNEL',
    # Exception-based bug types
    'VALUE_ERROR', 'RUNTIME_ERROR', 'FILE_NOT_FOUND',
    'PERMISSION_ERROR', 'OS_ERROR', 'IO_ERROR', 'IMPORT_ERROR',
    'NAME_ERROR', 'UNBOUND_LOCAL', 'TIMEOUT_ERROR',
    'CONNECTION_ERROR', 'UNICODE_ERROR', 'KEY_ERROR',
    'ATTRIBUTE_ERROR', 'INDEX_ERROR', 'STOP_ITERATION',
    'TYPE_ERROR', 'ZERO_DIVISION',
}

# All repos to analyze
REPOS = [
    'Counterfit', 'DebugPy', 'DeepSpeed', 'django', 'FLAML',
    'GraphRAG', 'Guidance', 'LightGBM', 'MSTICPY', 'ONNXRuntime',
    'Presidio', 'PromptFlow', 'pygoat', 'Pyright', 'Qlib',
    'RDAgent', 'RESTler', 'SemanticKernel',
]

# Output directory for results
RESULTS_DIR = Path(__file__).parent / 'results' / 'non_security_bugs'


def analyze_repo(repo_name: str, base_path: Path) -> Dict[str, Any]:
    """
    Analyze a single repo for non-security bugs using INTERPROCEDURAL analysis.
    
    Uses:
    1. InterproceduralBugTracker - finds bugs across function/file boundaries
    2. Z3-backed guard verification - proves guards prevent bugs
    3. Call chain tracking - shows how bugs are reached from entry points
    
    Returns a dict with:
    - repo_name: str
    - total_functions: int
    - bugs: List of bug dicts (with call chains)
    - bugs_by_type: Dict[bug_type, count]
    - interprocedural_stats: guard analysis statistics
    """
    repo_path = base_path / repo_name
    if not repo_path.exists():
        return {
            'repo_name': repo_name,
            'error': 'Repo not found',
            'total_functions': 0,
            'bugs': [],
            'bugs_by_type': {},
        }
    
    print(f"\n{'='*60}")
    print(f"Analyzing {repo_name} (INTERPROCEDURAL)...")
    print(f"{'='*60}")
    
    try:
        # Create interprocedural bug tracker from project path
        # This builds call graph, computes taint + crash summaries, and detects entry points
        print(f"  Building interprocedural analysis...")
        tracker = InterproceduralBugTracker.from_project(repo_path)
        
        cg = tracker.call_graph
        summaries = tracker.crash_summaries
        
        print(f"  Functions: {len(cg.functions)}")
        print(f"  Call sites: {sum(len(f.call_sites) for f in cg.functions.values())}")
        print(f"  Entry points: {len(tracker.entry_points)}")
        print(f"  Reachable functions: {len(tracker.reachable_functions)}")
        print(f"  Crash summaries: {len(summaries)}")
        
        # Find all bugs interprocedurally
        print(f"  Running interprocedural analysis...")
        all_bugs = tracker.find_all_bugs()
        print(f"  Total bugs found: {len(all_bugs)}")
        
        # Filter to non-security bugs
        non_security_bugs = [b for b in all_bugs if b.bug_type in NON_SECURITY_BUG_TYPES]
        print(f"  Non-security bugs: {len(non_security_bugs)}")
        
        # Apply interprocedural guard analysis with Z3
        bugs = []
        bugs_by_type = defaultdict(int)
        guarded_count = 0
        z3_verified_count = 0
        
        for bug in non_security_bugs:
            # Check if bug is guarded interprocedurally using Z3
            is_guarded = False
            guard_reason = None
            
            # Get the crash summary for this function
            crash_summary = summaries.get(bug.crash_function)
            if crash_summary:
                # Check intraprocedural guards first
                if bug.bug_type in crash_summary.guarded_bugs:
                    is_guarded = True
                    guard_reason = "intraprocedural"
                    guarded_count += 1
                
                # Check interprocedural guards with Z3
                if not is_guarded and bug.bug_variable:
                    try:
                        z3_result = check_bug_guarded_by_z3(bug, crash_summary, bug.call_chain)
                        if z3_result:
                            is_guarded = True
                            guard_reason = "interprocedural_z3"
                            z3_verified_count += 1
                            guarded_count += 1
                    except Exception:
                        pass  # Z3 check failed, conservatively keep the bug
            
            if not is_guarded:
                bug_entry = {
                    'function': bug.crash_function,
                    'bug_type': bug.bug_type,
                    'location': bug.crash_location,
                    'call_chain': bug.call_chain,
                    'reason': bug.reason,
                    'confidence': bug.confidence,
                    'variable': bug.bug_variable,
                    'is_guarded': False,
                    'guard_reason': None,
                }
                bugs.append(bug_entry)
                bugs_by_type[bug.bug_type] += 1
        
        print(f"  Guarded (filtered as FP): {guarded_count}")
        print(f"    - Intraprocedural: {guarded_count - z3_verified_count}")
        print(f"    - Interprocedural (Z3): {z3_verified_count}")
        print(f"  Unguarded bugs remaining: {len(bugs)}")
        
        for bt, count in sorted(bugs_by_type.items(), key=lambda x: -x[1])[:5]:
            print(f"    {bt}: {count}")
        
        return {
            'repo_name': repo_name,
            'total_functions': len(cg.functions),
            'total_summaries': len(summaries),
            'total_bugs_found': len(non_security_bugs),
            'guarded_count': guarded_count,
            'z3_verified_count': z3_verified_count,
            'bugs': bugs,
            'bugs_by_type': dict(bugs_by_type),
        }
        
    except Exception as e:
        import traceback
        print(f"  ERROR: {e}")
        traceback.print_exc()
        return {
            'repo_name': repo_name,
            'error': str(e),
            'total_functions': 0,
            'bugs': [],
            'bugs_by_type': {},
        }


def generate_repo_markdown(result: Dict[str, Any]) -> str:
    """Generate markdown content for a repo's bug report."""
    repo_name = result['repo_name']
    
    lines = [
        f"# {repo_name} - Non-Security Bug Analysis (Interprocedural)",
        "",
        "## Summary",
        "",
    ]
    
    if 'error' in result:
        lines.extend([
            f"**Error**: {result['error']}",
            "",
        ])
        return '\n'.join(lines)
    
    total_found = result.get('total_bugs_found', len(result['bugs']))
    guarded = result.get('guarded_count', 0)
    z3_verified = result.get('z3_verified_count', 0)
    fp_rate = (guarded / total_found * 100) if total_found > 0 else 0
    
    lines.extend([
        f"- **Total Functions**: {result['total_functions']}",
        f"- **Total Crash Summaries**: {result.get('total_summaries', 'N/A')}",
        "",
        "### Interprocedural Analysis Results",
        "",
        f"- **Total Non-Security Bugs Found**: {total_found}",
        f"- **Guarded (False Positives Filtered)**: {guarded} ({fp_rate:.1f}%)",
        f"  - Intraprocedural guards: {guarded - z3_verified}",
        f"  - Interprocedural guards (Z3-verified): {z3_verified}",
        f"- **Unguarded Bugs Remaining**: {len(result['bugs'])}",
        "",
        "## Bugs by Type",
        "",
        "| Bug Type | Count |",
        "|----------|-------|",
    ])
    
    for bug_type, count in sorted(result['bugs_by_type'].items(), key=lambda x: -x[1]):
        lines.append(f"| {bug_type} | {count} |")
    
    lines.extend([
        "",
        "## Detailed Bug List",
        "",
    ])
    
    # Group bugs by type
    bugs_by_type = defaultdict(list)
    for bug in result['bugs']:
        bugs_by_type[bug['bug_type']].append(bug)
    
    for bug_type in sorted(bugs_by_type.keys()):
        bugs = bugs_by_type[bug_type]
        lines.extend([
            f"### {bug_type} ({len(bugs)} instances)",
            "",
        ])
        
        # List up to 20 bugs per type
        for i, bug in enumerate(bugs[:20]):
            func = bug['function']
            loc = bug.get('location', '')
            var_info = f" [var: `{bug['variable']}`]" if bug.get('variable') else ""
            conf = bug.get('confidence', 1.0)
            
            lines.append(f"{i+1}. **`{func}`**{var_info}")
            if loc:
                lines.append(f"   - Location: {loc}")
            if bug.get('call_chain') and len(bug['call_chain']) > 1:
                chain = ' → '.join(bug['call_chain'][:5])
                if len(bug['call_chain']) > 5:
                    chain += f" → ... ({len(bug['call_chain'])} total)"
                lines.append(f"   - Call chain: {chain}")
            if bug.get('reason'):
                lines.append(f"   - Reason: {bug['reason'][:100]}")
            lines.append(f"   - Confidence: {conf:.2f}")
            lines.append(f"   - **Status**: ❓ UNCLASSIFIED")
            lines.append("")
        
        if len(bugs) > 20:
            lines.append(f"*... and {len(bugs) - 20} more*")
            lines.append("")
    
    lines.extend([
        "",
        "## Classification Legend",
        "",
        "- ✅ **TRUE POSITIVE**: Real bug that needs fixing",
        "- ❌ **FALSE POSITIVE**: Not a real bug (guarded, unreachable, etc.)",
        "- ❓ **UNCLASSIFIED**: Needs manual review",
        "",
    ])
    
    return '\n'.join(lines)


def main():
    """Main entry point."""
    base_path = Path(__file__).parent / 'external_tools'
    
    # Create results directory
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Select repos to analyze (can pass specific repo as argument)
    repos_to_analyze = REPOS
    if len(sys.argv) > 1:
        repos_to_analyze = [r for r in sys.argv[1:] if r in REPOS]
        if not repos_to_analyze:
            print(f"Unknown repos: {sys.argv[1:]}")
            print(f"Available: {REPOS}")
            sys.exit(1)
    
    # Analyze each repo
    all_results = []
    for repo in repos_to_analyze:
        result = analyze_repo(repo, base_path)
        all_results.append(result)
        
        # Generate and save markdown
        markdown = generate_repo_markdown(result)
        output_file = RESULTS_DIR / f"{repo}_bugs.md"
        output_file.write_text(markdown)
        print(f"  Saved: {output_file}")
    
    # Generate summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    total_bugs = 0
    bugs_by_type_all = defaultdict(int)
    
    for result in all_results:
        repo = result['repo_name']
        bug_count = len(result['bugs'])
        total_bugs += bug_count
        
        for bt, count in result.get('bugs_by_type', {}).items():
            bugs_by_type_all[bt] += count
        
        status = f"{bug_count} bugs" if 'error' not in result else f"ERROR: {result['error']}"
        print(f"  {repo}: {status}")
    
    print(f"\nTotal bugs across all repos: {total_bugs}")
    print("\nBy type:")
    for bt, count in sorted(bugs_by_type_all.items(), key=lambda x: -x[1]):
        print(f"  {bt}: {count}")
    
    # Save combined results as JSON
    combined_file = RESULTS_DIR / "combined_results.json"
    with open(combined_file, 'w') as f:
        json.dump({
            'repos': all_results,
            'total_bugs': total_bugs,
            'bugs_by_type': dict(bugs_by_type_all),
        }, f, indent=2, default=str)
    print(f"\nCombined results saved to: {combined_file}")
    
    print(f"\nRepo-specific files saved to: {RESULTS_DIR}/")


if __name__ == '__main__':
    main()
