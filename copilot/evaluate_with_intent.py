#!/usr/bin/env python3
"""
Enhanced evaluation with intent-aware false positive filtering.

Uses rigorous intent detection to classify bugs as:
- TRUE POSITIVE: Unintentional bug that should be fixed
- FALSE POSITIVE: Intentional behavior or protected by guards

The key insight is measuring P(unintentional) not just P(bug_condition).
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.semantics.intent_detector import (
    IntentDetector, 
    EnhancedBugFilter,
    IntentAnalysis,
    IntentCategory,
    create_intent_aware_filter,
)
from pyfromscratch.semantics.ast_guard_analysis import SafetyAnalyzer, ASTGuardAnalyzer


@dataclass
class ClassifiedBug:
    """A bug with intent analysis and classification."""
    bug_type: str
    file: str
    function: str
    line: Optional[str]
    variable: Optional[str]
    call_chain: List[str]
    original_confidence: float
    
    # Intent analysis
    intent_analysis: IntentAnalysis = field(default_factory=IntentAnalysis)
    adjusted_confidence: float = 1.0
    is_likely_tp: bool = True
    
    # Classification
    classification: str = "TP"  # "TP" or "FP"
    fp_reason: Optional[str] = None


# Repos to analyze
REPOS = ['pygoat', 'Counterfit', 'Presidio', 'GraphRAG']

# Output directory
OUTPUT_DIR = Path(__file__).parent / 'results' / 'intent_filtered'

# All bug types to report (both security and non-security)
# The intent filter will determine if they're high-confidence TPs
ALL_BUG_TYPES = {
    # Security bug types (taint-based)
    'SQL_INJECTION',
    'COMMAND_INJECTION', 
    'CODE_INJECTION',
    'XSS',
    'SSRF',
    'PATH_TRAVERSAL',
    'XXE',
    'LDAP_INJECTION',
    'XPATH_INJECTION',
    'OPEN_REDIRECT',
    'DESERIALIZATION',
    'PICKLE_INJECTION',
    'SSTI',
    'HEADER_INJECTION',
    'LOG_INJECTION',
    'REFLECTED_XSS',
    'STORED_XSS',
    'COOKIE_INJECTION',
    
    # Cleartext/crypto issues
    'CLEARTEXT_LOGGING',
    'CLEARTEXT_STORAGE',
    'CLEARTEXT_TRANSMISSION',
    'WEAK_CRYPTO',
    'HARDCODED_SECRET',
    
    # Core error bug types
    'ASSERT_FAIL',
    'DIV_ZERO',
    'FP_DOMAIN',
    'INTEGER_OVERFLOW',
    'BOUNDS',
    'NULL_PTR',
    'TYPE_CONFUSION',
    'STACK_OVERFLOW',
    'MEMORY_LEAK',
    'NON_TERMINATION',
    'ITERATOR_INVALID',
    'USE_AFTER_FREE',
    'DOUBLE_FREE',
    'UNINIT_MEMORY',
    'DATA_RACE',
    'DEADLOCK',
    'SEND_SYNC',
    'INFO_LEAK',
    'TIMING_CHANNEL',
    
    # Python-specific runtime errors (commonly detected)
    'VALUE_ERROR',
    'RUNTIME_ERROR',
    'FILE_NOT_FOUND',
    'IMPORT_ERROR',
    'KEY_ERROR',
    'ATTRIBUTE_ERROR',
    'INDEX_ERROR',
    'OS_ERROR',
    'IO_ERROR',
    'NAME_ERROR',
    'UNBOUND_LOCAL',
    'TIMEOUT_ERROR',
    'PERMISSION_ERROR',
    'CONNECTION_ERROR',
    'ENCODING_ERROR',
}

# Non-security bug types (for backward compatibility filtering)
NON_SECURITY_BUG_TYPES = {
    # Core error bug types
    'ASSERT_FAIL',
    'DIV_ZERO',
    'FP_DOMAIN',
    'INTEGER_OVERFLOW',
    'BOUNDS',
    'NULL_PTR',
    'TYPE_CONFUSION',
    'STACK_OVERFLOW',
    'MEMORY_LEAK',
    'NON_TERMINATION',
    'ITERATOR_INVALID',
    'USE_AFTER_FREE',
    'DOUBLE_FREE',
    'UNINIT_MEMORY',
    'DATA_RACE',
    'DEADLOCK',
    'SEND_SYNC',
    'INFO_LEAK',
    'TIMING_CHANNEL',
    
    # Python-specific runtime errors (commonly detected)
    'VALUE_ERROR',
    'RUNTIME_ERROR',
    'FILE_NOT_FOUND',
    'IMPORT_ERROR',
    'KEY_ERROR',
    'ATTRIBUTE_ERROR',
    'INDEX_ERROR',
    'OS_ERROR',
    'IO_ERROR',
    'NAME_ERROR',
    'UNBOUND_LOCAL',
    'TIMEOUT_ERROR',
    'PERMISSION_ERROR',
    'CONNECTION_ERROR',
    'ENCODING_ERROR',
}


def get_source_for_function(file_path: str, function_name: str) -> Optional[str]:
    """Try to read source code for a function."""
    try:
        path = Path(file_path)
        if path.exists():
            return path.read_text(encoding='utf-8', errors='ignore')
    except:
        pass
    return None


def extract_function_source(full_source: str, function_name: str) -> Optional[str]:
    """Extract just the function source from a file."""
    # For now, return full source - the analyzers handle finding the function
    return full_source


def analyze_repo_with_intent(repo_name: str, threshold: float = 0.7) -> Dict:
    """
    Analyze a repository with intent-aware filtering.
    
    Args:
        repo_name: Name of the repository
        threshold: Minimum P(unintentional) to classify as TP (default 0.7 = high confidence)
        
    Returns:
        Dictionary with classified bugs
    """
    repo_path = Path(__file__).parent / 'external_tools' / repo_name
    
    if not repo_path.exists():
        print(f"  Warning: {repo_path} does not exist")
        return {'tp': [], 'fp': [], 'stats': {}, 'intent_stats': {}}
    
    print(f"  Building interprocedural analysis...")
    try:
        tracker = InterproceduralBugTracker.from_project(repo_path)
    except Exception as e:
        print(f"  Error building tracker: {e}")
        import traceback
        traceback.print_exc()
        return {'tp': [], 'fp': [], 'stats': {}, 'intent_stats': {}}
    
    print(f"  Functions: {len(tracker.call_graph.functions)}")
    print(f"  Running analysis...")
    
    # Disable automatic intent filtering since we want to classify each bug manually
    all_bugs = tracker.find_all_bugs(apply_intent_filter=False)
    # Filter to all bug types (both security and non-security) for high-confidence reporting
    bugs_to_analyze = [b for b in all_bugs if b.bug_type in ALL_BUG_TYPES]
    print(f"  Total bugs: {len(all_bugs)}, Analyzed: {len(bugs_to_analyze)}")
    
    # Create intent-aware filter
    bug_filter = create_intent_aware_filter(threshold=threshold)
    safety_analyzer = SafetyAnalyzer()
    
    # Classify each bug
    tp_bugs = []
    fp_bugs = []
    intent_category_counts = defaultdict(int)
    
    for bug in bugs_to_analyze:
        # Parse location
        location_parts = bug.crash_location.split(':')
        crash_file = ':'.join(location_parts[:-1]) if len(location_parts) > 1 else bug.crash_location
        crash_line = location_parts[-1] if len(location_parts) > 1 else None
        
        # Try to get source code
        full_path = repo_path / crash_file.lstrip('/')
        if not full_path.exists():
            # Try without repo prefix
            full_path = repo_path / crash_file
        
        source_code = get_source_for_function(str(full_path), bug.crash_function)
        
        # Run intent analysis
        should_include, adjusted_conf, analysis = bug_filter.filter_bug(
            bug_type=bug.bug_type,
            file_path=crash_file,
            function_name=bug.crash_function,
            variable_name=bug.bug_variable,
            source_code=source_code,
            line_number=int(crash_line) if crash_line and crash_line.isdigit() else None,
            original_confidence=getattr(bug, 'confidence', 1.0),
        )
        
        # Additional AST-based safety check if we have source
        if source_code and should_include:
            func_name = bug.crash_function.split('.')[-1] if '.' in bug.crash_function else bug.crash_function
            is_guarded, guard_conf, guard_reason = safety_analyzer.is_bug_guarded(
                source=source_code,
                function_name=func_name,
                bug_type=bug.bug_type,
                variable=bug.bug_variable,
                line_number=int(crash_line) if crash_line and crash_line.isdigit() else None
            )
            
            if is_guarded and guard_conf > 0.7:
                should_include = False
                analysis.add_signal(
                    IntentCategory.GUARD_PATTERN_DETECTED,
                    guard_conf,
                    guard_reason
                )
        
        # Count intent categories
        for signal in analysis.signals:
            intent_category_counts[signal.category.name] += 1
        
        # Create classified bug
        classified = ClassifiedBug(
            bug_type=bug.bug_type,
            file=crash_file,
            function=bug.crash_function,
            line=crash_line,
            variable=bug.bug_variable,
            call_chain=bug.call_chain[:3] if len(bug.call_chain) > 3 else bug.call_chain,
            original_confidence=getattr(bug, 'confidence', 1.0),
            intent_analysis=analysis,
            adjusted_confidence=adjusted_conf,
            is_likely_tp=should_include,
            classification="TP" if should_include else "FP",
            fp_reason=analysis.primary_reason if not should_include else None,
        )
        
        if should_include:
            tp_bugs.append(classified)
        else:
            fp_bugs.append(classified)
    
    # Stats by type
    stats = defaultdict(lambda: {'tp': 0, 'fp': 0})
    for b in tp_bugs:
        stats[b.bug_type]['tp'] += 1
    for b in fp_bugs:
        stats[b.bug_type]['fp'] += 1
    
    print(f"  After intent filtering: {len(tp_bugs)} TP, {len(fp_bugs)} FP")
    print(f"  FP reduction: {len(bugs_to_analyze) - len(tp_bugs)} bugs filtered ({(len(bugs_to_analyze) - len(tp_bugs)) / max(1, len(bugs_to_analyze)) * 100:.1f}%)")
    
    return {
        'tp': tp_bugs,
        'fp': fp_bugs,
        'stats': dict(stats),
        'intent_stats': dict(intent_category_counts),
    }


def generate_markdown(repo_name: str, results: Dict) -> str:
    """Generate markdown report with intent analysis."""
    tp_bugs = results['tp']
    fp_bugs = results['fp']
    stats = results['stats']
    intent_stats = results.get('intent_stats', {})
    
    lines = []
    lines.append(f"# {repo_name} - Intent-Aware Bug Analysis")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **True Positives**: {len(tp_bugs)}")
    lines.append(f"- **False Positives (Filtered)**: {len(fp_bugs)}")
    lines.append(f"- **Total Analyzed**: {len(tp_bugs) + len(fp_bugs)}")
    lines.append(f"- **FP Reduction Rate**: {len(fp_bugs) / max(1, len(tp_bugs) + len(fp_bugs)) * 100:.1f}%")
    lines.append("")
    
    # Stats by type
    lines.append("## By Bug Type")
    lines.append("")
    lines.append("| Type | TP | FP | Total | FP Rate |")
    lines.append("|------|----|----|-------|---------|")
    for bug_type in sorted(stats.keys()):
        tp = stats[bug_type]['tp']
        fp = stats[bug_type]['fp']
        total = tp + fp
        fp_rate = fp / max(1, total) * 100
        lines.append(f"| {bug_type} | {tp} | {fp} | {total} | {fp_rate:.1f}% |")
    lines.append("")
    
    # Intent category breakdown
    if intent_stats:
        lines.append("## FP Filtering by Intent Category")
        lines.append("")
        lines.append("| Intent Category | Count |")
        lines.append("|-----------------|-------|")
        for category, count in sorted(intent_stats.items(), key=lambda x: -x[1]):
            lines.append(f"| {category} | {count} |")
        lines.append("")
    
    lines.append("---")
    lines.append("")
    
    # TRUE POSITIVES - listed first with full details
    lines.append("## TRUE POSITIVES (Likely Unintentional Bugs)")
    lines.append("")
    
    if not tp_bugs:
        lines.append("*No true positives found after intent filtering.*")
        lines.append("")
    else:
        # Group by type
        by_type = defaultdict(list)
        for b in tp_bugs:
            by_type[b.bug_type].append(b)
        
        for bug_type in sorted(by_type.keys()):
            bugs = by_type[bug_type]
            lines.append(f"### {bug_type} ({len(bugs)})")
            lines.append("")
            
            for i, b in enumerate(bugs, 1):
                var_info = f" on `{b.variable}`" if b.variable else ""
                lines.append(f"{i}. **{b.function}**{var_info}")
                lines.append(f"   - File: `{b.file}` (line {b.line})")
                lines.append(f"   - Confidence: {b.adjusted_confidence:.2f}")
                if b.call_chain and len(b.call_chain) > 1:
                    chain = " → ".join(b.call_chain)
                    lines.append(f"   - Call chain: `{chain}`")
                lines.append("")
    
    lines.append("---")
    lines.append("")
    
    # FALSE POSITIVES - grouped by reason
    lines.append("## FALSE POSITIVES (Intentional/Guarded)")
    lines.append("")
    
    if not fp_bugs:
        lines.append("*No false positives detected.*")
        lines.append("")
    else:
        # Group by reason
        by_reason = defaultdict(list)
        for b in fp_bugs:
            reason = b.fp_reason or "Unknown"
            # Extract category name
            if ':' in reason:
                category = reason.split(':')[0]
            else:
                category = reason
            by_reason[category].append(b)
        
        for reason in sorted(by_reason.keys(), key=lambda r: -len(by_reason[r])):
            bugs = by_reason[reason]
            lines.append(f"### {reason} ({len(bugs)})")
            lines.append("")
            
            # Show first 10 examples
            for i, b in enumerate(bugs[:10], 1):
                lines.append(f"{i}. `{b.bug_type}` in **{b.function}** - `{b.file}`")
            
            if len(bugs) > 10:
                lines.append(f"   *... and {len(bugs) - 10} more*")
            lines.append("")
    
    return '\n'.join(lines)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    all_results = {}
    total_tp = 0
    total_fp = 0
    total_original = 0
    
    # Use high confidence threshold - only report TPs found with high confidence
    threshold = 0.7
    
    for repo in REPOS:
        print(f"\n{'=' * 60}")
        print(f"Analyzing {repo}...")
        print('=' * 60)
        
        results = analyze_repo_with_intent(repo, threshold=threshold)
        all_results[repo] = results
        
        total_tp += len(results['tp'])
        total_fp += len(results['fp'])
        total_original += len(results['tp']) + len(results['fp'])
        
        # Generate and save markdown
        md_content = generate_markdown(repo, results)
        output_file = OUTPUT_DIR / f"{repo}_bugs.md"
        output_file.write_text(md_content)
        print(f"  Saved: {output_file}")
    
    # Print summary
    print(f"\n{'=' * 60}")
    print("SUMMARY (with Intent Filtering)")
    print('=' * 60)
    print("")
    print(f"{'Repo':<20} {'TP':>6} {'FP':>6} {'Total':>7} {'FP Rate':>10}")
    print('-' * 50)
    
    for repo in REPOS:
        results = all_results[repo]
        tp = len(results['tp'])
        fp = len(results['fp'])
        total = tp + fp
        fp_rate = fp / max(1, total) * 100
        print(f"{repo:<20} {tp:>6} {fp:>6} {total:>7} {fp_rate:>9.1f}%")
    
    print('-' * 50)
    fp_rate = total_fp / max(1, total_original) * 100
    print(f"{'TOTAL':<20} {total_tp:>6} {total_fp:>6} {total_original:>7} {fp_rate:>9.1f}%")
    print("")
    print(f"Bugs marked as TRUE POSITIVE: {total_tp}")
    print(f"Bugs filtered as FALSE POSITIVE: {total_fp}")
    print(f"FP Reduction from original: {total_fp / max(1, total_original) * 100:.1f}%")
    print("")
    print(f"Results saved to: {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
