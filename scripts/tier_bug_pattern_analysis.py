#!/usr/bin/env python3
"""
Comparative analysis of bug patterns between tier 1 and tier 2 public repo scans.
Iteration 85: Analyze semantic differences, false positive patterns, and coverage.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any

def load_tier1_data() -> Dict[str, Any]:
    """Load tier 1 triage report."""
    path = Path("results/public_repos/triage_report_tier1.json")
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)

def load_tier2_data() -> List[Dict[str, Any]]:
    """Load tier 2 DSE targets (represents tier 2 findings)."""
    path = Path("results/tier2_dse_targets.json")
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)

def analyze_bug_type_distribution(tier1_data: Dict, tier2_data: List) -> Dict:
    """Compare bug type distributions between tiers."""
    
    # Tier 1 bug types from context_issues
    tier1_bug_types = defaultdict(int)
    for repo, issues in tier1_data.get("context_issues", {}).items():
        for issue in issues:
            bug_type = issue.get("bug_type", "UNKNOWN")
            tier1_bug_types[bug_type] += 1
    
    # Tier 2 bug types
    tier2_bug_types = defaultdict(int)
    tier2_by_repo = defaultdict(lambda: defaultdict(int))
    for finding in tier2_data:
        bug_type = finding.get("bug_type", "UNKNOWN")
        repo = finding.get("repo", "unknown")
        tier2_bug_types[bug_type] += 1
        tier2_by_repo[repo][bug_type] += 1
    
    return {
        "tier1_distribution": dict(tier1_bug_types),
        "tier2_distribution": dict(tier2_bug_types),
        "tier2_by_repo": {k: dict(v) for k, v in tier2_by_repo.items()}
    }

def analyze_witness_trace_patterns(tier1_data: Dict, tier2_data: List) -> Dict:
    """Analyze common patterns in witness traces."""
    
    def extract_trace_features(trace: List[str]) -> Dict[str, Any]:
        """Extract semantic features from a witness trace."""
        opcodes = []
        imports = []
        exceptions = []
        
        for line in trace:
            if "IMPORT_NAME" in line:
                # Extract import name
                parts = line.split()
                if len(parts) >= 3:
                    imports.append(parts[-1])
            elif "EXCEPTION:" in line or "UNHANDLED EXCEPTION:" in line:
                exceptions.append(line.strip())
            else:
                # Extract opcode
                parts = line.split(":")
                if len(parts) >= 2:
                    opcode_part = parts[-1].strip().split()[0] if parts[-1].strip() else ""
                    if opcode_part:
                        opcodes.append(opcode_part)
        
        return {
            "opcodes": opcodes,
            "imports": imports,
            "exceptions": exceptions,
            "trace_length": len(trace)
        }
    
    tier1_patterns = []
    for repo, issues in tier1_data.get("context_issues", {}).items():
        for issue in issues:
            witness = issue.get("witness_preview", [])
            if witness:
                features = extract_trace_features(witness)
                features["repo"] = repo
                features["bug_type"] = issue.get("bug_type")
                tier1_patterns.append(features)
    
    tier2_patterns = []
    for finding in tier2_data:
        witness = finding.get("finding", {}).get("witness_trace", [])
        if witness:
            features = extract_trace_features(witness)
            features["repo"] = finding.get("repo")
            features["bug_type"] = finding.get("bug_type")
            tier2_patterns.append(features)
    
    return {
        "tier1_patterns": tier1_patterns,
        "tier2_patterns": tier2_patterns,
        "tier1_avg_trace_length": sum(p["trace_length"] for p in tier1_patterns) / len(tier1_patterns) if tier1_patterns else 0,
        "tier2_avg_trace_length": sum(p["trace_length"] for p in tier2_patterns) / len(tier2_patterns) if tier2_patterns else 0
    }

def analyze_import_related_bugs(tier1_data: Dict, tier2_data: List) -> Dict:
    """Analyze bugs related to imports and module initialization."""
    
    def is_import_related(trace: List[str], detail: str = None) -> bool:
        """Check if bug is related to import/module-init issues."""
        import_indicators = [
            "IMPORT_NAME", "IMPORT_FROM", "__future__", 
            "LOAD_BUILD_CLASS", "sys", "os"
        ]
        
        if detail and detail in ["__future__", "sys", "os"]:
            return True
        
        import_count = sum(1 for line in trace if any(ind in line for ind in import_indicators))
        return import_count > 5  # Heuristic: many imports suggest module-init phase
    
    tier1_import_bugs = 0
    tier1_total = 0
    for repo, issues in tier1_data.get("context_issues", {}).items():
        for issue in issues:
            tier1_total += 1
            witness = issue.get("witness_preview", [])
            detail = issue.get("detail")
            if is_import_related(witness, detail):
                tier1_import_bugs += 1
    
    tier2_import_bugs = 0
    tier2_total = len(tier2_data)
    for finding in tier2_data:
        witness = finding.get("finding", {}).get("witness_trace", [])
        if is_import_related(witness):
            tier2_import_bugs += 1
    
    return {
        "tier1_import_related": tier1_import_bugs,
        "tier1_total": tier1_total,
        "tier1_import_rate": tier1_import_bugs / tier1_total if tier1_total > 0 else 0,
        "tier2_import_related": tier2_import_bugs,
        "tier2_total": tier2_total,
        "tier2_import_rate": tier2_import_bugs / tier2_total if tier2_total > 0 else 0
    }

def analyze_exception_types(tier1_data: Dict, tier2_data: List) -> Dict:
    """Analyze the types of exceptions triggering bugs."""
    
    def extract_exception(trace: List[str]) -> str:
        """Extract the final exception type from trace."""
        for line in reversed(trace):
            if "EXCEPTION:" in line or "UNHANDLED EXCEPTION:" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    exc_part = parts[-1].strip()
                    return exc_part.split()[0] if exc_part else "Unknown"
        return "Unknown"
    
    tier1_exceptions = defaultdict(int)
    for repo, issues in tier1_data.get("context_issues", {}).items():
        for issue in issues:
            witness = issue.get("witness_preview", [])
            exc = extract_exception(witness)
            tier1_exceptions[exc] += 1
    
    tier2_exceptions = defaultdict(int)
    for finding in tier2_data:
        witness = finding.get("finding", {}).get("witness_trace", [])
        exc = extract_exception(witness)
        tier2_exceptions[exc] += 1
    
    return {
        "tier1_exceptions": dict(tier1_exceptions),
        "tier2_exceptions": dict(tier2_exceptions)
    }

def analyze_false_positive_patterns(tier1_data: Dict) -> Dict:
    """Analyze false positive patterns from tier 1 triaged data."""
    
    # Tier 1 classifies issues into categories
    stats = tier1_data.get("stats", {})
    
    total_context_issues = sum(repo_stats.get("context_issues", 0) for repo_stats in stats.values())
    total_analyzer_gaps = sum(repo_stats.get("analyzer_gaps", 0) for repo_stats in stats.values())
    total_real_bugs = sum(repo_stats.get("real_bugs", 0) for repo_stats in stats.values())
    
    # Context issues = false positives due to missing context (imports, etc.)
    # Analyzer gaps = false positives due to incomplete opcode/semantic support
    
    return {
        "total_context_issues": total_context_issues,
        "total_analyzer_gaps": total_analyzer_gaps,
        "total_real_bugs": total_real_bugs,
        "false_positive_rate": (total_context_issues + total_analyzer_gaps) / 
                              (total_context_issues + total_analyzer_gaps + total_real_bugs)
                              if (total_context_issues + total_analyzer_gaps + total_real_bugs) > 0 else 0,
        "context_issue_ratio": total_context_issues / 
                               (total_context_issues + total_analyzer_gaps)
                               if (total_context_issues + total_analyzer_gaps) > 0 else 0
    }

def compare_repo_complexity(tier1_data: Dict, tier2_data: List) -> Dict:
    """Compare repository characteristics between tiers."""
    
    tier1_repos = list(tier1_data.get("stats", {}).keys())
    tier2_repos = list(set(f.get("repo") for f in tier2_data))
    
    # Note: black and httpie are larger, more complex codebases than tier 1
    # This is documented in State.json: black had 58 files scanned, httpie had 88
    
    return {
        "tier1_repos": tier1_repos,
        "tier1_repo_count": len(tier1_repos),
        "tier2_repos": tier2_repos,
        "tier2_repo_count": len(tier2_repos),
        "tier2_finding_count": len(tier2_data),
        "avg_findings_per_tier2_repo": len(tier2_data) / len(tier2_repos) if tier2_repos else 0
    }

def main():
    print("=" * 80)
    print("TIER 1 vs TIER 2 BUG PATTERN COMPARATIVE ANALYSIS")
    print("Iteration 85: Semantic Model Evaluation")
    print("=" * 80)
    print()
    
    tier1_data = load_tier1_data()
    tier2_data = load_tier2_data()
    
    if not tier1_data:
        print("ERROR: No tier 1 data found")
        return 1
    if not tier2_data:
        print("ERROR: No tier 2 data found")
        return 1
    
    print(f"Tier 1 repos: {list(tier1_data.get('stats', {}).keys())}")
    print(f"Tier 2 repos: {list(set(f.get('repo') for f in tier2_data))}")
    print()
    
    # Analysis 1: Bug Type Distribution
    print("-" * 80)
    print("1. BUG TYPE DISTRIBUTION")
    print("-" * 80)
    bug_dist = analyze_bug_type_distribution(tier1_data, tier2_data)
    print("\nTier 1 bug types:")
    for bug_type, count in sorted(bug_dist["tier1_distribution"].items(), key=lambda x: -x[1]):
        print(f"  {bug_type}: {count}")
    
    print("\nTier 2 bug types:")
    for bug_type, count in sorted(bug_dist["tier2_distribution"].items(), key=lambda x: -x[1]):
        print(f"  {bug_type}: {count}")
    
    print("\nTier 2 by repo:")
    for repo, types in bug_dist["tier2_by_repo"].items():
        print(f"  {repo}: {types}")
    
    # Analysis 2: Import-Related Bugs
    print("\n" + "-" * 80)
    print("2. IMPORT-RELATED BUG PATTERNS")
    print("-" * 80)
    import_analysis = analyze_import_related_bugs(tier1_data, tier2_data)
    print(f"\nTier 1: {import_analysis['tier1_import_related']}/{import_analysis['tier1_total']} "
          f"({import_analysis['tier1_import_rate']:.1%}) import-related")
    print(f"Tier 2: {import_analysis['tier2_import_related']}/{import_analysis['tier2_total']} "
          f"({import_analysis['tier2_import_rate']:.1%}) import-related")
    
    print("\nInterpretation:")
    if import_analysis['tier1_import_rate'] > import_analysis['tier2_import_rate']:
        print("  Tier 1 has MORE import-related bugs (likely simpler module init)")
    else:
        print("  Tier 2 has MORE import-related bugs (more complex imports)")
    
    # Analysis 3: Exception Types
    print("\n" + "-" * 80)
    print("3. EXCEPTION TYPE DISTRIBUTION")
    print("-" * 80)
    exc_analysis = analyze_exception_types(tier1_data, tier2_data)
    print("\nTier 1 exceptions:")
    for exc, count in sorted(exc_analysis["tier1_exceptions"].items(), key=lambda x: -x[1]):
        print(f"  {exc}: {count}")
    
    print("\nTier 2 exceptions:")
    for exc, count in sorted(exc_analysis["tier2_exceptions"].items(), key=lambda x: -x[1]):
        print(f"  {exc}: {count}")
    
    # Analysis 4: Witness Trace Patterns
    print("\n" + "-" * 80)
    print("4. WITNESS TRACE CHARACTERISTICS")
    print("-" * 80)
    trace_analysis = analyze_witness_trace_patterns(tier1_data, tier2_data)
    print(f"\nTier 1 average trace length: {trace_analysis['tier1_avg_trace_length']:.1f} steps")
    print(f"Tier 2 average trace length: {trace_analysis['tier2_avg_trace_length']:.1f} steps")
    
    if abs(trace_analysis['tier1_avg_trace_length'] - trace_analysis['tier2_avg_trace_length']) > 10:
        if trace_analysis['tier2_avg_trace_length'] > trace_analysis['tier1_avg_trace_length']:
            print("\nTier 2 traces are LONGER (deeper module initialization / more complex paths)")
        else:
            print("\nTier 1 traces are LONGER")
    
    # Analysis 5: False Positive Patterns
    print("\n" + "-" * 80)
    print("5. FALSE POSITIVE ANALYSIS (Tier 1 Triaged)")
    print("-" * 80)
    fp_analysis = analyze_false_positive_patterns(tier1_data)
    print(f"\nContext issues (missing import context): {fp_analysis['total_context_issues']}")
    print(f"Analyzer gaps (unsupported opcodes): {fp_analysis['total_analyzer_gaps']}")
    print(f"Real bugs: {fp_analysis['total_real_bugs']}")
    print(f"\nFalse positive rate: {fp_analysis['false_positive_rate']:.1%}")
    print(f"Context issue ratio (of FPs): {fp_analysis['context_issue_ratio']:.1%}")
    
    # Analysis 6: Repo Complexity
    print("\n" + "-" * 80)
    print("6. REPOSITORY COMPLEXITY COMPARISON")
    print("-" * 80)
    complexity = compare_repo_complexity(tier1_data, tier2_data)
    print(f"\nTier 1: {complexity['tier1_repo_count']} repos ({', '.join(complexity['tier1_repos'])})")
    print(f"Tier 2: {complexity['tier2_repo_count']} repos ({', '.join(complexity['tier2_repos'])})")
    print(f"\nTier 2 findings per repo: {complexity['avg_findings_per_tier2_repo']:.1f}")
    
    # Synthesis
    print("\n" + "=" * 80)
    print("KEY FINDINGS")
    print("=" * 80)
    
    findings = []
    
    # Finding 1: Bug type similarity
    tier1_types = set(bug_dist["tier1_distribution"].keys())
    tier2_types = set(bug_dist["tier2_distribution"].keys())
    common_types = tier1_types & tier2_types
    findings.append(f"1. Bug type overlap: {len(common_types)}/{len(tier1_types | tier2_types)} types appear in both tiers")
    
    # Finding 2: Import-related pattern
    if import_analysis['tier2_import_rate'] > 0.5:
        findings.append(f"2. Tier 2 bugs are HEAVILY import-related ({import_analysis['tier2_import_rate']:.0%})")
        findings.append("   -> These may be false positives from module-init phase havoced imports")
    
    # Finding 3: Exception diversity
    tier1_exc_diversity = len(exc_analysis["tier1_exceptions"])
    tier2_exc_diversity = len(exc_analysis["tier2_exceptions"])
    findings.append(f"3. Exception diversity: T1={tier1_exc_diversity}, T2={tier2_exc_diversity}")
    
    # Finding 4: PANIC dominance
    if bug_dist["tier2_distribution"].get("PANIC", 0) > bug_dist["tier2_distribution"].get("BOUNDS", 0):
        findings.append("4. PANIC is dominant in tier 2 (suggests unhandled exception paths)")
    
    # Finding 5: DSE validation gap
    # From State.json: tier 2 has 80% DSE validation, but only 43% SAFE proof rate (vs tier 1's 100%)
    findings.append("5. Tier 2 DSE validation: 80% (4/5 realizable) but SAFE proof gap (43% vs tier 1 100%)")
    
    for finding in findings:
        print(f"\n{finding}")
    
    # Save results
    results = {
        "bug_distribution": bug_dist,
        "import_analysis": import_analysis,
        "exception_analysis": exc_analysis,
        "trace_analysis": {
            "tier1_avg_length": trace_analysis['tier1_avg_trace_length'],
            "tier2_avg_length": trace_analysis['tier2_avg_trace_length']
        },
        "false_positive_analysis": fp_analysis,
        "complexity_comparison": complexity,
        "key_findings": findings
    }
    
    output_path = Path("results/tier_comparative_analysis.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n\nResults saved to: {output_path}")
    print("\n" + "=" * 80)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
