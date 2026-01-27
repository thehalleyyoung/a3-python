#!/usr/bin/env python3
"""
Validation script for synthetic test suite.
Compares analyzer output against ground truth manifest.

Usage:
    python scripts/validate_synthetic_suite.py [--results <results_file>] [--verbose]
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict


def load_ground_truth(manifest_path: Path) -> Dict:
    """Load ground truth manifest."""
    with open(manifest_path, 'r') as f:
        return json.load(f)


def load_analyzer_results(results_path: Path) -> Dict:
    """Load analyzer results (JSON format expected)."""
    if not results_path.exists():
        print(f"Error: Results file not found: {results_path}", file=sys.stderr)
        sys.exit(1)
    
    with open(results_path, 'r') as f:
        return json.load(f)


def extract_file_verdict(file_path: str, bug_types: Dict) -> Tuple[str, str, str]:
    """Extract expected verdict from ground truth for a file.
    Returns: (expected_verdict, bug_type_or_none, filename)
    """
    file_name = Path(file_path).name
    
    for bug_type, files in bug_types.items():
        if file_name in files:
            file_info = files[file_name]
            return file_info["expected"], file_info.get("bug_type", ""), bug_type
    
    return "UNKNOWN", "", ""


def compare_results(ground_truth: Dict, analyzer_results: Dict, verbose: bool = False) -> Dict:
    """Compare analyzer results against ground truth."""
    
    bug_types = ground_truth["bug_types"]
    
    # Metrics per bug type
    metrics = defaultdict(lambda: {
        "true_positives": 0,
        "true_negatives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "unknowns": 0,
        "correct": 0,
        "incorrect": 0,
        "total": 0
    })
    
    # Overall metrics
    overall = {
        "true_positives": 0,
        "true_negatives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "unknowns": 0,
        "correct": 0,
        "incorrect": 0,
        "total": 0
    }
    
    discrepancies = []
    
    # Iterate through analyzer results
    results_dict = analyzer_results.get("results", analyzer_results)
    for file_path, result in results_dict.items():
        analyzer_verdict = result.get("verdict", "UNKNOWN")
        expected_verdict, expected_bug_type, bug_type_category = extract_file_verdict(
            file_path, bug_types
        )
        
        if expected_verdict == "UNKNOWN":
            if verbose:
                print(f"Warning: File not in ground truth: {file_path}")
            continue
        
        metrics[bug_type_category]["total"] += 1
        overall["total"] += 1
        
        # Classify the result
        correct = (analyzer_verdict == expected_verdict)
        
        if correct:
            metrics[bug_type_category]["correct"] += 1
            overall["correct"] += 1
        else:
            metrics[bug_type_category]["incorrect"] += 1
            overall["incorrect"] += 1
            discrepancies.append({
                "file": file_path,
                "expected": expected_verdict,
                "actual": analyzer_verdict,
                "bug_type": bug_type_category
            })
        
        # Detailed classification
        if expected_verdict == "BUG":
            if analyzer_verdict == "BUG":
                metrics[bug_type_category]["true_positives"] += 1
                overall["true_positives"] += 1
            elif analyzer_verdict == "SAFE":
                metrics[bug_type_category]["false_negatives"] += 1
                overall["false_negatives"] += 1
            elif analyzer_verdict == "UNKNOWN":
                metrics[bug_type_category]["unknowns"] += 1
                overall["unknowns"] += 1
        
        elif expected_verdict == "SAFE":
            if analyzer_verdict == "SAFE":
                metrics[bug_type_category]["true_negatives"] += 1
                overall["true_negatives"] += 1
            elif analyzer_verdict == "BUG":
                metrics[bug_type_category]["false_positives"] += 1
                overall["false_positives"] += 1
            elif analyzer_verdict == "UNKNOWN":
                metrics[bug_type_category]["unknowns"] += 1
                overall["unknowns"] += 1
    
    return {
        "metrics": dict(metrics),
        "overall": overall,
        "discrepancies": discrepancies
    }


def calculate_rates(metrics: Dict) -> Dict:
    """Calculate precision, recall, accuracy rates."""
    tp = metrics["true_positives"]
    tn = metrics["true_negatives"]
    fp = metrics["false_positives"]
    fn = metrics["false_negatives"]
    total = metrics["total"]
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
        "f1_score": f1_score
    }


def print_results(comparison: Dict, verbose: bool = False):
    """Print validation results."""
    
    overall = comparison["overall"]
    metrics_by_type = comparison["metrics"]
    discrepancies = comparison["discrepancies"]
    
    print("\n" + "=" * 80)
    print("SYNTHETIC SUITE VALIDATION RESULTS")
    print("=" * 80)
    
    # Overall metrics
    print("\n📊 OVERALL METRICS:")
    print(f"   Total files analyzed: {overall['total']}")
    print(f"   Correct verdicts: {overall['correct']} ({100*overall['correct']/overall['total']:.1f}%)")
    print(f"   Incorrect verdicts: {overall['incorrect']} ({100*overall['incorrect']/overall['total']:.1f}%)")
    print()
    print(f"   True Positives (BUG correctly detected): {overall['true_positives']}")
    print(f"   True Negatives (SAFE correctly confirmed): {overall['true_negatives']}")
    print(f"   False Positives (SAFE incorrectly flagged as BUG): {overall['false_positives']}")
    print(f"   False Negatives (BUG missed): {overall['false_negatives']}")
    print(f"   Unknown (analyzer returned UNKNOWN): {overall['unknowns']}")
    
    rates = calculate_rates(overall)
    print(f"\n   Precision: {rates['precision']:.3f}")
    print(f"   Recall: {rates['recall']:.3f}")
    print(f"   Accuracy: {rates['accuracy']:.3f}")
    print(f"   F1 Score: {rates['f1_score']:.3f}")
    
    # Per bug-type breakdown
    print("\n" + "=" * 80)
    print("📋 PER BUG TYPE BREAKDOWN:")
    print("=" * 80)
    
    for bug_type in sorted(metrics_by_type.keys()):
        m = metrics_by_type[bug_type]
        if m["total"] == 0:
            continue
        
        rates = calculate_rates(m)
        correct_pct = 100 * m["correct"] / m["total"]
        
        status = "✅" if correct_pct == 100.0 else "⚠️" if correct_pct >= 80.0 else "❌"
        
        print(f"\n{status} {bug_type}:")
        print(f"   Correct: {m['correct']}/{m['total']} ({correct_pct:.1f}%)")
        print(f"   TP: {m['true_positives']}, TN: {m['true_negatives']}, FP: {m['false_positives']}, FN: {m['false_negatives']}, UNK: {m['unknowns']}")
        print(f"   Precision: {rates['precision']:.3f}, Recall: {rates['recall']:.3f}, F1: {rates['f1_score']:.3f}")
    
    # Discrepancies
    if discrepancies:
        print("\n" + "=" * 80)
        print("🔍 DISCREPANCIES (Expected vs Actual):")
        print("=" * 80)
        
        for d in discrepancies:
            print(f"\n❌ {d['file']}")
            print(f"   Bug Type: {d['bug_type']}")
            print(f"   Expected: {d['expected']}")
            print(f"   Actual: {d['actual']}")
    else:
        print("\n✅ No discrepancies found! All analyzer verdicts match ground truth.")
    
    # Summary verdict
    print("\n" + "=" * 80)
    if overall["incorrect"] == 0:
        print("🎉 VALIDATION PASSED: Analyzer output matches ground truth perfectly!")
    else:
        print(f"⚠️ VALIDATION FAILED: {overall['incorrect']} discrepancies found.")
        print(f"   False Positives: {overall['false_positives']}")
        print(f"   False Negatives: {overall['false_negatives']}")
    print("=" * 80 + "\n")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate analyzer results against synthetic suite ground truth")
    parser.add_argument("--results", type=Path, default=Path("results/synthetic_suite_results.json"),
                        help="Path to analyzer results JSON file")
    parser.add_argument("--manifest", type=Path, 
                        default=Path("tests/synthetic_suite/GROUND_TRUTH_MANIFEST.json"),
                        help="Path to ground truth manifest")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", type=Path, help="Save validation report to file")
    
    args = parser.parse_args()
    
    # Load ground truth
    if not args.manifest.exists():
        print(f"Error: Ground truth manifest not found: {args.manifest}", file=sys.stderr)
        sys.exit(1)
    
    ground_truth = load_ground_truth(args.manifest)
    
    # Load analyzer results
    analyzer_results = load_analyzer_results(args.results)
    
    # Compare
    comparison = compare_results(ground_truth, analyzer_results, args.verbose)
    
    # Print results
    print_results(comparison, args.verbose)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(comparison, f, indent=2)
        print(f"\nDetailed validation report saved to: {args.output}")
    
    # Exit with error code if validation failed
    if comparison["overall"]["incorrect"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
