#!/usr/bin/env python3
"""
Combined evaluation script for the py_synthetic test suite.
Runs both standalone and multi-file evaluations and produces combined metrics.
"""
import os
import sys
import json
import subprocess
from pathlib import Path
import argparse

def main():
    parser = argparse.ArgumentParser(description="Run combined py_synthetic evaluation")
    parser.add_argument(
        "--no-concolic",
        action="store_true",
        help="Disable all concrete execution (pure symbolic/static analysis)",
    )
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("="*70)
    print("PY_SYNTHETIC EVALUATION SUITE")
    print("="*70)
    
    # Run standalone evaluation
    print("\n>>> Running standalone tests...")
    standalone_cmd = [sys.executable, os.path.join(base_dir, "standalone", "evaluate.py")]
    if args.no_concolic:
        standalone_cmd.append("--no-concolic")
    standalone_result = subprocess.run(
        standalone_cmd,
        capture_output=True, text=True, cwd=base_dir
    )
    
    # Run multi-file evaluation
    print("\n>>> Running multi-file tests...")
    multifile_cmd = [sys.executable, os.path.join(base_dir, "multifile", "evaluate.py")]
    if args.no_concolic:
        multifile_cmd.append("--no-concolic")
    multifile_result = subprocess.run(
        multifile_cmd,
        capture_output=True, text=True, cwd=base_dir
    )
    
    # Load results
    standalone_results_path = os.path.join(base_dir, "standalone", "evaluation_results.json")
    multifile_results_path = os.path.join(base_dir, "multifile", "evaluation_results.json")
    
    with open(standalone_results_path) as f:
        standalone = json.load(f)
    
    with open(multifile_results_path) as f:
        multifile = json.load(f)
    
    # Combine metrics
    s = standalone["metrics"]
    m = multifile["metrics"]
    
    combined = {
        "true_positives": s["true_positives"] + m["true_positives"],
        "false_positives": s["false_positives"] + m["false_positives"],
        "false_negatives": s["false_negatives"] + m["false_negatives"],
        "true_negatives": s["true_negatives"] + m["true_negatives"],
        "errors": s["errors"] + m["errors"]
    }
    
    tp = combined["true_positives"]
    fp = combined["false_positives"]
    fn = combined["false_negatives"]
    tn = combined["true_negatives"]
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\n" + "="*70)
    print("COMBINED EVALUATION RESULTS")
    print("="*70)
    print(f"\nStandalone tests: {s['true_positives']} TP, {s['false_negatives']} FN, {s['true_negatives']} TN")
    print(f"Multi-file tests: {m['true_positives']} TP, {m['false_negatives']} FN, {m['true_negatives']} TN")
    print("-"*70)
    print(f"\nCOMBINED TOTALS:")
    print(f"  True Positives:  {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Negatives:  {tn}")
    print(f"  Errors:          {combined['errors']}")
    print("-"*70)
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print("="*70)
    
    # Save combined results
    output_path = os.path.join(base_dir, "combined_results.json")
    with open(output_path, 'w') as f:
        json.dump({
            "standalone": standalone["metrics"],
            "multifile": multifile["metrics"],
            "combined": {
                **combined,
                "precision": precision,
                "recall": recall,
                "f1_score": f1
            }
        }, f, indent=2)
    
    print(f"\nCombined results saved to: {output_path}")
    
    if f1 == 1.0:
        print("\n✓ PERFECT F1 SCORE ACHIEVED!")
        return 0
    else:
        print(f"\n✗ F1 Score is {f1:.4f}, not 1.0")
        return 1

if __name__ == "__main__":
    sys.exit(main())
