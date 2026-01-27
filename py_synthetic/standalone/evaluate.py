#!/usr/bin/env python3
"""
Evaluate the analyzer on standalone test files.
Each file is a complete program that can be analyzed directly.
"""
import os
import sys
import json
import argparse

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pathlib import Path
from pyfromscratch.analyzer import Analyzer

def analyze_file(filepath, *, enable_concolic: bool = True):
    """Analyze a single Python file and return the verdict."""
    try:
        analyzer = Analyzer(
            max_paths=500,
            max_depth=500,
            verbose=False,
            enable_concolic=enable_concolic,
            enable_lockstep_concolic=True,
            lockstep_max_steps=600,
        )
        result = analyzer.analyze_file(Path(filepath))

        if getattr(result, "lockstep", None) and result.lockstep.get("status") != "ok":
            return f"ERROR: lockstep {result.lockstep.get('status')}: {result.lockstep.get('message')}"
        
        # Extract verdict
        if result.verdict == "BUG":
            return result.bug_type or "UNSAFE"
        elif result.verdict == "SAFE":
            return "SAFE"
        else:
            return result.verdict  # UNKNOWN
    except Exception as e:
        return f"ERROR: {e}"

def main():
    parser = argparse.ArgumentParser(description="Evaluate analyzer on standalone test files")
    parser.add_argument(
        "--no-concolic",
        action="store_true",
        help="Disable all concrete execution (pure symbolic/static analysis)",
    )
    args = parser.parse_args()

    standalone_dir = os.path.dirname(os.path.abspath(__file__))
    ground_truth_path = os.path.join(standalone_dir, "ground_truth.json")
    
    with open(ground_truth_path, 'r') as f:
        ground_truth = json.load(f)
    
    results = {
        "true_positives": [],
        "false_positives": [],
        "false_negatives": [],
        "true_negatives": [],
        "errors": []
    }
    
    for filename, info in ground_truth["files"].items():
        filepath = os.path.join(standalone_dir, filename)
        expected = info["expected"]
        description = info["description"]
        
        if not os.path.exists(filepath):
            results["errors"].append({
                "file": filename,
                "error": "File not found"
            })
            continue
        
        actual = analyze_file(filepath, enable_concolic=not args.no_concolic)
        
        print(f"{filename}: expected={expected}, actual={actual}")
        
        if expected == "SAFE":
            if actual == "SAFE":
                results["true_negatives"].append(filename)
            else:
                results["false_positives"].append({
                    "file": filename,
                    "expected": expected,
                    "actual": actual,
                    "description": description
                })
        else:
            # Expected is a bug type
            if actual == expected:
                results["true_positives"].append({
                    "file": filename,
                    "bug_type": expected,
                    "description": description
                })
            elif actual == "SAFE":
                results["false_negatives"].append({
                    "file": filename,
                    "expected": expected,
                    "actual": actual,
                    "description": description
                })
            elif actual.startswith("ERROR"):
                results["errors"].append({
                    "file": filename,
                    "expected": expected,
                    "error": actual
                })
            else:
                # Detected a bug but wrong type - count as partial TP
                results["true_positives"].append({
                    "file": filename,
                    "expected_type": expected,
                    "actual_type": actual,
                    "description": description,
                    "note": "Different bug type detected"
                })
    
    # Calculate metrics
    tp = len(results["true_positives"])
    fp = len(results["false_positives"])
    fn = len(results["false_negatives"])
    tn = len(results["true_negatives"])
    errors = len(results["errors"])
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)
    print(f"True Positives:  {tp}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Negatives:  {tn}")
    print(f"Errors:          {errors}")
    print("-"*60)
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print("="*60)
    
    if results["false_negatives"]:
        print("\nFALSE NEGATIVES (bugs missed):")
        for item in results["false_negatives"]:
            print(f"  - {item['file']}: expected {item['expected']}, got {item['actual']}")
            print(f"    Description: {item['description']}")
    
    if results["false_positives"]:
        print("\nFALSE POSITIVES (safe marked unsafe):")
        for item in results["false_positives"]:
            print(f"  - {item['file']}: expected SAFE, got {item['actual']}")
    
    if results["errors"]:
        print("\nERRORS:")
        for item in results["errors"]:
            print(f"  - {item['file']}: {item.get('error', 'Unknown error')}")
    
    # Save detailed results
    output_path = os.path.join(standalone_dir, "evaluation_results.json")
    with open(output_path, 'w') as f:
        json.dump({
            "results": results,
            "metrics": {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": tn,
                "errors": errors,
                "precision": precision,
                "recall": recall,
                "f1_score": f1
            }
        }, f, indent=2)
    
    print(f"\nDetailed results saved to: {output_path}")
    return f1

if __name__ == "__main__":
    f1 = main()
    sys.exit(0 if f1 == 1.0 else 1)
