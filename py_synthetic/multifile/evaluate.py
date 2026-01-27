#!/usr/bin/env python3
"""
Evaluate the analyzer on multi-file test programs.
Each main.py file is analyzed as a complete program.
"""
import os
import sys
import json
from pathlib import Path
import argparse

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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
            lockstep_max_steps=800,
        )
        result = analyzer.analyze_file(Path(filepath))

        if getattr(result, "lockstep", None) and result.lockstep.get("status") != "ok":
            return f"ERROR: lockstep {result.lockstep.get('status')}: {result.lockstep.get('message')}"
        
        if result.verdict == "BUG":
            return result.bug_type or "UNSAFE"
        elif result.verdict == "SAFE":
            return "SAFE"
        else:
            return result.verdict
    except Exception as e:
        return f"ERROR: {e}"

def main():
    parser = argparse.ArgumentParser(description="Evaluate analyzer on multi-file test programs")
    parser.add_argument(
        "--no-concolic",
        action="store_true",
        help="Disable all concrete execution (pure symbolic/static analysis)",
    )
    args = parser.parse_args()

    multifile_dir = os.path.dirname(os.path.abspath(__file__))
    ground_truth_path = os.path.join(multifile_dir, "ground_truth.json")
    
    with open(ground_truth_path, 'r') as f:
        ground_truth = json.load(f)
    
    results = {
        "true_positives": [],
        "false_positives": [],
        "false_negatives": [],
        "true_negatives": [],
        "errors": []
    }
    
    for prog_name, prog_info in ground_truth["programs"].items():
        print(f"\n=== Program: {prog_name} ===")
        print(f"Description: {prog_info['description']}")
        
        for filename, file_info in prog_info["files"].items():
            filepath = os.path.join(multifile_dir, prog_name, filename)
            expected = file_info["expected"]
            
            if not os.path.exists(filepath):
                results["errors"].append({
                    "program": prog_name,
                    "file": filename,
                    "error": "File not found"
                })
                continue
            
            actual = analyze_file(filepath, enable_concolic=not args.no_concolic)
            
            print(f"  {filename}: expected={expected}, actual={actual}")
            
            if expected == "SAFE":
                if actual == "SAFE":
                    results["true_negatives"].append(f"{prog_name}/{filename}")
                else:
                    results["false_positives"].append({
                        "program": prog_name,
                        "file": filename,
                        "expected": expected,
                        "actual": actual
                    })
            else:
                # Expected is a bug type
                if actual == expected:
                    results["true_positives"].append({
                        "program": prog_name,
                        "file": filename,
                        "bug_type": expected
                    })
                elif actual == "SAFE":
                    results["false_negatives"].append({
                        "program": prog_name,
                        "file": filename,
                        "expected": expected,
                        "actual": actual
                    })
                elif actual.startswith("ERROR"):
                    results["errors"].append({
                        "program": prog_name,
                        "file": filename,
                        "expected": expected,
                        "error": actual
                    })
                else:
                    # Detected a bug but different type - still a TP
                    results["true_positives"].append({
                        "program": prog_name,
                        "file": filename,
                        "expected_type": expected,
                        "actual_type": actual,
                        "note": "Different bug type"
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
    print("MULTI-FILE EVALUATION RESULTS")
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
        print("\nFALSE NEGATIVES:")
        for item in results["false_negatives"]:
            print(f"  - {item['program']}/{item['file']}: expected {item['expected']}, got {item['actual']}")
    
    if results["false_positives"]:
        print("\nFALSE POSITIVES:")
        for item in results["false_positives"]:
            print(f"  - {item['program']}/{item['file']}: expected SAFE, got {item['actual']}")
    
    # Save results
    output_path = os.path.join(multifile_dir, "evaluation_results.json")
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
    
    print(f"\nResults saved to: {output_path}")
    return f1

if __name__ == "__main__":
    f1 = main()
    sys.exit(0 if f1 == 1.0 else 1)
