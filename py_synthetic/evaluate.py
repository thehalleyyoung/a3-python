#!/usr/bin/env python3
"""
Evaluation script for PythonFromScratch analyzer on synthetic dataset.

Runs the analyzer on all synthetic programs, compares results with ground truth,
and calculates precision, recall, and F1 score.
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer, AnalysisResult


@dataclass
class EvaluationResult:
    """Results of evaluation."""
    true_positives: List[Tuple[str, str, str]] = field(default_factory=list)  # (file, func, bug_type)
    false_positives: List[Tuple[str, str, str]] = field(default_factory=list)
    false_negatives: List[Tuple[str, str, str]] = field(default_factory=list)
    true_negatives: int = 0
    
    @property
    def tp(self) -> int:
        return len(self.true_positives)
    
    @property
    def fp(self) -> int:
        return len(self.false_positives)
    
    @property
    def fn(self) -> int:
        return len(self.false_negatives)
    
    @property
    def precision(self) -> float:
        if self.tp + self.fp == 0:
            return 0.0
        return self.tp / (self.tp + self.fp)
    
    @property
    def recall(self) -> float:
        if self.tp + self.fn == 0:
            return 0.0
        return self.tp / (self.tp + self.fn)
    
    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)


def load_ground_truth(path: Path) -> dict:
    """Load ground truth from JSON file."""
    with open(path) as f:
        return json.load(f)


def extract_function_name(name: str) -> str:
    """Extract base function name from qualified name like 'ClassName.method'."""
    if '.' in name:
        return name.split('.')[-1]
    return name


def run_analyzer_on_file(filepath: Path, verbose: bool = False, *, enable_concolic: bool = True) -> AnalysisResult:
    """Run analyzer on a single file."""
    analyzer = Analyzer(
        max_paths=500,
        max_depth=200,
        verbose=verbose,
        enable_concolic=enable_concolic,
        enable_lockstep_concolic=True,
        lockstep_max_steps=800,
    )
    try:
        return analyzer.analyze_file(filepath)
    except Exception as e:
        if verbose:
            print(f"  Error analyzing {filepath}: {e}")
        return AnalysisResult(
            verdict="UNKNOWN",
            message=f"Analysis error: {e}"
        )


def get_detected_bugs(result: AnalysisResult, filepath: Path) -> Set[Tuple[str, str]]:
    """Extract (function_name, bug_type) pairs from analysis result."""
    bugs = set()
    
    if result.verdict == "BUG" and result.bug_type:
        # Try to extract function name from counterexample
        func_name = "unknown"
        if result.counterexample:
            # Look for function name in trace or location
            if 'location' in result.counterexample:
                loc = result.counterexample['location']
                if isinstance(loc, dict) and 'function' in loc:
                    func_name = loc['function']
                elif isinstance(loc, str):
                    # Try to parse function name from location string
                    if ':' in loc:
                        func_name = loc.split(':')[0]
            
            if 'trace' in result.counterexample:
                trace = result.counterexample['trace']
                if trace:
                    # Get last function from trace
                    for step in reversed(trace):
                        if isinstance(step, str) and 'CALL' in step:
                            parts = step.split()
                            for part in parts:
                                if not part.startswith('<') and not part.startswith('('):
                                    func_name = part
                                    break
                            break
        
        bugs.add((func_name, result.bug_type))
    
    return bugs


def evaluate_program(
    program_name: str,
    program_dir: Path,
    ground_truth: dict,
    verbose: bool = False,
    *,
    enable_concolic: bool = True,
) -> EvaluationResult:
    """Evaluate analyzer on a single program using test_harness.py."""
    result = EvaluationResult()
    
    program_gt = ground_truth.get("programs", {}).get(program_name, {})
    if not program_gt:
        if verbose:
            print(f"  Warning: No ground truth for {program_name}")
        return result
    
    # Build set of expected bugs: (file, func, bug_type)
    expected_bugs: Set[Tuple[str, str, str]] = set()
    safe_functions: Set[Tuple[str, str]] = set()  # (file, func)
    
    for filename, file_bugs in program_gt.get("bugs", {}).items():
        for func_name, bug_info in file_bugs.items():
            bug_type = bug_info["bug"]
            base_func = extract_function_name(func_name)
            expected_bugs.add((filename, base_func, bug_type))
    
    for func_name in program_gt.get("safe_functions", []):
        safe_functions.add(func_name)
    
    # Run analyzer on test_harness.py which contains trigger code for all bugs
    detected_bugs: Set[Tuple[str, str, str]] = set()
    
    harness_path = program_dir / "test_harness.py"
    if harness_path.exists():
        if verbose:
            print(f"  Analyzing test harness: {harness_path}...")
        
        analysis_result = run_analyzer_on_file(harness_path, verbose=False, enable_concolic=enable_concolic)
        
        if verbose:
            print(f"    Verdict: {analysis_result.verdict}")
            if analysis_result.bug_type:
                print(f"    Bug type: {analysis_result.bug_type}")
        
        # Extract detected bugs from harness
        if analysis_result.verdict == "BUG" and analysis_result.bug_type:
            # Map bug type to expected format
            bug_type = analysis_result.bug_type
            # Try to find which function triggered it from trace
            func_name = "unknown"
            if analysis_result.counterexample and 'trace' in analysis_result.counterexample:
                trace = analysis_result.counterexample['trace']
                for step in reversed(trace):
                    if isinstance(step, str) and 'test_' in step:
                        # Extract test function name
                        parts = step.split()
                        for part in parts:
                            if 'test_' in part:
                                func_name = part.replace('()', '').strip()
                                break
                        break
            
            # For harness-based detection, we mark it as detected
            detected_bugs.add(("test_harness.py", func_name, bug_type))
    else:
        if verbose:
            print(f"  Warning: No test harness found at {harness_path}")
    
    # For evaluation, we use a simpler approach:
    # Count total bugs detected vs expected
    # Since harness tests multiple functions, we check bug type matches
    
    # Group expected bugs by type
    expected_by_type: Dict[str, int] = {}
    for _, _, bug_type in expected_bugs:
        expected_by_type[bug_type] = expected_by_type.get(bug_type, 0) + 1
    
    # Count detected by type
    detected_by_type: Dict[str, int] = {}
    for _, _, bug_type in detected_bugs:
        detected_by_type[bug_type] = detected_by_type.get(bug_type, 0) + 1
    
    # For now, mark as FN all expected bugs since harness approach is limited
    for bug in expected_bugs:
        result.false_negatives.append(bug)
    
    for bug in detected_bugs:
        result.false_positives.append(bug)
    
    return result


def evaluate_all(
    synthetic_dir: Path,
    ground_truth: dict,
    verbose: bool = False,
    *,
    enable_concolic: bool = True,
) -> EvaluationResult:
    """Evaluate analyzer on all synthetic programs."""
    total_result = EvaluationResult()
    
    for program_name in ground_truth.get("programs", {}).keys():
        program_dir = synthetic_dir / program_name
        if not program_dir.exists():
            if verbose:
                print(f"Warning: Program directory not found: {program_dir}")
            continue
        
        if verbose:
            print(f"\nEvaluating {program_name}...")
        
        result = evaluate_program(program_name, program_dir, ground_truth, verbose, enable_concolic=enable_concolic)
        
        # Aggregate results
        total_result.true_positives.extend(result.true_positives)
        total_result.false_positives.extend(result.false_positives)
        total_result.false_negatives.extend(result.false_negatives)
        
        if verbose:
            print(f"  TP: {result.tp}, FP: {result.fp}, FN: {result.fn}")
    
    return total_result


def print_detailed_results(result: EvaluationResult):
    """Print detailed evaluation results."""
    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)
    
    print(f"\nTrue Positives ({result.tp}):")
    for file, func, bug_type in sorted(result.true_positives):
        print(f"  ✓ {file}:{func} - {bug_type}")
    
    print(f"\nFalse Positives ({result.fp}):")
    for file, func, bug_type in sorted(result.false_positives):
        print(f"  ✗ {file}:{func} - {bug_type} (spurious)")
    
    print(f"\nFalse Negatives ({result.fn}):")
    for file, func, bug_type in sorted(result.false_negatives):
        print(f"  ✗ {file}:{func} - {bug_type} (missed)")
    
    print("\n" + "-"*60)
    print("METRICS:")
    print(f"  True Positives:  {result.tp}")
    print(f"  False Positives: {result.fp}")
    print(f"  False Negatives: {result.fn}")
    print(f"  Precision:       {result.precision:.4f}")
    print(f"  Recall:          {result.recall:.4f}")
    print(f"  F1 Score:        {result.f1:.4f}")
    print("="*60)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Evaluate analyzer on synthetic dataset")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--no-concolic",
        action="store_true",
        help="Disable all concrete execution (pure symbolic/static analysis)",
    )
    parser.add_argument("--synthetic-dir", type=Path, 
                        default=Path(__file__).parent,
                        help="Path to synthetic dataset directory")
    args = parser.parse_args()
    
    synthetic_dir = args.synthetic_dir
    ground_truth_path = synthetic_dir / "ground_truth.json"
    
    if not ground_truth_path.exists():
        print(f"Error: Ground truth not found at {ground_truth_path}")
        return 1
    
    print(f"Loading ground truth from {ground_truth_path}...")
    ground_truth = load_ground_truth(ground_truth_path)
    
    print(f"Synthetic dataset: {ground_truth['summary']['total_programs']} programs, "
          f"{ground_truth['summary']['total_bugs']} bugs")
    
    print("\nRunning evaluation...")
    result = evaluate_all(synthetic_dir, ground_truth, verbose=args.verbose, enable_concolic=not args.no_concolic)
    
    print_detailed_results(result)
    
    # Save results to JSON
    results_path = synthetic_dir / "evaluation_results.json"
    with open(results_path, 'w') as f:
        json.dump({
            "true_positives": result.true_positives,
            "false_positives": result.false_positives,
            "false_negatives": result.false_negatives,
            "metrics": {
                "precision": result.precision,
                "recall": result.recall,
                "f1": result.f1
            }
        }, f, indent=2)
    print(f"\nResults saved to {results_path}")
    
    return 0 if result.f1 == 1.0 else 1


if __name__ == "__main__":
    sys.exit(main())
