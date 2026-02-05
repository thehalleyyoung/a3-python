#!/usr/bin/env python3
"""
Test improved false positive reduction on known FP cases from HONEST_BUG_REVIEW.md
"""
import json
import sys
from pathlib import Path

# Add pyfromscratch to path
sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.barriers.extreme_verification import ExtremeContextVerifier
from pyfromscratch.interprocedural_bug_tracker import InterproceduralBugTracker

def test_known_false_positives():
    """Test on bugs we know are false positives"""
    
    deepspeed_path = Path("/Users/halleyyoung/Documents/PythonFromScratch/external_tools/DeepSpeed")
    
    # Load previous results
    results_path = Path("results/extreme_deepspeed_results.json")
    with open(results_path) as f:
        previous_results = json.load(f)
    
    # Initialize tracker and verifier
    tracker = InterproceduralBugTracker(
        root_dir=str(deepspeed_path),
        enable_interprocedural=True
    )
    
    verifier = ExtremeContextVerifier()
    
    # Test cases from HONEST_BUG_REVIEW.md that were false positives
    test_cases = [
        {
            "name": "Bug #3: max(y_max, 1e-9) safe idiom",
            "file": "deepspeed/runtime/zero/stage_1_and_2.py",
            "line": 1670,
            "expected": "SAFE"
        },
        {
            "name": "Bug #19: Alignment constant",
            "file": "deepspeed/nvme_io_utils/io.py", 
            "line": 165,
            "expected": "SAFE"
        },
        {
            "name": "Bug #7: Function definition (no actual division)",
            "file": "deepspeed/ops/adam/cpu_adam.py",
            "line": 24,
            "expected": "SAFE"
        },
    ]
    
    print("=" * 80)
    print("TESTING IMPROVED FALSE POSITIVE REDUCTION")
    print("=" * 80)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[TEST {i}] {test_case['name']}")
        print(f"File: {test_case['file']}:{test_case['line']}")
        
        # Find this bug in previous results
        full_path = str(deepspeed_path / test_case['file'])
        bug = None
        for b in previous_results.get('bugs', []):
            if b['file'] == full_path and abs(b['line'] - test_case['line']) < 5:
                bug = b
                break
        
        if not bug:
            print(f"❌ Bug not found in results")
            continue
        
        print(f"Original severity: {bug.get('severity', 'UNKNOWN')}")
        print(f"Bug type: {bug.get('bug_type', 'UNKNOWN')}")
        
        # Re-verify with improved strategies
        crash_summary = tracker.crash_summaries.get(f"{bug['file']}:{bug['line']}")
        
        if crash_summary:
            result = verifier.verify_bug_extreme(crash_summary, bug['bug_type'])
            
            actual = "SAFE" if result.is_safe else "BUG"
            expected = test_case['expected']
            
            if actual == expected:
                print(f"✅ PASS: Correctly classified as {actual}")
                if result.is_safe and result.proof_method:
                    print(f"   Proof: {result.proof_method}")
            else:
                print(f"❌ FAIL: Expected {expected}, got {actual}")
                print(f"   Confidence: {result.confidence}")
        else:
            print(f"⚠️  Could not find crash summary")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    test_known_false_positives()
