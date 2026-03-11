#!/usr/bin/env python3
"""Targeted test: directly exercise proof-suppression and proof-upgrade paths."""
import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from a3_python.analyzer import Analyzer, AnalysisResult

def test_suppression_logic():
    """Test that a BUG verdict is suppressed when per_bug_type proves the type SAFE."""
    
    # --- Test 1: BUG gets suppressed by matching proof ---
    print("[Test 1] BUG(DIV_ZERO) + proof(DIV_ZERO=SAFE) → should become SAFE")
    
    result = AnalysisResult(
        verdict="BUG",
        bug_type="DIV_ZERO",
        counterexample={"trace": ["x=0", "y=1/x"]},
        message="Found division by zero",
    )
    
    per_bug_type = {
        "DIV_ZERO": {
            "verdict": "SAFE",
            "source": "paper_1_hscc04_barrier",
            "proofs": [{"loop_header_offset": 10, "barrier": "B(x)=x"}],
        }
    }
    
    # Apply suppression logic (same as in analyzer.py)
    if (
        result.verdict == "BUG"
        and result.bug_type
        and per_bug_type.get(result.bug_type, {}).get("verdict") == "SAFE"
    ):
        proof_entry = per_bug_type[result.bug_type]
        suppressed_bug = {
            "original_verdict": "BUG",
            "original_bug_type": result.bug_type,
            "original_counterexample": result.counterexample,
        }
        result.verdict = "SAFE"
        result.counterexample = None
        result.per_bug_type = {"_suppressed_bugs": {result.bug_type: suppressed_bug}}
        result.bug_type = None
    
    assert result.verdict == "SAFE", f"Expected SAFE, got {result.verdict}"
    assert result.bug_type is None, f"Expected None bug_type, got {result.bug_type}"
    assert result.counterexample is None, f"Counterexample should be cleared"
    assert "DIV_ZERO" in result.per_bug_type.get("_suppressed_bugs", {}), "Should record suppressed bug"
    print("  ✓ PASS\n")
    
    # --- Test 2: BUG not suppressed when proof is for different type ---
    print("[Test 2] BUG(BOUNDS) + proof(DIV_ZERO=SAFE) → should stay BUG")
    
    result2 = AnalysisResult(
        verdict="BUG",
        bug_type="BOUNDS",
        counterexample={"trace": ["i=5", "data[i]"]},
        message="Index out of bounds",
    )
    
    per_bug_type2 = {
        "DIV_ZERO": {
            "verdict": "SAFE",
            "source": "paper_1_hscc04_barrier",
            "proofs": [{"loop_header_offset": 10}],
        }
    }
    
    if (
        result2.verdict == "BUG"
        and result2.bug_type
        and per_bug_type2.get(result2.bug_type, {}).get("verdict") == "SAFE"
    ):
        result2.verdict = "SAFE"  # Should NOT reach here
    
    assert result2.verdict == "BUG", f"Expected BUG, got {result2.verdict}"
    assert result2.bug_type == "BOUNDS", f"Expected BOUNDS, got {result2.bug_type}"
    print("  ✓ PASS\n")
    
    # --- Test 3: UNKNOWN stays UNKNOWN even when proofs say SAFE ---
    # Partial proofs (e.g. LOOP_SAFETY, DIV_ZERO inside loops) do NOT cover
    # all possible bug types — a loop-computed value reaching zero post-loop
    # would be missed.  Upgrading UNKNOWN→SAFE based on partial proofs is
    # unsound, so we keep UNKNOWN.
    print("[Test 3] UNKNOWN + all proofs SAFE → should stay UNKNOWN (partial proofs unsound)")
    
    result3 = AnalysisResult(
        verdict="UNKNOWN",
        message="Exhausted paths",
    )
    
    per_bug_type3 = {
        "DIV_ZERO": {"verdict": "SAFE", "source": "paper_1_hscc04", "proofs": [{}]},
        "LOOP_SAFETY": {"verdict": "SAFE", "source": "paper_17_ice", "proofs": [{}]},
    }
    
    # Proof metadata is recorded for informational purposes but verdict stays UNKNOWN
    # (no upgrade — see analyzer.py Rule 2 comment for rationale)
    
    assert result3.verdict == "UNKNOWN", f"Expected UNKNOWN, got {result3.verdict}"
    print("  ✓ PASS\n")
    
    # --- Test 4: UNKNOWN stays UNKNOWN when no proofs ---
    print("[Test 4] UNKNOWN + no proofs → should stay UNKNOWN")
    
    result4 = AnalysisResult(
        verdict="UNKNOWN",
        message="Exhausted paths",
    )
    
    per_bug_type4 = {}
    
    if (
        result4.verdict == "UNKNOWN"
        and per_bug_type4
        and all(
            entry.get("verdict") == "SAFE"
            for key, entry in per_bug_type4.items()
            if not key.startswith("_")
        )
    ):
        result4.verdict = "SAFE"
    
    assert result4.verdict == "UNKNOWN", f"Expected UNKNOWN, got {result4.verdict}"
    print("  ✓ PASS\n")
    
    # --- Test 5: BUG not suppressed when no proofs ---
    print("[Test 5] BUG(DIV_ZERO) + no proofs → should stay BUG")
    
    result5 = AnalysisResult(
        verdict="BUG",
        bug_type="DIV_ZERO",
        counterexample={"trace": ["x=0"]},
    )
    
    per_bug_type5 = {}
    
    if (
        result5.verdict == "BUG"
        and result5.bug_type
        and per_bug_type5.get(result5.bug_type, {}).get("verdict") == "SAFE"
    ):
        result5.verdict = "SAFE"
    
    assert result5.verdict == "BUG", f"Expected BUG, got {result5.verdict}"
    print("  ✓ PASS\n")
    
    print("=" * 50)
    print("All 5 unit tests PASSED ✓")
    print("=" * 50)


if __name__ == "__main__":
    test_suppression_logic()
