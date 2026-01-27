"""
Verification script for ITERATION 469: SSRF Detection

This script verifies that SSRF detection works correctly after fixing
the source/sink ordering issue.
"""

from pathlib import Path
from pyfromscratch.semantics.intraprocedural_taint import IntraproceduralTaintAnalyzer
import types

def test_ssrf_detection():
    """Test SSRF detection on PyGoat ssrf_lab2 function."""
    
    # Read and compile the views.py file
    views_path = Path("external_tools/pygoat/introduction/views.py")
    with open(views_path) as f:
        code = compile(f.read(), str(views_path), 'exec')
    
    # Find the ssrf_lab2 function
    for const in code.co_consts:
        if isinstance(const, types.CodeType) and const.co_name == 'ssrf_lab2':
            # Run intraprocedural analysis
            analyzer = IntraproceduralTaintAnalyzer(
                const, 
                function_name="ssrf_lab2",
                file_path=str(views_path)
            )
            
            bugs = analyzer.analyze()
            
            # Filter for SSRF bugs at line 957 (the real bug, not the false positive)
            ssrf_bugs_957 = [b for b in bugs 
                            if 'SSRF' in b.bug_type 
                            and b.line_number == 957
                            and 'requests.get' in b.sink_description]
            
            # Verify we found the expected SSRF
            assert len(ssrf_bugs_957) >= 1, "SSRF at line 957 not detected!"
            
            bug = ssrf_bugs_957[0]
            print("✓ SSRF Detection Verified!")
            print(f"  Bug Type: {bug.bug_type}")
            print(f"  Line: {bug.line_number}")
            print(f"  Sink: {bug.sink_description}")
            print(f"  Source: {bug.source_description}")
            print(f"  Taint: tau={bin(bug.taint_label.tau)} (has_untrusted={bug.taint_label.has_untrusted_taint()})")
            
            # Verify taint properties
            assert bug.taint_label.has_untrusted_taint(), "Bug should have untrusted taint"
            assert bug.line_number == 957, f"Expected line 957, got {bug.line_number}"
            assert 'request' in bug.source_description.lower(), "Source should mention request"
            
            print("\n✓ All assertions passed!")
            print("\nSemantic Justification:")
            print("  Unsafe region: U_SSRF = { σ | π = π_requests.get ∧ τ(url) ∩ {HTTP_PARAM} ≠ ∅ }")
            print(f"  Reached state: π = 957, τ(url) = {bin(bug.taint_label.tau)}")
            print(f"  HTTP_PARAM bit: {bug.taint_label.has_untrusted_taint()}")
            print("  Conclusion: σ ∈ U_SSRF → BUG")
            
            return True
    
    raise Exception("Could not find ssrf_lab2 function")

if __name__ == '__main__':
    test_ssrf_detection()
    print("\n" + "="*60)
    print("ITERATION 469: SSRF Detection - VERIFIED ✓")
    print("="*60)
