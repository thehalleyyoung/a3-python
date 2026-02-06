#!/usr/bin/env python3
"""Force test Papers #11-15 by disabling earlier papers"""

import sys
from unittest.mock import patch

# Mock Papers #1-10 to fail
def mock_verify_12345_fail(*args, **kwargs):
    return (False, "Paper #1", {})

def mock_verify_6to10_fail(*args, **kwargs):
    return (False, "Paper #6", {})

print("=" * 80)
print("FORCING PAPERS #1-10 TO FAIL TO TEST PAPERS #11-15")
print("=" * 80)
print()

# Apply mocks
with patch('pyfromscratch.barriers.papers_1_to_5_complete.Papers1to5UnifiedEngine.verify_safety', mock_verify_12345_fail):
    with patch('pyfromscratch.barriers.papers_6_to_10_complete.Papers6to10UnifiedEngine.verify_safety', mock_verify_6to10_fail):
        # Now import and test
        from pyfromscratch.barriers.synthesis_engine import UnifiedSynthesisEngine
        
        print("Creating test scenario...")
        class MockMetadata:
            function_name = 'test_func'
            instructions = []
            guard_facts = {'x': ['ZERO_CHECK']}
        
        # Create barrier engine
        engine = UnifiedSynthesisEngine()
        
        # Create a problem with Python bug context
        problem = {
            'system': {
                'bug_type': 'DIV_ZERO',
                'bug_variable': 'x',
                'crash_summary': MockMetadata()
            },
            'property': {},
            'n_vars': 2
        }
        
        print("Running synthesis with Papers #1-10 mocked to fail...")
        result = engine._run_sos_safety(problem)
        
        print()
        print("=" * 80)
        print("RESULT")
        print("=" * 80)
        print(f"Status: {result.status}")
        print(f"Method: {result.method_used}")
        print(f"Certificate: {result.certificate}")
        print()
        
        if any(f"#{i}" in str(result.method_used) for i in range(11, 16)):
            print("✅ SUCCESS - Papers #11-15 invoked and working!")
        elif "Paper #1" in str(result.method_used) or any(f"#{i}" in str(result.method_used) for i in range(1, 11)):
            print("❌ Papers #11-15 NOT invoked (earlier paper executed)")
        else:
            print(f"⚠️  Unexpected method: {result.method_used}")
