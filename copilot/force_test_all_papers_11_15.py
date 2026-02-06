#!/usr/bin/env python3
"""Force test each Paper #11-15 individually by testing them directly then in pipeline"""

from unittest.mock import patch, MagicMock

print("=" * 80)
print("PART 1: TEST EACH PAPER #11-15 IN ISOLATION")
print("=" * 80)
print()

from pyfromscratch.barriers.papers_11_to_15_complete import (
    IMCVerifier, CEGARVerifier, PredicateAbstractionVerifier,
    BooleanProgramVerifier, IMPACTVerifier
)

class MockMetadata:
    function_name = 'test_func'
    instructions = []
    guard_facts = {'x': ['ZERO_CHECK']}

papers = [
    (11, 'IMC Interpolation', IMCVerifier(), 'verify_via_interpolation'),
    (12, 'CEGAR', CEGARVerifier(), 'verify_with_cegar'),
    (13, 'Predicate Abstraction', PredicateAbstractionVerifier(), 'verify_with_predicates'),
    (14, 'Boolean Programs', BooleanProgramVerifier(), 'verify_via_boolean_program'),
    (15, 'IMPACT', IMPACTVerifier(), 'verify_with_impact'),
]

isolation_results = []
metadata = MockMetadata()

for paper_num, paper_name, verifier, method_name in papers:
    try:
        method = getattr(verifier, method_name)
        is_safe, certificate = method('DIV_ZERO', 'x', metadata)
        
        status = '✅ SAFE' if is_safe else '❌ UNKNOWN'
        isolation_results.append((paper_num, is_safe))
        
        print(f"Paper #{paper_num} ({paper_name}): {status}")
        
    except Exception as e:
        print(f"Paper #{paper_num} ({paper_name}): ❌ ERROR - {str(e)[:60]}")
        isolation_results.append((paper_num, False))

print()
print("=" * 80)
print("PART 2: TEST UNIFIED ENGINE WITH SELECTIVE FORCING")
print("=" * 80)
print()

# Test the unified engine directly
from pyfromscratch.barriers.papers_11_to_15_complete import Papers11to15UnifiedEngine

engine = Papers11to15UnifiedEngine()

print("Testing Papers11to15UnifiedEngine (natural order)...")
is_safe, paper_name, cert = engine.verify_safety('DIV_ZERO', 'x', metadata)
print(f"  Result: {paper_name}")
print(f"  Safe: {is_safe}")
print(f"  Certificate: {cert}")
print()

print("=" * 80)
print("PART 3: TEST IN PIPELINE WITH FORCED FALLTHROUGH")
print("=" * 80)
print()

# Mock Papers #1-10 to fail
def mock_fail(*args, **kwargs):
    return (False, "Mocked failure", {})

with patch('pyfromscratch.barriers.papers_1_to_5_complete.Papers1to5UnifiedEngine.verify_safety', mock_fail):
    with patch('pyfromscratch.barriers.papers_6_to_10_complete.Papers6to10UnifiedEngine.verify_safety', mock_fail):
        from pyfromscratch.barriers.synthesis_engine import UnifiedSynthesisEngine
        
        engine = UnifiedSynthesisEngine()
        
        problem = {
            'system': {
                'bug_type': 'DIV_ZERO',
                'bug_variable': 'x',
                'crash_summary': metadata
            },
            'property': {},
            'n_vars': 2
        }
        
        print("Running synthesis_engine._run_sos_safety()...")
        result = engine._run_sos_safety(problem)
        
        print(f"  Status: {result.status}")
        print(f"  Method: {result.method_used}")
        print(f"  Certificate: {result.certificate}")
        print()
        
        if any(f"#{i}" in str(result.method_used) for i in range(11, 16)):
            print("✅ SUCCESS - Papers #11-15 invoked in pipeline!")
            pipeline_works = True
        else:
            print(f"❌ Papers #11-15 NOT invoked. Got: {result.method_used}")
            pipeline_works = False

print()
print("=" * 80)
print("FINAL SUMMARY")
print("=" * 80)
print()

isolation_count = sum(1 for _, safe in isolation_results if safe)
print(f"Isolation tests:  {isolation_count}/5 papers working")
print(f"Pipeline test:    {'✅ Working' if pipeline_works else '❌ Not working'}")
print()

if isolation_count >= 4 and pipeline_works:
    print("🎉 EXCELLENT - Papers #11-15 fully integrated!")
elif isolation_count >= 3:
    print("✅ GOOD - Most papers working")
else:
    print("⚠️  NEEDS WORK - Some papers failing")
