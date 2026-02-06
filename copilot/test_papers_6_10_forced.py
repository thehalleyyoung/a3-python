#!/usr/bin/env python3
"""
Test Papers #6-10 by creating a scenario where Papers #1-5 can't prove safety
but Papers #6-10 might succeed with structured/sparse techniques.
"""

import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(name)s - %(message)s')

# Monkey-patch Papers #1-5 to fail
print("="*80)
print("FORCING PAPERS #1-5 TO FAIL TO TEST PAPERS #6-10")
print("="*80)
print()

from pyfromscratch.barriers import papers_1_to_5_complete

# Save originals
original_paper1 = papers_1_to_5_complete.HybridBarrierSynthesizer.synthesize_hybrid_barrier
original_paper2 = papers_1_to_5_complete.StochasticBarrierSynthesizer.synthesize_stochastic_barrier
original_paper3 = papers_1_to_5_complete.SOSSafetyVerifier.verify_safety_sos
original_paper4 = papers_1_to_5_complete.SOSTOOLSFramework.synthesize_barrier
original_paper5 = papers_1_to_5_complete.PositivstellensatzProver.prove_positivity

# Make ALL Papers #1-5 fail
def failing_paper1(self, *args, **kwargs):
    print("[Paper #1] FORCED TO FAIL for testing")
    return None

def failing_paper2(self, *args, **kwargs):
    print("[Paper #2] FORCED TO FAIL for testing")
    return False, 0.0

def failing_paper3(self, *args, **kwargs):
    print("[Paper #3] FORCED TO FAIL for testing")
    return False, None

def failing_paper4(self, *args, **kwargs):
    print("[Paper #4] FORCED TO FAIL for testing")
    return False, None

def failing_paper5(self, *args, **kwargs):
    print("[Paper #5] FORCED TO FAIL for testing")
    return False, None

papers_1_to_5_complete.HybridBarrierSynthesizer.synthesize_hybrid_barrier = failing_paper1
papers_1_to_5_complete.StochasticBarrierSynthesizer.synthesize_stochastic_barrier = failing_paper2
papers_1_to_5_complete.SOSSafetyVerifier.verify_safety_sos = failing_paper3
papers_1_to_5_complete.SOSTOOLSFramework.synthesize_barrier = failing_paper4
papers_1_to_5_complete.PositivstellensatzProver.prove_positivity = failing_paper5

# Now test
from pyfromscratch.barriers.synthesis_engine import UnifiedSynthesisEngine

class MockSummary:
    function_name = 'sparse_case'
    instructions = []
    guard_facts = {'param_0': ['ZERO_CHECK']}  # Has guards

system = {
    'bug_type': 'DIV_ZERO',
    'bug_variable': 'param_0',
    'crash_summary': MockSummary(),
    'n_vars': 2,
    'initial': 'true',
    'safe': 'x != 0',
    'unsafe': 'x == 0',
    'dynamics': 'x\' = x'
}

property_spec = {
    'type': 'safety',
    'avoid': 'x == 0'
}

print("Testing with Papers #1-5 forced to fail...")
print()

engine = UnifiedSynthesisEngine()
result = engine.verify(system, property_spec)

print()
print("="*80)
print("RESULT")
print("="*80)
print(f"Status: {result.status}")
print(f"Method: {result.method_used}")
if hasattr(result, 'certificate'):
    print(f"Certificate: {result.certificate}")

# Restore originals
papers_1_to_5_complete.HybridBarrierSynthesizer.synthesize_hybrid_barrier = original_paper1
papers_1_to_5_complete.StochasticBarrierSynthesizer.synthesize_stochastic_barrier = original_paper2
papers_1_to_5_complete.SOSSafetyVerifier.verify_safety_sos = original_paper3
papers_1_to_5_complete.SOSTOOLSFramework.synthesize_barrier = original_paper4
papers_1_to_5_complete.PositivstellensatzProver.prove_positivity = original_paper5
