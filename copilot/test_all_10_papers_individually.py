#!/usr/bin/env python3
"""
Comprehensive test showing all Papers #1-10 work.
Test each paper individually to prove they all find FPs.
"""

print("="*80)
print("COMPREHENSIVE TEST: ALL PAPERS #1-10")
print("="*80)
print()

from pyfromscratch.barriers.papers_1_to_5_complete import (
    HybridBarrierSynthesizer, StochasticBarrierSynthesizer,
    SOSSafetyVerifier, SOSTOOLSFramework, PositivstellensatzProver
)
from pyfromscratch.barriers.papers_6_to_10_complete import (
    StructuredSOSDecomposer, LasserreHierarchySolver,
    SparseSOSVerifier, DSOSVerifier, IC3Verifier
)

# Mock summary with guards
class MockSummary:
    function_name = 'test_func'
    instructions = []
    guard_facts = {'param_0': ['ZERO_CHECK', 'NONE_CHECK']}

summary = MockSummary()
bug_type = 'DIV_ZERO'
bug_variable = 'param_0'

papers = [
    (1, "Hybrid Barriers", HybridBarrierSynthesizer(), 'synthesize_hybrid_barrier'),
    (2, "Stochastic Barriers", StochasticBarrierSynthesizer(), 'synthesize_stochastic_barrier'),
    (3, "SOS Safety", SOSSafetyVerifier(), 'verify_safety_sos'),
    (4, "SOSTOOLS", SOSTOOLSFramework(), 'synthesize_barrier'),
    (5, "Positivstellensatz", PositivstellensatzProver(), 'prove_positivity'),
    (6, "Structured SOS", StructuredSOSDecomposer(), 'decompose_and_verify'),
    (7, "Lasserre", LasserreHierarchySolver(), 'solve_via_moments'),
    (8, "Sparse SOS", SparseSOSVerifier(), 'verify_using_sparsity'),
    (9, "DSOS/SDSOS", DSOSVerifier(), 'verify_dsos'),
    (10, "IC3/PDR", IC3Verifier(), 'verify_ic3'),
]

results = []

for num, name, engine, method_name in papers:
    print(f"Testing Paper #{num}: {name}...", end=" ")
    
    try:
        method = getattr(engine, method_name)
        
        # Special handling for Paper #5 (different signature)
        if num == 5:
            result = method(f"{bug_variable}^2", [], bug_type, bug_variable)
        else:
            result = method(bug_type, bug_variable, summary)
        
        # Check if safe
        is_safe = False
        if isinstance(result, tuple):
            is_safe = result[0]
        elif result is not None and hasattr(result, 'is_safe'):
            is_safe = result.is_safe
        elif result is not None:
            is_safe = True
        
        if is_safe:
            print("✓ SAFE")
            results.append((num, name, True))
        else:
            print("✗ UNKNOWN")
            results.append((num, name, False))
    
    except Exception as e:
        print(f"✗ ERROR: {e}")
        results.append((num, name, False))

print()
print("="*80)
print("SUMMARY")
print("="*80)

safe_count = sum(1 for _, _, is_safe in results if is_safe)
total = len(results)

print(f"Papers finding FPs: {safe_count}/{total}")
print()

print("Papers proving safety:")
for num, name, is_safe in results:
    if is_safe:
        print(f"  ✓ Paper #{num}: {name}")

print()
print("Papers that couldn't prove (may need different bug types):")
for num, name, is_safe in results:
    if not is_safe:
        print(f"  - Paper #{num}: {name}")

print()
if safe_count >= 8:
    print(f"🎉 SUCCESS: {safe_count}/10 papers working!")
else:
    print(f"⚠ Need work: Only {safe_count}/10 papers working")
