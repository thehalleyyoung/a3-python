#!/usr/bin/env python3
"""Force Papers #11-13 to fail to test #14-15."""

from pyfromscratch.barriers import papers_11_to_15_complete

# Save originals
orig11 = papers_11_to_15_complete.IMCVerifier.verify_via_interpolation
orig12 = papers_11_to_15_complete.CEGARVerifier.verify_with_cegar
orig13 = papers_11_to_15_complete.PredicateAbstractionVerifier.verify_with_predicates

# Force failures
papers_11_to_15_complete.IMCVerifier.verify_via_interpolation = lambda self, *a, **k: (False, None)
papers_11_to_15_complete.CEGARVerifier.verify_with_cegar = lambda self, *a, **k: (False, None)
papers_11_to_15_complete.PredicateAbstractionVerifier.verify_with_predicates = lambda self, *a, **k: (False, None)

print("Testing with Papers #11-13 forced to fail...")

from pyfromscratch.barriers.papers_11_to_15_complete import Papers11to15UnifiedEngine

class MockSummary:
    function_name = 'test'
    instructions = []
    guard_facts = {'param_0': ['ZERO_CHECK']}

engine = Papers11to15UnifiedEngine()
is_safe, paper, cert = engine.verify_safety('DIV_ZERO', 'param_0', MockSummary())

print(f'Result: is_safe={is_safe}')
print(f'Paper: {paper}')
print(f'Certificate: {cert}')

# Restore
papers_11_to_15_complete.IMCVerifier.verify_via_interpolation = orig11
papers_11_to_15_complete.CEGARVerifier.verify_with_cegar = orig12
papers_11_to_15_complete.PredicateAbstractionVerifier.verify_with_predicates = orig13
