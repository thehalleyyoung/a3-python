#!/usr/bin/env python3
"""Test that Papers #6-10 are actually being invoked when needed."""

import logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(name)s - %(message)s')

from pyfromscratch.barriers.synthesis_engine import UnifiedSynthesisEngine

# Create test case where Papers #1-5 should fail but #6-10 might succeed
class MockSummary:
    function_name = 'complex_case'
    instructions = []
    guard_facts = {}  # No guards - Papers #1-5 might fail

print("="*80)
print("TESTING PAPERS #6-10 INVOCATION")
print("="*80)
print()

# Create synthesis problem with Python bug context
problem = {
    'system': {
        'bug_type': 'DIV_ZERO',
        'bug_variable': 'denominator',
        'crash_summary': MockSummary(),
        'n_vars': 2,
        'initial': 'true',
        'safe': 'x != 0',
        'unsafe': 'x == 0',
        'dynamics': 'x\' = x'
    },
    'property': {
        'type': 'safety',
        'avoid': 'x == 0'
    },
    'n_vars': 2
}

print("Testing synthesis engine with Papers #1-10...")
print()

engine = UnifiedSynthesisEngine()

# Fix: verify() takes system and property separately
system = problem['system']
property_spec = problem['property']

result = engine.verify(system, property_spec)

print()
print("="*80)
print("RESULT")
print("="*80)
print(f"Status: {result.status}")
print(f"Method: {result.method_used}")
print(f"Certificate: {result.certificate}")
