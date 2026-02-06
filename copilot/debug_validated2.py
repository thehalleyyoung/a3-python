#!/usr/bin/env python3
"""Trace why ValidatedParamsBarrier isn't firing."""
from pyfromscratch.barriers.enhanced_barrier_theory import (
    EnhancedDeepBarrierTheoryEngine, ValidatedParamsBarrier
)
import pickle

with open('results/deepspeed_crash_summaries_v2.pkl', 'rb') as f:
    summaries = pickle.load(f)

engine = EnhancedDeepBarrierTheoryEngine(all_summaries=summaries)

# Check which checkers have which methods
for i, checker in enumerate(engine.checkers):
    methods = [m for m in dir(checker) if m.startswith('check_')]
    print(f"  [{i}] {checker.__class__.__name__}: {methods}")

print()

# Test directly with one known case
test_func = 'deepspeed.module_inject.fusedqkv_utils._transpose_fused_qkvw'
test_summary = summaries[test_func]
test_bug = 'VALUE_ERROR'

print(f"Testing: {test_func} / {test_bug}")
print(f"  validated_params: {test_summary.validated_params}")

# Test the barrier directly
barrier = ValidatedParamsBarrier()
cert = barrier.check_validated_params(test_bug, '<v>', test_summary)
print(f"  Direct call result: {cert}")

# Now test through the engine
is_safe, cert = engine.verify_via_deep_barriers(test_bug, '<v>', test_summary)
print(f"  Engine result: is_safe={is_safe}, cert={cert}")
if cert:
    print(f"    barrier_type={cert.barrier_type}")
    print(f"    proof={cert.proof_sketch[:100]}")
