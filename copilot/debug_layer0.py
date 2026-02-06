#!/usr/bin/env python3
"""Debug why Layer 0 returns 0 FPs"""

import pickle
from pyfromscratch.barriers.fast_barrier_filters import FastBarrierFilterPipeline

# Load summaries
with open('results/deepspeed_crash_summaries.pkl', 'rb') as f:
    all_summaries = pickle.load(f)

# Get one inference function
inference_funcs = {k: v for k, v in all_summaries.items()
                  if '.inference' in k.lower() or 'inference.' in k.lower()}

# Get first function
func_name = list(inference_funcs.keys())[0]
summary = inference_funcs[func_name]

print(f"Testing function: {func_name}")
print(f"Has instructions: {hasattr(summary, 'instructions')}")
if hasattr(summary, 'instructions'):
    print(f"Instruction count: {len(summary.instructions)}")
print(f"Has guard_facts: {hasattr(summary, 'guard_facts')}")
print()

# Create pipeline
pipeline = FastBarrierFilterPipeline()
pipeline.learn_from_codebase(inference_funcs)

# Test each technique separately
print("="*80)
print("TESTING EACH TECHNIQUE")
print("="*80)
print()

# Test 1: Stochastic barriers
print("1. Stochastic Barriers:")
is_safe, conf = pipeline.stochastic.proves_safe('DIV_ZERO', 'param_0', summary)
print(f"   DIV_ZERO/param_0: is_safe={is_safe}, conf={conf:.3f}")

is_safe, conf = pipeline.stochastic.proves_safe('NULL_PTR', 'param_0', summary)
print(f"   NULL_PTR/param_0: is_safe={is_safe}, conf={conf:.3f}")
print()

# Test 2: Likely invariants
print("2. Likely Invariants:")
is_safe, conf = pipeline.likely_invariants.proves_safe('DIV_ZERO', 'param_0')
print(f"   DIV_ZERO/param_0: is_safe={is_safe}, conf={conf:.3f}")

is_safe, conf = pipeline.likely_invariants.proves_safe('NULL_PTR', 'param_0')
print(f"   NULL_PTR/param_0: is_safe={is_safe}, conf={conf:.3f}")
print()

# Test 3: Separation logic
print("3. Separation Logic:")
is_safe, conf = pipeline.separation_logic.proves_safe('NULL_PTR', 'param_0', summary)
print(f"   NULL_PTR/param_0: is_safe={is_safe}, conf={conf:.3f}")
print()

# Test 4: Refinement types
print("4. Refinement Types:")
is_safe, conf = pipeline.refinement_types.proves_safe('DIV_ZERO', 'param_0', summary)
print(f"   DIV_ZERO/param_0: is_safe={is_safe}, conf={conf:.3f}")

is_safe, conf = pipeline.refinement_types.proves_safe('NULL_PTR', 'param_0', summary)
print(f"   NULL_PTR/param_0: is_safe={is_safe}, conf={conf:.3f}")
print()

# Test 5: Interval analysis
print("5. Interval Analysis:")
is_safe, conf = pipeline.interval_analysis.proves_safe('DIV_ZERO', 'param_0', summary)
print(f"   DIV_ZERO/param_0: is_safe={is_safe}, conf={conf:.3f}")
print()

# Test the full pipeline
print("="*80)
print("FULL PIPELINE TEST")
print("="*80)
print()

is_safe, conf, technique = pipeline.try_prove_safe('DIV_ZERO', 'param_0', summary)
print(f"DIV_ZERO/param_0:")
print(f"  is_safe: {is_safe}")
print(f"  confidence: {conf:.3f}")
print(f"  technique: {technique}")
print()

is_safe, conf, technique = pipeline.try_prove_safe('NULL_PTR', 'param_0', summary)
print(f"NULL_PTR/param_0:")
print(f"  is_safe: {is_safe}")
print(f"  confidence: {conf:.3f}")
print(f"  technique: {technique}")
print()

# Check stochastic barrier details
print("="*80)
print("STOCHASTIC BARRIER DETAILS")
print("="*80)
print()

barrier = pipeline.stochastic.synthesize_barrier('DIV_ZERO', 'param_0', summary)
print(f"Barrier probability: {barrier.probability:.3f}")
print(f"Threshold: 0.85")
print(f"Is safe: {barrier.is_safe(threshold=0.85)}")
print()

# Try with different bug variables
print("Testing with different variables...")
for var in ['param_0', 'param_1', 'count', 'size', 'length']:
    is_safe, conf, technique = pipeline.try_prove_safe('DIV_ZERO', var, summary)
    print(f"  {var}: is_safe={is_safe}, conf={conf:.3f}, technique={technique}")
