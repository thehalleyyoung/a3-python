#!/usr/bin/env python3
"""Test which bugs Paper #1 catches vs Paper #25."""

import pickle
from pyfromscratch.barriers.papers_1_to_5_complete import Papers1to5UnifiedEngine
from pyfromscratch.barriers.fast_barrier_filters import StochasticBarrierSynthesis

# Load summaries
with open('results/deepspeed_crash_summaries.pkl', 'rb') as f:
    all_summaries = pickle.load(f)

inference_funcs = {k: v for k, v in all_summaries.items()
                  if '.inference' in k.lower() or 'inference.' in k.lower()}

# Create test bugs
test_bugs = []
for i, (fname, summary) in enumerate(list(inference_funcs.items())[:10]):
    test_bugs.append({
        'id': i+1,
        'type': 'DIV_ZERO' if i % 3 == 0 else 'NULL_PTR',
        'variable': 'param_0',
        'summary': summary
    })

# Test both engines
papers_engine = Papers1to5UnifiedEngine()
layer0_engine = StochasticBarrierSynthesis()

print('Testing which bugs are caught by which paper:')
print('='*70)
print()

for bug in test_bugs:
    # Try Papers #1-5
    is_safe_papers, paper_name, cert = papers_engine.verify_safety(
        bug['type'], bug['variable'], bug['summary']
    )
    
    # Try Layer 0 (Paper #25) - returns (is_safe, confidence)
    is_safe_layer0, conf = layer0_engine.proves_safe(bug['type'], bug['variable'], bug['summary'])
    
    print(f"Bug #{bug['id']}: {bug['type']}")
    if is_safe_papers and paper_name:
        print(f"  ✓ {paper_name}")
    if is_safe_layer0:
        print(f"  ✓ Paper #25: Stochastic (Layer 0) - P={conf:.0%}")
    if not is_safe_papers and not is_safe_layer0:
        print(f"  ✗ NOT CAUGHT")
    print()

print()
print("="*70)
print("SUMMARY")
print("="*70)
papers_caught = sum(1 for b in test_bugs if papers_engine.verify_safety(b['type'], b['variable'], b['summary'])[0])
layer0_caught = sum(1 for b in test_bugs if layer0_engine.proves_safe(b['type'], b['variable'], b['summary'])[0])
print(f"Papers #1-5 caught: {papers_caught}/10")
print(f"Paper #25 caught: {layer0_caught}/10")
print(f"Total unique: {max(papers_caught, layer0_caught)}/10 (at least)")
