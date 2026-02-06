#!/usr/bin/env python3
"""
Test the fully implemented Layer 0 Fast Barrier Filters.

This tests all 5 papers (Papers #21-25):
- Paper #21: Likely invariants
- Paper #22: Separation logic
- Paper #23: Refinement types
- Paper #24: Interval analysis
- Paper #25: Stochastic barriers
"""

import pickle
import sys
from pyfromscratch.barriers.fast_barrier_filters import FastBarrierFilterPipeline
from pyfromscratch.barriers.extreme_verification import ExtremeContextVerifier

def load_summaries():
    """Load DeepSpeed summaries."""
    with open('results/deepspeed_crash_summaries.pkl', 'rb') as f:
        return pickle.load(f)

def test_layer0_on_deepspeed_subset():
    """Test Layer 0 on DeepSpeed inference subset."""
    print("="*80)
    print("TESTING LAYER 0 FAST BARRIER FILTERS (Papers #21-25)")
    print("="*80)
    print()
    
    # Load summaries
    print("Loading DeepSpeed summaries...")
    all_summaries = load_summaries()
    
    # Filter to inference code only (smaller subset)
    inference_funcs = {k: v for k, v in all_summaries.items()
                      if '.inference' in k.lower() or 'inference.' in k.lower()}
    
    print(f"Total functions: {len(all_summaries)}")
    print(f"Inference functions: {len(inference_funcs)}")
    print()
    
    # Create verifier
    verifier = ExtremeContextVerifier()
    pipeline = verifier.fast_filters
    
    # Train Layer 0 on the codebase
    print("Training Layer 0 on codebase...")
    pipeline.learn_from_codebase(inference_funcs)
    print(f"  ✓ Learned from {len(inference_funcs)} functions")
    print()
    
    # Create synthetic bugs for testing
    print("Creating synthetic test bugs...")
    bugs = []
    
    # Sample 50 functions for testing
    sample_funcs = list(inference_funcs.items())[:50]
    
    for func_name, summary in sample_funcs:
        # Create DIV_ZERO bug
        bugs.append({
            'function': func_name,
            'bug_type': 'DIV_ZERO',
            'bug_variable': 'param_0',
        })
        
        # Create NULL_PTR bug
        bugs.append({
            'function': func_name,
            'bug_type': 'NULL_PTR',
            'bug_variable': 'param_0',
        })
        
        # Create VALUE_ERROR bug
        bugs.append({
            'function': func_name,
            'bug_type': 'VALUE_ERROR',
            'bug_variable': 'param_0',
        })
    
    print(f"  Created {len(bugs)} synthetic bugs")
    print()
    
    # Test Layer 0 on each bug
    print("Testing Layer 0 on each bug...")
    print("-"*80)
    
    layer0_results = {
        'refinement_types': 0,
        'likely_invariants': 0,
        'interval_analysis': 0,
        'separation_logic': 0,
        'stochastic_barriers': 0,
        'none': 0,
    }
    
    safe_count = 0
    total_bugs = 0
    
    for bug in bugs:
        total_bugs += 1
        
        func_name = bug['function']
        bug_type = bug['bug_type']
        
        # Get summary
        summary = inference_funcs.get(func_name)
        if not summary:
            continue
        
        # Get bug variable
        bug_variable = bug.get('bug_variable', 'param_0')
        
        # Test Layer 0
        is_safe, confidence, technique = pipeline.try_prove_safe(
            bug_type, bug_variable, summary
        )
        
        if is_safe:
            safe_count += 1
            layer0_results[technique] += 1
            
            if safe_count <= 10:  # Show first 10
                print(f"✓ #{safe_count} [{technique}] conf={confidence:.1%}")
                print(f"    Function: {func_name}")
                print(f"    Bug type: {bug_type}, Variable: {bug_variable}")
                print()
    
    print("-"*80)
    print()
    
    # Summary
    print("LAYER 0 RESULTS:")
    print("="*80)
    print(f"Total bugs tested: {total_bugs}")
    print(f"Proven safe by Layer 0: {safe_count} ({100*safe_count/max(total_bugs,1):.1f}%)")
    print()
    
    print("Breakdown by technique:")
    for technique, count in layer0_results.items():
        if count > 0:
            pct = 100 * count / max(safe_count, 1)
            print(f"  Paper #{technique:20s}: {count:3d} FPs ({pct:.1f}%)")
    print()
    
    # Compare with Phase -2
    print("COMPARISON WITH PHASE -2:")
    print("-"*80)
    from pyfromscratch.barriers.quick_precheck import quick_barrier_precheck
    
    phase2_count = 0
    for bug in bugs:
        func_name = bug['function']
        bug_type = bug['bug_type']
        summary = inference_funcs.get(func_name)
        if not summary:
            continue
        
        bug_variable = bug.get('bug_variable', 'param_0')
        is_safe, conf, reason = quick_barrier_precheck(bug_type, bug_variable, summary)
        
        if is_safe and conf > 0.75:
            phase2_count += 1
    
    print(f"Phase -2 (Quick Pre-Check): {phase2_count} FPs")
    print(f"Layer 0 (Fast Barriers):    {safe_count} FPs")
    print()
    
    if safe_count > phase2_count:
        improvement = safe_count - phase2_count
        print(f"✓ Layer 0 finds {improvement} MORE FPs than Phase -2!")
        print(f"  ({100*improvement/max(phase2_count,1):.1f}% improvement)")
    elif safe_count < phase2_count:
        print(f"⚠ Layer 0 finds {phase2_count - safe_count} FEWER FPs than Phase -2")
    else:
        print(f"= Layer 0 and Phase -2 find the same number of FPs")
    print()
    
    return safe_count, phase2_count, layer0_results

if __name__ == '__main__':
    try:
        safe_count, phase2_count, breakdown = test_layer0_on_deepspeed_subset()
        
        print("="*80)
        print("FINAL RESULTS")
        print("="*80)
        print(f"Layer 0 implementation: {'✓ WORKING' if safe_count > 0 else '✗ NOT WORKING'}")
        print(f"FPs caught: {safe_count}")
        print()
        
        sys.exit(0 if safe_count > 0 else 1)
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
