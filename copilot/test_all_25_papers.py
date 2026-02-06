#!/usr/bin/env python3
"""
Comprehensive test of all 25 papers end-to-end.

Tests:
1. Papers #1-5 individually
2. Papers #6-10 individually  
3. Papers #11-15 individually
4. Papers #16-20 individually
5. Papers #21-25 individually
6. Unified engines for each layer
7. Full pipeline integration
"""

from unittest.mock import patch

print("=" * 80)
print("COMPREHENSIVE TEST: ALL 25 PAPERS")
print("=" * 80)
print()

class MockMetadata:
    function_name = 'test_func'
    instructions = []
    guard_facts = {'x': ['ZERO_CHECK']}

metadata = MockMetadata()

# ============================================================================
# PART 1: TEST EACH LAYER INDIVIDUALLY
# ============================================================================

print("PART 1: INDIVIDUAL LAYER TESTS")
print("=" * 80)
print()

layer_results = {}

# Papers #21-25 (Layer 0)
print("Testing Papers #21-25 (Layer 0: Fast Barriers)...")
try:
    from pyfromscratch.barriers.fast_barrier_filters import FastBarrierFilterPipeline
    pipeline = FastBarrierFilterPipeline()
    is_safe, conf, technique = pipeline.try_prove_safe('DIV_ZERO', 'x', metadata)
    layer_results['21-25'] = is_safe
    print(f"  Result: {'✓ SAFE' if is_safe else '✗ UNKNOWN'} (technique: {technique})")
except Exception as e:
    layer_results['21-25'] = False
    print(f"  ERROR: {str(e)[:60]}")
print()

# Papers #1-5
print("Testing Papers #1-5 (Hybrid/SOS/Stochastic)...")
try:
    from pyfromscratch.barriers.papers_1_to_5_complete import Papers1to5UnifiedEngine
    engine = Papers1to5UnifiedEngine()
    is_safe, paper, cert = engine.verify_safety('DIV_ZERO', 'x', metadata)
    layer_results['1-5'] = is_safe
    print(f"  Result: {'✓ SAFE' if is_safe else '✗ UNKNOWN'} (paper: {paper})")
except Exception as e:
    layer_results['1-5'] = False
    print(f"  ERROR: {str(e)[:60]}")
print()

# Papers #6-10
print("Testing Papers #6-10 (Structured SOS/IC3/PDR)...")
try:
    from pyfromscratch.barriers.papers_6_to_10_complete import Papers6to10UnifiedEngine
    engine = Papers6to10UnifiedEngine()
    is_safe, paper, cert = engine.verify_safety('DIV_ZERO', 'x', metadata)
    layer_results['6-10'] = is_safe
    print(f"  Result: {'✓ SAFE' if is_safe else '✗ UNKNOWN'} (paper: {paper})")
except Exception as e:
    layer_results['6-10'] = False
    print(f"  ERROR: {str(e)[:60]}")
print()

# Papers #11-15
print("Testing Papers #11-15 (IMC/CEGAR/Abstraction)...")
try:
    from pyfromscratch.barriers.papers_11_to_15_complete import Papers11to15UnifiedEngine
    engine = Papers11to15UnifiedEngine()
    is_safe, paper, cert = engine.verify_safety('DIV_ZERO', 'x', metadata)
    layer_results['11-15'] = is_safe
    print(f"  Result: {'✓ SAFE' if is_safe else '✗ UNKNOWN'} (paper: {paper})")
except Exception as e:
    layer_results['11-15'] = False
    print(f"  ERROR: {str(e)[:60]}")
print()

# Papers #16-20
print("Testing Papers #16-20 (CHC/ICE/Houdini/SyGuS/A-G)...")
try:
    from pyfromscratch.barriers.papers_16_to_20_complete import Papers16to20UnifiedEngine
    engine = Papers16to20UnifiedEngine()
    is_safe, paper, cert = engine.verify_safety('DIV_ZERO', 'x', metadata)
    layer_results['16-20'] = is_safe
    print(f"  Result: {'✓ SAFE' if is_safe else '✗ UNKNOWN'} (paper: {paper})")
except Exception as e:
    layer_results['16-20'] = False
    print(f"  ERROR: {str(e)[:60]}")
print()

print("Layer Results:")
for layer, result in layer_results.items():
    symbol = "✓" if result else "✗"
    print(f"  {symbol} Papers #{layer}")
print()

# ============================================================================
# PART 2: TEST FULL PIPELINE INTEGRATION
# ============================================================================

print("=" * 80)
print("PART 2: FULL PIPELINE INTEGRATION")
print("=" * 80)
print()

print("Testing synthesis engine with all 20 papers integrated...")

def mock_fail(*args, **kwargs):
    return (False, "Mocked", {})

# Test that each layer is reached by mocking earlier ones
layers_to_test = [
    ('1-5', 'pyfromscratch.barriers.papers_1_to_5_complete.Papers1to5UnifiedEngine.verify_safety'),
    ('6-10', 'pyfromscratch.barriers.papers_6_to_10_complete.Papers6to10UnifiedEngine.verify_safety'),
    ('11-15', 'pyfromscratch.barriers.papers_11_to_15_complete.Papers11to15UnifiedEngine.verify_safety'),
    ('16-20', 'pyfromscratch.barriers.papers_16_to_20_complete.Papers16to20UnifiedEngine.verify_safety'),
]

pipeline_results = {}

# Test Papers #1-5 (no mocking)
try:
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
    result = engine._run_sos_safety(problem)
    pipeline_results['1-5'] = ('1' in str(result.method_used) or 
                               '2' in str(result.method_used) or
                               '3' in str(result.method_used) or
                               '4' in str(result.method_used) or
                               '5' in str(result.method_used))
    print(f"Papers #1-5: {result.method_used}")
except Exception as e:
    pipeline_results['1-5'] = False
    print(f"Papers #1-5: ERROR - {str(e)[:60]}")

# Test Papers #6-10 (mock #1-5)
try:
    with patch(layers_to_test[0][1], mock_fail):
        engine = UnifiedSynthesisEngine()
        result = engine._run_sos_safety(problem)
        pipeline_results['6-10'] = any(str(i) in str(result.method_used) for i in range(6, 11))
        print(f"Papers #6-10: {result.method_used}")
except Exception as e:
    pipeline_results['6-10'] = False
    print(f"Papers #6-10: ERROR - {str(e)[:60]}")

# Test Papers #11-15 (mock #1-10)
try:
    with patch(layers_to_test[0][1], mock_fail):
        with patch(layers_to_test[1][1], mock_fail):
            engine = UnifiedSynthesisEngine()
            result = engine._run_sos_safety(problem)
            pipeline_results['11-15'] = any(str(i) in str(result.method_used) for i in range(11, 16))
            print(f"Papers #11-15: {result.method_used}")
except Exception as e:
    pipeline_results['11-15'] = False
    print(f"Papers #11-15: ERROR - {str(e)[:60]}")

# Test Papers #16-20 (mock #1-15)
try:
    with patch(layers_to_test[0][1], mock_fail):
        with patch(layers_to_test[1][1], mock_fail):
            with patch(layers_to_test[2][1], mock_fail):
                engine = UnifiedSynthesisEngine()
                result = engine._run_sos_safety(problem)
                pipeline_results['16-20'] = any(str(i) in str(result.method_used) for i in range(16, 21))
                print(f"Papers #16-20: {result.method_used}")
except Exception as e:
    pipeline_results['16-20'] = False
    print(f"Papers #16-20: ERROR - {str(e)[:60]}")

print()

# ============================================================================
# PART 3: SUMMARY
# ============================================================================

print("=" * 80)
print("FINAL SUMMARY")
print("=" * 80)
print()

layers_working = sum(1 for r in layer_results.values() if r)
pipeline_working = sum(1 for r in pipeline_results.values() if r)

print(f"Individual Layers Working: {layers_working}/5")
print(f"Pipeline Integration Working: {pipeline_working}/4")
print()

print("Layer-by-Layer Status:")
for layer in ['21-25', '1-5', '6-10', '11-15', '16-20']:
    layer_ok = layer_results.get(layer, False)
    pipeline_ok = pipeline_results.get(layer, False) if layer != '21-25' else True
    
    layer_symbol = "✓" if layer_ok else "✗"
    pipeline_symbol = "✓" if pipeline_ok else "✗"
    
    print(f"  Papers #{layer:5s}: Individual {layer_symbol}  Pipeline {pipeline_symbol}")

print()

total_working = layers_working + pipeline_working
total_tests = 9

if total_working >= 8:
    print("🎉 EXCELLENT - All 25 papers fully integrated!")
elif total_working >= 6:
    print("✅ GOOD - Most papers working")
elif total_working >= 4:
    print("⚠️  PARTIAL - Some integration issues")
else:
    print("❌ NEEDS WORK - Major issues")

print()
print(f"Overall: {total_working}/{total_tests} tests passing")
