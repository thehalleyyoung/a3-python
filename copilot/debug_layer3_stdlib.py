#!/usr/bin/env python3
"""
Debug why Layer 3 ICE stdlib barriers aren't catching more FPs.
"""
import sys
from pathlib import Path
import pickle
import logging

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s: %(message)s'
)

from pyfromscratch.barriers.extreme_verification import ExtremeContextVerifier
from pyfromscratch.semantics.crash_summaries import CrashSummary

# Load summaries
cache_file = Path('results/deepspeed_crash_summaries.pkl')
if not cache_file.exists():
    print(f"ERROR: {cache_file} not found")
    sys.exit(1)

print("Loading summaries...")
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)
print(f"Loaded {len(summaries)} summaries\n")

# Create verifier
verifier = ExtremeContextVerifier()

print("="*80)
print("TESTING LAYER 3 ICE STDLIB BARRIER SYNTHESIS")
print("="*80)
print()

# Test on functions that should benefit
test_cases = []

# Find functions with len(), max(), range(), enumerate()
for func_name, summary in list(summaries.items())[:500]:
    if not hasattr(summary, 'may_trigger') or not hasattr(summary, 'instructions'):
        continue
    
    instructions = summary.instructions
    
    # Check for stdlib patterns
    has_len = any(hasattr(i, 'argval') and 'len' in str(i.argval).lower() for i in instructions)
    has_max = any(hasattr(i, 'argval') and 'max' in str(i.argval).lower() for i in instructions)
    has_range = any(hasattr(i, 'argval') and 'range' in str(i.argval).lower() for i in instructions)
    has_enumerate = any(hasattr(i, 'argval') and 'enumerate' in str(i.argval).lower() for i in instructions)
    
    if any([has_len, has_max, has_range, has_enumerate]):
        for bug_type in summary.may_trigger:
            if bug_type in ['DIV_ZERO', 'BOUNDS', 'NULL_PTR']:
                test_cases.append({
                    'function': func_name,
                    'bug_type': bug_type,
                    'has_len': has_len,
                    'has_max': has_max,
                    'has_range': has_range,
                    'has_enumerate': has_enumerate,
                    'summary': summary
                })
                
                if len(test_cases) >= 20:
                    break
    
    if len(test_cases) >= 20:
        break

print(f"Found {len(test_cases)} test cases with stdlib patterns")
print()

# Test each case
caught_by_layer3 = 0
failed_cases = []

for i, test in enumerate(test_cases[:10], 1):
    print(f"\nTest {i}: {test['function']}")
    print(f"  Bug type: {test['bug_type']}")
    print(f"  Patterns: len={test['has_len']}, max={test['has_max']}, range={test['has_range']}, enumerate={test['has_enumerate']}")
    
    try:
        # Try to verify
        result = verifier.verify_bug_extreme(
            bug_type=test['bug_type'],
            bug_variable='test_var',
            crash_summary=test['summary'],
            call_chain_summaries=[],
            code_object=None,
            source_code=None
        )
        
        print(f"  Result: is_safe={result.is_safe}")
        
        if result.is_safe:
            print(f"  ✓ Caught by verification")
            caught_by_layer3 += 1
        else:
            print(f"  ✗ Not caught")
            failed_cases.append(test)
            
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()
        failed_cases.append(test)

print()
print("="*80)
print("SUMMARY")
print("="*80)
print(f"Total test cases: {len(test_cases[:10])}")
print(f"Caught by Layer 3: {caught_by_layer3}")
print(f"Failed: {len(failed_cases)}")
print()

if failed_cases:
    print("Failed cases to investigate:")
    for fc in failed_cases[:3]:
        print(f"  - {fc['function']}: {fc['bug_type']}")
        print(f"    Patterns: len={fc['has_len']}, max={fc['has_max']}, range={fc['has_range']}, enumerate={fc['has_enumerate']}")
        
        # Check why it failed - look at instructions
        instrs = fc['summary'].instructions
        print(f"    Instructions: {len(instrs)}")
        for instr in instrs[:5]:
            if hasattr(instr, 'argval'):
                print(f"      {instr.opname}: {instr.argval}")
        print()
