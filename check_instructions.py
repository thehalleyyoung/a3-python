#!/usr/bin/env python3
"""
Check what's actually in the summaries and instructions.
"""
import sys
from pathlib import Path
import pickle
from collections import Counter

cache_file = Path('results/deepspeed_crash_summaries.pkl')
if not cache_file.exists():
    print(f"ERROR: {cache_file} not found")
    sys.exit(1)

print("Loading summaries...")
with open(cache_file, 'rb') as f:
    summaries = pickle.load(f)
print(f"Loaded {len(summaries)} summaries\n")

print("="*80)
print("ANALYZING SUMMARY STRUCTURE")
print("="*80)
print()

# Check what attributes summaries have
sample = list(summaries.values())[0]
print(f"Sample summary attributes: {dir(sample)}")
print()

# Check if instructions exist and what they look like
has_instructions = sum(1 for s in summaries.values() if hasattr(s, 'instructions'))
print(f"Summaries with 'instructions' attribute: {has_instructions}/{len(summaries)}")

if has_instructions > 0:
    # Get a sample with instructions
    sample_with_instrs = next(s for s in summaries.values() if hasattr(s, 'instructions'))
    print(f"\nSample instructions (first 10):")
    if sample_with_instrs.instructions:
        for i, instr in enumerate(sample_with_instrs.instructions[:10]):
            print(f"  {i}: {instr}")
            print(f"      opname: {instr.opname if hasattr(instr, 'opname') else 'N/A'}")
            print(f"      argval: {instr.argval if hasattr(instr, 'argval') else 'N/A'}")
    else:
        print("  Instructions list is empty")

print()
print("="*80)
print("SEARCHING FOR STDLIB PATTERNS")
print("="*80)
print()

stdlib_funcs = ['len', 'max', 'min', 'range', 'enumerate', 'abs']
found_patterns = Counter()

for func_name, summary in list(summaries.items())[:1000]:
    if not hasattr(summary, 'instructions'):
        continue
    
    if not summary.instructions:
        continue
    
    for instr in summary.instructions:
        if hasattr(instr, 'argval'):
            argval_str = str(instr.argval).lower()
            for stdlib_func in stdlib_funcs:
                if stdlib_func in argval_str:
                    found_patterns[stdlib_func] += 1
                    
                    if found_patterns[stdlib_func] <= 3:  # Show first 3 examples
                        print(f"Found {stdlib_func} in {func_name}:")
                        print(f"  Instruction: {instr.opname} {instr.argval}")
                        
                        # Show bug types for this function
                        if hasattr(summary, 'may_trigger'):
                            print(f"  Bug types: {summary.may_trigger}")
                        print()

print()
print("Pattern frequency:")
for pattern, count in found_patterns.most_common():
    print(f"  {pattern}: {count} occurrences")

print()
print("="*80)
print("DIAGNOSIS")
print("="*80)
print()

if found_patterns:
    print("✓ Found stdlib patterns in bytecode")
    print()
    print("Possible issues:")
    print("1. The _synthesize_stdlib_barrier_with_ice() function isn't being called")
    print("2. The function is raising exceptions silently")
    print("3. The confidence threshold (0.88) is too high")
    print("4. The barrier synthesis is failing internally")
else:
    print("✗ No stdlib patterns found in bytecode!")
    print()
    print("This means:")
    print("- The instructions might not contain function names in argval")
    print("- Need to check LOAD_GLOBAL or LOAD_NAME opcodes instead")
    print("- The stdlib calls might be in a different representation")
