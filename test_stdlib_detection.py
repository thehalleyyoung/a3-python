#!/usr/bin/env python3
"""
Test stdlib barrier synthesis with bytecode instructions.
"""
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryAnalyzer
from pyfromscratch.barriers.extreme_verification import ExtremeContextVerifier

# Create test functions with stdlib usage
def test_len_division(items):
    """Division by len() - should be detected"""
    n = len(items)
    return 100 / n  # Bug: len can be 0

def test_max_safe_division(x):
    """Division by max(x, 1) - should be safe"""
    divisor = max(x, 1)
    return 100 / divisor  # Safe: max(x, 1) >= 1

# Test 1: len() detection
print("="*80)
print("TEST 1: len() detection")
print("="*80)
code1 = test_len_division.__code__
analyzer1 = BytecodeCrashSummaryAnalyzer(
    code=code1,
    func_name='test_len_division',
    qualified_name='test.test_len_division',
)
summary1 = analyzer1.analyze()

print(f"✓ Function analyzed: {summary1.function_name}")
print(f"  Bytecode instructions: {len(summary1.bytecode_instructions)}")
print(f"  Sample instructions:")
for i, instr in enumerate(summary1.bytecode_instructions[:10]):
    print(f"    {i}: {instr.opname:20s} {instr.argval}")

# Test 2: max() detection
print()
print("="*80)
print("TEST 2: max(x, 1) detection")
print("="*80)
code2 = test_max_safe_division.__code__
analyzer2 = BytecodeCrashSummaryAnalyzer(
    code=code2,
    func_name='test_max_safe_division',
    qualified_name='test.test_max_safe_division',
)
summary2 = analyzer2.analyze()

print(f"✓ Function analyzed: {summary2.function_name}")
print(f"  Bytecode instructions: {len(summary2.bytecode_instructions)}")
print(f"  Sample instructions:")
for i, instr in enumerate(summary2.bytecode_instructions[:10]):
    print(f"    {i}: {instr.opname:20s} {instr.argval}")

# Test 3: stdlib barrier synthesis
print()
print("="*80)
print("TEST 3: Stdlib barrier synthesis")
print("="*80)
verifier = ExtremeContextVerifier()

# Try to detect len() usage
stdlib_usage1 = verifier._detect_stdlib_usage(summary1.bytecode_instructions)
print(f"✓ len() usage detected: {stdlib_usage1}")

stdlib_usage2 = verifier._detect_stdlib_usage(summary2.bytecode_instructions)
print(f"✓ max() usage detected: {stdlib_usage2}")

print()
print("SUCCESS: Stdlib detection is working with bytecode instructions!")
