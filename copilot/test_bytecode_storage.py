#!/usr/bin/env python3
"""
Test that bytecode instructions are stored in crash summaries.
"""
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryAnalyzer
import dis

# Create a test function
def test_div(x, y):
    """Test function with division"""
    if y != 0:
        return x / y
    return 0

# Get code object
code = test_div.__code__

# Analyze
analyzer = BytecodeCrashSummaryAnalyzer(
    code=code,
    func_name='test_div',
    qualified_name='test.test_div',
)
summary = analyzer.analyze()

# Check bytecode instructions were stored
print('✓ BytecodeCrashSummaryAnalyzer created')
print(f'  Function: {summary.function_name}')
print(f'  Bytecode instructions stored: {len(summary.bytecode_instructions)}')
print(f'  Sample instructions:')
for i, instr in enumerate(summary.bytecode_instructions[:5]):
    print(f'    {i}: {instr.opname:20s} {instr.argval}')

if summary.bytecode_instructions:
    print()
    print('SUCCESS: Bytecode instructions are now stored in crash summaries!')
else:
    print()
    print('ERROR: No bytecode instructions stored!')
