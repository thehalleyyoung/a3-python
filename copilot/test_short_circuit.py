#!/usr/bin/env python3
"""Test short-circuit evaluation tracking."""

from pyfromscratch.semantics.bytecode_summaries import BytecodeAbstractInterpreter

# Test 1: or pattern (should detect bug with high confidence)
def test_or(x):
    if x or x[0]:
        return 1
    return 0

# Test 2: and pattern (should NOT detect bug - x is truthy when x[0] is evaluated)
def test_and(x):
    if x and x[0]:
        return 1
    return 0

# Test 3: no guard (should detect with moderate confidence)
def test_no_guard(x):
    return x[0]

for func, name in [(test_or, 'if x or x[0]'), 
                   (test_and, 'if x and x[0]'),
                   (test_no_guard, 'return x[0]')]:
    analyzer = BytecodeAbstractInterpreter(
        code=func.__code__,
        func_name=func.__name__,
        qualified_name=func.__name__,
        callee_summaries={},
    )
    summary = analyzer.analyze()
    
    print(f'\n{name}:')
    if analyzer.potential_bugs:
        for bug in analyzer.potential_bugs:
            print(f'  {bug.bug_type} at line {bug.line_number}, confidence={bug.confidence}')
    else:
        print('  No bugs found')
