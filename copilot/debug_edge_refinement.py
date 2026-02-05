#!/usr/bin/env python3
"""Debug the edge refinement for short-circuit evaluation."""

from pyfromscratch.semantics.bytecode_summaries import BytecodeAbstractInterpreter, Emptiness, analyze_function, AbstractValue, AbstractState
from pyfromscratch.cfg.control_flow import build_cfg, EdgeType

# Simple test case with the buggy pattern: if x or x[0]
def buggy(x):
    if x or x[0]:  # Bug: if x is empty, x[0] will fail
        return True
    return False

# Create the analyzer and manually trace block 1
analyzer = BytecodeAbstractInterpreter(buggy.__code__, 'buggy', 'test.buggy')

# First, run the analysis to get the entry state for block 1
summary = analyzer.analyze()

# Now let's trace through block 1 manually
block1 = analyzer.cfg.blocks[1]
entry_state_1 = analyzer.block_entry_states[1]

print('Block 1 entry state:')
print(f'  x (local 0) emptiness: {entry_state_1.locals[0].emptiness.name}')
print(f'  Stack: {[v.emptiness.name for v in entry_state_1.stack]}')

# Trace instruction by instruction
state = entry_state_1.copy()
for instr in block1.instructions:
    print(f'\n  {instr.offset}: {instr.opname} {instr.argval}')
    
    if instr.opname == 'LOAD_FAST_BORROW':
        idx = instr.arg
        if idx in state.locals:
            loaded_val = state.locals[idx]
            print(f'    Loading x with emptiness={loaded_val.emptiness.name}')
            state.push(loaded_val)
        else:
            state.push(AbstractValue.top())
    elif instr.opname == 'LOAD_SMALL_INT':
        state.push(AbstractValue.from_const(instr.argval))
    elif instr.opname == 'BINARY_OP' and instr.argval == 26:  # subscript
        right = state.pop()
        left = state.pop()
        print(f'    BINARY_OP []: left.emptiness={left.emptiness.name}')
        if left.emptiness == Emptiness.EMPTY:
            print('    -> Would report high-confidence BOUNDS!')
    elif instr.opname == 'NOT_TAKEN':
        pass  # no-op

# Check bugs
print('\n--- Bugs Found ---')
print(f'Total bugs: {len(summary.potential_bugs)}')
for i, bug in enumerate(summary.potential_bugs):
    print(f'  [{i}] {bug.bug_type} at offset {bug.offset}, line {bug.line_number}, confidence={bug.confidence:.2f}')
