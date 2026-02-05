#!/usr/bin/env python3
"""Debug script to trace the analysis and see why the emptiness isn't being used."""

from pyfromscratch.semantics.bytecode_summaries import BytecodeAbstractInterpreter, Emptiness, AbstractValue, BINARY_OPS_SUBSCRIPT
from pyfromscratch.cfg.control_flow import build_cfg, EdgeType
import dis

def test_func(x):
    if x or x[0]:
        return 1
    return 0

# Create analyzer
analyzer = BytecodeAbstractInterpreter(
    code=test_func.__code__,
    func_name='test_func',
    qualified_name='test_func',
    callee_summaries={},
)

# Patch _refine_truthiness_on_edge to trace
original_refine = analyzer._refine_truthiness_on_edge
def traced_refine(state, block, edge_type):
    before = {idx: (v.emptiness.name, v.zeroness.name) for idx, v in state.locals.items()}
    original_refine(state, block, edge_type)
    after = {idx: (v.emptiness.name, v.zeroness.name) for idx, v in state.locals.items()}
    if before != after:
        print(f'  Refine on block {block.id}, edge {edge_type}:')
        for idx in state.locals:
            if before.get(idx) != after.get(idx):
                print(f'    locals[{idx}]: {before.get(idx)} -> {after.get(idx)}')

analyzer._refine_truthiness_on_edge = traced_refine

# Patch _handle_binary_op to trace
original_binary = analyzer._handle_binary_op
def traced_binary(state, oparg, offset, guards, instr):
    if oparg in BINARY_OPS_SUBSCRIPT:
        # Check the stack before the operation
        print(f'  BINARY_OP at offset {offset}: stack depth={len(state.stack)}')
        if len(state.stack) >= 2:
            right = state.stack[-1]
            left = state.stack[-2]
            print(f'    left.emptiness={left.emptiness.name}, right.zeroness={right.zeroness.name}')
            if left.emptiness == Emptiness.EMPTY:
                print(f'    -> SHOULD report high-confidence BOUNDS!')
        elif len(state.stack) >= 1:
            print(f'    Only one item on stack: {state.stack[-1].emptiness.name}')
        else:
            print(f'    Stack is empty!')
    original_binary(state, oparg, offset, guards, instr)

analyzer._handle_binary_op = traced_binary

# Patch _transfer_block to trace
original_transfer = analyzer._transfer_block
def traced_transfer(block, entry):
    print(f'Transfer block {block.id}:')
    if 0 in entry.locals:
        print(f'  Entry locals[0].emptiness = {entry.locals[0].emptiness.name}')
    return original_transfer(block, entry)

analyzer._transfer_block = traced_transfer

# Patch _transfer_instr to trace all instructions
original_instr = analyzer._transfer_instr
def traced_instr(instr, state, block_id):
    print(f'  Instr {instr.offset}: {instr.opname} {instr.argval}, block={block_id}, stack depth={len(state.stack)}')
    if state.stack:
        print(f'    stack[-1].emptiness={state.stack[-1].emptiness.name}')
    
    if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW') and instr.arg == 0:
        val = state.locals.get(0, AbstractValue.top())
        print(f'    -> LOAD_FAST will push: emptiness={val.emptiness.name}')
    
    result = original_instr(instr, state, block_id)
    
    print(f'    After: stack depth={len(result.stack)}')
    if result.stack:
        print(f'      stack[-1].emptiness={result.stack[-1].emptiness.name}')
    
    return result

analyzer._transfer_instr = traced_instr

print('=== Running analysis ===')
summary = analyzer.analyze()

print('\n=== Results ===')
print(f'Total bugs: {len(analyzer.potential_bugs)}')
for bug in analyzer.potential_bugs:
    print(f'  {bug.bug_type} at offset {bug.offset}, line {bug.line_number}, confidence={bug.confidence}')
