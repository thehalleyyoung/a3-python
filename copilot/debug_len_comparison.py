#!/usr/bin/env python3
"""Debug trace for len comparison refinement."""

from pyfromscratch.semantics.bytecode_summaries import BytecodeAbstractInterpreter, Emptiness
from pyfromscratch.cfg.control_flow import EdgeType

def safe_pattern(child_params):
    if len(child_params) > 0 and child_params[0].numel() == 0:
        return True
    return False

analyzer = BytecodeAbstractInterpreter(
    code=safe_pattern.__code__,
    func_name='safe_pattern',
    qualified_name='safe_pattern',
    callee_summaries={},
)

# Patch to trace both refinement methods
original_refine_truth = analyzer._refine_truthiness_on_edge
def traced_refine_truth(state, block, edge_type):
    before = state.locals.get(0)
    original_refine_truth(state, block, edge_type)
    after = state.locals.get(0)
    if before and after:
        if before.emptiness != after.emptiness:
            print(f'_refine_truthiness_on_edge: block {block.id}, edge {edge_type}')
            print(f'  Refined locals[0]: {before.emptiness.name} -> {after.emptiness.name}')

analyzer._refine_truthiness_on_edge = traced_refine_truth

original_refine_len = analyzer._refine_len_comparison_on_edge
def traced_refine_len(state, block, edge_type):
    before = state.locals.get(0)
    original_refine_len(state, block, edge_type)
    after = state.locals.get(0)
    if before and after:
        if before.emptiness != after.emptiness:
            print(f'_refine_len_comparison_on_edge: block {block.id}, edge {edge_type}')
            print(f'  Refined locals[0]: {before.emptiness.name} -> {after.emptiness.name}')

analyzer._refine_len_comparison_on_edge = traced_refine_len

summary = analyzer.analyze()
print()
print(f'Bugs: {len(analyzer.potential_bugs)}')
for bug in analyzer.potential_bugs:
    print(f'  {bug.bug_type} at line {bug.line_number}, offset {bug.offset}, confidence={bug.confidence}')
