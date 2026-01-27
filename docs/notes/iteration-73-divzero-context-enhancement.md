# Iteration 73: Enhanced DIV_ZERO Context Tracking

## Objective

Enhance symbolic execution DIV_ZERO unsafe checking to capture precise semantic context about division-by-zero operations, improving bug report quality and debuggability.

## Changes Made

### 1. Added Context Tracking to Machine State

Added `div_by_zero_context` field to `SymbolicMachineState` to store semantic information about DIV_ZERO detections:

```python
div_by_zero_context: Optional[dict] = None  # Contains: operation, offset, function_name, left_val, right_val
```

This field captures:
- **operation**: Type of division (true_divide, floor_divide, modulo)
- **offset**: Bytecode instruction offset where div-by-zero occurs
- **function_name**: Name of the function containing the division
- **left_symbolic**: Symbolic representation of left operand
- **right_symbolic**: Symbolic representation of right operand  
- **div_zero_constraint**: Z3 constraint capturing the zero condition

### 2. Enhanced BINARY_OP Handling

Modified the three division operations in `_execute_instruction`:
- **TRUE_DIVIDE (op == 11)**: Captures context when `right == 0` is feasible
- **FLOOR_DIVIDE (op == 2)**: Captures context when `right == 0` is feasible
- **MODULO (op == 6)**: Captures context when `right == 0` is feasible

Each detection now populates `state.div_by_zero_context` with precise information immediately when the unsafe condition is detected via Z3 SAT check.

### 3. Enhanced Counterexample Extraction

Updated `extract_counterexample()` in `pyfromscratch/unsafe/div_zero.py` to include the context information in bug reports:

```python
if hasattr(state, 'div_by_zero_context') and state.div_by_zero_context:
    counterexample['context'] = state.div_by_zero_context
```

This provides human-readable and machine-processable details about the exact division operation that caused the bug.

### 4. Updated State Copying

Modified `SymbolicMachineState.copy()` to properly deep-copy the `div_by_zero_context` dictionary when branching paths.

## Semantic Grounding

This enhancement maintains the barrier-certificate theory discipline:

1. **No heuristics added**: Detection still relies on Z3 SAT checking of `div_zero` constraint derived from symbolic semantics
2. **Context is post-detection**: We only capture context AFTER Z3 confirms the unsafe predicate `U_DIV_ZERO(σ)` is reachable
3. **Precise location tracking**: Uses bytecode offset and function name from machine state, not source text patterns
4. **Transparent to semantics**: Context capture doesn't affect reachability computation or path conditions

## Testing

All 23 DIV_ZERO tests pass (10 BUG cases, 13 NON-BUG cases), including the counterexample extraction test.

Full test suite: **717 passed, 10 skipped, 15 xfailed, 12 xpassed** - no regressions.

Example enhanced output:
```
context: {
  'operation': 'true_divide',
  'offset': 6,
  'function_name': '<module>',
  'left_symbolic': 'SymbolicValue(tag=2, payload=10)',
  'right_symbolic': 'SymbolicValue(tag=2, payload=0)',
  'div_zero_constraint': '0 == 0'
}
```

## Quality Bar Answers

**Q: What is the exact semantic unsafe region, in terms of the machine state?**  
A: `U_DIV_ZERO(σ) = σ.div_by_zero_reached ∨ σ.exception == "ZeroDivisionError"`, where `div_by_zero_reached` is set when Z3 proves `right == 0` is SAT under the current path condition during TRUE_DIVIDE/FLOOR_DIVIDE/MODULO operations.

**Q: What is the exact transition relation you used?**  
A: BINARY_OP bytecode instruction with division operations (opcodes 11, 2, 6). Transition splits on `div_zero` constraint: unsafe branch sets exception and context; safe branch adds `¬div_zero` to path condition.

**Q: Where is the Z3 query that proves reachability?**  
A: Lines 1360-1367, 1407-1414, 1449-1456 in `symbolic_vm.py`. Each performs `solver.check()` on path condition conjuncted with `div_zero` and `¬none_misuse`.

**Q: Where is the extracted witness trace?**  
A: `extract_counterexample()` in `div_zero.py` constructs witness with trace, final state, path condition, and new context information.

## Impact

- **Better debugging**: Bug reports now include operation type, location, and operand values
- **DSE oracle integration**: Context provides concrete targets for dynamic validation
- **Public repo triage**: More actionable reports for real-world findings
- **No false positive/negative changes**: Pure enhancement to existing correct detection

## Files Changed

1. `pyfromscratch/semantics/symbolic_vm.py` - Added context field and capture logic
2. `pyfromscratch/unsafe/div_zero.py` - Enhanced counterexample extraction
3. `docs/notes/iteration-73-divzero-context-enhancement.md` - This note

## Next Actions

Continue with CONTINUOUS_REFINEMENT queue:
- Encode precise step relation as Z3 constraints
- Expand barrier templates (polynomial, disjunctive)
- Expand stdlib stubs based on high-usage modules from scans
