# Iteration 49: Closure Support (MAKE_CELL and Related Opcodes)

## Summary

Implemented full closure support for Python symbolic execution by adding four key opcodes:
- MAKE_CELL: Creates cells for closure variables
- STORE_DEREF: Stores values into cells/freevars  
- LOAD_DEREF: Loads values from cells/freevars
- COPY_FREE_VARS: Initializes free variables from outer scope

## Implementation Details

### Data Structure Changes

Extended `SymbolicFrame` to include:
- `cells: dict[int, Optional[SymbolicValue]]` - Maps cell indices to values for variables captured by closures
- `freevars: dict[int, Optional[SymbolicValue]]` - Maps freevar indices to values from outer scope

### Opcode Semantics

**MAKE_CELL(i)**: Creates a cell for variable at index i in co_cellvars or co_freevars. Called at function entry for variables that will be captured by nested functions. Initializes cell as empty (None).

**STORE_DEREF(i)**: Stores top-of-stack value into cell or freevar at index i. Handles both cellvars (this function's captured variables) and freevars (captured from outer scope).

**LOAD_DEREF(i)**: Loads cell or freevar at index i onto stack. Raises UnboundLocalError if cell is uninitialized, NameError if freevar is not set.

**COPY_FREE_VARS(n)**: Copies n free variables from closure into frame at function entry. For symbolic execution, creates fresh symbolic values for each freevar.

## Testing

Created `tests/test_closures.py` with 13 tests covering:
- Simple closures (single and multiple variables)
- Nested closures (multiple levels)
- Closure variable modification patterns
- Edge cases (unused closures, partial capture)
- Bug detection in closures (2 xfailed - see Known Limitations)

Results: 11 passed, 2 xfailed

## Known Limitations

The two xfailed tests expose a fundamental architectural limitation: **user-defined function calls do not execute bytecode**. The current CALL opcode implementation treats all functions as external contracts rather than creating new frames and executing their bytecode.

This means:
- Closure opcodes work correctly when executed
- But nested function calls (like `inner()` in closures) don't actually execute the inner function's bytecode
- Bug detection within called functions doesn't work yet

This limitation affects all user-defined function calls, not just closures. Fixing it requires:
1. Distinguishing user-defined functions from stdlib/external functions
2. For user-defined functions: create new SymbolicFrame and execute bytecode
3. For external functions: continue using contracts

This is a significant architectural change deferred to future iterations.

## Semantic Correctness

The implementation follows Python 3.11+ semantics:
- Cell indices combine co_cellvars and co_freevars
- Cells are distinct from locals (separate storage)
- Proper exception handling (UnboundLocalError, NameError)
- Initialization semantics match CPython

## Impact

These opcodes enable the symbolic VM to:
- Parse and analyze code with closures without crashing
- Track closure variable flow (when functions are inlined)
- Maintain semantic correctness for nested scopes

Total opcodes implemented: 56
Phase: PUBLIC_REPO_EVAL (continuing)
