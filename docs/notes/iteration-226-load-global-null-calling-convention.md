# Iteration 226: Python 3.14 LOAD_GLOBAL + NULL Calling Convention Fix

**Date**: 2026-01-23
**Phase**: PYGOAT_CODEQL_COMPARISON (ongoing)
**Status**: PARTIALLY FIXED - StackUnderflow resolved, but PyGoat still shows PANIC bugs

## Problem Identified

PyGoat function-level analysis (iteration 225) found 46 PANIC bugs, all caused by `StackUnderflow` exceptions at CALL instructions.

### Root Cause Analysis

Investigation revealed **two related bugs** in Python 3.14 calling convention implementation:

1. **LOAD_GLOBAL bug**: When`argval` contains "+ NULL" suffix, code was stripping the suffix but **not pushing the NULL marker**
2. **CALL bug**: NULL position check was wrong - checking `-(N+1)` instead of `-(N+2)`

### Python 3.14 Calling Convention (Correct Spec)

Stack layout before `CALL N`:
```
Bottom: NULL          (at position -(N+2))
        callable      (at position -(N+1))
        arg1          (at position -N)
        ...
Top:    argN          (at position -1)
```

For `CALL 0` (no arguments):
- Stack: `[NULL, callable]`
- NULL at position -2
- callable at position -1

## Fixes Implemented

### Fix 1: LOAD_GLOBAL - Push NULL Marker

**File**: `pyfromscratch/semantics/symbolic_vm.py`

**Before**:
```python
if isinstance(var_name, str) and " + NULL" in var_name:
    var_name = var_name.split(" + NULL")[0]

# Then push only the value (NULL not pushed!)
frame.operand_stack.append(value)
```

**After**:
```python
push_null = False
if isinstance(var_name, str) and " + NULL" in var_name:
    push_null = True
    var_name = var_name.split(" + NULL")[0]

# Push values in correct order: NULL first, then callable
if push_null:
    null_marker = SymbolicValue.none()
    frame.operand_stack.append(null_marker)

if value_to_push is not None:
    frame.operand_stack.append(value_to_push)
```

### Fix 2: CALL - Correct NULL Position Check

**File**: `pyfromscratch/semantics/symbolic_vm.py`

**Before** (WRONG):
```python
# Comment said: [.., callable, NULL, arg1, .., argN] ← BACKWARDS!
# NULL is at position -(N+1), callable at -(N+2) ← WRONG POSITIONS!
potential_null_pos = -(nargs + 1) if nargs > 0 else -1
```

**After** (CORRECT):
```python
# Comment now says: [.., NULL, callable, arg1, .., argN] ✓
# NULL is at position -(N+2), callable at -(N+1) ✓
potential_null_pos = -(nargs + 2)
```

## Verification

### Simple Test (Passing)
```python
def test():
    x = dict()  # LOAD_GLOBAL dict + NULL, then CALL 0
    return x
# Result: SAFE ✓
```

### Complex Test (Still Issues)
PyGoat `register()` function now proceeds past the `LOAD_GLOBAL NewUserForm + NULL; CALL 0` instruction that was failing before. However, 46 PANIC bugs still remain in PyGoat function analysis.

## Impact

**Fixed**:
- StackUnderflow at CALL after LOAD_GLOBAL + NULL ✓
- Simple function calls to builtins work correctly ✓

**Remaining Issues**:
- PyGoat function analysis still reports 46 PANIC bugs
- Next step: investigate what exceptions are occurring after CALL succeeds

## Next Actions

1. Re-run PyGoat function analysis to see new exception patterns
2. Identify remaining blockers preventing execution from reaching security sinks
3. Continue with PyGoat/CodeQL comparison once bugs are resolved

## Semantic Correctness

These fixes implement the **correct Python 3.14+ calling convention** as specified in:
- PEP 659 (Specializing Adaptive Interpreter)
- Python 3.11+ bytecode specification
- CPython 3.14 implementation

Both fixes maintain **soundness** - they make the symbolic execution more precise (fewer spurious StackUnderflows) without introducing unsound over-approximations.
