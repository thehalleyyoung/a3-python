# Iteration 151: Frozenset Constants and Python 3.14 Combined Fast Locals

**Date**: 2026-01-23

## Summary

Implemented LOAD_CONST support for frozenset constants and SET_UPDATE opcode to eliminate the FastAPI false positive. Fixed Python 3.14 combined fast locals layout handling for LOAD_FAST_BORROW, LOAD_DEREF, STORE_DEREF, and MAKE_CELL opcodes, fixing closure support.

## Changes Made

### 1. Frozenset Constant Loading

**File**: `pyfromscratch/semantics/symbolic_vm.py`

Added frozenset support to LOAD_CONST:
- Frozensets are loaded as immutable tuple-like collections
- Elements are sorted for determinism in symbolic execution
- Supports int, float, bool, str, None element types
- Unsupported element types use OBJ as sound over-approximation

**Rationale**: Python compiles set literals like `{"GET", "POST", "PUT"}` into bytecode:
```
BUILD_SET
LOAD_CONST frozenset({'GET', 'POST', 'PUT'})
SET_UPDATE
```

The frozenset appears as a constant in LOAD_CONST.

### 2. SET_UPDATE Opcode

**File**: `pyfromscratch/semantics/symbolic_vm.py`

Implemented SET_UPDATE(i):
- Pops iterable from stack
- Updates set at stack[-i] with elements from iterable
- Extracts elements from tuple constants (frozensets loaded as tuples)
- Uses havoc (sound over-approximation) for symbolic iterables

**Stack Effect**: `[..., set, iterable] → [..., set]`

### 3. Python 3.14 Combined Fast Locals Layout

**Issue**: Python 3.11+ uses a combined fast locals layout:
```
combined_fast_locals = co_varnames + co_cellvars + co_freevars
```

Opcodes LOAD_FAST, LOAD_FAST_BORROW, LOAD_DEREF, STORE_DEREF, and MAKE_CELL use indices into this combined layout.

**Example**:
```python
def outer():       # co_varnames=('inner',), co_cellvars=('x',)
    x = 1         # STORE_DEREF 1  -> combined[1]=x (cell index 0)
    def inner():
        return x
    return inner
```

**Fixes Applied**:

1. **LOAD_FAST / LOAD_FAST_BORROW**: Check if variable is in co_cellvars first, load from cells if so
2. **LOAD_DEREF**: Map combined index to cell/freevar index: `cell_idx = var_idx - len(co_varnames)`
3. **STORE_DEREF**: Same mapping as LOAD_DEREF
4. **MAKE_CELL**: Same mapping as LOAD_DEREF

### 4. FastAPI False Positive Eliminated

**Before**: FastAPI `openapi/constants.py` raised NotImplementedError for frozenset constant
- Bug type: PANIC
- Reason: LOAD_CONST for frozenset not implemented

**After**: Analyzes correctly as SAFE
- Result: `SAFE: Verified with barrier certificate`
- Paths explored: 12
- Validation rate: 100% (34/34 bugs validated)

## Test Results

**All Tests Pass**: 1066 passed, 14 skipped, 18 xfailed, 12 xpassed

**Closure Tests**: Fixed test_simple_closure_creation
- Previously: UnboundLocalError due to incorrect cell indexing
- Now: Passes with proper cell variable handling

## Impact

### FastAPI Validation (Tier 3)
- **Previous**: 97.1% validation rate (33/34), 1 FP due to frozenset gap
- **Current**: 100% validation rate (34/34), 0 FPs
- **True bug rate**: 34% (middle tier 3)

### Tier 3 Overall
- 5 repos evaluated
- 4/5 with DSE validation
- Overall validation rate improved from 97.7% to near-perfect

### Semantic Model Improvements
1. Frozenset constants handled correctly
2. SET_UPDATE operation implemented
3. Python 3.14 combined fast locals layout fully supported
4. Closure variable access fixed for Python 3.14

## Opcodes Added

- **SET_UPDATE**: Set update operation (adds iterable elements to set)

## Technical Details

### Combined Fast Locals Layout

Python 3.11+ introduced a unified fast locals indexing scheme:

```python
# Layout: [co_varnames...] [co_cellvars...] [co_freevars...]
# Index:   0...n_vars-1     n_vars...n_vars+n_cells-1   ...

# Example:
co_varnames = ('a', 'b')      # indices 0, 1
co_cellvars = ('x', 'y')      # indices 2, 3 (combined), 0, 1 (cell storage)
co_freevars = ('z',)          # index 4 (combined), 0 (freevar storage)

# LOAD_DEREF 2 -> combined[2]=x -> cells[0]
# LOAD_DEREF 3 -> combined[3]=y -> cells[1]
# LOAD_DEREF 4 -> combined[4]=z -> freevars[0]
```

### Frozenset Semantics

Frozensets are immutable sets. In symbolic execution:
- Represented as immutable tuple-like collections
- No ordering guarantees (sorted for determinism only)
- Over-approximate for unsupported element types
- Maintains soundness: `Sem_frozenset ⊆ R_frozenset`

## Next Steps

Queue after this iteration:
1. Update tier 3 validation summary (4/5 repos, 100% validation rate)
2. Analyze tier 3 bug type profiles (PANIC vs diverse)
3. Tier 3 comparative analysis (validation rates across repos)
4. Scan additional tier 3 repos (httpx, uvicorn)
5. Phase 4 - defaultdict semantics
6. Phase 4 - variadic function inlining

## Files Changed

- `pyfromscratch/semantics/symbolic_vm.py`: Frozenset, SET_UPDATE, combined fast locals fixes
- `State.json`: Updated iteration, validation metrics
- `tests/fixtures/frozenset_test.py`: Test fixture (created)
