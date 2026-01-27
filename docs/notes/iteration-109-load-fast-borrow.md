# Iteration 109: LOAD_FAST_BORROW Opcode Implementation

**Date**: 2026-01-23  
**Phase**: PUBLIC_REPO_EVAL  
**Task**: Implement LOAD_FAST_BORROW opcode (NumPy priority #5, final missing opcode)

## Executive Summary

Implemented LOAD_FAST_BORROW, a Python 3.14+ performance optimization opcode. Semantically identical to LOAD_FAST but uses borrowed reference (avoiding refcount increments). This completes the 5 missing opcodes identified in NumPy analysis. 6/6 tests pass.

## Implementation Details

### Opcode Semantics

**LOAD_FAST_BORROW** (Python 3.14+):
- Loads local variable with borrowed reference semantics
- Avoids unnecessary reference count increments for performance
- **Symbolically identical** to LOAD_FAST: loads `frame.locals[varname]` onto stack
- Raises `UnboundLocalError` if variable not in locals (detected as NULL_PTR)

### Code Changes

**File**: `pyfromscratch/semantics/symbolic_vm.py`

Added LOAD_FAST_BORROW handler after LOAD_FAST (lines 795-803):
```python
elif opname == "LOAD_FAST_BORROW":
    # Python 3.14+ performance optimization
    # Loads local variable with borrowed reference (no refcount increment)
    # Semantically identical to LOAD_FAST for symbolic execution
    var_name = instr.argval
    if var_name in frame.locals:
        frame.operand_stack.append(frame.locals[var_name])
    else:
        state.exception = "UnboundLocalError"
        return
    frame.instruction_offset = self._next_offset(frame, instr)
```

### Key Design Decisions

1. **Semantic Equivalence**: LOAD_FAST_BORROW ≡ LOAD_FAST for symbolic execution
   - Reference counting is a CPython implementation detail
   - Symbolic values have no refcounts
   - Borrowed vs owned references don't affect reachability/safety

2. **UnboundLocalError Detection**: Same as LOAD_FAST
   - Detects uninitialized local variables
   - Reported as NULL_PTR or PANIC depending on context

3. **No Special Handling**: No need for borrowed reference tracking
   - Symbolic heap doesn't model ownership
   - Value semantics sufficient for bug detection

## Test Coverage

**File**: `tests/test_load_fast_borrow.py`

6 tests covering:
1. ✅ Basic local variable load
2. ✅ Multiple local variables
3. ✅ Loop context (repeated loads)
4. ✅ Nested functions (closure + local)
5. ✅ Exception handling context
6. ✅ Arithmetic operations

All tests pass (6/6).

## NumPy Opcode Gap Closure

### Status Before This Iteration

From iteration 104 analysis, 5 missing opcodes caused 31% of NumPy bugs:

| Opcode | Status | File |
|--------|--------|------|
| EXTENDED_ARG | ✅ Iteration 105 | numpy/ma/core.py |
| CONTAINS_OP | ✅ Iteration 106 | benchmarks/asv_pip_nopep517.py |
| DICT_UPDATE | ✅ Iteration 107 | numpy/_expired_attrs_2_0.py |
| BUILD_STRING | ✅ Iteration 108 | doc/neps/conf.py |
| **LOAD_FAST_BORROW** | ✅ **Iteration 109** | **benchmarks/benchmarks/bench_ufunc_strides.py** |

### Status After This Iteration

**All 5 NumPy missing opcodes now implemented** (iterations 105-109).

Expected impact:
- 5 NumPy "Unimplemented_Opcode" false positives eliminated
- NumPy bug rate: 16/100 → 11/100 = **11%** (down from 16%)
- 31% reduction in NumPy false positives

## Validation

### Test Execution
```bash
$ python3 -m pytest tests/test_load_fast_borrow.py -v
6 passed in 0.26s
```

### Opcode Verification
```python
>>> import opcode
>>> opcode.opmap['LOAD_FAST_BORROW']
86
>>> opcode.stack_effect(86, 0)
1  # Pushes 1 value onto stack
```

## Performance Characteristics

- **Stack effect**: +1 (identical to LOAD_FAST)
- **Symbolic complexity**: O(1) dictionary lookup
- **Path explosion**: None (deterministic load)
- **Z3 constraints**: None (structural operation)

## Next Steps

1. **Immediate**: Rescan NumPy with all 5 opcodes implemented
   - Measure actual bug rate reduction
   - Validate 11% predicted bug rate
   - Compare to pandas (6%) and scikit-learn (7%)

2. **Analysis**: DSE validate remaining NumPy bugs
   - Focus on NameError (8 bugs, 50%)
   - Focus on TypeError (2 bugs, 12.5%)
   - Separate true semantic bugs from environment gaps

3. **Environment Enhancement**: Mock globals() and __name__
   - Would eliminate ~50% of NameError bugs
   - Improves module initialization symbolic execution

## Semantic Correctness

### Why LOAD_FAST_BORROW ≡ LOAD_FAST

**Reference counting** is an implementation detail of CPython's memory management:
- Borrowed reference = no refcount increment (caller owns object)
- Owned reference = refcount increment (callee owns object)

**Symbolic execution** abstracts away memory management:
- No heap allocation/deallocation
- No reference counting
- Values exist in symbolic domain

Therefore:
- Loading a borrowed vs owned reference has **identical semantics**
- Both access `frame.locals[varname]`
- Both raise `UnboundLocalError` if missing
- Both push same symbolic value onto stack

### Bug Detection Equivalence

Both LOAD_FAST and LOAD_FAST_BORROW detect:
- **NULL_PTR**: Uninitialized local variable (UnboundLocalError)
- **TYPE_CONFUSION**: If loaded value used incorrectly
- **BOUNDS**: If loaded value used as index
- **DIV_ZERO**: If loaded value is divisor

No difference in reachability analysis.

## Implementation Completeness

### Python 3.14 Opcode Coverage

With LOAD_FAST_BORROW, we now support **96 opcodes** including all NumPy-critical operations:

**Core**: LOAD_CONST, LOAD_FAST, **LOAD_FAST_BORROW**, STORE_FAST, etc.  
**Extended**: EXTENDED_ARG, CONTAINS_OP, DICT_UPDATE, BUILD_STRING  
**Control**: POP_JUMP_IF_*, JUMP_BACKWARD, FOR_ITER  
**Calls**: CALL, CALL_KW, CALL_INTRINSIC_1  
**Exceptions**: PUSH_EXC_INFO, RERAISE, CHECK_EXC_MATCH  

### Remaining Gaps

Minor opcodes not yet seen in tier 2 repos:
- LOAD_CLOSURE (rare in module-level code)
- SETUP_WITH (less common)
- Specialized/adaptive opcodes (Python 3.11+ JIT)

These are **lower priority** (no impact on current evaluation).

## Conclusion

LOAD_FAST_BORROW implementation is **trivial but essential**:
- Semantically identical to LOAD_FAST
- Eliminates 1 NumPy false positive
- Completes 5-opcode gap closure (iterations 105-109)
- No semantic complexity or edge cases

**All 5 NumPy missing opcodes now implemented**. Ready for rescan.

---

## Appendix: LOAD_FAST vs LOAD_FAST_BORROW

### CPython Difference
```c
// LOAD_FAST (owned reference)
PyObject *value = GETLOCAL(oparg);
Py_INCREF(value);  // Increment refcount
PUSH(value);

// LOAD_FAST_BORROW (borrowed reference)
PyObject *value = GETLOCAL(oparg);
// No Py_INCREF - borrow caller's reference
PUSH(value);
```

### Symbolic Execution Equivalence
```python
# Both opcodes:
var_name = instr.argval
if var_name in frame.locals:
    frame.operand_stack.append(frame.locals[var_name])
else:
    state.exception = "UnboundLocalError"
```

**No difference** in symbolic semantics.
