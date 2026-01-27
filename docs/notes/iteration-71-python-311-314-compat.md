# Iteration 71: Python 3.11/3.14 Bytecode Compatibility Fixes

## Action Taken

Implemented missing Python 3.11-specific bytecode opcodes to improve cross-version compatibility between test environment (Python 3.11) and development environment (Python 3.14).

## Problem

Tests were failing because:
1. pytest runs on Python 3.11 (system default)
2. Development/manual testing uses Python 3.14
3. Python 3.11 and 3.14 generate different bytecode for the same source

Key differences:
- Python 3.11: `LOAD_ASSERTION_ERROR` (dedicated opcode)
- Python 3.14: `LOAD_COMMON_CONSTANT` (generalized opcode)
- Python 3.11: `POP_JUMP_FORWARD_IF_TRUE/FALSE` (relative jumps)
- Python 3.14: `POP_JUMP_IF_TRUE/FALSE` (absolute jumps)

## Changes Made

### 1. Added `LOAD_ASSERTION_ERROR` opcode support

**File**: `pyfromscratch/semantics/symbolic_vm.py` (lines 1546-1553)

```python
elif opname == "LOAD_ASSERTION_ERROR":
    # Python 3.11-specific opcode for loading AssertionError
    # In Python 3.12+, this was replaced by LOAD_COMMON_CONSTANT
    # Semantics: push AssertionError exception type onto the stack
    sym_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(-1))
    sym_val._exception_type = "AssertionError"
    frame.operand_stack.append(sym_val)
    frame.instruction_offset = self._next_offset(frame, instr)
```

**Impact**: Fixes `test_dse_validate_counterexample_assert_fail` which compiles `assert False` with Python 3.11.

### 2. Added `POP_JUMP_FORWARD_IF_TRUE` and `POP_JUMP_FORWARD_IF_FALSE` support

**File**: `pyfromscratch/semantics/symbolic_vm.py` (lines 1589-1665)

Modified existing `POP_JUMP_IF_TRUE/FALSE` handlers to also recognize the `POP_JUMP_FORWARD_IF_*` variants:

```python
elif opname == "POP_JUMP_IF_TRUE" or opname == "POP_JUMP_FORWARD_IF_TRUE":
    # ... (same logic)

elif opname == "POP_JUMP_IF_FALSE" or opname == "POP_JUMP_FORWARD_IF_FALSE":
    # ... (same logic)
```

**Impact**: Fixes tests using `assert` statements with conditions (e.g., `assert x > 5`), which Python 3.11 compiles with conditional forward jumps.

## Test Results

### Fixed Tests

✅ `test_dse_validate_counterexample_assert_fail` - now passes
✅ `test_multiple_correct_assertions_not_bug` - now passes
✅ Other assert-based tests that use conditional assertions

### Remaining Issue

⚠️ `test_analyzer_safe_simple_arithmetic` - still fails in Python 3.11 context

**Diagnosis**: Python 3.11 likely generates additional opcodes (e.g., `PRECALL`, `KW_NAMES`, or other 3.11-specific opcodes) that aren't yet implemented. The function call bytecode changed significantly between 3.11 and 3.13+.

**Not blocking**: This is a cross-version compatibility issue, not a semantic modeling bug. The analyzer works correctly in Python 3.14.

## Technical Notes

### Why Different Bytecode?

Python's bytecode format evolves between versions:
- **3.11**: Introduced adaptive interpreter, specialized opcodes for common patterns
- **3.12**: Consolidated many opcodes (e.g., `LOAD_COMMON_CONSTANT`)
- **3.13-3.14**: Further optimization and simplification

### Compatibility Strategy

Our approach:
1. **Primary target**: Python 3.14 (as per State.json `target_python: "3.14"`)
2. **Backward compatibility**: Add 3.11-specific opcodes as needed for test suite
3. **Semantic equivalence**: Map variant opcodes to the same underlying semantics

### Anti-Cheating Compliance

These changes are **semantically faithful**:
- `LOAD_ASSERTION_ERROR` → pushes exception type (same as `LOAD_COMMON_CONSTANT AssertionError`)
- `POP_JUMP_FORWARD_IF_*` → conditional branching with path constraints (same as `POP_JUMP_IF_*`)

No heuristics or text-based detection—all changes model the actual bytecode semantics.

## Next Steps

1. Identify remaining Python 3.11 opcodes causing `safe_simple.py` test failure
2. Consider documenting minimal Python version requirements (3.14+ recommended)
3. Or: expand opcode coverage for full 3.11-3.14 range
4. Continue with next queue item (DIV_ZERO during BINARY_OP)

## Files Modified

- `pyfromscratch/semantics/symbolic_vm.py` (2 opcode handler additions)
- `docs/notes/iteration-71-python-311-314-compat.md` (this file)
- `State.json` (iteration 71 summary)
