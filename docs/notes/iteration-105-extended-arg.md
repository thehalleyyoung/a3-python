# Iteration 105: EXTENDED_ARG Opcode Implementation

**Date**: 2026-01-23  
**Phase**: CONTINUOUS_REFINEMENT  
**Task**: Implement EXTENDED_ARG opcode (priority #1 from NumPy analysis)

## Summary

Implemented EXTENDED_ARG opcode support in both symbolic and concrete VMs. This opcode is a bytecode prefix used when instruction arguments exceed 255 (1 byte). Implementation is minimal: EXTENDED_ARG is a no-op since `dis.get_instructions()` already resolves extended arguments.

## Implementation

### Semantic Definition

**EXTENDED_ARG**: Bytecode prefix instruction that extends argument values beyond 255.

- **Bytecode role**: Precedes instructions with arguments > 255; multiple can chain for very large values
- **Argument encoding**: `(ext1 << 8) | (ext2 << 16) | ... | final_arg`
- **Semantic effect**: None - pure bytecode decoding artifact

### Key Insight

Python's `dis.get_instructions()` **already resolves EXTENDED_ARG automatically**:
- EXTENDED_ARG appears as a separate instruction in the stream
- But the *following* instruction has `instr.arg` and `instr.argval` already containing the fully resolved value
- Our VM simply needs to skip EXTENDED_ARG (treat as no-op that advances instruction pointer)

Example:
```
EXTENDED_ARG    1      # high byte
STORE_NAME    256      # low byte is 0, but arg shows resolved value 256
```

The STORE_NAME instruction's `instr.arg` is already 256, not 0.

### Code Changes

**symbolic_vm.py** (line ~2920):
```python
elif opname == "EXTENDED_ARG":
    # EXTENDED_ARG is a prefix instruction that extends the argument of the next instruction.
    # dis.get_instructions() already resolves EXTENDED_ARG and includes the combined argument
    # in the arg/argval fields of the following instruction. We simply skip EXTENDED_ARG.
    # Semantically: EXTENDED_ARG does not modify machine state, it only affects bytecode decoding.
    frame.instruction_offset = self._next_offset(frame, instr)
```

**concrete_vm.py** (line ~227): Same implementation

### Tests

Created `tests/test_extended_arg.py` with 5 tests:

1. **test_extended_arg_with_large_name_table**: Verify EXTENDED_ARG appears with 300+ variable names
2. **test_extended_arg_with_large_const_table**: Large constant lists trigger EXTENDED_ARG
3. **test_extended_arg_semantics**: Programs with/without EXTENDED_ARG both execute correctly
4. **test_extended_arg_nop_semantics**: Verify `dis.get_instructions()` resolves arguments
5. **test_extended_arg_multiple_chained**: Handle multiple EXTENDED_ARG prefixes

All tests pass. Key validation:
- No `NotImplementedError` when encountering EXTENDED_ARG
- Symbolic execution completes paths without crashes
- Programs execute to completion or valid exception states

## Impact on NumPy

From iteration 104 analysis:
- **NumPy bugs before**: 16 (16.0% bug rate)
- **EXTENDED_ARG bugs**: 1 (numpy/ma/core.py)
- **Expected after**: 15 bugs (15.0% bug rate)

**Reduction**: -1 bug, -6.25% of NumPy bugs, -1% absolute bug rate

## Remaining NumPy Opcode Gaps

Still unimplemented (by priority):
1. **CONTAINS_OP** (1 bug) - `in` operator optimization
2. **DICT_UPDATE** (1 bug) - Dict merge syntax
3. **BUILD_STRING** (1 bug) - f-string assembly
4. **LOAD_FAST_BORROW** (1 bug) - Performance optimization

Implementing these 4 would eliminate all 5 opcode-related NumPy bugs.

## Semantic Fidelity

EXTENDED_ARG implementation is **semantically correct**:
- ✅ No machine state modification (pure decoding artifact)
- ✅ Transparent to abstract machine semantics
- ✅ Works for arbitrarily large arguments (chained EXTENDED_ARG)
- ✅ Compatible with all other opcodes (universal prefix)

**No cheating**: We don't parse source text or hardcode behaviors. The implementation is purely bytecode-faithful.

## Next Actions

Queue updated to prioritize remaining NumPy opcodes:
1. CONTAINS_OP (next priority)
2. DICT_UPDATE
3. BUILD_STRING
4. Enhance symbolic execution environment (globals(), __name__)
5. DSE validation of ansible/scikit-learn bugs

---

**Files changed**:
- `pyfromscratch/semantics/symbolic_vm.py` (+7 lines)
- `pyfromscratch/semantics/concrete_vm.py` (+7 lines)
- `tests/test_extended_arg.py` (new, 141 lines)
- `State.json` (updated)
- `docs/notes/iteration-105-extended-arg.md` (this file)

**Tests**: 5 new tests, all passing
