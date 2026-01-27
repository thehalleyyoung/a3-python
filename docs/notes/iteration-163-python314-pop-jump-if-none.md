# Iteration 163: Python 3.14 POP_JUMP_IF_NONE / POP_JUMP_IF_NOT_NONE Opcodes

## Summary

Implemented Python 3.14 opcodes `POP_JUMP_IF_NONE` and `POP_JUMP_IF_NOT_NONE` for None-checking patterns.

## Motivation

httpx `_decoders.py` was hitting an unimplemented opcode error for `POP_JUMP_IF_NOT_NONE`. This is a Python 3.14-specific opcode used for common None-checking patterns like:
- `if x is not None: ...`
- `if x is None: ...`

These opcodes replace the older pattern of `COMPARE_OP (is) + POP_JUMP_IF_TRUE/FALSE`.

## Implementation

### POP_JUMP_IF_NOT_NONE

```python
elif opname == "POP_JUMP_IF_NOT_NONE":
    # Python 3.14 opcode: pop TOS, jump if it is not None
    value = frame.operand_stack.pop()
    is_none = (value.tag == z3.IntVal(ValueTag.NONE.value))
    target_offset = instr.argval
    
    # Check feasibility of both paths
    # - not-none path → jump taken
    # - none path → fall through
    
    # Take feasible path, prioritizing fall-through (none path)
```

### POP_JUMP_IF_NONE

```python
elif opname == "POP_JUMP_IF_NONE":
    # Python 3.14 opcode: pop TOS, jump if it is None
    value = frame.operand_stack.pop()
    is_none = (value.tag == z3.IntVal(ValueTag.NONE.value))
    target_offset = instr.argval
    
    # Check feasibility of both paths
    # - none path → jump taken
    # - not-none path → fall through
    
    # Take feasible path, prioritizing fall-through (not-none path)
```

### Semantic Model

Both opcodes follow the same pattern as other conditional jumps:
1. Pop TOS value
2. Construct symbolic None-check: `value.tag == NONE.value`
3. Use Z3 to check feasibility of both branches
4. Add appropriate path constraint and update instruction pointer
5. Report `InfeasiblePath` exception if neither branch is feasible

Soundness: Over-approximates by exploring both paths when both are feasible (via path explosion in caller).

## Testing

Created comprehensive test suite (`test_pop_jump_if_none.py`) with 7 tests:
- `test_pop_jump_if_not_none_simple`: None check with non-None value
- `test_pop_jump_if_not_none_bug`: Bug when passing None without check
- `test_pop_jump_if_none_simple`: None check with non-None value
- `test_pop_jump_if_none_with_none`: None check handling None correctly
- `test_walrus_with_none_check`: Walrus operator `:=` with None check
- `test_none_guard_pattern`: Common None-guard pattern
- `test_none_guard_bug`: Missing None check (over-approximation)

All tests pass. Full test suite: **1081 passed, 14 skipped, 18 xfailed, 12 xpassed**.

## Impact: httpx _decoders.py

Before:
- Status: ERROR (unimplemented opcode `POP_JUMP_IF_NOT_NONE`)

After:
- Bugs: 0
- Safe proofs: 1
- Unknown: 0
- Errors: 0

**SUCCESS**: File now analyzes without error.

## Updated State

- Added `POP_JUMP_IF_NOT_NONE` to implemented opcodes
- Added `POP_JUMP_IF_NONE` to implemented opcodes
- Removed both from unimplemented opcode blacklist in inlining check
- Tests: +7 new tests (all passing)

## Next Steps

Remaining Python 3.14 opcodes from queue:
1. `LOAD_CONST_LOAD_FAST` (combined operation)
2. `JUMP_FORWARD` (alternative to JUMP_BACKWARD)
3. `JUMP_BACKWARD_NO_INTERRUPT` (async-related)
4. `LOAD_FROM_DICT_OR_DEREF` (closure optimization)
5. `LOAD_FROM_DICT_OR_GLOBALS` (namespace optimization)

## Correctness

- **Semantics**: Matches CPython 3.14 behavior for None-checking
- **Path exploration**: Correctly branches on feasible paths
- **Z3 encoding**: Uses existing `ValueTag.NONE` check infrastructure
- **Soundness**: Maintains over-approximation guarantee (explores all feasible paths)
