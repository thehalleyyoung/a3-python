# Iteration 64: LOAD_FAST_AND_CLEAR Opcode Implementation

## Summary

Implemented the `LOAD_FAST_AND_CLEAR` opcode, which is used in list/set/dict comprehensions for exception-safe variable handling. This opcode loads a local variable onto the stack and then clears it from the locals dictionary, ensuring proper cleanup in exception handlers.

## Semantics

The `LOAD_FAST_AND_CLEAR` opcode has the following semantics:

- **If the variable exists in locals**: Push its current value to the stack, then delete it from locals
- **If the variable doesn't exist**: Push `None` to the stack (no exception raised)

This differs from `LOAD_FAST`, which raises `UnboundLocalError` if the variable doesn't exist.

## Use in Comprehensions

Python 3.11+ uses `LOAD_FAST_AND_CLEAR` in comprehensions to save outer-scope variables:

```python
def f():
    x = 100
    result = [x * 2 for x in [1, 2, 3]]
    return x  # x is restored to 100
```

Bytecode pattern:
1. `LOAD_FAST_AND_CLEAR x` - save x and clear it
2. `SWAP 2` - rearrange stack
3. Comprehension loop body
4. `STORE_FAST x` - restore x (in both normal and exception paths)

## Implementation Details

Added handler in `symbolic_vm.py` after `LOAD_FAST`:

```python
elif opname == "LOAD_FAST_AND_CLEAR":
    var_name = instr.argval
    if var_name in frame.locals:
        frame.operand_stack.append(frame.locals[var_name])
        del frame.locals[var_name]
    else:
        frame.operand_stack.append(SymbolicValue.none())
    frame.instruction_offset = self._next_offset(frame, instr)
```

## Testing

Created comprehensive tests in `test_load_fast_and_clear.py`:

1. **Manual unit tests**: Direct opcode execution with existing/nonexistent variables
2. **Bytecode verification**: Confirm opcode appears in comprehension bytecode
3. **Exception safety**: Verify variable restoration in exception handlers
4. **Nested comprehensions**: Test multiple levels of variable saving
5. **Generator expressions**: Verify different handling (generators use separate code objects)

All 9 tests pass. Full test suite: 663 passed, 10 skipped, 15 xfailed, 12 xpassed.

## Impact on Semantic Model

This opcode improves the fidelity of our Python bytecode semantics:

- Comprehensions now have proper variable save/restore semantics
- Exception handling in comprehensions is more accurate
- Better alignment with CPython 3.11+ bytecode behavior

## No False Positives/Negatives Expected

The implementation is semantically sound:

- Over-approximates by pushing `None` for nonexistent variables (safe)
- Correctly models the variable clearing behavior
- No impact on existing unsafe predicates (just stack/locals manipulation)
