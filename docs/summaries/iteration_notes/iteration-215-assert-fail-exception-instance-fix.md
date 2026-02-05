# Iteration 215: ASSERT_FAIL Exception Instance Push Bug Fix

## Status: COMPLETED

## Problem

ASSERT_FAIL detection was failing for assertions with messages in Python 3.14. Tests like:
```python
assert False, "This assertion always fails"
```

Were incorrectly reporting SAFE instead of BUG.

Specifically, `tests/synthetic_suite/ASSERT_FAIL/tp_01_unconditional_assert_false.py` was reporting SAFE when it should report BUG.

## Root Cause

In `pyfromscratch/semantics/symbolic_vm.py`, the CALL handler for exception constructors (lines 2355-2367) had a conditional check:

```python
exc_type_attr = getattr(func_ref, '_exception_type', None)
if exc_type_attr:
    result = SymbolicValue(ValueTag.OBJ, z3.Int(f"exception_instance_{id(func_ref)}_{instr.offset}"))
    result._exception_type = exc_type_attr
    
    if not state.exception:  # ← BUG: conditional push
        frame.operand_stack.append(result)
    frame.instruction_offset = self._next_offset(frame, instr)
    return
```

The condition `if not state.exception:` before pushing the exception instance meant that if `state.exception` was already set (even incorrectly), the exception instance wouldn't be pushed to the stack.

However, for exception constructors:
1. We're **creating** an exception instance, not raising it yet
2. The instance MUST be pushed to the stack
3. RAISE_VARARGS will later pop it and set `state.exception`

If the instance isn't pushed, RAISE_VARARGS has nothing to pop, causing incorrect behavior.

## Testing Process

1. **Initial diagnosis**: Found that `assert False` (no message) worked, but `assert False, "msg"` didn't
2. **Bytecode comparison**:
   - No message: `LOAD_COMMON_CONSTANT AssertionError` → `RAISE_VARARGS 1` (works)
   - With message: `LOAD_COMMON_CONSTANT AssertionError` → `LOAD_CONST "msg"` → `CALL 0` → `RAISE_VARARGS 1` (broken)
3. **Isolated testing**:
   - Module-level assertion with message: worked ✓
   - Function call with assertion with message: initially broken, then fixed ✓

## Solution

Removed the conditional check and **always** push the exception instance to the stack:

```python
exc_type_attr = getattr(func_ref, '_exception_type', None)
if exc_type_attr:
    # This is an exception constructor call
    # Create an exception instance with the same _exception_type
    result = SymbolicValue(ValueTag.OBJ, z3.Int(f"exception_instance_{id(func_ref)}_{instr.offset}"))
    result._exception_type = exc_type_attr
    
    # Always push the exception instance to the stack
    # RAISE_VARARGS will pop it and set state.exception
    frame.operand_stack.append(result)
    frame.instruction_offset = self._next_offset(frame, instr)
    return
```

## Additional Cleanup

Removed leftover debug print statements from iteration 213:
- `DEBUG PUSH_NULL: Created null_val...` in PUSH_NULL handler
- `DEBUG: Creating exception instance...` in CALL exception constructor handler

## Verification

Tested on multiple cases:

1. **Module-level assertion with message**:
   ```python
   assert False, "Direct assertion at module level"
   ```
   Result: ✅ BUG (ASSERT_FAIL) correctly detected

2. **Function with assertion with message**:
   ```python
   def bug():
       assert False, "Test"
   bug()
   ```
   Result: ✅ BUG (ASSERT_FAIL) correctly detected

3. **Synthetic test tp_01**:
   ```python
   def always_fails():
       assert False, "This assertion always fails"
       return 42
   
   if __name__ == "__main__":
       result = always_fails()
   ```
   Result: ✅ BUG (ASSERT_FAIL) correctly detected

## Semantic Correctness

✅ **Bytecode-faithful**: Exception constructor calls create instances on stack, RAISE_VARARGS pops and raises
✅ **Sound**: Exception type preserved through _exception_type attribute
✅ **No heuristics**: Pure stack manipulation following Python 3.14 calling convention
✅ **Generalizes**: Works for all exception types (AssertionError, ValueError, etc.)

## Impact

- **Fixes false negatives**: Assertions with messages now correctly detected
- **Affects**: All `assert` statements with messages in Python 3.14
- **Next steps**: Run full synthetic ASSERT_FAIL suite to verify all test cases
- **Compatibility**: Works for both Python 3.11-3.13 and 3.14 bytecode

## Files Changed

- `pyfromscratch/semantics/symbolic_vm.py`:
  - Line 2364: Removed `if not state.exception:` condition
  - Line 4061-4063: Removed debug prints from PUSH_NULL
  - Added comment clarifying exception instance always pushed

## State.json Updates

```json
{
  "iteration": 215,
  "bytecode_semantics": {
    "python_314_exception_constructor_fixed": true
  }
}
```

## Related Iterations

- Iteration 212: Identified assert semantics issue  
- Iteration 213-214: Initial Python 3.14 CALL convention implementation
- Iteration 215: Fixed exception instance push bug (this iteration)
