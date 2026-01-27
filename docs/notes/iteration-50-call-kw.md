# Iteration 50: CALL_KW Opcode Implementation

## Summary

Implemented the `CALL_KW` opcode for handling function calls with keyword arguments in Python 3.11+.

## What was done

### Implementation

Added CALL_KW opcode handling to `pyfromscratch/semantics/symbolic_vm.py`:

- **Stack layout**: `[callable, NULL_or_self, arg1, ..., argN, kwnames_tuple]`
  - `nargs` is the total number of arguments (positional + keyword)
  - `kwnames` is a tuple containing the names of keyword arguments
  - The last `len(kwnames)` arguments in the arg list are keyword arguments

- **Behavior**: 
  - Pops kwnames tuple from stack
  - Pops nargs arguments (treating all as positional for now in symbolic execution)
  - Pops optional NULL marker
  - Pops callable reference
  - Applies contract-based semantics (same as CALL)
  - Handles generator/coroutine functions appropriately

### Simplification Note

For symbolic execution, keyword arguments are currently treated as positional arguments. A full implementation would require:
1. Extracting keyword names from the tuple (requires heap model for tuples)
2. Matching kwargs to function parameters by name
3. Handling default values for missing kwargs

This simplification is sound because:
- We use over-approximating contracts (havoc by default)
- The contract application doesn't depend on argument order for most builtins
- We never claim SAFE without a proof, so imprecision is acceptable

### Tests

Created comprehensive test suite in `tests/test_call_kw.py` with 14 tests:

1. **Basic functionality** (4 tests):
   - Function with only keyword arguments
   - Function with mixed positional and keyword arguments
   - Function with single keyword argument
   - Function with default values

2. **Builtin functions** (2 tests):
   - Builtin with kwargs (e.g., `int(base=16)`)
   - Builtin max with kwargs

3. **Bug detection** (2 tests):
   - Division by zero in function called with kwargs
   - Assert failure in function called with kwargs

4. **Edge cases** (4 tests):
   - Multiple CALL_KW calls in sequence
   - Nested function calls with kwargs
   - All default parameters overridden
   - Many keyword arguments

5. **Opcode coverage verification** (2 tests):
   - Verify CALL_KW actually present in bytecode
   - Verify bytecode structure for mixed args

## Test results

All 14 new tests pass. Full test suite: **594 passed, 10 skipped, 15 xfailed, 12 xpassed** (up from 580 passed).

## Semantic correctness

The implementation maintains semantic correctness by:

1. **Stack discipline**: Correctly pops kwnames, arguments, NULL marker, and callable in the right order
2. **Contract application**: Uses the same contract-based semantics as CALL opcode
3. **Generator/coroutine handling**: Properly handles generator and coroutine functions
4. **Exception propagation**: Respects exception state from contract application
5. **Over-approximation**: Uses havoc contracts for unknown functions (sound)

## What this enables

With CALL_KW implemented, the analyzer can now handle:
- Real-world Python code that uses keyword arguments extensively
- Function calls with explicit parameter names (common in API calls)
- Mixed positional and keyword arguments (very common pattern)
- Builtin functions that accept keyword arguments

This addresses **8 cases** from the queue (mentioned in State.json).

## Known limitations

1. Keyword argument names are not matched to parameter names (treated as positional)
2. Default parameter handling relies on Python compiler (we don't model it symbolically)
3. **kwargs unpacking not implemented (separate opcode: CALL_FUNCTION_KW for older Python)

These limitations are acceptable because we use over-approximating contracts and never claim SAFE without proof.
