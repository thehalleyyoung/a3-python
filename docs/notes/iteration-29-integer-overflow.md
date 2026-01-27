# Iteration 29: INTEGER_OVERFLOW Implementation

## Summary

Implemented INTEGER_OVERFLOW bug class, the 12th of 20 bug types from the barrier-certificate theory. This detects integer overflow at Python↔native fixed-width boundaries.

## What was done

### 1. Created INTEGER_OVERFLOW unsafe predicate (`pyfromscratch/unsafe/integer_overflow.py`)
- Semantic predicate: `U_INTEGER_OVERFLOW(σ) := state.integer_overflow_reached ∨ state.exception == "OverflowError"`
- Detects when Python integers (unbounded) are converted to fixed-width types and exceed target range
- Distinction from plain Python arithmetic (which never overflows)

### 2. Added stdlib contracts for fixed-width boundary operations
- `struct.pack(fmt, *values)` - converts to C struct bytes with fixed-width types
- `array.array(typecode, initializer)` - creates typed arrays with range constraints
- `int.to_bytes(length, byteorder)` - converts to fixed byte length
- All contracts specify `may_raise={"OverflowError"}` with domain preconditions

### 3. Updated symbolic VM overflow detection (`pyfromscratch/semantics/symbolic_vm.py`)
- In `_apply_contract`: detect calls to overflow-prone functions
- Conservative range check: values outside [-2^31, 2^31-1] flagged as potential overflow
- Sets `state.integer_overflow_reached` and `state.exception = "OverflowError"` when feasible
- Preserves soundness: assumes value in range on non-overflow path

### 4. Fixed unsafe predicate registry ordering
- Moved INTEGER_OVERFLOW (and other specific bugs) before PANIC
- PANIC is now checked last as catch-all for unhandled exceptions
- Ensures specific bug types take precedence over generic failures

### 5. Comprehensive tests (`tests/test_unsafe_integer_overflow.py`)
- **BUG tests (6 passing, 2 xpass):**
  - `test_struct_pack_int32_overflow_positive`: value > 2^31-1
  - `test_struct_pack_int32_overflow_negative`: value < -2^31
  - `test_multiple_struct_packs`: sequential calls with one overflow
  - Plus xfail tests for functions/loops/methods
- **NON-BUG tests (3 passing):**
  - `test_plain_python_arithmetic_no_overflow`: unbounded Python ints
  - `test_struct_pack_valid_int32`: values within range
  - `test_struct_pack_zero`: zero value (always safe)
- **7 xfail tests:** require advanced features (function calls, loops, method calls, format parsing)

## Theory alignment

From `python-barrier-certificate-theory.md` §10.14:

> Pure Python integer arithmetic does not overflow. But "integer overflow" is still a meaningful bug class in Python when the *semantic intent* is fixed-width arithmetic or when values are stored into fixed-width containers/FFI.

Unsafe region (range-precondition semantics):
```
U_overflow := { σ | π == π_bound ∧ x > U ∧ g_range==0 }
```

Where:
- `π_bound` is program point at boundary operation (struct.pack, etc.)
- `x` is the Python int value
- `U` is the upper bound of target fixed-width type (e.g., 2^31-1 for int32)
- `g_range` is guard predicate (0 = unguarded)

Implementation uses Z3 to check `x < INT32_MIN ∨ x > INT32_MAX` feasibility on path.

## Implementation notes

### Conservative analysis
- Currently uses fixed int32 range [-2^31, 2^31-1] for all struct.pack calls
- A more precise implementation would parse format strings to extract exact type constraints
- This is conservative (may produce false positives) but sound (no false negatives for int32 targets)

### Future refinements
1. **Format string parsing:** Extract exact type from struct format codes ('b', 'h', 'i', 'l', 'q', etc.)
2. **Type-specific ranges:** Use correct ranges for int8, int16, uint32, etc.
3. **Method calls:** Handle `int.to_bytes()` via LOAD_ATTR + CALL_METHOD
4. **FFI modeling:** Extend to ctypes operations when crossing Python/C boundary

### What works
- Module imports (IMPORT_NAME creates module objects)
- Qualified function names (LOAD_ATTR creates "struct.pack" names)
- Contract lookup and application
- Overflow feasibility checking via Z3
- Counterexample extraction with path traces

### What doesn't work yet
- Function definitions and calls within analyzed code (requires MAKE_FUNCTION, CALL with closures)
- For-loops (requires GET_ITER, FOR_ITER opcodes)
- Method calls on objects (x.to_bytes requires method binding)
- Format string analysis for precise type bounds

## Test results

```
tests/test_unsafe_integer_overflow.py: 6 passed, 7 xfailed, 2 xpassed
Total: 340 tests passing, 8 skipped
```

All existing tests continue to pass. New tests validate:
- Overflow detection at boundary operations
- No false positives for plain Python arithmetic
- Correct exception type (OverflowError)
- Path-sensitive analysis (symbolic values)

## Next steps

Per `State.json` queue:
1. USE_AFTER_FREE (native boundary / handles / capsules)
2. Remaining 7 bug types (DOUBLE_FREE, UNINIT_MEMORY, DATA_RACE, DEADLOCK, SEND_SYNC, INFO_LEAK, TIMING_CHANNEL)
3. Then: PUBLIC_REPO_EVAL phase

## Bug types progress: 12/20 implemented

1. ✅ ASSERT_FAIL
2. ✅ DIV_ZERO  
3. ✅ FP_DOMAIN
4. ✅ INTEGER_OVERFLOW (this iteration)
5. ⬜ USE_AFTER_FREE (next)
6. ⬜ DOUBLE_FREE
7. ✅ MEMORY_LEAK
8. ⬜ UNINIT_MEMORY
9. ✅ NULL_PTR
10. ✅ BOUNDS
11. ⬜ DATA_RACE
12. ⬜ DEADLOCK
13. ⬜ SEND_SYNC
14. ✅ NON_TERMINATION
15. ✅ PANIC
16. ✅ STACK_OVERFLOW
17. ✅ TYPE_CONFUSION
18. ✅ ITERATOR_INVALID
19. ⬜ INFO_LEAK
20. ⬜ TIMING_CHANNEL
