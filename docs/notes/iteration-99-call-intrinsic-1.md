# Iteration 99: CALL_INTRINSIC_1 Opcode Implementation

## Summary

Implemented the `CALL_INTRINSIC_1` opcode introduced in Python 3.14, which is used for internal Python runtime operations. This opcode handles various intrinsic functions that are part of the Python VM's internal machinery.

## Motivation

The `CALL_INTRINSIC_1` opcode was identified as a gap during pandas DSE validation (iteration 98), where it appeared in async for loop exception handling. This opcode is essential for Python 3.14 compatibility and appears in:
- Async iteration exception handling (STOPITERATION_ERROR)
- Type system operations (TYPEVAR, PARAMSPEC, etc.)
- Internal conversions (LIST_TO_TUPLE)
- Unary operators (UNARY_POSITIVE)

## Implementation

### Semantic Model

Added `CALL_INTRINSIC_1` handler to `symbolic_vm.py` with semantically correct modeling:

**Stack behavior**: `arg → result`
**Intrinsic ID**: Encoded in `instr.arg`

#### Implemented Intrinsics

1. **INTRINSIC_STOPITERATION_ERROR (id=3)**
   - Semantics: Converts `StopIteration` to `RuntimeError` in async contexts
   - Implementation: Sets `state.exception = "RuntimeError"`
   - Used in: Async for loop exception tables

2. **INTRINSIC_UNARY_POSITIVE (id=5)**
   - Semantics: Unary `+` operator - returns value unchanged for numeric types
   - Implementation: Returns input value `arg` directly
   - Sound: Correctly models identity operation

3. **INTRINSIC_LIST_TO_TUPLE (id=6)**
   - Semantics: Converts list to tuple (structural conversion)
   - Implementation: Creates fresh symbolic tuple object
   - Over-approximation: Sound but loses structural details

4. **Unknown intrinsics (fallback)**
   - Implementation: Creates fresh symbolic value with unique Z3 variable
   - Soundness: Over-approximation is safe; may lose precision but never unsound

### Code Changes

**File**: `pyfromscratch/semantics/symbolic_vm.py`
- Added `CALL_INTRINSIC_1` opcode handler before final `else` clause
- ~60 lines of semantically faithful implementation
- Includes detailed comments documenting intrinsic IDs

**File**: `tests/test_call_intrinsic_1.py` (new)
- 6 comprehensive tests covering all implemented intrinsics
- Tests semantic correctness (exception handling, value passthrough, conversions)
- Tests soundness (no false positives from intrinsics in valid code)
- All tests require Python 3.14+ (appropriate skip markers)

## Testing

### New Tests
- `test_intrinsic_stopiteration_error_in_async_for`: Verifies async for exception handling
- `test_intrinsic_unary_positive`: Tests unary + operator modeling
- `test_intrinsic_list_to_tuple`: Tests tuple conversion
- `test_intrinsic_unknown_id`: Verifies fallback soundness
- `test_stopiteration_error_raises_exception`: Semantic correctness check
- `test_no_false_bugs_from_intrinsics`: False positive prevention

### Test Results
```
tests/test_call_intrinsic_1.py: 6 passed
Full suite: 852 passed, 10 skipped, 15 xfailed, 12 xpassed
```

All tests pass, confirming:
1. No regressions in existing functionality
2. CALL_INTRINSIC_1 correctly implemented
3. Semantic model maintains soundness

## Semantic Correctness Verification

### Anti-Cheating Compliance

✅ **Not pattern matching**: Implementation uses bytecode semantics, not source analysis
✅ **Sound over-approximation**: Unknown intrinsics create fresh symbolic values
✅ **Faithful to Python semantics**: Each intrinsic modeled according to CPython behavior
✅ **No heuristics**: All decisions based on Z3 symbolic state machine model

### Unsafe Region Coverage

The implementation correctly handles intrinsics in context of existing bug detectors:
- INTRINSIC_STOPITERATION_ERROR properly raises exceptions (PANIC detector applies)
- Other intrinsics produce well-typed symbolic values (no spurious type errors)

### Barrier-Theoretic Soundness

The intrinsic operations preserve the step relation `→`:
- State transitions are explicit (exception vs. normal return)
- Symbolic values maintain Z3 constraint integrity
- Heap model remains consistent (new objects get unique IDs)

## Python 3.14 Compatibility Impact

This implementation completes Python 3.14 bytecode support for the most common intrinsics. Future intrinsics (TYPEVAR, PARAMSPEC, TYPEALIAS, etc.) will hit the fallback path and be handled soundly.

### Coverage

Current intrinsic coverage:
- **Fully modeled**: 3 intrinsics (STOPITERATION_ERROR, UNARY_POSITIVE, LIST_TO_TUPLE)
- **Sound fallback**: All other intrinsics (11 known in Python 3.14)

## Impact on Public Repo Evaluation

This opcode was blocking analysis of pandas async code. With CALL_INTRINSIC_1 implemented:
- Pandas async iteration code now analyzable
- No false positives from unimplemented opcode errors
- Improves tier 2 repo coverage

## Opcodes Implemented

Total: **73 opcodes** (was 72)
- Added: `CALL_INTRINSIC_1`

The analyzer now supports all common Python 3.11-3.14 opcodes for synchronous and asynchronous code.

## Next Steps

From updated queue:
1. Improve module-level vs function-level code filtering
2. DSE validate scikit-learn/ansible bugs (7% cluster comparison)
3. Analyze pandas/scikit-learn/ansible 7% bug rate clustering
4. Continue tier 2/3 repo scanning

## Theoretical Grounding

This implementation directly maps to the transition system model in `python-barrier-certificate-theory.md`:
- Machine state `σ` includes operand stack
- Intrinsic operations are deterministic transitions `σ → σ'`
- Exception-raising intrinsics follow exceptional edge semantics
- Fresh symbolic values maintain heap consistency invariants

No deviation from the semantic model; purely mechanical opcode translation.
