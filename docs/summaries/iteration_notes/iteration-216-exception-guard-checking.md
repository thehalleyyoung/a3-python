# Iteration 216: Exception Handler Guard Checking

## Problem
True negative tests tn_04 and tn_05 were failing - programs with caught exceptions were being reported as BUG even though the exceptions were handled.

The unsafe predicates (`is_unsafe_assert_fail`, `is_unsafe_panic`) were checking if `state.exception` was set, but not checking whether the exception was caught by a handler.

## Root Cause
```python
# Before (assert_fail.py line 25-28):
if state.exception == "AssertionError":
    # For now, we mark any AssertionError as unsafe
    # Later, we'll check exception handler tables
    return True
```

The comment even acknowledged this was incomplete - "Later, we'll check exception handler tables".

## Solution
The guard system already existed (`state.set_guard("catch", exception_type)` on line 653 of symbolic_vm.py when jumping to exception handler). I updated the unsafe predicates to check for g_catch guards:

### assert_fail.py
```python
def is_unsafe_assert_fail(state) -> bool:
    if state.exception == "AssertionError":
        # Check if exception is caught by a handler
        if hasattr(state, 'has_catch_guard') and state.has_catch_guard("AssertionError"):
            return False  # Exception is caught, not unsafe
        return True  # Exception is uncaught, unsafe
    return False
```

### panic.py
```python
def is_unsafe_panic(state) -> bool:
    exc = getattr(state, "exception", None)
    if exc is None or exc == "InfeasiblePath":
        return False
    
    # Check if exception is caught by a handler
    if hasattr(state, 'has_catch_guard') and state.has_catch_guard(exc):
        return False  # Exception is caught, not unsafe
    
    return True  # Exception is uncaught, unsafe
```

## Validation

### Minimal Tests
```python
# Uncaught assertion
assert False, "bug"
# Result: BUG (ASSERT_FAIL) ✓

# Caught assertion
try:
    assert False, "caught"
except AssertionError:
    pass
# Result: SAFE ✓
```

### ASSERT_FAIL Synthetic Suite
**Before iteration 216:**
- True Positives: 4/5 detected (1 had exception instance push bug fixed in iter 215)
- True Negatives: 0/5 correct

**After iteration 216:**
- True Positives: 5/5 detected (100%) ✓
- True Negatives: 2/5 correct (40%)

The 3 remaining TN failures are due to separate implementation bugs:
- tn_03, tn_04: StackUnderflow at print() call with f-string
- tn_05: TypeError in list handling

These are **secondary bugs**, not related to exception guard checking. The core fix is working:
- Uncaught exceptions → BUG (correct)
- Caught exceptions → SAFE (correct, when execution completes)

## Semantic Correctness

This fix implements the proper unsafe region predicate from barrier-certificate-theory.tex:

**Unsafe region for ASSERT_FAIL:**
```
U_ASSERT_FAIL = { σ | σ.exception == AssertionError ∧ ¬g_catch(AssertionError, σ) }
```

Where `g_catch(exc_type, σ)` is the guard established when jumping to an exception handler that matches `exc_type`.

**Barrier certificate implication:**
A program is safe from unhandled AssertionError if:
```
B(σ) := { δ_handler(σ) ∨ (1 - δ_exc_AssertionError(σ)) }
```

Where:
- `δ_handler(σ) = 1` iff currently in exception handler (g_catch established)
- `δ_exc_AssertionError(σ) = 1` iff AssertionError is raised

The unsafe region is unreachable iff the barrier holds at all reachable states.

## Files Changed
- `pyfromscratch/unsafe/assert_fail.py`: Updated `is_unsafe_assert_fail` to check g_catch guard
- `pyfromscratch/unsafe/panic.py`: Updated `is_unsafe_panic` to check g_catch guard
- `docs/notes/iteration-216-exception-guard-checking.md`: This file

## Next Actions
1. Fix StackUnderflow bug in print() handling (affects tn_03, tn_04)
2. Fix TypeError in list handling (affects tn_05)
3. Verify all ASSERT_FAIL tests pass after secondary bug fixes
4. Consider extending guard system to other exception-based bug types (DIV_ZERO, BOUNDS, NULL_PTR)
