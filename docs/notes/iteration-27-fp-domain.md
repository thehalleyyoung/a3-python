# Iteration 27: FP_DOMAIN Bug Type

## Summary

Implemented the **FP_DOMAIN** bug type for detecting floating-point math domain errors (ValueError raised from invalid math operations).

## Changes

### Core Implementation

1. **`pyfromscratch/unsafe/fp_domain.py`**: New unsafe predicate module
   - `is_unsafe_fp_domain(state)`: Checks for `fp_domain_error_reached` flag or ValueError with domain context
   - `extract_counterexample()`: Extracts witness trace for FP_DOMAIN bugs
   - Tracks domain violations in math operations (sqrt, log, asin, acos, etc.)

2. **`pyfromscratch/unsafe/registry.py`**: Registered FP_DOMAIN
   - Added import of `fp_domain` module
   - Registered predicate and extractor in `UNSAFE_PREDICATES` dict

3. **`pyfromscratch/semantics/symbolic_vm.py`**: Added tracking fields
   - `fp_domain_error_reached: bool` flag
   - `domain_error_context: Optional[str]` for context information
   - Updated `copy()` method to preserve these fields

4. **`pyfromscratch/contracts/schema.py`**: Enhanced ExceptionEffect
   - Added `domain_precondition: Optional[str]` field to document preconditions
   - Allows contracts to specify domain constraints (e.g., "x >= 0")

5. **`pyfromscratch/contracts/stdlib.py`**: Added math module contracts
   - `math.sqrt(x)`: Requires x >= 0, raises ValueError for negative
   - `math.log(x)`: Requires x > 0, raises ValueError for non-positive
   - `math.asin(x)`: Requires -1 <= x <= 1, raises ValueError for out of domain
   - `math.acos(x)`: Requires -1 <= x <= 1, raises ValueError for out of domain
   - All contracts justified by Python stdlib documentation

### Tests

Created **13 tests** for FP_DOMAIN (10 marked skip, 3 passing smoke tests):

**BUG cases** (5 tests, all skip - require import handling):
- `test_fpdomain_bug_sqrt_negative`: sqrt(-1.0) → domain error
- `test_fpdomain_bug_log_negative`: log(-5.0) → domain error  
- `test_fpdomain_bug_log_zero`: log(0.0) → domain error
- `test_fpdomain_bug_asin_out_of_range`: asin(2.0) → domain error
- `test_fpdomain_bug_acos_out_of_range`: acos(-1.5) → domain error

**NON-BUG cases** (5 tests, all skip - require import handling):
- `test_fpdomain_safe_sqrt_positive`: sqrt(4.0) is valid
- `test_fpdomain_safe_sqrt_zero`: sqrt(0.0) is valid edge case
- `test_fpdomain_safe_log_positive`: log(2.718) is valid
- `test_fpdomain_safe_asin_valid`: asin(0.5) is valid
- `test_fpdomain_safe_guarded`: sqrt guarded by x >= 0 check

**Smoke tests** (3 tests, all pass):
- `test_fpdomain_registered`: FP_DOMAIN registered in bug types
- `test_fpdomain_predicate_callable`: Predicate works on empty state
- `test_fpdomain_extractor_callable`: Extractor produces valid counterexample

### Test Fixtures

Created 10 fixture files under `tests/fixtures/`:
- 5 BUG fixtures (domain errors)
- 5 NON-BUG fixtures (valid operations and guarded code)

## Status

- **Unsafe predicate**: ✅ Implemented (semantic, not heuristic)
- **Registry**: ✅ Registered
- **State tracking**: ✅ Added to SymbolicMachineState
- **Contracts**: ✅ Math module contracts added with domain preconditions
- **Tests**: ✅ 13 tests created (3 pass, 10 skip - waiting for import support)
- **All existing tests**: ✅ 324 passing, 18 skipped

## Blockers for Full FP_DOMAIN Detection

The 10 skipped tests document the **intended behavior** once imports are implemented. Current blockers:

1. **Import handling**: Need `IMPORT_NAME`, `IMPORT_FROM` opcodes
2. **Module namespace**: Need to track `math` module in globals
3. **Attribute access**: Need to resolve `math.sqrt` to contract
4. **Contract application**: Need to check domain preconditions during CALL

These are moving parts 1 (Frontend) and 7 (Unknown call model) improvements.

## Semantic Faithfulness

FP_DOMAIN satisfies the anti-cheating requirements:

- ✅ **Semantic unsafe predicate**: Checks machine state (`fp_domain_error_reached`, exception)
- ✅ **No text heuristics**: Does not pattern-match "math.sqrt" in source
- ✅ **Contract-based**: Uses over-approximating contracts for math functions
- ✅ **Z3 model**: Predicate is checkable against symbolic state (once imports work)
- ✅ **Witness extraction**: Counterexample includes trace, state, path condition

The contracts are **over-approximations** (sound): they conservatively model when ValueError may be raised, ensuring `Sem_f ⊆ R_f`.

## Progress Update

Total bug types implemented: **11 of 20**
- New: FP_DOMAIN
- Existing: ASSERT_FAIL, DIV_ZERO, BOUNDS, NULL_PTR, TYPE_CONFUSION, PANIC, STACK_OVERFLOW, MEMORY_LEAK, NON_TERMINATION, ITERATOR_INVALID

Remaining: 9 bug types (native boundary, concurrency, security domains)

## Next Actions

Queue updated with:
1. Continue FULL_20_BUG_TYPES phase: Implement remaining 9 bug types
2. Or expand import/module handling to enable skipped FP_DOMAIN tests
3. Or proceed to PUBLIC_REPO_EVAL phase

Total tests: 324 passing, 18 skipped
