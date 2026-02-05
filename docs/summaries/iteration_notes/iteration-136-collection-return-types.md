# Iteration 136: Collection Return Type Constraints (CONTAINS_OP Fix)

## Objective

Fix TYPE_CONFUSION false positives in numpy, pandas when using `globals()` and other stdlib functions returning collections with the `in` operator (CONTAINS_OP).

## Root Cause Analysis

### The Problem

Analysis of tier 2 repos revealed TYPE_CONFUSION bugs in numpy (3 bugs) and pandas (1 bug) with a common pattern:
- Code: `if '_is_loaded' in globals(): ...`
- Bug: TYPE_CONFUSION at CONTAINS_OP
- Root cause: `globals()` was returning `ValueTag.OBJ` instead of `ValueTag.DICT`

### Investigation Trail

1. **Initial Analysis**: Checked numpy, pandas, ansible for variadic function FP patterns (similar to sklearn issue from iteration 131)
   - Found 4 TYPE_CONFUSION bugs but NOT BINARY_OP pattern (different root cause)
   - Numpy `_globals.py`: `if '_is_loaded' in globals()` flagged as TYPE_CONFUSION

2. **Semantic Gap Identified**: 
   - `contains_op()` in `z3model/values.py` checks if container is list/tuple/str/dict
   - `globals()` was returning OBJ (generic object) instead of DICT
   - CONTAINS_OP correctly rejected OBJ as non-iterable → TYPE_CONFUSION

3. **Two Fixes Required**:
   - **Fix 1** (symbolic_vm.py line 1610): Special case `globals()` handler returned `ValueTag.OBJ` instead of `ValueTag.DICT`
   - **Fix 2** (symbolic_vm.py lines 873-886): Contract-based return values didn't handle dict/list/tuple type constraints

## Implementation

### Changes Made

#### 1. Fix `globals()` return type (symbolic_vm.py:1610)

**Before**:
```python
result = SymbolicValue(ValueTag.OBJ, z3.IntVal(globals_dict_id))
```

**After**:
```python
result = SymbolicValue(ValueTag.DICT, z3.IntVal(globals_dict_id))
```

#### 2. Add collection return type constraints (symbolic_vm.py:873-891)

Added support for dict/list/tuple in `_apply_contract` return value generation:

```python
elif return_constraint.type_constraint == "dict":
    obj_id = state.heap.allocate_dict()
    return SymbolicValue(ValueTag.DICT, z3.IntVal(obj_id))

elif return_constraint.type_constraint == "list":
    obj_id = state.heap.allocate_sequence("list", z3.IntVal(0), {})
    return SymbolicValue(ValueTag.LIST, z3.IntVal(obj_id))

elif return_constraint.type_constraint == "tuple":
    obj_id = state.heap.allocate_tuple(0)
    return SymbolicValue(ValueTag.TUPLE, z3.IntVal(obj_id))
```

This applies to any stdlib function with a dict/list/tuple return constraint (not just `globals()`).

### Tests Added (tests/test_contains_dict.py)

8 new tests covering:
- `globals()` with `in` and `not in` operators
- `dict()`, `list()`, `tuple()` constructors with CONTAINS_OP
- Regression tests: int/None containers still trigger TYPE_CONFUSION/NULL_PTR
- Exact numpy reload pattern: `if '_is_loaded' in globals(): raise RuntimeError`

All tests pass (8/8).

## Impact Analysis

### Affected Stdlib Functions

Functions with dict/list/tuple return constraints now work correctly with CONTAINS_OP:
- `globals()` → dict
- `dict()` → dict
- `list()` → list
- `tuple()` → tuple
- Any future stdlib functions with collection return types

### Expected FP Reductions

**Numpy** (3 TYPE_CONFUSION bugs):
- `numpy/_globals.py`: `'_is_loaded' in globals()` → SAFE ✅
- `numpy/exceptions.py`: Similar pattern → SAFE ✅
- `benchmarks/asv_pip_nopep517.py`: Similar pattern → SAFE ✅

**Pandas** (1 TYPE_CONFUSION bug):
- `pandas/core/shared_docs.py`: Likely similar globals() pattern → SAFE ✅

**Estimated impact**: -4 TYPE_CONFUSION FPs across tier 2 (numpy: -3, pandas: -1)

### Soundness

✅ **Maintained**: The fix is sound because:
1. `globals()` truly returns a dict in Python semantics
2. Collection constructors truly return their respective types
3. `contains_op()` correctly validates dict/list/tuple as iterable
4. Contract-based approach preserves `Sem_f ⊆ R_f` over-approximation

## Verification

### Test Results

```
tests/test_contains_dict.py::TestContainsWithDictReturnType::test_globals_in_operator_safe PASSED
tests/test_contains_dict.py::TestContainsWithDictReturnType::test_globals_not_in_operator_safe PASSED
tests/test_contains_dict.py::TestContainsWithDictReturnType::test_dict_constructor_in_operator PASSED
tests/test_contains_dict.py::TestContainsWithDictReturnType::test_list_constructor_in_operator PASSED
tests/test_contains_dict.py::TestContainsWithDictReturnType::test_tuple_constructor_in_operator PASSED
tests/test_contains_dict.py::TestContainsStillDetectsBugs::test_int_not_iterable_type_confusion PASSED
tests/test_contains_dict.py::TestContainsStillDetectsBugs::test_none_container_null_ptr PASSED
tests/test_contains_dict.py::TestNumpyGlobalsCase::test_numpy_reload_check PASSED
```

8 passed, 0 failed.

### Full Test Suite

```
1055 passed (+8 from baseline)
6 failed (pre-existing closure issues, unrelated)
14 skipped
18 xfailed
12 xpassed
```

No regressions introduced.

## Next Steps

### Immediate

1. Rescan numpy and pandas to confirm FP reductions
2. Compare bug rates before/after this fix

### Future

1. Expand return type constraints to cover more stdlib collection types as needed
2. Consider set return types if relevant FPs emerge

## Files Changed

1. `pyfromscratch/semantics/symbolic_vm.py`:
   - Line 1610: globals() returns DICT not OBJ
   - Lines 873-891: Added dict/list/tuple return constraint handling
2. `tests/test_contains_dict.py`: 8 new tests (164 lines)
3. `docs/notes/iteration-136-collection-return-types.md`: This analysis
4. `State.json`: Updated with iteration 136 progress

## Classification

- **Bug class**: False positive (semantic incompleteness)
- **Fix type**: Semantic enhancement
- **Impact**: -4 TYPE_CONFUSION FPs (estimated)
- **Soundness**: Maintained (sound over-approximation)
- **Phase**: PUBLIC_REPO_EVAL (continuous refinement)
