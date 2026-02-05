# Iteration 106: CONTAINS_OP Implementation

**Date**: 2026-01-23  
**Phase**: PUBLIC_REPO_EVAL → CONTINUOUS_REFINEMENT  
**Action**: Implement CONTAINS_OP opcode (priority #2 from NumPy bug analysis)

## Motivation

From iteration 104 NumPy bug analysis, CONTAINS_OP was identified as one of 5 missing opcodes causing false positives. This opcode implements the `in` and `not in` operators for containment testing.

## Implementation

### Semantics (pyfromscratch/z3model/values.py)

Added `contains_op()` function:
- **Signature**: `(item, container, heap, solver) → (result, type_ok, none_misuse)`
- **Semantics**:
  - Container must be list, tuple, str, or dict
  - Returns nondeterministic boolean (conservative overapproximation)
  - Detects NULL_PTR: container is None
  - Detects TYPE_CONFUSION: container not iterable
- **Justification**: Conservative overapproximation since symbolic heap doesn't track all elements. Full implementation would require checking `item` against all `container.elements`.

### Symbolic VM (pyfromscratch/semantics/symbolic_vm.py)

Added CONTAINS_OP handler after COMPARE_OP:
- **Stack**: `[..., item, container] → [..., result]`
- **Arg**: 0 = `in`, 1 = `not in`
- **Bug detection**:
  - NULL_PTR when `none_misuse` is SAT
  - TYPE_CONFUSION when `¬type_ok` is SAT
- **Inversion**: For `not in`, invert boolean payload after containment check

### Concrete VM (pyfromscratch/semantics/concrete_vm.py)

Added CONTAINS_OP handler:
- Uses Python's native `in` operator
- Catches exceptions (TypeError for None/non-iterable)
- Handles inversion for `not in`

## Tests (tests/test_contains_op.py)

**17 passed, 4 skipped**

### Concrete tests (8/11 passed, 3 skipped):
- ✅ `in` with list (found/not found)
- ✅ `not in` with list (true/false)
- ✅ Tuple and string containment
- ✅ Empty list
- ✅ TypeError for non-iterable (42)
- ⏭️ Dict tests (BUILD_MAP not implemented in concrete VM)
- ⏭️ None container (STORE_NAME not implemented in concrete VM)

### Symbolic tests (7/8 passed, 1 skipped):
- ✅ List, tuple, string containment
- ✅ NULL_PTR detection (None container)
- ✅ TYPE_CONFUSION detection (non-iterable)
- ⏭️ Dict test (BUILD_MAP symbolic execution incomplete)

### Differential tests (3 passed):
- ✅ List found/not found agreement
- ✅ None error detection (symbolic only)

## Barrier-Certificate Compliance

**Unsafe predicates**: CONTAINS_OP detects:
1. `NULL_PTR`: `container.is_none()` checked via Z3 SAT query
2. `TYPE_CONFUSION`: `¬type_ok` (container not iterable) checked via Z3 SAT query

**No heuristics**: Result is nondeterministic symbolic boolean, not pattern-matched from source text.

**Conservative overapproximation**: Since we don't track all symbolic container elements, we return `Bool(fresh_var)` which may be True or False. This is sound: we never claim SAFE without proof.

## Impact on NumPy Bug Rate

**Before**: 16 bugs (21% rate), 5 from unimplemented opcodes  
**After CONTAINS_OP**: Expected reduction: 1/16 bugs eliminated → 15 bugs remaining

**Remaining opcodes** (4/5):
- DICT_UPDATE
- BUILD_STRING  
- LOAD_FAST_BORROW
- ~~EXTENDED_ARG~~ (iteration 105)
- ~~CONTAINS_OP~~ (this iteration)

## Updated State

- `progress.bytecode_semantics.implemented_opcodes`: +1 (CONTAINS_OP)
- `queue.next_actions`: CONTAINS_OP removed, DICT_UPDATE now priority #1

## Notes

- CONTAINS_OP is optimization introduced in Python 3.9+ (PEP 584)
- Before 3.9: `x in y` compiled to `COMPARE_OP("in")`
- After 3.9: separate opcode for better performance
- Our implementation handles both 'in' and 'not in' via arg flag
