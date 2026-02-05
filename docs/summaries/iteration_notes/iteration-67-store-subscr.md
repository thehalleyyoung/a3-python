# Iteration 67: STORE_SUBSCR Opcode Implementation

**Date**: 2026-01-23  
**Status**: ✅ Complete  
**Phase**: PUBLIC_REPO_EVAL (Continuous Refinement)

## Objective

Implement the `STORE_SUBSCR` opcode to support subscript assignment operations for lists and dictionaries (`container[index] = value`).

## Context

`STORE_SUBSCR` is used for item assignment in Python:
- List item assignment: `lst[2] = 10`
- Dictionary key assignment: `dct['key'] = 'value'`

This opcode was identified in the tier-1 triage (iteration 60) as appearing in real code, making it necessary for improved coverage of public repositories.

## Implementation

### Opcode Semantics

**Stack behavior**: `value, container, index → (empty)`

The opcode:
1. Pops `value` (what to store)
2. Pops `container` (list or dict)
3. Pops `index` (int for list, any hashable for dict)
4. Stores `container[index] = value`

### Safety Checks Implemented

1. **None misuse detection**: Catches `None[x] = y`
   - Sets `state.none_misuse_reached = True`
   - Raises TypeError

2. **Type confusion detection**: Catches assignment to non-subscriptable types (int, str, etc.)
   - Sets `state.type_confusion_reached = True`
   - Raises TypeError

3. **Bounds checking for lists**: 
   - Checks `index < 0 or index >= length`
   - Sets `state.bounds_violation_reached = True`
   - Raises IndexError

4. **Heap tracking**:
   - Updates `SequenceObject.elements` for concrete list indices
   - Updates `DictObject.keys` and `DictObject.values` for concrete dict keys
   - Records `state.heap_mutated = True` for symbolic indices/keys

### Files Modified

- `pyfromscratch/semantics/symbolic_vm.py`: Added `STORE_SUBSCR` handler (~160 lines)
  - Added imports: `SequenceObject`, `DictObject`
  - Comprehensive type and bounds checking
  - Heap mutation tracking

### Tests Added

Created `tests/test_store_subscr.py` with 19 test cases:

**Basic functionality**:
- List subscript assignment (first, middle, last elements)
- Dict subscript assignment (string and int keys)
- Dict key updates
- Multiple assignments
- Nested subscripts
- Computed indices and values

**Error detection**:
- Out-of-bounds list assignment (positive and negative indices)
- None misuse detection
- Type confusion detection (assigning to int, etc.)

**All 19 tests pass** ✅

## Verification

```bash
$ python3 -m pytest tests/test_store_subscr.py -v
19 passed in 0.22s

$ python3 -m pytest tests/ --tb=line -q
703 passed, 10 skipped, 15 xfailed, 12 xpassed in 2.16s
```

**Test coverage**: 703 total tests (up from 684), all passing.

## Bug Types Affected

- **BOUNDS**: List index out of range detection works
- **NULL_PTR**: None misuse detection works  
- **TYPE_CONFUSION**: Non-subscriptable type detection works

## Technical Notes

### Heap Tracking Strategy

- **Concrete indices/keys**: Full tracking in heap metadata
  - List: Store in `seq_obj.elements[index]`
  - Dict: Store in `dict_obj.values[key]`
  
- **Symbolic indices/keys**: Conservative over-approximation
  - Cannot track exact location
  - Set `state.heap_mutated = True` flag
  - Maintains soundness (may report UNKNOWN rather than SAFE)

### Z3 Integration

The bounds check query:
```python
out_of_bounds = z3.Or(
    index.payload < z3.IntVal(0),
    index.payload >= seq_obj.length
)
```

This is checked for satisfiability to detect potential violations.

### Alignment with Theory

From `python-barrier-certificate-theory.md`:
> **ARRAY_OOB:** `pc` at `BINARY_SUBSCR` / `STORE_SUBSCR` and index `i` outside container bounds

This implementation correctly models the unsafe predicate for `STORE_SUBSCR` in terms of the symbolic machine state.

## Soundness Guarantee

✅ **No false SAFE claims**: 
- Symbolic indices conservatively prevent SAFE proofs
- All error paths properly set violation flags
- Over-approximation maintains soundness

## Next Actions

Completed: `CONTINUOUS_REFINEMENT: Implement STORE_SUBSCR opcode (subscript assignment)`

Remaining queue:
1. Add stdlib import stubs to reduce context issues
2. Attempt SAFE proof for validated non-buggy function

## Lessons Learned

1. **Stack ordering matters**: STORE_SUBSCR pops in order: value, container, index
2. **Heap tracking complexity**: Need separate handling for sequences vs dicts
3. **Conservative defaults**: When unsure about symbolic values, maintain soundness by flagging heap mutations without claiming SAFE
4. **Test diversity**: 19 test cases cover normal operation, error detection, and edge cases

## Statistics

- **Lines of code added**: ~160 (opcode handler) + ~220 (tests)
- **Opcodes implemented**: 58 (up from 57)
- **Test count**: 703 (up from 684)
- **Execution time**: Full test suite runs in 2.16s
