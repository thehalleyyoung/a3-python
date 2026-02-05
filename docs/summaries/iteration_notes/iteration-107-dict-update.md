# Iteration 107: DICT_UPDATE Opcode Implementation

## Summary
Implemented DICT_UPDATE opcode (Python 3.11+) to support dict unpacking syntax `{**d1, **d2}` and function `**kwargs`. This is NumPy priority #3 from the missing opcodes analysis (iteration 104).

## Implementation

### Opcode Semantics
- **Purpose**: Merges one dict into another (dict unpacking)
- **Stack effect**: `..., dict_target, dict_source → ..., dict_target`
- **Bytecode usage**: `{**d1, **d2}` compiles to BUILD_MAP + DICT_UPDATE sequences
- **Python semantics**: Source dict overwrites target dict keys

### Symbolic Execution Strategy
1. **NULL_PTR detection**: Check if source is None (Z3 solver query)
2. **TYPE_CONFUSION detection**: Check if source is not OBJ-tagged (not a dict-like object)
3. **Heap metadata tracking**: Extend target dict metadata with source pairs
4. **Conservative length tracking**: Overapproximate final length (sum of both, ignoring duplicates)
5. **Havoc semantics**: Unknown source dicts create symbolic length with constraints

### Bug Detection
- **NULL_PTR**: `{**d1, **None}` → TypeError (NoneType not a mapping)
- **TYPE_CONFUSION**: `{**d1, **42}` → TypeError (int not a mapping)
- Uses state flags: `state.null_ptr_reached`, `state.type_confusion_reached`

## Testing
Created `tests/test_dict_update.py` with 8 tests:
- 3 concrete tests (expressions with dict unpacking)
- 5 symbolic tests (basic merges, None handling, multiple unpacks)
- All 8 tests pass

## Files Modified
1. `pyfromscratch/semantics/symbolic_vm.py` - Added DICT_UPDATE handler (100 lines)
2. `tests/test_dict_update.py` - New test file (119 lines)
3. `State.json` - Updated opcode list and iteration

## NumPy Impact
DICT_UPDATE was identified as causing 1/16 NumPy bugs (6% of opcode-related bugs). With EXTENDED_ARG (iter 105) and CONTAINS_OP (iter 106) already implemented, 3/5 missing opcodes are now complete. Remaining: BUILD_STRING, LOAD_FAST_BORROW.

## Next Steps
1. Implement BUILD_STRING (f-string assembly) - NumPy priority #4
2. Rescan NumPy after opcode implementations to measure cumulative impact
3. Continue CONTINUOUS_REFINEMENT phase

## Technical Notes
- Tag comparisons must use Z3 IntVal comparison, not direct Python `==`
- Path conditions use `z3.And(state.path_condition, constraint)` pattern
- Dict metadata tracks pairs and length symbolically
- Conservative overapproximation: doesn't track duplicate keys
