# Iteration 66: UNPACK_SEQUENCE Opcode Implementation

## Goal
Implement the `UNPACK_SEQUENCE` opcode to support tuple and list unpacking in Python code.

## What was done

### 1. UNPACK_SEQUENCE opcode implementation
Added full semantic support for `UNPACK_SEQUENCE(count)` in `symbolic_vm.py`:

**Semantics:**
- Pops one sequence value from stack
- Unpacks it into `count` individual values
- Pushes the values onto stack in order
- Raises `TypeError` if value is None (NULL_PTR bug class detection)
- Raises `TypeError` if value is not a sequence (TYPE_CONFUSION bug class)
- Raises `ValueError` if sequence length doesn't match expected count

**Implementation details:**
- Properly checks sequence type using Z3 constraints
- Extracts elements from heap-allocated sequence objects
- Creates symbolic values for unknown/symbolic elements
- Maintains type tags (LIST/TUPLE) through unpacking

### 2. Fixed nested sequence handling in LOAD_CONST
Discovered and fixed a bug where nested tuples/lists were incorrectly stored with `ValueTag.NONE`:
- Added recursive handling for nested tuples in tuple constants
- Added recursive handling for nested lists in tuple constants
- Added recursive handling for nested tuples in list constants
- Added recursive handling for nested lists in list constants
- Now properly preserves `ValueTag.TUPLE` and `ValueTag.LIST` for nested structures

### 3. Fixed BUILD_LIST to use proper tags
Changed `BUILD_LIST` opcode to:
- Use `state.heap.allocate_sequence()` for proper heap allocation
- Return `SymbolicValue.list(obj_id)` with `ValueTag.LIST` (not `ValueTag.OBJ`)
- Store elements in heap's sequence structure (not separate metadata)
- Consistent with how `LOAD_CONST` handles lists

### 4. Comprehensive test suite
Created `tests/test_unpack_sequence.py` with 13 tests:
- Basic tuple and list unpacking
- Multi-element unpacking (2, 3 elements)
- TypeError for None (NULL_PTR detection)
- TypeError for non-sequences (int)
- ValueError for length mismatch (too short, too long)
- Function-local unpacking with STORE_FAST
- Nested tuple unpacking `(a, b), (c, d) = x`
- Edge cases: empty tuple, single element, swap pattern

### 5. Updated test expectations
Fixed `test_build_list.py::test_build_list_empty` to expect `ValueTag.LIST` instead of `ValueTag.OBJ`.

## Test results
- New tests: 13/13 passed
- Full suite: 684 passed, 10 skipped, 15 xfailed, 12 xpassed
- No regressions

## Semantic correctness
The implementation is **semantically grounded**:
1. **Unsafe predicates checked:**
   - `NULL_PTR`: None.is_none() check with Z3
   - `TYPE_CONFUSION`: sequence type check with Z3
   - `BOUNDS` (implicitly): length mismatch detection
   
2. **Z3 symbolic model:**
   - Uses heap-allocated sequences with proper tags
   - Extracts concrete obj_id via solver model
   - Creates symbolic values for unknown elements
   - Path condition maintained throughout

3. **No heuristics:**
   - All checks are via Z3 constraints
   - No pattern matching or AST inspection
   - Exception raising is semantic (machine state)

## Files changed
1. `pyfromscratch/semantics/symbolic_vm.py`:
   - Added UNPACK_SEQUENCE opcode handler
   - Fixed LOAD_CONST nested sequence handling
   - Fixed BUILD_LIST to use proper heap allocation
2. `tests/test_unpack_sequence.py`: New comprehensive test suite
3. `tests/test_build_list.py`: Updated expectation for ValueTag.LIST
4. `State.json`: Added UNPACK_SEQUENCE to implemented opcodes

## Next actions remaining in queue
- STORE_SUBSCR opcode (subscript assignment)
- Add stdlib import stubs
- Attempt SAFE proof for validated non-buggy function
