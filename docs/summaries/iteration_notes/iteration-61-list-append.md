# Iteration 61: LIST_APPEND Opcode Implementation

## Date
2026-01-23

## Objective
Implement the LIST_APPEND opcode to support list comprehensions in the symbolic executor.

## Context
From tier 1 triage (iteration 60), LIST_APPEND was identified as missing in 16 files across the scanned public repos. This opcode is used exclusively by list comprehensions and is critical for analyzing real-world Python code.

## What was done

### 1. Analyzed LIST_APPEND bytecode behavior
- Examined Python 3.14 bytecode compilation for list comprehensions
- Determined that LIST_APPEND takes an argument `i` indicating stack position
- Stack semantics: `LIST_APPEND(i)` pops TOS and appends it to list at `stack[-i]` (after pop)

### 2. Implemented LIST_APPEND in symbolic_vm.py
- Added handler between LIST_EXTEND and BUILD_MAP (line 2103)
- Correct stack indexing: `list_obj = frame.operand_stack[-i]` after popping item
- Integrates with existing `state.heap.list_metadata` tracking
- Handles both concrete integer lengths and symbolic lengths
- Initializes list metadata if not yet tracked (defensive)

### 3. Created test suite
- `tests/test_list_append.py` with 3 unit tests
- Tests verify opcode mechanics directly (stack manipulation, metadata updates)
- Tests cover argval=1, argval=2, and multiple appends
- Note: Full list comprehension tests blocked on LOAD_FAST_AND_CLEAR opcode (see next action)

## Testing
- All 3 new tests pass
- Full test suite: 646 passed, 10 skipped, 15 xfailed, 12 xpassed
- No regressions introduced

## Semantic correctness

### Unsafe region preservation
LIST_APPEND correctly preserves all unsafe region checking:
- BOUNDS: List length is tracked; subsequent subscript operations will check bounds
- DIV_ZERO: Items being appended can trigger div-by-zero during computation
- Type errors: Symbolic values maintain tags through append operation
- Memory tracking: List growth is recorded in heap metadata

### Soundness guarantee
- Over-approximation: When list length becomes symbolic (unknown iterable), we create a fresh symbolic variable
- No spurious SAFE claims: LIST_APPEND never claims a list is safe when it isn't
- Reachability preserved: All paths through comprehension loops are explored

## Implementation notes

### Key design decisions
1. **Stack indexing**: After extensive testing, confirmed that `stack[-i]` is correct (not `-i+1`)
2. **Metadata initialization**: Defensive initialization ensures we handle lists created outside BUILD_LIST
3. **Symbolic length handling**: Transitions to symbolic Z3.Int when extending with unknown iterables

### What LIST_APPEND does NOT do
- Does NOT implement LOAD_FAST_AND_CLEAR (exception handling in comprehensions)
- Does NOT implement STORE_FAST_LOAD_FAST (optimization in comprehensions)
- Does NOT model iterator invalidation during append (that's ITERATOR_INVALID)

## Next steps
From queue priority order:
1. **MAP_ADD**: Dict comprehensions (similar pattern to LIST_APPEND)
2. **BUILD_SET**: Set literals
3. **LOAD_FAST_AND_CLEAR**: Exception handling (blocks full comprehension testing)
4. **STORE_FAST_LOAD_FAST**: Comprehension optimization
5. **UNPACK_SEQUENCE**: Tuple unpacking
6. **STORE_SUBSCR**: Subscript assignment

## Anti-cheating checklist
✓ Semantic unsafe region: LIST_APPEND doesn't introduce new unsafe states; items come from existing computation  
✓ Transition relation: Opcode modifies heap metadata; transition is explicit in symbolic semantics  
✓ Z3 encoding: Uses existing heap.list_metadata; no new Z3 constraints needed for append itself  
✓ No heuristics: Implementation is pure bytecode semantics, no pattern matching  
✓ Witness extraction: List contents tracked in metadata; accessible for counterexample traces  

## Files changed
- `pyfromscratch/semantics/symbolic_vm.py`: Added LIST_APPEND opcode handler (32 lines)
- `tests/test_list_append.py`: Created test suite (149 lines, 3 tests)
- `docs/notes/iteration-61-list-append.md`: This file
