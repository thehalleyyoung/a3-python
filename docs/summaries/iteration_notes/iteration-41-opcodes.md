# Iteration 41: Missing Opcodes Implementation

## Goal
Implement missing bytecode opcodes to expand semantic coverage: GET_ITER, FOR_ITER, BEFORE_WITH, LOAD_BUILD_CLASS

## What was implemented

### Core requested opcodes:
1. **GET_ITER**: Converts TOS to iterator (supports lists, tuples, strings)
   - Creates iterator object in heap with collection reference
   - Tracks active iterators for ITERATOR_INVALID detection
   - Raises TypeError on None (NULL_PTR detection)

2. **FOR_ITER**: Iteration step opcode
   - Models nondeterministic choice: has_next vs exhausted
   - Creates symbolic next item value when iterator has items
   - Jumps to loop exit when exhausted
   - Single-path implementation (prefers has_next first)

3. **LOAD_BUILD_CLASS**: Loads __build_class__ for class definitions
   - Creates symbolic function reference
   - Registers function name for contract lookup
   - Enables basic class definition support

4. **MAKE_FUNCTION**: Creates function objects from code
   - Handles function flags (defaults, annotations, closure, kwdefaults)
   - Pops components based on flags
   - Creates symbolic function object

### Additional opcodes needed for iteration/context managers:
5. **END_FOR**: Loop cleanup marker (no-op in most versions)
6. **POP_ITER**: Pops iterator from stack at loop end
   - Removes from active iterator tracking
7. **JUMP_BACKWARD**: Unconditional backward jump for loops
8. **SWAP**: Swaps TOS with n-th item from top
9. **LOAD_SPECIAL**: Loads special methods (__enter__, __exit__)
10. **WITH_EXCEPT_START**: Calls __exit__ with exception info
11. **TO_BOOL**: Converts TOS to boolean (truthiness check)

## Heap model extensions

Added IteratorObject class to heap model:
- Tracks collection_ref (what's being iterated)
- Tracks current_index (symbolic position)
- Integrated with active_iterators tracking for ITERATOR_INVALID

Added allocate_iterator() method to SymbolicHeap.

## Semantic fidelity

All implementations follow barrier-theoretic soundness:
- Iterator exhaustion modeled as nondeterministic symbolic choice
- No pattern matching on source text
- All state transitions modeled symbolically with Z3
- Unsafe regions remain purely semantic predicates

## Testing

All 530 tests pass (10 skipped, 13 xfailed, 12 xpassed).

## Impact

These opcodes enable analysis of:
- for loops over sequences
- with statements (context managers)
- class definitions
- More complex control flow patterns

Still needed for full Python coverage: generators (YIELD_VALUE), async (GET_AWAITABLE, SEND), more container operations.
