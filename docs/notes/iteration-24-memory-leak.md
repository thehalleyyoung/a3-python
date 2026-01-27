# Iteration 24: MEMORY_LEAK Bug Type Implementation

**Date**: 2026-01-23  
**Phase**: BARRIERS_AND_PROOFS → FULL_20_BUG_TYPES transition  
**Bug Types**: 8/20 implemented

## What was done

Implemented the `MEMORY_LEAK` bug type, bringing the total from 7 to 8 implemented bug types.

### Core semantic predicate

Created `pyfromscratch/unsafe/memory_leak.py` with:

1. **Unsafe predicate `U_MEMORY_LEAK(σ)`**:
   - Checks for `heap_size_unbounded` flag (unbounded allocation pattern)
   - Checks for `resource_leak_detected` flag (resource handle exhaustion)
   - Conservative threshold check on heap size (> 10000 objects)

2. **Python-specific interpretation**:
   - Unlike C/Rust, Python has GC, so "leak" means unbounded growth or retention
   - Two leak types: unbounded heap growth, resource handle leaks (files, sockets)
   - Detection requires tracking allocation patterns over paths

3. **Counterexample extraction**:
   - Includes leak type (unbounded_growth, resource_leak, heap_size_threshold)
   - Heap size and flag state
   - Full trace and path condition

### State tracking

Extended `SymbolicMachineState` with new flags:
- `heap_size_unbounded: bool` - for unbounded allocation patterns in loops
- `resource_leak_detected: bool` - for resource handle exhaustion

Updated the `copy()` method to preserve these flags during path branching.

### Registration

Registered in `pyfromscratch/unsafe/registry.py`:
- Added import for `memory_leak` module
- Added entry in `UNSAFE_PREDICATES` dict

### Testing

Created comprehensive test suite (`tests/test_unsafe_memory_leak.py`):
- 15 new tests covering predicate, extractor, documentation, semantics
- Tests verify conservative approach (no false positives without evidence)
- Tests verify both flag types trigger detection
- All 280 tests pass (265 original + 15 new)

Also created test fixtures:
- `memory_leak_unbounded_list.py` - BUG example (unbounded growth)
- `memory_leak_bounded_list.py` - NON-BUG example (bounded allocation)

## Semantic correctness notes

**Conservative detection**: The predicate only fires when explicit evidence exists:
1. Flags must be set by loop/pattern analysis (not yet implemented in VM)
2. Heap size threshold is a bounded approximation
3. True unboundedness requires proving heap size → ∞ (needs ranking functions)

**Soundness**: We never report SAFE for programs with potential leaks unless we have a proof. The flags are over-approximations.

**Future work**: 
- Loop analysis to detect unbounded allocation patterns and set flags
- Resource tracking in heap model for file handles, sockets, etc.
- Integration with NON_TERMINATION analysis (infinite loops often cause leaks)

## Progress

- **Implemented bug types**: 8/20 (40%)
  - ASSERT_FAIL, DIV_ZERO, BOUNDS, NULL_PTR, TYPE_CONFUSION, PANIC, STACK_OVERFLOW, MEMORY_LEAK
- **Remaining**: 12/20 (60%)
  - Next: NON_TERMINATION, ITERATOR_INVALID, FP_DOMAIN

## Next actions

Per the queue:
1. NON_TERMINATION (ranking functions) - closely related to MEMORY_LEAK
2. ITERATOR_INVALID (collection mutation during iteration)
3. FP_DOMAIN (math domain errors like sqrt(-1), log(0))
