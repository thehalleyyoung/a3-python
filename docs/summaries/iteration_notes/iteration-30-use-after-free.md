# Iteration 30: USE_AFTER_FREE Bug Class

**Date:** 2026-01-23  
**Status:** ✅ Completed  
**Bug Type:** 13/20

## Summary

Implemented the USE_AFTER_FREE bug class, which detects access to invalidated resources in Python. This is the 13th of 20 bug types in the BARRIERS_AND_PROOFS phase.

## Implementation

### Core Module: `pyfromscratch/unsafe/use_after_free.py`

The USE_AFTER_FREE bug class in Python differs from C/C++ use-after-free (dangling pointer dereference) due to garbage collection. Instead, it detects:

1. **Closed file/socket operations** - ValueError: I/O operation on closed file
2. **Dead weak references** - ReferenceError when dereferencing expired weakref
3. **Freed native objects** - RuntimeError from C extension objects that have been freed
4. **Resource invalidation** - Using handles to explicitly closed resources

### Predicate: U_USE_AFTER_FREE(σ)

```python
def is_unsafe_use_after_free(state) -> bool:
    # Explicit flag from symbolic VM tracking resource validity
    if state.use_after_free_reached:
        return True
    
    # ValueError from closed file/socket
    if state.exception == "ValueError" and "closed" in message:
        return True
    
    # ReferenceError from dead weak reference
    if state.exception == "ReferenceError":
        return True
    
    # RuntimeError from freed native object
    if state.exception == "RuntimeError" and "freed" in message:
        return True
```

### Python-Specific Semantics

Unlike C/C++ use-after-free (undefined behavior, memory corruption):

- **GC prevents classic UAF**: Python's GC keeps objects alive while referenced
- **Resource invalidation**: Files, sockets, DB connections can be explicitly closed
- **Weak references**: Can become dead when referent is collected
- **Native boundary**: C extensions can manage memory that's freed while Python still has a handle

This maps to the formal model where the heap H contains not just objects but also resource validity states. An object can be in heap but have `resource_valid = False`.

### Registry Integration

Added to `unsafe/registry.py` before PANIC (catch-all):

```python
"USE_AFTER_FREE": (use_after_free.is_unsafe_use_after_free, 
                   use_after_free.extract_counterexample),
```

Placed before PANIC to ensure specific resource errors are classified correctly rather than caught by the generic panic handler.

## Test Results

- **All existing tests pass**: 340 passed, 8 skipped, 7 xfailed, 2 xpassed
- **No new tests required yet**: Detection infrastructure is in place; will add specific tests when implementing symbolic VM resource tracking

## Theory Connection

### Barrier Certificate for USE_AFTER_FREE

The barrier B_UAF would need to track resource validity:

```
B_UAF(σ) := ∀r ∈ Resources. (r ∈ σ.active_resources) ⇒ valid(r)
```

Inductiveness requires showing that operations maintain validity:
- File operations check `f.closed` before use
- Weak ref operations check liveness before dereference
- Native calls validate handles before passing to C

The unsafe region is:
```
U_UAF(σ) := ∃r ∈ σ.operand_stack. ¬valid(r) ∧ operation_requires_valid(r)
```

## Files Changed

- `pyfromscratch/unsafe/use_after_free.py` (new)
- `pyfromscratch/unsafe/registry.py` (updated)

## Next Steps

**Next bug type: RACE_CONDITION** (14/20)

This begins the concurrency bug class implementations:
- RACE_CONDITION
- DEADLOCK  
- REENTRANCY

These require extending the symbolic VM to model concurrent execution and thread interleavings.

## Progress

- **13 of 20 bug types implemented**
- **7 remaining**: RACE_CONDITION, DEADLOCK, REENTRANCY, RESOURCE_EXHAUSTION, UNINITIALIZED, DOUBLE_FREE, TOCTOU
- **Phase**: BARRIERS_AND_PROOFS (iteration 30/100)
