# Iteration 31: DOUBLE_FREE Bug Class Implementation

## Summary

Implemented the 14th of 20 bug types: **DOUBLE_FREE**.

## DOUBLE_FREE in Python Context

Unlike C/C++ where double-free corrupts heap metadata, Python's GC prevents classic
memory corruption. However, resource management double-free still manifests as
semantic bugs:

1. **File/Socket**: Closing the same file handle or socket twice
2. **Locks/Semaphores**: Releasing the same synchronization primitive twice
3. **Native Objects**: Double-freeing native extension objects (capsules, buffers)
4. **Resources**: Multiple explicit cleanup/close calls on same resource

## Semantic Unsafe Predicate U_DOUBLE_FREE(σ)

The predicate detects:
- `double_free_reached` flag (symbolic VM tracks resource lifecycle)
- Resource state tracking: `free_count >= 2` for any resource
- `ValueError` from closing already-closed file/socket
- `RuntimeError` from double-releasing locks
- `SystemError` from native extension double-free

## Implementation Files

- `pyfromscratch/unsafe/double_free.py`: Unsafe predicate and counterexample extractor
- `pyfromscratch/unsafe/registry.py`: Updated to include DOUBLE_FREE
- `tests/test_unsafe_double_free.py`: 29 tests (23 passed, 3 xfailed, 3 xpassed)

## Test Coverage

### Unit Tests (12 tests, all passing)
- Flag-based detection
- Resource lifecycle tracking (free_count)
- Exception-based detection (ValueError, RuntimeError, SystemError)
- Safe state validation
- Unrelated exceptions correctly ignored

### Counterexample Extraction (4 tests, all passing)
- Flag-based extraction
- Resource state extraction
- Exception-based extraction
- Multiple resource types (file, lock, native)

### Integration Tests (3 xfailed)
- File double-close
- Lock double-release
- Conditional double-free paths

These are xfailed because full resource lifecycle tracking in the symbolic VM
is not yet implemented. The predicates are ready for when tracking is added.

### Non-Bug Tests (7 tests, 4 passing + 3 xpassed)
- Single close operations (safe)
- No close operations (not double-free, may be leak)
- Context managers (automatic single close)
- Different resources (independent tracking)
- Unrelated exceptions

### Semantic Validation Tests (3 tests, all passing)
- DOUBLE_FREE vs USE_AFTER_FREE distinction
- Free count tracking correctness (0, 1 = safe; 2+ = bug)
- Multiple resources tracked independently

## Next Steps

According to the 20 bug type list, 6 bug types remain:
1. UNINIT_MEMORY (native boundary)
2. DATA_RACE (concurrency)
3. DEADLOCK (concurrency)
4. SEND_SYNC (thread-safety contract)
5. INFO_LEAK (taint analysis)
6. TIMING_CHANNEL (secret-dependent timing)

## Notes on Resource Lifecycle Tracking

To fully detect DOUBLE_FREE in real programs, the symbolic VM needs:
- Resource allocation tracking (open/acquire/alloc)
- Resource free tracking (close/release/free)
- Per-resource free_count state
- Alias analysis (same resource accessed via different names)

Current implementation provides the semantic predicate structure, ready to
integrate with resource tracking when added to the symbolic VM.
