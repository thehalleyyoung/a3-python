# Iteration 42: Enhanced Barrier Certificate Templates

## Summary

Added 6 new barrier certificate templates to improve synthesis for common safe patterns:

1. **Conditional guard barrier**: Models if-guarded operations (e.g., `if x >= 0: sqrt(x)`)
2. **Loop range barrier**: Proves termination for bounded loops (`for i in range(n)`)
3. **Disjunction barrier**: Combines barriers with OR (at least one holds)
4. **Collection size barrier**: Bounds collection growth (lists/dicts/sets)
5. **Progress measure barrier**: Generic decreasing quantity for termination
6. **Invariant region barrier**: Encodes boolean invariants as barriers

## Motivation

Previous synthesis only had:
- Constant barriers
- Single/multi-variable linear combinations
- Stack depth barriers
- Conjunction (AND) of barriers

This limited our ability to prove SAFE for common patterns like:
- Conditionally guarded operations (sqrt/log with domain checks)
- Bounded iteration (for loops with known limits)
- Control-flow dependent safety (different paths, different invariants)
- Collection size bounds (memory leak prevention)

## Changes

### `pyfromscratch/barriers/templates.py`

Added 6 new template functions:

1. `conditional_guard_barrier(condition, var, threshold)`:
   - B(σ) = if condition then (var - threshold) else +∞
   - Models patterns where guard implies safety
   - Example: `if x >= 0: result = math.sqrt(x)`

2. `loop_range_barrier(iterator, max_iterations)`:
   - B(σ) = max_iterations - iterator
   - Proves termination for bounded loops
   - Example: `for i in range(100): ...`

3. `disjunction_barrier(B1, B2)`:
   - B(σ) = max(B1(σ), B2(σ))
   - At least one component barrier holds
   - Useful for control-flow dependent safety

4. `collection_size_barrier(collection_size, max_size)`:
   - B(σ) = max_size - len(collection)
   - Bounds memory usage / prevents unbounded growth
   - Useful for MEMORY_LEAK detection

5. `progress_measure_barrier(progress)`:
   - B(σ) = progress(σ)
   - Generic decreasing quantity
   - Useful for NON_TERMINATION proofs

6. `invariant_region_barrier(predicate)`:
   - B(σ) = if predicate then +1 else -1
   - Encodes arbitrary boolean invariants
   - Enables Z3 inductive checking on predicates

### `pyfromscratch/barriers/synthesis.py`

Enhanced `_generate_templates()` to include:

- Phase 3.5: Loop range barriers for iterator-like variables
- Phase 3.6: Collection size barriers for collection-like variables
- Phase 3.7: Progress measure barriers for all variables
- Uses heuristics on variable names to prioritize templates

Total template budget unchanged (max_templates=100 by default).

### `tests/test_barriers.py`

Added `TestNewBarrierTemplates` class with 8 tests:
- All 6 new templates tested for correctness
- Tests verify evaluation on symbolic states
- Tests verify proper handling of edge cases (condition true/false)

### Bug fixes

Fixed conjunction_barrier and disjunction_barrier to handle both Int and Real sorts:
- Previous implementation assumed ToReal could be called on all values
- Now checks `z3.is_real()` and `z3.is_int()` before converting

## Testing

All 538 tests pass:
- 34 barrier tests (including 8 new tests)
- All unsafe predicate tests still pass
- No regressions in symbolic execution or synthesis

## Semantic Correctness

All new templates are semantically grounded:

1. **Conditional guard**: Models implication correctly via If-Then-Else
2. **Loop range**: Standard linear decreasing function
3. **Disjunction**: max(B1, B2) is valid barrier if either component is valid
4. **Collection size**: Linear bound on resource usage
5. **Progress measure**: Direct encoding of decreasing function
6. **Invariant region**: Standard encoding of boolean as barrier (±1)

None of these are heuristics - all are formal barrier certificate constructions.

## Impact

These templates enable synthesis to prove SAFE for:
- Domain-checked math operations (FP_DOMAIN)
- Bounded loops (NON_TERMINATION)
- Bounded collections (MEMORY_LEAK)
- Control-flow dependent invariants

Expected reduction in UNKNOWN results when re-scanning public repos.

## Next Steps

1. Re-run tier 1 public repo scan to measure improvement
2. Consider CEGIS (counterexample-guided synthesis) for template parameters
3. Add template caching to avoid redundant Z3 queries
4. Explore quadratic/polynomial barrier templates (current: only linear)
