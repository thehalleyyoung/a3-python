# Iteration 171: Expanded Builtin Relational Summaries

**Date**: 2026-01-23  
**Phase**: UNKNOWN_CALLS_AND_CONTRACTS  
**Status**: Completed

## Objective

Expand relational summaries for high-frequency Python builtins to reduce UNKNOWN results and enable more precise symbolic reasoning.

## Actions Taken

### 1. Added Relational Summaries for Key Builtins

Implemented sound over-approximating relational summaries (Sem_f ⊆ R_f) for:

#### Iterator-Producing Functions
- **range(stop) / range(start, stop, step)**
  - Returns: OBJ (range object) with SeqLen observer
  - Constraints: len >= 0, with precise length calculation for 1-2 arg cases
  - May raise: ValueError (if step == 0)
  
- **enumerate(iterable, start=0)**
  - Returns: OBJ (enumerate object) with SeqLen matching input
  - Each item: (int, item) tuple
  - May raise: TypeError (if not iterable)
  
- **zip(*iterables, strict=False)**
  - Returns: OBJ (zip object) with SeqLen = min(input lengths)
  - Empty args case: len == 0
  - May raise: TypeError (if args not iterable)
  
- **reversed(seq)**
  - Returns: OBJ (reverse iterator) with SeqLen matching input
  - Works on sequences with __reversed__ or __len__+__getitem__
  - May raise: TypeError

- **map(func, *iterables)**
  - Returns: OBJ (map object) with SeqLen = min(iterable lengths)
  - Like zip, but applies function
  - May raise: TypeError
  
- **filter(func, iterable)**
  - Returns: OBJ (filter object) with SeqLen <= input length
  - Conservative: constrains >= 0
  - May raise: TypeError

#### Collection Processing Functions
- **sorted(iterable, *, key=None, reverse=False)**
  - Returns: LIST with SeqLen matching input
  - Preserves length but reorders elements
  - May raise: TypeError (if items not comparable)

#### Boolean Reduction Functions
- **all(iterable)**
  - Returns: BOOL (fresh symbolic - can't determine statically)
  - True if all elements truthy (or empty)
  - May raise: TypeError
  
- **any(iterable)**
  - Returns: BOOL (fresh symbolic - can't determine statically)
  - True if any element truthy, False if empty
  - May raise: TypeError

### 2. Integration with Heap Observers

All iterator-producing functions use the `seq_len` observer to:
- Track symbolic lengths through heap references
- Enable length-based reasoning (bounds checking, iteration counts)
- Maintain relationships between input/output lengths (e.g., zip, map)

### 3. Testing

Added 9 new tests in `test_relational_summaries.py`:
- Registration verification for all new builtins
- Structure validation (cases, havoc, provenance)
- All 18 tests pass

Verified no regressions:
- `test_contracts.py`: 13 tests pass
- `test_contracts_integration.py`: 12 tests pass
- `test_heap_observers.py`: 8 tests pass

## Semantic Properties Enforced

### Soundness (Sem_f ⊆ R_f)
- All summaries are over-approximations of true semantics
- Havoc fallback ensures soundness when guards don't hold
- Exception behaviors explicitly modeled (may_raise)

### Length Preservation Semantics
- `sorted`, `reversed`: output length == input length
- `enumerate`: output length == input length
- `zip`, `map`: output length == min(input lengths)
- `filter`: output length <= input length
- `range(stop)`: length == max(0, stop)
- `range(start, stop)`: length == max(0, stop - start)

### Observer Integration
- All iterables tied to SeqLen observers
- Enables structural reasoning (e.g., "if len(x) == 5, then len(sorted(x)) == 5")
- Avoids pattern matching on source text

## Files Changed

1. **pyfromscratch/contracts/builtin_relations.py**
   - Added 9 new relational summaries
   - Total builtins with relational summaries: 12
   - Lines added: ~200

2. **tests/test_relational_summaries.py**
   - Added 9 new test cases
   - Total tests: 18 (all passing)

## Impact

### Before
- 3 builtins with relational summaries: len, abs, isinstance
- Limited iterator reasoning capability
- Many UNKNOWN results for common patterns

### After
- 12 builtins with relational summaries
- Full coverage of iterator protocol fundamentals
- Length-preserving/transforming operations modeled
- Expected impact: fewer UNKNOWN results in code using these builtins

## Next Priority

Continue expanding relational summaries:
1. String methods (str.split, str.join, str.replace)
2. Dict methods (dict.get with no KeyError, dict.items/keys/values)
3. Math module functions (math.sqrt with FP_DOMAIN)
4. List/set methods (list.extend, set.union, set.intersection)

## Soundness Notes

- All summaries maintain Sem_f ⊆ R_f property
- Havoc fallback present for all functions (required)
- Exception behaviors explicitly documented
- No pattern matching on source text (semantic-only reasoning)
- Observer constraints enable structural reasoning without text inspection

## Quality Bar Met

For each new summary, can answer:
- ✅ Exact semantic behavior in Z3 (guards, postconditions, observers)
- ✅ Over-approximation property maintained (havoc fallback)
- ✅ Exception behaviors enumerated (may_raise lists)
- ✅ Length/structure relationships preserved
- ✅ No source text patterns used (semantic only)

This continues the elevation plan from iteration 170, systematically building out the library semantics layer while maintaining soundness guarantees.
