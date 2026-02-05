# Heap Observers Implementation (Iteration 170)

## Summary

Implemented heap observers (SeqLen, DictSize, HasKey) for structural reasoning without pattern matching. This enables relational summaries to express semantic constraints about collection properties using Z3, avoiding the anti-cheating violation of text-based pattern matching.

## Core Principle

**Structural reasoning without pattern matching**: Instead of recognizing patterns in source code (e.g., "if x == []"), we reason about heap properties using symbolic observers that are constrained to match the actual heap state.

## Implementation

### 1. Heap Observer Types (relations.py)

```python
class HeapObserver(Enum):
    SEQ_LEN = "SeqLen"      # Length of list/tuple/str
    DICT_SIZE = "DictSize"  # Size of dict
    STR_LEN = "StrLen"      # Length of string
    HAS_KEY = "HasKey"      # Whether dict has key
```

### 2. Symbolic Heap Extensions (heap.py)

Added three new fields to `SymbolicHeap`:

```python
seq_len_observers: Dict[int, z3.ArithRef]     # ObjId -> SeqLen(obj)
dict_size_observers: Dict[int, z3.ArithRef]   # ObjId -> DictSize(obj)
has_key_observers: Dict[tuple, z3.BoolRef]    # (dict_id, key_hash) -> HasKey(dict, key)
```

### 3. Observer Methods

- `get_seq_len_observer(obj_id)`: Returns Z3 Int representing sequence length
- `get_dict_size_observer(obj_id)`: Returns Z3 Int representing dict size
- `get_has_key_observer(dict_id, key)`: Returns Z3 Bool for key membership
- `constrain_observers()`: Returns Z3 constraints tying observers to heap state

### 4. Automatic Observer Initialization

Modified `allocate_sequence()` and `allocate_dict()` to automatically initialize observers when objects are created. This ensures SeqLen and DictSize observers always exist and are constrained correctly.

### 5. Integration with Symbolic VM

Updated `explore_bounded()` to add observer constraints when checking path feasibility:

```python
observer_constraints = path.state.heap.constrain_observers()
for constraint in observer_constraints:
    self.solver.add(constraint)
```

### 6. Relational Summary Integration

Enhanced `_apply_relational_summary()` to handle `observer_updates` in PostCondition:

```python
if observer_type == 'seq_len':
    obj_id, ret_sym = update_data
    seq_len = state.heap.get_seq_len_observer(obj_id)
    state.path_condition = z3.And(
        state.path_condition,
        ret_sym == seq_len
    )
```

### 7. Enhanced len() Builtin

Updated `len()` relational summary to use heap observers:

```python
if arg.tag == ValueTag.OBJ:
    obj_id = arg.payload
    return PostCondition(
        return_value=SymbolicValue(ValueTag.INT, ret_sym),
        path_constraints=[ret_sym >= 0],
        observer_updates={'seq_len': (obj_id, ret_sym)}
    )
```

## Soundness Property

The observer constraints maintain semantic faithfulness:

- `SeqLen(obj) == obj.length` for all sequences
- `DictSize(obj) == len(obj.keys)` for all dicts
- Observer constraints are checked with every path feasibility test
- Observers survive heap copies (for path branching)

This ensures that reasoning about `len(lst)` is grounded in the actual heap semantics, not text patterns.

## Anti-Cheating Validation

This implementation satisfies the anti-cheating rule:

✅ **No pattern matching**: We don't check source text for patterns like "len(x) == 0"  
✅ **Semantic grounding**: Observers are Z3 variables constrained to heap state  
✅ **Sound over-approximation**: Observers can be under-constrained (returning fresh symbolic values) but never unsound  
✅ **Provenance tracked**: Each observer is tied to a specific heap object via ObjId  

## Test Coverage

Created `test_heap_observers.py` with 8 tests:

1. `test_seq_len_observer_basic`: SeqLen correctly initialized and constrained
2. `test_dict_size_observer_basic`: DictSize correctly initialized and constrained
3. `test_len_builtin_uses_observer`: len() integrates with observers
4. `test_len_empty_list`: Empty list has SeqLen == 0
5. `test_len_nonempty_list`: Non-empty list has correct SeqLen
6. `test_len_symbolic_list`: Symbolic reasoning about len() works
7. `test_multiple_sequences_observers`: Independent observers for different objects
8. `test_observer_survives_heap_copy`: Observers preserved across branching

All tests pass ✅

## Next Steps (Queue Priority)

1. **Add heap observers to more builtins**: `dict.get()`, `dict.keys()`, `str.split()`, etc.
2. **Expand relational summaries**: range, sorted, enumerate, zip with observer-based reasoning
3. **Add stdlib module summaries**: math.sqrt (domain checks), os.path.exists (bool), etc.
4. **Known-behavior suite**: Curated fixtures with known SAFE/BUG outcomes

## Files Changed

- `pyfromscratch/z3model/heap.py`: Added observers infrastructure
- `pyfromscratch/contracts/builtin_relations.py`: Enhanced len() with observers
- `pyfromscratch/semantics/symbolic_vm.py`: Integrated observers into VM
- `tests/test_heap_observers.py`: Comprehensive test suite (new)
- `State.json`: Updated progress tracking

## Technical Debt

- **HasKey observer**: Currently creates fresh symbolic bools; need proper symbolic key membership modeling
- **String length**: StrLen is an alias for SeqLen; could be unified
- **Observer constraints complexity**: O(N) constraints per path check; may need optimization for large heaps

## References

- ELEVATION_PLAN.md: Relational semantics for library calls
- python-barrier-certificate-theory.md: Heap observers concept
- RustFromScratch/: Anti-cheating discipline
