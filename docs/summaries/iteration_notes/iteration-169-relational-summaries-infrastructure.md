# Iteration 169: Relational Summaries System (ELEVATION_PLAN.md Implementation)

## Context

Per ELEVATION_PLAN.md and State.json queue, the next priority is to expand library summaries/contracts using **relational summaries with required havoc fallback** instead of the current simple Contract-based approach.

This iteration implements the foundational infrastructure for the "cases + havoc" pattern that enables:
1. Structural semantic reasoning (not source pattern matching)
2. Sound over-approximations (Sem_f ⊆ R_f)
3. Uniform application mechanism (plug-in point for adding library semantics)
4. Heap observers (future work) for symbolic heap reasoning

## Changes Made

### 1. Relational Summary Schema (`pyfromscratch/contracts/relations.py`)

Created the core data structures for relational summaries:

```python
@dataclass
class RelationalCase:
    """One case in a relational summary: guard → post."""
    name: str
    guard: Callable[..., z3.BoolRef]  # (state, args) -> Z3 constraint
    post: Callable[..., 'PostCondition']  # (state, args, fresh) -> effect
    may_raise: List[str]
    provenance: str

@dataclass
class PostCondition:
    """Postcondition of a relational case."""
    return_value: Optional[SymbolicValue]
    path_constraints: List[z3.BoolRef]
    heap_constraints: List[z3.BoolRef]
    observer_updates: Dict[str, Any]

@dataclass
class HavocCase:
    """Required fallback case: maximum over-approximation."""
    may_read_heap: bool = True
    may_write_heap: bool = True
    may_allocate: bool = True
    may_raise_any: bool = True
    
@dataclass
class RelationalSummary:
    """Complete relational summary: cases + required fallback."""
    function_id: str
    cases: List[RelationalCase]
    havoc: HavocCase  # Always present for soundness
    provenance: str
```

**Key invariant**: The havoc fallback ensures `Sem_f ⊆ R_f` even when no case guard holds.

### 2. Builtin Relations (`pyfromscratch/contracts/builtin_relations.py`)

Implemented relational summaries for core builtins as proof-of-concept:

**`len(obj)`**:
- Case 1: `obj` is LIST/TUPLE/STR/DICT → return int >= 0
- Case 2: `obj` is generic OBJ → might succeed or raise TypeError
- Havoc: fallback for unknown types

**`abs(x)`**:
- Case 1: `x` is INT or FLOAT → return |x| with constraints:
  - `ret >= 0`
  - `(x >= 0 => ret == x) AND (x < 0 => ret == -x)`
- Havoc: fallback for non-numeric types

**`isinstance(obj, classinfo)`**:
- Case 1: Two arguments → return symbolic bool (unknown which)
- Havoc: fallback for invalid arguments

### 3. VM Integration (`pyfromscratch/semantics/symbolic_vm.py`)

Added `_apply_relational_summary` method that:
- Evaluates case guards in order
- Applies postcondition if guard holds (`z3.is_true`)
- Falls back to havoc if no guard holds (soundness)
- Maintains path_condition with postcondition constraints

Modified CALL and CALL_KW instructions to:
1. Check for relational summary first (`has_relational_summary`)
2. Fall back to Contract if no summary exists
3. Maintain backward compatibility

**Critical fix**: Use per-state counter for fresh symbol generation (not `id(tuple)`) to avoid Z3 variable name collisions across multiple calls.

### 4. Testing (`tests/test_relational_summaries.py`)

Created 9 tests validating:
- Summary registration and retrieval
- Data structure well-formedness
- Havoc fallback is always present (soundness)
- Integration with symbolic VM

## Technical Correctness

### Soundness Property

For each registered relational summary `R_f`:
- **Before**: Contract-based havoc fallback ensured `Sem_f ⊆ R_f`
- **After**: Cases + required havoc fallback ensure `Sem_f ⊆ R_f`

The havoc case is **always reachable** when no guard can be proven true, preventing unsound SAFE claims.

### Path Constraint Accumulation

Postconditions are conjuncted into `state.path_condition`:
```python
for constraint in post.path_constraints:
    state.path_condition = z3.And(state.path_condition, constraint)
```

This enables downstream reasoning: constraints from `abs(x)` propagate to `x[abs(y)]` bounds checks, etc.

### Fresh Symbol Generation

**Bug found and fixed**: Initial implementation used `id((state, frame, args))` which Python reuses → same Z3 variable names → unsat paths.

**Fix**: Per-state counter `state._relational_call_counter` ensures unique names:
```python
if not hasattr(state, '_relational_call_counter'):
    state._relational_call_counter = 0
state._relational_call_counter += 1
fresh_id = state._relational_call_counter
```

## Impact

### Immediate

- **Backward compatible**: Existing Contract-based semantics unchanged
- **No regressions**: Full test suite passes (1107 passed, 14 skipped, 18 xfailed, 12 xpassed)
- **Infrastructure ready**: Can now add library summaries without modifying VM

### Future (ELEVATION_PLAN.md Next Steps)

1. **Heap observers** (§4 of plan):
   - `SeqLen(obj_id)`, `DictSize(obj_id)`, `HasKey(dict_id, key)`
   - Enable bounds reasoning without pattern matching

2. **More builtins**:
   - `range`, `sorted`, `enumerate`, `zip`, etc.
   - Each as relational summary with semantic constraints

3. **Stdlib modules**:
   - `math.sqrt` with domain precondition
   - `dict.get` with no-KeyError guarantee
   - `list.append` with SeqLen mutation

4. **Bounds example** (§5 of plan):
   - `len(x)` summary + subscript semantics → automatic off-by-one detection
   - No `len(x)-1` pattern matching needed

## Files Changed

- `pyfromscratch/contracts/relations.py` (new, 5751 chars)
- `pyfromscratch/contracts/builtin_relations.py` (new, 6763 chars)
- `pyfromscratch/contracts/__init__.py` (import builtin_relations)
- `pyfromscratch/semantics/symbolic_vm.py` (import + _apply_relational_summary + CALL integration + fresh ID fix)
- `tests/test_relational_summaries.py` (new, 9 tests)

## Testing

```bash
# All tests pass
pytest tests/ -x --tb=short -q
# 1107 passed, 14 skipped, 18 xfailed, 12 xpassed

# New relational summary tests
pytest tests/test_relational_summaries.py -xvs
# 9 passed

# Specific integration test (was failing, now fixed)
pytest tests/test_contracts_integration.py::TestContractIntegration::test_multiple_calls_in_sequence -xvs
# PASSED
```

## State Updates

```json
{
  "iteration": 169,
  "phase": "UNKNOWN_CALLS_AND_CONTRACTS",
  "progress": {
    "unknown_calls": {
      "mode": "havoc_with_stdlib_contracts_and_relational_summaries",
      "relational_summaries": {
        "implemented": true,
        "builtins_with_summaries": ["len", "abs", "isinstance"],
        "schema": "cases + havoc fallback",
        "soundness": "Sem_f ⊆ R_f maintained"
      }
    }
  },
  "queue": {
    "next_actions": [
      "UNKNOWN_CALLS_AND_CONTRACTS: Add heap observers (SeqLen, DictSize) to enable structural reasoning",
      "UNKNOWN_CALLS_AND_CONTRACTS: Expand relational summaries for more builtins (range, sorted, etc.)",
      "UNKNOWN_CALLS_AND_CONTRACTS: Add stdlib module summaries (math, collections, etc.)",
      "EVAL_KNOWN_BEHAVIOR: Add known-outcome fixture suite",
      "PUBLIC_REPO_EVAL: Tiered public-repo scanning after known-behavior suite is stable"
    ]
  }
}
```

## Key Findings

1. **Infrastructure > Incremental additions**: The relational summary system is a **structural upgrade** that makes adding new library semantics trivial (plug-in pattern)

2. **Soundness by construction**: Required havoc fallback prevents semantic optimism

3. **Z3 variable hygiene matters**: Fresh symbol generation must be truly unique across execution

4. **Backward compatibility preserved**: Existing contracts still work, migration path is smooth

## Next Iteration

Implement heap observers (`SeqLen`, `DictSize`) to enable:
- `len(x)` summary that exposes length as symbolic property
- Subscript bounds checks using `SeqLen(container)`
- Truthiness semantics using observers
- Automatic off-by-one detection without pattern matching

This is the **missing piece** for the bounds example in ELEVATION_PLAN.md §5.
