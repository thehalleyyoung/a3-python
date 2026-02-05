# Iteration 138: defaultdict Semantics Gap (sklearn FP)

## Task
DSE validate sklearn/_min_dependencies.py BOUNDS bug revealed after TYPE_CONFUSION fix (iteration 117).

## Finding
**FALSE POSITIVE**: The BOUNDS bug is NOT a real bug. It's a semantic gap in how we model `defaultdict`.

### Analysis

**File**: `sklearn/_min_dependencies.py`
**Line 64**: `tag_to_packages[extra].append(...)`
**Bug type reported**: BOUNDS (IndexError)
**Actual behavior**: No error - `tag_to_packages` is a `defaultdict(list)`

### Code Context
```python
tag_to_packages: dict = defaultdict(list)
for package, (min_version, extras) in dependent_packages.items():
    for extra in extras.split(", "):
        tag_to_packages[extra].append("{}>={}".format(package, min_version))
```

### Why It's a False Positive

`defaultdict.__getitem__` has special semantics:
- Regular dict: `d[key]` raises `KeyError` if `key` not in `d`
- defaultdict: `d[key]` **creates** `d[key] = default_factory()` if `key` not in `d`, never raises KeyError

Our subscript operation (`binary_op_subscript` in `values.py:835`) conservatively assumes all dict subscripts may raise KeyError/IndexError (line 904: `bounds_violated = z3.BoolVal(True)`). This is sound over-approximation for regular dicts, but not precise for defaultdict.

### Root Cause

**Location**: `pyfromscratch/z3model/values.py:899-906`

```python
# For dicts: key must exist (concrete check for now)
# Full symbolic dict semantics requires more modeling

# Default: return fresh symbolic value, flag bounds violation as possible
result = SymbolicValue.fresh_int("subscript_default", solver)
bounds_violated = z3.BoolVal(True)  # Conservative: assume may violate
```

The code path for dict subscripts conservatively assumes bounds may be violated because we don't have full symbolic dict modeling.

### Why defaultdict Is Special

`defaultdict` from `collections` overrides `__getitem__` to call `self.default_factory()` for missing keys instead of raising KeyError. This is a fundamental semantic difference that requires:

1. Tracking whether a dict object is a defaultdict vs regular dict
2. Modeling the factory function (e.g., `list`, `int`, `set`)
3. Updating heap state when keys are auto-created

## Fix Options

### Option 1: Full defaultdict Semantics (Complex)
- Track defaultdict type in heap objects
- Model factory functions as contracts
- Implement auto-creation in subscript operation
- Update heap state on missing key access
- **Effort**: High (3-5 subtasks)
- **Benefit**: Precise modeling, eliminates FPs

### Option 2: Stdlib Contract for defaultdict (Pragmatic)
- Add `defaultdict.__getitem__` to stdlib contracts
- Specify: never raises KeyError, returns default_factory() result type
- Mark as "no bounds violation" for defaultdict subscripts
- **Effort**: Low (1 subtask)
- **Benefit**: Eliminates FPs without full implementation

### Option 3: Accept FP (Current)
- Document as known semantic gap
- Track in State.json false_positives
- Defer to Phase 4 or later
- **Effort**: None
- **Benefit**: Focus on higher-priority features

## Decision

**Choose Option 3 for now**: Document and defer.

**Rationale**:
1. This is 1 FP out of 6 sklearn bugs (17% FP rate, 83% validated)
2. Full defaultdict semantics is Phase 4 complexity (like variadic functions)
3. stdlib contract would require tracking object types more precisely (also complex)
4. Over-approximation is sound (Sem ⊆ R property maintained)
5. Other higher-priority work in queue (comparative analysis, tier expansion)

## Validation Result

✓ DSE confirmed: The analyzer flagged IndexError on line 410 (`BINARY_OP []`)
✓ Real Python execution: No error - defaultdict auto-creates missing keys
✓ Conclusion: **FALSE POSITIVE** due to semantic gap, not unsoundness

## Semantic Correctness

Our over-approximation `R_defaultdict ⊇ Sem_defaultdict` is maintained:
- We model: "may raise KeyError"
- Reality: "never raises KeyError"
- Therefore: R ⊇ Sem ✓ (sound)

The FP is acceptable over-approximation, not an unsound under-approximation.

## Impact

**sklearn validation rate**: 83% (5/6 validated, 1 FP)
- Previously (iter 116): 67% (4/6 validated, 2 FPs)
- Improvement: +16pp from iteration 117-136 semantic fixes
- This FP is known, documented semantic gap

## State Update

- Added to `State.json.progress.evaluation.false_positives`
- Categorized as "defaultdict semantics gap" (Phase 4 feature)
- Marked as "sound over-approximation" (not unsound)

## Next Actions

Continue with queue:
1. ✓ DSE validate sklearn BOUNDS (this iteration)
2. Comparative analysis of validation rates across repos
3. Analyze PANIC dominance pattern
4. Additional tier scanning
5. Phase 4: variadic functions, defaultdict, advanced features
