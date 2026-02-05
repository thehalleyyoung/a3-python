# Iteration 135: Unary Operations Implementation

**Date**: 2026-01-23  
**Status**: Complete  
**Tests**: 1047 passing (+34), 6 failed (closures - unchanged)

## Objective

Implement unary operations (`-x`, `+x`, `~x`, `not x`) completing Python operator coverage for the symbolic executor.

## Implementation

### 1. Z3 Symbolic Functions (`pyfromscratch/z3model/values.py`)

Added four unary operation functions:

**`unary_op_negative(operand, solver)`**
- Semantics: `-x` for int, float, bool
- Type checking: rejects None and non-numeric types
- Returns: `(result, type_ok, none_misuse)`
- Bool conversion: `-True = -1`, `-False = 0`

**`unary_op_positive(operand, solver)`**
- Semantics: `+x` (identity for numeric types)
- Type checking: rejects None and non-numeric types
- Returns: `(result, type_ok, none_misuse)`
- Bool conversion: `+True = 1`, `+False = 0`

**`unary_op_invert(operand, solver)`**
- Semantics: `~x = -(x+1)` (bitwise NOT)
- Type checking: int and bool only (not float)
- Returns: `(result, type_ok, none_misuse)`
- Bool conversion: `~True = -2`, `~False = -1`

**`unary_op_not(operand, solver)`**
- Semantics: `not x` (logical NOT)
- Never raises TypeError (all types have truthiness)
- Returns: `(result, none_misuse)`
- None is valid: `not None = True`

### 2. Bytecode Handlers (`pyfromscratch/semantics/symbolic_vm.py`)

**Added opcodes:**
- `UNARY_NEGATIVE` (line 2216-2254)
- `UNARY_INVERT` (line 2256-2294)
- `UNARY_NOT` (line 2296-2309)

**Enhanced CALL_INTRINSIC_1:**
- Updated intrinsic 5 (`INTRINSIC_UNARY_POSITIVE`) to use proper semantics
- Was just returning arg unchanged, now does type checking and conversion

**Bug detection pattern:**
All three type-checking unary ops follow standard pattern:
1. Check None misuse → sets `state.none_misuse_reached`
2. Check type confusion → sets `state.type_confusion_reached`
3. Update path condition with constraints
4. Push result to operand stack

### 3. Comprehensive Tests (`tests/test_unary_operations.py`)

**Test coverage (34 tests):**

| Category | Tests | Coverage |
|----------|-------|----------|
| UNARY_NEGATIVE | 7 | Safe (int/float/bool/zero), NULL_PTR (None), TYPE_CONFUSION (str), double negative |
| UNARY_POSITIVE | 5 | Safe (int/float/bool/zero), NULL_PTR (None) |
| UNARY_INVERT | 7 | Safe (int/bool/zero/negative/bitmask), NULL_PTR (None), TYPE_CONFUSION (float) |
| UNARY_NOT | 7 | Safe (bool/int/None/list/float/str), double not |
| Mixed operations | 5 | Combinations: `-(+x)`, `not (-x)`, `~(-x)`, expressions, conditionals |
| Bug detection | 3 | Direct None usage with `-`, `~`, `+` |

**Key test pattern:**
```python
# Module-level code (not function) for immediate analysis
code = "x = -None\n"
p = tmp_path / "test.py"
p.write_text(code)
result = analyze(p)
assert result.verdict == "BUG"
assert result.bug_type == "NULL_PTR"
```

## Semantic Correctness

### Python Unary Operation Semantics

1. **Numeric negation (`-`)**:
   - `int` → `int`: `-5 = -5`
   - `float` → `float`: `-3.14 = -3.14`
   - `bool` → `int`: `-True = -1`, `-False = 0`
   - Others → `TypeError`

2. **Numeric positive (`+`)**:
   - Identity operation (except bool→int conversion)
   - `+True = 1`, `+False = 0`

3. **Bitwise invert (`~`)**:
   - Formula: `~x = -(x+1)`
   - `~0 = -1`, `~(-1) = 0`, `~5 = -6`
   - Only int/bool, not float

4. **Logical not (`not`)**:
   - Always returns bool
   - Never raises TypeError
   - Truthiness: `None`, `0`, `0.0`, `""`, `[]` are falsy

### Bug Detection

**NULL_PTR detection:**
- `-None`, `+None`, `~None` all detected correctly
- TypeError in Python: `bad operand type for unary X: 'NoneType'`

**TYPE_CONFUSION detection:**
- Bitwise ops on float: `~3.14` detected
- String/other incompatible types rejected

## State Updates

**Opcodes implemented (now 83):**
- Added: `UNARY_NEGATIVE`, `UNARY_INVERT`, `UNARY_NOT`
- Enhanced: `CALL_INTRINSIC_1` (intrinsic 5)

**Semantic enhancements:**
```json
{
  "unary_operations": true,
  "unary_negative": true,
  "unary_positive": true,
  "unary_invert": true,
  "unary_not": true
}
```

## Testing Results

```
Platform: macOS / Python 3.14.0
Tests: 1047 passed (+34), 6 failed (closures), 14 skipped, 18 xfailed, 12 xpassed
Time: 17.47s
```

**New tests:** All 34 unary operation tests pass  
**Regressions:** None (1047 vs 1013 = +34 net)  
**Known failures:** 6 closure tests (pre-existing, unrelated)

## Impact on Public Repo Evaluation

Unary operations are common in real code:
- `-x` in arithmetic and data processing
- `~x` in bitmask/flag operations
- `not x` in conditionals everywhere

**Expected improvements:**
- Fewer UNKNOWN results (previously unimplemented opcodes)
- Better NULL_PTR detection (e.g., `if not x: -x.field`)
- More complete path exploration in numeric code

**Next tier 2 scan will capture:**
- NumPy/SciPy: extensive use of `-` and `~` in array operations
- Pandas: negation in data transformations
- General Python: `not` in every conditional

## Barrier Theory Alignment

**Unsafe predicates now expressible:**
- `NULL_PTR`: `∃path. operand.tag = NONE ∧ none_misuse`
- `TYPE_CONFUSION`: `∃path. ¬type_ok ∧ ¬none_misuse`

**Soundness maintained:**
- All type checks are Z3 queries on symbolic state
- No text-based heuristics
- Over-approximation for unknown types (OBJ tag)

**Completeness:**
With this addition, Python's core operator set is nearly complete:
- ✅ Binary arithmetic: `+`, `-`, `*`, `/`, `//`, `%`, `**`
- ✅ Binary bitwise: `<<`, `>>`, `&`, `|`, `^`
- ✅ Unary arithmetic: `-`, `+`
- ✅ Unary bitwise: `~`
- ✅ Unary logical: `not`
- ✅ Comparison: `<`, `<=`, `>`, `>=`, `==`, `!=`
- ✅ Membership: `in`, `not in`

Missing operators (less common):
- `@` (matrix multiply)
- `is`, `is not` (identity, not equality)

## Next Actions

1. Phase 4 variadic functions (sklearn FP remaining)
2. Tier 2 rescan post-unary implementation
3. Consider implementing `@` for NumPy/scientific code
4. Consider implementing augmented assignment (`+=`, `-=`, etc.) as separate opcodes if distinct from `BINARY_OP`
