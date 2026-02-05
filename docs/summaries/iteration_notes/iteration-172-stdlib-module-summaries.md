# Iteration 172: Stdlib Module Relational Summaries (math.sqrt, math.log, math.asin, math.acos)

## Task
Expanded relational summaries to cover stdlib module functions (math module), with focus on FP_DOMAIN bug detection through domain validation.

## Motivation
The queue specified: "Add stdlib module summaries (math.sqrt with FP_DOMAIN, dict.get with no KeyError, etc.)". The existing contracts for math functions were using the older Contract-based approach, not the new relational summaries framework with observer-based reasoning.

## Implementation

### Created `pyfromscratch/contracts/stdlib_module_relations.py`
New module for stdlib (math, os, sys, etc.) relational summaries, separate from builtins.

Implemented 4 math functions with full "cases + havoc fallback" pattern:

1. **math.sqrt(x)**:
   - Case 1: x >= 0 → returns float >= 0, with constraint `result^2 == x`
   - Case 2: x < 0 → raises ValueError (FP_DOMAIN bug)
   - Case 3: non-numeric → raises TypeError
   
2. **math.log(x)**:
   - Case 1: x > 0 → returns float (natural logarithm)
   - Case 2: x <= 0 → raises ValueError (FP_DOMAIN bug)
   - Case 3: non-numeric → raises TypeError

3. **math.asin(x)**:
   - Case 1: -1 <= x <= 1 → returns float in [-π/2, π/2]
   - Case 2: x < -1 or x > 1 → raises ValueError (FP_DOMAIN bug)
   - Case 3: non-numeric → raises TypeError

4. **math.acos(x)**:
   - Case 1: -1 <= x <= 1 → returns float in [0, π]
   - Case 2: x < -1 or x > 1 → raises ValueError (FP_DOMAIN bug)
   - Case 3: non-numeric → raises TypeError

### Key Design Decisions

1. **Z3 Simplification**: All guards use `z3.simplify()` to reduce expressions like `4 >= 0` to `True`. This is essential for the VM's guard checking logic which uses `z3.is_true()`.

2. **Exception Signaling**: Invalid domain cases return `PostCondition(return_value=None, observer_updates={'exception_raised': (exc_type, msg)})`. The VM will need to handle this to detect FP_DOMAIN bugs.

3. **Symbolic Constraints**: Valid domain cases add precise constraints:
   - `math.sqrt(9)` constrains result with `result^2 == 9` (Z3 can solve to exactly 3.0)
   - `math.asin(x)` constrains result to [-1.5708, 1.5708]
   - `math.acos(x)` constrains result to [0, 3.1416]

4. **Type Safety**: Each function has a type error case that rejects definitely-incompatible types (STR, LIST, TUPLE, DICT, NONE). OBJ is conservatively accepted (might be a numeric object).

### Tests

Created `tests/test_stdlib_module_relations.py` with 20 tests covering:
- Summary registration
- Guard evaluation (valid/invalid/type error cases)
- Postcondition constraints (return types, domain constraints)
- Exception signaling (FP_DOMAIN ValueError)
- Soundness properties (havoc fallback, provenance)

All 20 tests pass. Existing 18 relational summary tests still pass (no regressions).

## Soundness Guarantees

1. **Over-approximation maintained**: `Sem_f ⊆ R_f` for all functions
   - Valid domain cases are precise
   - Invalid domain cases signal exceptions (to be caught by FP_DOMAIN detector)
   - Type error cases signal exceptions (to be caught by TYPE_CONFUSION detector)
   - Havoc fallback always present (for unknown/symbolic cases)

2. **FP_DOMAIN Detection**: When guard for invalid domain holds (e.g., `x < 0` for sqrt), postcondition signals `exception_raised: ValueError`. This enables the unsafe region detector to identify FP_DOMAIN bugs.

3. **Provenance**: All summaries document provenance as "python_stdlib_docs" - derived from Python standard library documentation.

## Integration

- Added import in `pyfromscratch/contracts/__init__.py` to register summaries on module load
- VM already supports relational summaries via `_apply_relational_summary()` method
- Exception handling in VM needs enhancement to detect `exception_raised` observer updates

## Next Steps

1. Enhance VM to detect `exception_raised` in observer_updates and fork exception path
2. Connect exception_raised to FP_DOMAIN unsafe region detector
3. Add more math functions (math.tan, math.atan, math.exp, etc.)
4. Add dict methods (dict.get, dict.pop, etc.) with no KeyError cases
5. Add str methods with relational constraints

## Metrics

- Functions added: 4 (math.sqrt, math.log, math.asin, math.acos)
- Test cases: 20 (all passing)
- Lines of code: ~520 (stdlib_module_relations.py) + ~400 (tests)
- Bug types supported: FP_DOMAIN, TYPE_CONFUSION (via exception signaling)
- Soundness: Maintained (Sem_f ⊆ R_f for all summaries)
