# Iteration 28: Import and Module Handling

## Goal
Unblock FP_DOMAIN tests by implementing minimal import/module support for stdlib functions.

## What Was Blocking
All 10 FP_DOMAIN integration tests were skipped because they required:
1. `IMPORT_NAME` opcode to load modules
2. `LOAD_ATTR` opcode to access module attributes
3. Domain precondition checking for math functions

## Changes Made

### 1. Added IMPORT_NAME opcode handler
- Pops level and fromlist from stack (for stack consistency)
- Creates symbolic module object with negative ID to distinguish from regular objects
- Stores module name in `state.module_names` dictionary for LOAD_ATTR lookup
- Models modules as `ValueTag.OBJ` with special IDs

### 2. Added LOAD_ATTR opcode handler
- For module objects: resolves qualified function names (e.g., `math.sqrt`)
- Creates symbolic function reference with qualified name
- Stores in `state.func_names` for contract lookup in CALL
- For non-module objects: havoces the result (sound over-approximation)

### 3. Enhanced _apply_contract with domain precondition checking
- Checks `domain_precondition` field in contract's `exception_effect`
- Parses simple preconditions: "x >= 0", "x > 0", "-1 <= x <= 1"
- Uses Z3 to check if precondition violation is reachable
- Sets `fp_domain_error_reached` and `domain_error_context` when violated
- Raises ValueError exception in state (matching Python semantics)
- On non-exception path, assumes precondition holds (adds to path condition)

### 4. Updated SymbolicMachineState
- Added `module_names: dict[int, str]` field
- Updated `copy()` method to copy module_names dictionary

## Results

### Tests
- All 13 FP_DOMAIN tests now pass (10 previously skipped)
- Total: 334 tests passing (up from 324), 8 skipped
- No regressions in existing tests

### Opcodes Implemented
- Added `IMPORT_NAME` and `LOAD_ATTR` to implemented opcodes list
- Updated `bytecode_semantics.imports` to `true`

## Semantics Notes

### Module Representation
Modules are modeled as symbolic objects with:
- Negative object IDs (-2000 - hash(name) % 10000) to distinguish from regular objects
- Module name stored in metadata (`state.module_names`)
- Module attributes resolved at LOAD_ATTR time to qualified names

### Contract-Based Function Modeling
Functions from modules are modeled via contracts:
- Qualified names like "math.sqrt" match stdlib contracts
- Domain preconditions are checked symbolically with Z3
- Violations are detected as reachable unsafe states (FP_DOMAIN)
- Sound over-approximation: unknown modules/attrs are havoced

### FP_DOMAIN Detection
Math domain errors are detected by:
1. Contract declares domain precondition (e.g., "x >= 0")
2. Symbolic executor checks if violation is reachable (Z3 query)
3. If sat: marks `fp_domain_error_reached` and sets exception
4. Produces semantic witness trace (not text pattern matching)

## Alignment with Theory

This implementation follows barrier-certificate principles:
- **Semantic unsafe predicate**: FP_DOMAIN is defined as reaching a state where domain precondition is violated
- **Z3-based reachability**: Uses Z3 solver to check if violation is reachable
- **Sound contracts**: Module functions modeled as over-approximating relations R_f
- **No heuristics**: Detection is based on symbolic execution, not text patterns

The import handling is minimal but sufficient for the math module contracts needed by FP_DOMAIN.
Expansion to full import semantics (sys.path, package resolution, import hooks) is deferred.

## Next Actions

With FP_DOMAIN tests unblocked, the queue points to:
1. **INTEGER_OVERFLOW**: Next bug type from the 20 (Python↔native boundary)
2. **USE_AFTER_FREE**: Native boundary bug type
3. Continue expanding the 20 bug types coverage
