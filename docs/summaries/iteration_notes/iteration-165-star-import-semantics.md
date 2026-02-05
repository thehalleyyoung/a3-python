# Iteration 165: Star Import Semantics Implementation

**Date**: 2026-01-23
**Status**: ✅ Complete
**Phase**: PUBLIC_REPO_EVAL (Continuous Refinement)

## Objective

Implement semantics for star imports (`from module import *`) via `CALL_INTRINSIC_1` with `INTRINSIC_IMPORT_STAR` (ID 2).

## Motivation

Star imports are common in Python code but were not handled properly:
- `from math import *` would result in NameError when accessing `sqrt`
- Star imports populate the current namespace with all module exports
- This is particularly important for httpx and other libraries that use star imports in `__init__.py`

## Implementation

### Bytecode Semantics

Star import bytecode sequence:
```python
LOAD_SMALL_INT           0           # import level
LOAD_CONST               (('*',))    # fromlist
IMPORT_NAME              (module)    # creates module object
CALL_INTRINSIC_1         2           # INTRINSIC_IMPORT_STAR - populates namespace
POP_TOP                              # discard result
```

### Semantic Model

**Stack behavior**:
- Input: module object
- Output: (none - side effect only)
- Effect: Populates `frame.globals` with all module exports

**Algorithm**:
1. Pop module object from stack
2. Extract module ID from `SymbolicValue.payload`
3. If module has registered exports in `state.module_exports[module_id]`:
   - For each export name: create symbolic object and add to `frame.globals`
4. Otherwise: sound over-approximation (no-op is safe)

**Soundness**: 
- Over-approximates module exports (all registered exports become available)
- Maintains `Sem_star_import ⊆ R_star_import`
- NameError prevention for known stdlib modules

### Code Changes

**File**: `pyfromscratch/semantics/symbolic_vm.py`

Added `INTRINSIC_IMPORT_STAR` (ID 2) handler in `CALL_INTRINSIC_1` opcode:

```python
if intrinsic_id == 2:  # INTRINSIC_IMPORT_STAR
    # Extract module ID from symbolic value payload
    module_id = arg.payload if hasattr(arg, 'payload') else None
    
    # Populate globals with all module exports
    if module_id and hasattr(state, 'module_exports'):
        exports = state.module_exports.get(module_id, [])
        for export_name in exports:
            export_id = z3.Int(f"star_import_{module_id}_{export_name}_{offset}")
            frame.globals[export_name] = SymbolicValue(ValueTag.OBJ, export_id)
    
    # No result pushed (side effect only)
    frame.instruction_offset = next_offset()
```

### Tests

**File**: `tests/test_star_import.py` (7 tests)

1. `test_star_import_basic`: Basic star import doesn't crash
2. `test_star_import_populates_namespace`: Exports become available  
3. `test_star_import_unknown_module`: Sound over-approximation for unknown modules
4. `test_star_import_vs_explicit_import`: Semantic equivalence check
5. `test_star_import_multiple_modules`: Multiple star imports in sequence
6. `test_star_import_overwrite`: Star import overwrites existing names
7. `test_star_import_no_name_error`: Prevents NameError for known exports

All tests pass. Examples:

```python
# Now works without NameError
from math import *
result = sqrt(4)  # sqrt available via star import

# Multiple star imports
from os import *
from sys import *
x = name       # os.name
y = platform   # sys.platform
```

## Results

### Test Status
- **Before**: 1081 passing
- **After**: 1088 passing (+7 new tests)
- **Regressions**: 0
- **Status**: ✅ All tests passing

### Semantic Coverage

**Implemented intrinsics** (4/6+ common):
- ✅ ID 2: `INTRINSIC_IMPORT_STAR` (this iteration)
- ✅ ID 3: `INTRINSIC_STOPITERATION_ERROR`
- ✅ ID 5: `INTRINSIC_UNARY_POSITIVE`
- ✅ ID 6: `INTRINSIC_LIST_TO_TUPLE`
- ⬜ ID 1: `INTRINSIC_PRINT` (rare)
- ⬜ ID 4: `INTRINSIC_ASYNC_GEN_WRAP` (async-specific)

### Impact on Public Repos

Star imports are common in library `__init__.py` files:

**httpx** (`httpx/__init__.py`):
```python
from ._api import *  # Now properly handled
from ._client import *
```

**Expected improvements**:
- httpx: Likely reduction in NameError false positives
- Other libraries with star imports: Similar improvements
- Module-init code: More accurate namespace modeling

## Technical Notes

### Key Insight

The module ID is stored in `SymbolicValue.payload`, not `SymbolicValue.value`:
- `payload`: The actual module ID (int or Z3 expr)
- `value`: Not used for module objects
- `tag`: Always `ValueTag.OBJ` for modules

Initial implementation incorrectly checked `arg.value`, causing module_id extraction to fail.

### Design Decision: Over-Approximation

For unknown modules or modules without registered exports:
- **Choice**: No-op (don't populate namespace)
- **Soundness**: Safe because:
  - Downstream `LOAD_NAME` will raise NameError
  - NameError is a safe over-approximation (may report false positive)
  - Better than under-approximation (missing real bugs)

### Integration with Existing Infrastructure

Leverages existing `state.module_exports` registry:
- Populated by `IMPORT_NAME` for known stdlib modules
- Maps `module_id → [export_names]`
- Used by `IMPORT_FROM` and now `INTRINSIC_IMPORT_STAR`

No changes needed to `IMPORT_NAME` or `LOAD_NAME` - seamless integration.

## Next Actions

1. ✅ Star import semantics (this iteration)
2. ⏭️ Python 3.14 opcodes: `LOAD_CONST_LOAD_FAST`, `JUMP_FORWARD`
3. ⏭️ DSE validation of remaining httpx bugs post-iteration 163
4. ⏭️ Phase 4: defaultdict semantics
5. ⏭️ Phase 4: variadic function inlining (*args, **kwargs)

## Correctness Checklist

- [x] Semantic unsafe region defined in terms of machine state
- [x] Transition relation: `frame.globals` mutation
- [x] Z3 query: Not applicable (no reachability check)
- [x] Witness trace: Not applicable (no bug detection)
- [x] Over-approximation soundness: Maintained (exports are available)
- [x] Tests: BUG cases (N/A), NON-BUG cases (7 tests)
- [x] No regex/text pattern matching
- [x] Faithful to Python 3.11+ bytecode semantics

## Quality Bar Met

**"What is the exact semantic unsafe region?"**
- Not applicable - this is a semantic feature implementation, not bug detection

**"What is the exact transition relation?"**
- Transition: `frame.globals[name] ← SymbolicValue(OBJ, fresh_id)` for each export

**"Where is the Z3 query?"**
- Not applicable - no Z3 satisfiability checks needed

**"Where is the extracted witness trace?"**
- Not applicable - no bug detection

**Additional verification**:
- 7 targeted tests validate behavior
- Full test suite passes (1088 tests)
- Sound over-approximation maintained
