# Iteration 57: DSE Execution Context Improvements

## Goal
Improve DSE (dynamic symbolic execution) oracle execution context to properly handle module-level code and reduce spurious NameError/ImportError exceptions.

## Problem Analysis (from Iteration 55)
DSE validation of production bugs revealed execution context issues:
- Missing module globals: `__name__`, `__file__`, `__package__`, etc.
- Missing import context: sys.path not set up for relative imports
- Module-level code executed without proper environment

These caused spurious exceptions that are NOT bugs in the analyzed code, but rather artifacts of incomplete execution setup.

## Changes Made

### 1. Enhanced ConcreteInput
**File**: `pyfromscratch/dse/concolic.py`

Added module context fields to `ConcreteInput`:
```python
module_name: Optional[str]  # For __name__
file_path: Optional[str]    # For __file__
```

Added factory method for module-level execution:
```python
@staticmethod
def for_module(module_name: str, file_path: str, 
               globals_dict: Optional[Dict[str, Any]] = None) -> 'ConcreteInput'
```

### 2. Improved Globals Dictionary Setup
**File**: `pyfromscratch/dse/concolic.py`

Added `_build_globals()` method to `ConcreteExecutor`:
- Always includes `__builtins__`
- Sets `__name__` from input (defaults to `__main__`)
- Sets `__file__` if file path provided
- Derives `__package__` from module name for relative imports
- Adds `__spec__`, `__doc__`, `__cached__`, `__loader__` (set to None for simplicity)

This prevents NameError on standard module globals.

### 3. Import Context Setup
**File**: `pyfromscratch/dse/concolic.py`

Modified `execute()` to:
- Add file's directory to `sys.path` during execution
- Restore original `sys.path` after execution (no side effects)

This allows imports relative to the executed file.

### 4. Updated Validation Script
**File**: `scripts/validate_bugs_with_dse.py`

Changed from:
```python
concrete_input = ConcreteInput.empty()
```

To:
```python
concrete_input = ConcreteInput.for_module(
    module_name=inferred_module_name,
    file_path=file_path
)
```

Infers module name from file path (e.g., `flask/views.py` → `flask.views`).

### 5. Comprehensive Tests
**File**: `tests/test_dse_context.py` (new, 17 tests)

Test coverage:
- Context setup (module name, file path, globals)
- Standard globals availability
- Module-level execution patterns
- Import context and sys.path handling
- Error capture and isolation
- Oracle usage documentation

## Per Workflow Rules

### DSE as Refinement Oracle
This improvement maintains the correct DSE usage:
- **Success** = concrete witness (attach to bug report)
- **Failure** = NO proof of infeasibility (may need better inputs/context)
- Never shrink over-approximations based solely on DSE failure

### Soundness Preservation
The improvements are sound:
- Better execution context may REDUCE spurious failures
- Does NOT introduce false successes
- Maintains over-approximation property (may still fail to validate real bugs due to insufficient constraint solving)

### Anti-Cheating Compliance
Not a cheat:
- Does NOT inspect source text for heuristics
- Does NOT hardcode behaviors
- Provides proper Python execution environment (semantics-faithful)
- Explicitly documents that failure ≠ proof of infeasibility

## Impact

### Reduced Spurious Exceptions
Module-level code like:
```python
if __name__ == '__main__':
    main()
```
Will no longer raise NameError on `__name__`.

### Better Import Support
Code that imports from the same package:
```python
from .utils import helper
```
Will have better chance of executing (though may still fail if dependencies not available).

### More Accurate Validation
DSE validation results will better distinguish:
1. **Real bugs**: Actual semantic issues in code
2. **Context issues**: Missing execution environment (now reduced)
3. **Implementation gaps**: Unimplemented opcodes/features

## Limitations & Next Steps

### Still Simplified
This is NOT full constraint solving. We:
- Use `for_module()` with no arguments (empty args list)
- Don't solve path constraints to find specific inputs
- Don't handle complex import dependencies

Full DSE would:
1. Extract path constraints from symbolic trace
2. Solve with Z3 to get concrete input values
3. Set up complete execution environment
4. Validate that concrete trace matches symbolic trace

### Next Actions (Updated Queue)
1. **DSE_ORACLE**: Extract path constraints from symbolic traces
2. **DSE_ORACLE**: Integrate Z3 solving for concrete input generation
3. **PUBLIC_REPO_EVAL**: Re-run validation with improved context
4. **PUBLIC_REPO_EVAL**: Produce filtered report (real bugs vs context issues)

## Metrics
- DSE concolic.py: 109 lines added/changed
- Validation script: 18 lines changed
- Tests: 17 new tests, 100% pass
- Full suite: 625 passed, 10 skipped, 15 xfailed, 12 xpassed

## Status
✓ Completed: DSE execution context improvements
✓ Tested: All tests pass
✓ Documented: This iteration note
→ Queue: Updated with follow-up constraint solving work
