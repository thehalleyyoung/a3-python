# Iteration 58: Path Constraint Extraction and Z3 Solving

**Date**: 2026-01-23  
**Phase**: PUBLIC_REPO_EVAL  
**Status**: Complete

## Summary

Implemented path constraint extraction and Z3 solving infrastructure to bridge symbolic execution and dynamic execution. This enables generating concrete inputs from symbolic path conditions, completing a key component of the DSE (Dynamic Symbolic Execution) oracle workflow.

## What Was Implemented

### 1. Constraint Extraction (`pyfromscratch/dse/constraint_solver.py`)

**ConstraintExtractor**: Extracts Z3 constraints from symbolic execution paths
- Extracts `path_condition` from `SymbolicMachineState` 
- Identifies symbolic input variables (locals, globals) that need concrete values
- Produces `PathConstraints` object containing:
  - Z3 path condition formula
  - Mapping of variable names to symbolic values
  - Fresh Z3 solver with constraints added

**Key Methods**:
- `extract_from_path(path: SymbolicPath) -> PathConstraints`
- `_extract_symbolic_inputs(state: SymbolicMachineState) -> Dict[str, SymbolicValue]`
- `_is_symbolic(value: SymbolicValue) -> bool` - distinguishes symbolic from concrete values

### 2. Constraint Solving (`ConstraintSolver`)

**ConstraintSolver**: Solves path constraints to generate concrete inputs
- Uses Z3 solver with configurable timeout
- Checks satisfiability of path constraints
- Extracts concrete values from Z3 models
- Maps Z3 model values to Python concrete values (int, bool, str, None)

**Key Methods**:
- `solve(constraints: PathConstraints) -> Optional[ConcreteInput]`
- `_model_to_concrete_input(model: z3.ModelRef, symbolic_inputs: Dict) -> ConcreteInput`
- `_extract_value_from_model(model: z3.ModelRef, sym_value: SymbolicValue) -> Any`

### 3. Convenience Functions

- `extract_and_solve_path(path: SymbolicPath, timeout_ms: int) -> Optional[ConcreteInput]` - One-step extraction and solving
- `validate_path_with_input(path: SymbolicPath, concrete_input: ConcreteInput) -> bool` - Sanity check that input satisfies constraints

## Test Coverage

Created comprehensive test suite (`tests/test_constraint_solver.py`) with 15 tests covering:

1. **Constraint Extraction** (3 tests)
   - Trivial paths with no conditions
   - Extracting symbolic input variables
   - Paths with branch conditions

2. **Constraint Solving** (4 tests)
   - Trivially satisfiable constraints
   - Unsatisfiable constraints (returns None)
   - Multiple variables with interdependent constraints
   - Boolean constraints

3. **End-to-End Integration** (3 tests)
   - Simple conditional paths (if x > 5)
   - Division-by-zero avoidance constraints
   - Array bounds checking constraints

4. **Model Extraction** (3 tests)
   - Integer value extraction
   - Boolean value extraction
   - Concrete values remain unchanged

5. **Path Validation** (2 tests)
   - Validating satisfying inputs
   - Detecting unsatisfiable paths

All 15 tests pass. Full test suite: 640 passed, 10 skipped, 15 xfailed, 12 xpassed.

## Semantic Faithfulness

This implementation maintains strict alignment with the barrier-certificate theory:

1. **No Heuristics**: Concrete inputs are generated purely from Z3 solutions to path constraints, not pattern matching or guessing
2. **Soundness**: Unsatisfiable constraints correctly return `None` rather than fabricating inputs
3. **Oracle Role**: This is explicitly positioned as an **oracle** for validation, not a proof of infeasibility
4. **Over-Approximation Preserved**: When solving fails (timeout/unknown), we return `None` rather than claiming the path is spurious

## Integration Points

This module bridges:
- **Symbolic VM** → `SymbolicPath` with `path_condition` 
- **Constraint Solver** → Z3 solving
- **Concolic Executor** → `ConcreteInput` for dynamic execution

Next iteration will integrate this with the concolic executor to:
1. Extract constraints from symbolic counterexample traces
2. Solve for concrete inputs
3. Execute with concrete inputs to validate/produce repros
4. Use DSE results to refine contracts (while preserving soundness)

## Files Changed

- `pyfromscratch/dse/constraint_solver.py` (new, 304 lines)
- `tests/test_constraint_solver.py` (new, 341 lines)

## Moving Parts Progress

This completes a key component of **Moving Part #8: DSE (refinement oracle)**:
- ✅ Path constraint extraction from symbolic states
- ✅ Z3 solving to generate concrete inputs
- ✅ Model-to-concrete-value mapping
- 🔄 Integration with concolic executor (next iteration)
- 🔄 Contract refinement loop (future)
