# Iteration 79: Template Inference from Program Structure

**Date**: 2026-01-23  
**Phase**: PUBLIC_REPO_EVAL / CONTINUOUS_REFINEMENT  
**Status**: Completed successfully

## Summary

Added automatic barrier template selection based on program structure analysis. The system now analyzes Python bytecode to detect loops, nesting depth, and variable usage patterns, then automatically selects appropriate barrier template complexity (linear, quadratic, cubic) for CEGIS synthesis.

## Changes Made

### 1. New Module: `pyfromscratch/barriers/program_analysis.py`

Created comprehensive program structure analyzer:

- **Loop Detection**: Identifies loops via `JUMP_BACKWARD` bytecode instructions
- **Nesting Analysis**: Computes loop nesting depth (1 = single loop, 2 = nested, 3+ = deeply nested)
- **Variable Tracking**: Identifies variables modified within loops
- **Conditional Detection**: Detects if/else branches in code
- **Complexity Scoring**: Heuristic metric for overall program complexity

Key classes:
- `LoopInfo`: Information about a detected loop (start/end offsets, nesting, modified variables)
- `ProgramStructure`: Complete analysis with template suggestions

Template selection strategy:
- No loops or simple single loop → **linear** template (degree 1)
- Multiple sequential loops or nested loops → **quadratic** template (degree 2)
- Deeply nested loops (3+ levels) → **cubic** template (degree 3)
- Conditionals in loops → suggests disjunctive templates

### 2. Enhanced CEGIS: `pyfromscratch/barriers/cegis.py`

**Added linear template support**:
- `_create_parameter_variables` now handles "linear" template family
- `_add_parameter_constraints` constrains linear coefficients
- `_build_barrier` constructs linear barriers: B(x) = a·x + b
- `_evaluate_template_at_point` evaluates linear templates at concrete values

**New auto-template synthesis function**:
- `synthesize_barrier_with_auto_template(code, ...)` - main entry point
- Analyzes program structure to select initial template
- Falls back to higher-degree templates if synthesis fails:
  - Linear fails → try quadratic
  - Quadratic fails → try cubic
  - Cubic fails → report UNKNOWN
- Returns both `CEGISResult` and `ProgramStructure` analysis

### 3. Bug Fix: Variable Collection

Fixed `analyze_program_structure` to collect variables from both:
- `code.co_varnames` (local variables in functions)
- `code.co_names` (global names in module-level code)

This ensures loop counters and module-level variables are tracked correctly.

## Testing

Created 37 new tests across two test files:

### `tests/test_program_analysis.py` (23 tests)

**Loop Detection**:
- No loops detected in linear code
- Single for/while loops detected
- Nested loops detected with correct nesting level
- Triple-nested loops (degree 3)
- Sequential (non-nested) loops distinguished

**Variable Analysis**:
- Variables modified in loops tracked
- Loop counters identified
- Total variables includes co_varnames + co_names

**Conditionals**:
- If/else statements detected
- Conditionals in loops flagged

**Template Selection**:
- Linear for no loops
- Quadratic for nested loops
- Cubic for deep nesting (3+ levels)

**Complexity**:
- More loops → higher complexity
- Deeper nesting → higher complexity

**Edge Cases**:
- Empty functions
- Loops with break/continue
- List comprehensions

### `tests/test_auto_template_synthesis.py` (14 tests)

**Auto-Template Selection**:
- Program structure analysis correctly suggests template degree
- Linear selected for simple code
- Quadratic selected for nested loops
- Cubic selected for triple nesting

**Integration**:
- `synthesize_barrier_with_auto_template` returns structure analysis
- Fallback logic escalates template degree on failure
- Custom CEGISConfig passed through correctly

**Linear Template CEGIS**:
- Parameter variables created (coeff_x, constant)
- Template evaluation at concrete points
- Barrier construction from parameter values

**All 802 tests pass** (including 37 new tests)

## Motivation

Previously, CEGIS required manual template selection. For complex programs with nested loops, choosing too simple a template (e.g., linear) would fail, while choosing too complex (e.g., quartic) wastes synthesis time.

This enhancement:
1. **Reduces manual tuning**: Template complexity automatically matches program structure
2. **Improves synthesis efficiency**: Start with appropriate degree, escalate only if needed
3. **Provides program insights**: Loop nesting and variable analysis useful for debugging
4. **Aligns with theory**: Template degree should match loop nesting for polynomial invariants

## Soundness

This is a **heuristic guidance** enhancement, not a semantic change:
- Template selection only affects synthesis **efficiency**, not **correctness**
- All synthesized barriers are still verified for inductiveness by Z3
- Fallback ensures we don't give up too early
- Still reports UNKNOWN (not SAFE) if no template succeeds

The anti-cheating rule is preserved: barrier certificates are still checked against the Z3 transition system model.

## Next Steps (Remaining Queue)

1. ✅ **Template inference from program structure** (this iteration)
2. Integrate explicit Z3 variable tracking for better counterexample extraction
3. Rescan tier 1 repos with expanded stubs to measure impact

## Files Changed

- `pyfromscratch/barriers/program_analysis.py` (new, 358 lines)
- `pyfromscratch/barriers/cegis.py` (enhanced: added linear template, auto-select function)
- `tests/test_program_analysis.py` (new, 23 tests)
- `tests/test_auto_template_synthesis.py` (new, 14 tests)
- `State.json` (updated)

## Impact

**Test Count**: 765 → 802 (+37 tests)  
**All tests passing**: 802 passed, 10 skipped, 15 xfailed, 12 xpassed

Template selection is now **semantics-aware** and **adaptive**, improving CEGIS synthesis efficiency while maintaining verification soundness.
