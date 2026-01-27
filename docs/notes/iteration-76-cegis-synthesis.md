# Iteration 76: CEGIS (CounterExample-Guided Inductive Synthesis) for Barrier Certificates

## Summary

Implemented CEGIS (CounterExample-Guided Inductive Synthesis) loop for automatic barrier certificate synthesis. CEGIS alternates between parameter synthesis, verification, and counterexample-guided refinement to find valid barrier certificates.

## What Changed

### New Module: `pyfromscratch/barriers/cegis.py`

Implemented full CEGIS synthesizer with:

1. **CEGISBarrierSynthesizer class**
   - Main CEGIS loop: synthesize → verify → refine
   - Parameter space exploration using Z3 SMT solving
   - Counterexample-guided constraint refinement

2. **Template families supported**:
   - Quadratic: `a·x² + b·x + c`
   - Cubic: `a·x³ + b·x² + c·x + d`
   - Quartic: `a·x⁴ + b·x³ + c·x² + d·x + e`

3. **Key components**:
   - `CEGISConfig`: Configuration for CEGIS loop (max iterations, timeouts, parameter ranges)
   - `CEGISResult`: Result with success/failure, synthesized barrier, counterexamples collected
   - `Counterexample`: Counterexample from failed verification (init/unsafe/step)

4. **CEGIS loop phases**:
   - **SYNTHESIS**: Find candidate parameters using Z3 solver
   - **VERIFICATION**: Check inductiveness with InductivenessChecker
   - **REFINEMENT**: Extract counterexamples, add exclusion constraints

5. **Parameter search**:
   - Parameters as Z3 Real variables
   - Constraints: bounded ranges, non-degeneracy conditions
   - Exclusion constraints to avoid retrying failed parameters
   - Counterexample-guided constraints (heuristics for init/unsafe/step failures)

### Test Suite: `tests/test_cegis_synthesis.py`

Added 10 comprehensive tests:

1. **Basic functionality tests**:
   - Configuration and setup
   - Parameter variable creation (quadratic/cubic/quartic)
   - Parameter constraints
   - Exclusion constraint correctness
   - Parameter value extraction from Z3 models

2. **Synthesis tests**:
   - Simple bounded counter (should find barrier)
   - Diverging loop (should NOT find barrier)
   - Quadratic growth pattern
   - Cubic template usage
   - Full synthesis workflow (integration test)

All tests use simplified state representation for testing (avoiding full SymbolicMachineState complexity).

### Integration

Updated `pyfromscratch/barriers/__init__.py` to export:
- `CEGISConfig`
- `CEGISResult`
- `CEGISBarrierSynthesizer`
- `synthesize_barrier_cegis` (convenience function)
- `Counterexample`

## Theory Alignment

### CEGIS Overview

CEGIS is a classic synthesis technique from program verification:

1. **Synthesis**: Generate candidate solution from current constraints
2. **Verification**: Check if candidate satisfies specification
3. **Refinement**: If verification fails, extract counterexample and add constraints

Terminates when:
- Valid solution found (success)
- Parameter space exhausted (failure)
- Timeout/resource limit (unknown)

### Barrier Certificate CEGIS

For barrier certificate `B(σ)`, we synthesize parameters (e.g., coefficients) such that:

- **Init**: `∀s∈S₀. B(s) ≥ ε`
- **Unsafe**: `∀s∈U. B(s) ≤ -ε`
- **Step**: `∀s,s'. (B(s) ≥ 0 ∧ s→s') ⇒ B(s') ≥ 0`

CEGIS finds parameters by:
1. Positing parameter variables `p₁, p₂, ...`
2. Adding constraints on parameters (ranges, non-degeneracy)
3. Iteratively:
   - Solve for parameters satisfying constraints
   - Check if resulting barrier is inductive
   - If not, extract counterexample and refine constraints

### Soundness

- Only reports SAFE when Z3 proves inductiveness
- Counterexamples guide search but don't weaken safety
- Parameter constraints are over-approximations
- All generated barriers are fully verified before reporting success

### Advantages over Template Enumeration

Compared to the existing `synthesis.py` (template enumeration):

- **Guided search**: Uses failures to improve next candidates
- **Continuous parameter space**: Not limited to discrete grid
- **Adaptive**: Learns from counterexamples
- **Fewer candidates**: More efficient when template family is known

## Test Results

All 9 non-slow tests pass:
- `test_cegis_basic_configuration`: ✓
- `test_cegis_parameter_variable_creation`: ✓
- `test_cegis_parameter_constraints`: ✓
- `test_cegis_exclusion_constraint`: ✓
- `test_cegis_simple_bounded_counter`: ✓
- `test_cegis_diverging_loop`: ✓
- `test_cegis_quadratic_growth`: ✓
- `test_cegis_cubic_template`: ✓
- `test_cegis_parameter_extraction`: ✓

Full test suite: **758 passed, 10 skipped, 15 xfailed, 12 xpassed** (+9 new tests)

## Implementation Notes

### Current Limitations

1. **Counterexample utilization**: Current refinement is basic (exclusion constraints)
   - Future: Extract concrete state values from counterexamples
   - Future: Add quantitative constraints from CE traces
   - Future: Interpolation-based refinement

2. **Template families**: Currently univariate polynomials only
   - Future: Bivariate templates (for two-variable systems)
   - Future: Piecewise templates
   - Future: Template inference from program structure

3. **Synthesis guidance**: Parameter constraints are generic
   - Future: Bug-type-specific hints
   - Future: Program-structure-based initial guesses
   - Future: Learning from past successes

### Integration with Analyzer

CEGIS is ready to integrate with the main analyzer:

```python
from pyfromscratch.barriers.cegis import synthesize_barrier_cegis

# Try CEGIS with quadratic template
result = synthesize_barrier_cegis(
    template_family="quadratic",
    initial_state_builder=...,
    unsafe_predicate=...,
    step_relation=...,
    variable_name="x",
    variable_extractor=...,
)

if result.success:
    print(f"Found barrier: {result.barrier.name}")
    # Use result.barrier for SAFE proof
```

### Next Steps

To fully realize CEGIS potential:

1. **Concrete counterexample values**: Extract and use state values from Z3 models
2. **Template selection heuristics**: Choose template family based on program structure
3. **Compositional synthesis**: Combine CEGIS with disjunctive/conjunctive barriers
4. **Learning**: Track successful parameter patterns across programs

## Adherence to Workflow Discipline

✓ Read `State.json` at start
✓ Updated `State.json` at start (iteration 76, status=running)
✓ Single focused task: Implement CEGIS loop
✓ Implementation + comprehensive tests
✓ No test regressions (758 passed)
✓ Theory-grounded: CEGIS follows formal synthesis methodology
✓ No heuristics masquerading as verification: All barriers fully verified
✓ Documentation of design decisions and limitations

## Files Changed

1. `pyfromscratch/barriers/cegis.py` (new, 585 lines)
2. `tests/test_cegis_synthesis.py` (new, 408 lines)
3. `pyfromscratch/barriers/__init__.py` (updated exports)
4. `docs/notes/iteration-76-cegis-synthesis.md` (this file)
5. `State.json` (to be updated at end)
