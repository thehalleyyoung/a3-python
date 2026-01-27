# Iteration 75: Polynomial and Enhanced Disjunctive Barrier Templates

## Objective
Expand barrier certificate templates beyond linear forms to support more expressive safety proofs.

## Changes Made

### 1. New Polynomial Barrier Templates

Added to `pyfromscratch/barriers/templates.py`:

#### Quadratic Barriers
- `quadratic_barrier(var, coeff_x2, coeff_x, constant)`: B(σ) = a·x² + b·x + c
- Useful for proving bounded growth with non-linear patterns
- Example: B(n) = 100 - n² proves |n| ≤ 10

#### General Polynomial Barriers
- `polynomial_barrier(var, coefficients)`: B(σ) = c₀ + c₁·x + ... + cₙ·xⁿ
- Supports arbitrary degree polynomials
- Uses Horner's method for efficient evaluation
- Degrees 3+ for complex invariants

#### Bivariate Quadratic Barriers
- `bivariate_quadratic_barrier(x, y, ...)`: B(σ) = a·x² + b·y² + c·xy + d·x + e·y + f
- Models relationships between two variables
- Supports elliptical, hyperbolic, and parabolic safety regions
- Example: B(x,y) = 100 - x² - y² proves x² + y² ≤ 100 (circle)

#### Piecewise Linear Barriers
- `piecewise_linear_barrier(var, breakpoints)`: Different linear forms in different regions
- Useful for phase-dependent invariants (initialization, main loop, cleanup)
- Each region has its own slope and intercept

### 2. Enhanced Disjunctive and Conjunctive Barriers

#### N-way Disjunction
- `disjunctive_region_barrier(barriers)`: B(σ) = max(B₁(σ), ..., Bₙ(σ))
- Generalizes 2-way disjunction to arbitrary N
- Models "at least one condition must hold"
- Useful for control-flow dependent safety (different paths have different invariants)

#### N-way Conjunction
- `conjunctive_region_barrier(barriers)`: B(σ) = min(B₁(σ), ..., Bₙ(σ))
- Generalizes 2-way conjunction to arbitrary N
- Models "all conditions must hold simultaneously"
- Useful for multi-variable bounds

### 3. Updated Synthesis Pipeline

Modified `pyfromscratch/barriers/synthesis.py` to include new templates:

**Phase 5**: Quadratic barriers for single variables
- Downward parabolas: B = c - x²
- Shifted parabolas with linear terms
- Common patterns for bounded growth

**Phase 6**: Bivariate quadratic barriers
- Elliptical bounds (x² + y²)
- Hyperbolic bounds (x² - y²)
- Cross-term interactions

**Phase 7**: Cubic polynomials
- Higher-degree growth patterns
- Example: B = 10 - 5x + 0.01x³

**Phase 8**: Piecewise linear barriers
- Phase-dependent invariants
- Different bounds for different execution regions

**Phase 9**: Disjunctive combinations
- Try N-way disjunctions of simple barriers
- Captures "any of these conditions"

**Phase 10**: Conjunctive combinations
- Try N-way conjunctions for multi-variable bounds
- Captures "all of these conditions"

**Phase 11**: Higher-degree polynomials (quartic, quintic)
- Only for selected variables to avoid combinatorial explosion

### 4. Comprehensive Tests

Created `tests/test_polynomial_barriers.py` with 16 test cases:

- **TestQuadraticBarriers**: Downward parabolas, shifted parabolas, upward with negative linear
- **TestPolynomialBarriers**: Cubic, quartic, linear-as-polynomial
- **TestBivariateQuadraticBarriers**: Circular, elliptical, hyperbolic bounds
- **TestPiecewiseLinearBarriers**: Three-phase barriers
- **TestDisjunctiveBarriers**: 2-way and 3-way disjunctions
- **TestConjunctiveBarriers**: 2-way and 3-way conjunctions
- **TestBarrierCombinations**: Mixed quadratic+linear, quadratic+quadratic

All 16 tests pass, validating:
- Correct barrier evaluation
- Z3 constraint satisfaction
- Boundary conditions
- Safe/unsafe region separation

## Mathematical Foundation

### Quadratic Separators
Linear barriers can only separate convex regions. Quadratic barriers enable:
- Circular/elliptical safety regions: B = R² - x² - y²
- Parabolic bounds: B = c - x²
- Non-convex separators via piecewise combinations

### Polynomial Hierarchy
- Degree 1 (linear): Separates half-spaces
- Degree 2 (quadratic): Separates conic sections
- Degree 3+ (polynomial): Increasingly complex separators
- Trade-off: expressiveness vs solver complexity

### Disjunctive Safety
B(σ) = max(B₁, ..., Bₙ) is inductive if:
- Init: ∀s∈S₀. max(B₁(s), ..., Bₙ(s)) ≥ ε
- Unsafe: ∀s∈U. max(B₁(s), ..., Bₙ(s)) ≤ -ε
- Step: ∀s,s'. (max(Bᵢ) ≥ 0 ∧ s→s') ⇒ max(B'ᵢ) ≥ 0

This captures path-dependent safety: different execution paths maintain different invariants, but at least one always holds.

## Impact on Analysis

### Enhanced Expressiveness
- Linear templates: ~50-100 candidates
- With polynomials: ~200-300 candidates (controlled)
- Piecewise/disjunctive: Additional ~50-100 combinations

### Use Cases

**Quadratic**: 
- Array access with quadratic bounds: `for i in range(n): access[i*i]`
- Growth rate proofs: prove n² stays below threshold

**Bivariate**:
- Resource trade-offs: time vs space constraints
- Coupled loop counters: i + j ≤ N

**Piecewise**:
- Initialization phases with different bounds
- Multi-stage algorithms (quicksort partition/recurse)

**Disjunctive**:
- Branch-dependent safety: if-then-else with different invariants
- Multiple exit conditions

### Solver Performance
- Z3 handles quadratic constraints efficiently (NRA solver)
- Higher-degree polynomials may timeout (configured to 5s per template)
- Synthesis tries simple templates first, complex ones only if needed

## Verification

Test results:
```
748 passed, 10 skipped, 15 xfailed, 12 xpassed
```

No regressions. Net +16 tests for polynomial barriers.

## Next Steps

Potential future enhancements (not urgent):
1. CEGIS loop for template parameter synthesis (instead of enumeration)
2. Template inference from program structure (loop bounds → polynomial degree)
3. SOS (Sum-of-Squares) barriers for global optimality guarantees
4. Exponential barrier improvements (currently limited approximation)

## Semantics Commitment

All new barriers are checked via Z3:
- No heuristics decide BUG/SAFE
- Inductive invariant checking remains sound
- Barrier evaluation is purely symbolic (Z3 expressions)

The polynomial forms are direct mathematical extensions of the linear form, preserving the barrier certificate theory:
- Init, Unsafe, Step conditions unchanged
- Only the barrier function space expanded
- Still verified per the transition system model
