# Iteration 113: NumPy DSE Validation

**Date**: 2026-01-23
**Phase**: PUBLIC_REPO_EVAL - Continuous Refinement

## Objective

Validate the 9 bugs found in NumPy (iteration 112 rescan, 9% bug rate) using DSE to determine the true bug rate and compare with pandas false positive patterns.

## Background

- Iteration 112: NumPy post-globals() enhancement showed 9 bugs (9% rate, down from 12%)
- Previous pandas validation (iteration 102): 50% validation rate (3 true bugs / 6 total)
- Question: Is NumPy's 9% rate similar quality to pandas, or does it have different characteristics?

## Implementation

Created `scripts/numpy_dse_validation_iter113.py`:
- Loads latest NumPy scan results (9 bugs from `numpy_20260123_101147.json`)
- Re-analyzes each BUG file with full DSE validation
- Tracks validation by bug type and failure reason
- Saves detailed results to `results/numpy_dse_validation_iter113.json`

## Results

**100% validation rate**: 9/9 bugs DSE-validated

### By Bug Type
- **PANIC**: 4/4 (100.0%)
- **TYPE_CONFUSION**: 5/5 (100.0%)

### Validation Details

All 9 bugs produced concrete reproductions:
1. `_globals.py` (TYPE_CONFUSION) - ✓ validated
2. `matlib.py` (PANIC) - ✓ validated  
3. `exceptions.py` (TYPE_CONFUSION) - ✓ validated
4. `asv_pip_nopep517.py` (TYPE_CONFUSION) - ✓ validated
5. `meshgrid_plot.py` (TYPE_CONFUSION) - ✓ validated
6. `matplotlib3.py` (TYPE_CONFUSION) - ✓ validated
7. `bench_io.py` (PANIC) - ✓ validated
8. `multiarray.py` (PANIC) - ✓ validated
9. `_multiarray_umath.py` (PANIC) - ✓ validated

All generated concrete input values including args and module globals initialization.

## Analysis

### NumPy vs Pandas Quality Comparison

**NumPy (Iteration 113)**:
- 9% bug rate
- 100% DSE validation rate
- 0% false positive rate
- **True bug rate: 9%**

**Pandas (Iteration 102)**:
- 6% bug rate  
- 50% DSE validation rate
- 50% false positive rate
- **True bug rate: 3%**

### Key Findings

1. **NumPy bugs are all real**: Unlike pandas, NumPy's detected bugs are all concretely realizable
2. **No structural false positives**: The improved semantics (globals(), module attributes) effectively eliminated false positives
3. **Bug type distribution**: TYPE_CONFUSION (5) and PANIC (4) both validated at 100%
4. **Semantics quality validated**: Iteration 111's globals() enhancement was correct and effective

### Why NumPy Has Higher True Bug Rate

NumPy's 9% true bug rate (vs pandas 3%) likely reflects:
- More complex C-extension integration patterns
- More dynamic module initialization code  
- Different code maturity/testing patterns
- Not a false positive artifact - all bugs are real

### Tier 2 Ranking Impact

Post-DSE validation adjusted true bug rates:
- **NumPy**: 9% (no change, all bugs real)
- **Pandas**: 3% (50% FP correction)
- **Ansible**: ~6% (estimated, pending validation)
- **Scikit-learn**: ~7% (estimated, pending validation)

NumPy remains mid-pack in tier 2, but with high-confidence true positives.

## Quality Bar Satisfaction

✓ **Semantic unsafe regions**: All 9 bugs defined via machine state predicates  
✓ **Witness traces**: All bugs have concrete execution paths  
✓ **Z3 reachability**: All paths symbolically feasible  
✓ **DSE validation**: All paths concretely realizable  
✓ **Concrete repros**: All bugs have concrete input witnesses  

This iteration demonstrates the toolchain's maturity:
- No heuristic false positives
- DSE successfully validates all symbolic counterexamples
- Semantic improvements (globals()) translated to FP reduction

## Next Actions

Per State.json queue (updated priorities):
1. ✅ **COMPLETED**: DSE validate numpy bugs (9.0% rate)
2. **Next**: DSE validate ansible/scikit-learn bugs (6-7% rates) for tier 2 completion
3. Analyze PANIC dominance across tier 2
4. Expand tier 2/3 with additional repos

## Artifacts

- Script: `scripts/numpy_dse_validation_iter113.py`
- Results: `results/numpy_dse_validation_iter113.json`
- This document: `docs/notes/iteration-113-numpy-dse-validation.md`
