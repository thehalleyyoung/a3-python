# Iteration 104: NumPy High Bug Rate Analysis

**Date**: 2026-01-23  
**Phase**: PUBLIC_REPO_EVAL  
**Task**: Investigate why numpy has highest tier 2 bug rate (16%) despite being mature scientific library

## Executive Summary

NumPy's 16% bug rate is **2.7× higher than pandas (6%)** and **2.3× higher than scikit-learn (7%)**, despite all being mature, well-tested scientific libraries. The root cause is **unimplemented opcodes** (31% of numpy bugs) rather than genuine semantic bugs.

## Key Findings

### 1. Bug Rate Ranking (Tier 2)

| Rank | Repository   | Bug Rate | Bugs | Files |
|------|--------------|----------|------|-------|
| 1    | numpy        | 16.0%    | 16   | 100   |
| 2    | black        | 15.5%    | 9    | 58    |
| 3    | django       | 13.0%    | 13   | 100   |
| 4    | httpie       | 10.2%    | 9    | 88    |
| 5    | scikit-learn | 7.0%     | 7    | 100   |
| 6    | pandas       | 6.0%     | 6    | 100   |
| 7    | ansible      | 6.0%     | 6    | 100   |

**Overall tier 2**: 66 bugs / 646 files = **10.2% bug rate**

### 2. Bug Type Distribution (All Tier 2)

- **PANIC**: 60 bugs (90.9%) - overwhelmingly dominant
- **TYPE_CONFUSION**: 4 bugs (6.1%)
- **NULL_PTR**: 1 bug (1.5%)
- **BOUNDS**: 1 bug (1.5%)

All repos show 83-100% PANIC bugs, confirming this is not numpy-specific.

### 3. Error Category Breakdown

#### NumPy (16 bugs):
- **NameError**: 8 (50.0%) - `globals()` not mocked, `__name__` missing
- **Unimplemented Opcode**: 5 (31.2%) - `EXTENDED_ARG`, `DICT_UPDATE`, `CONTAINS_OP`, `BUILD_STRING`, `LOAD_FAST_BORROW`
- **TypeError**: 2 (12.5%)
- **ImportError**: 1 (6.2%)

#### Pandas (6 bugs):
- **ImportError**: 4 (66.7%) - heavy conditional imports
- **NameError**: 1 (16.7%)
- **TypeError**: 1 (16.7%)
- **Unimplemented Opcode**: 0 (0%)

#### Scikit-learn (7 bugs):
- **ImportError**: 3 (42.9%)
- **Unimplemented Opcode**: 2 (28.6%)
- **NameError**: 2 (28.6%)

#### Ansible (6 bugs):
- **ImportError**: 5 (83.3%) - extensive conditional imports
- **Other**: 1 (16.7%)

### 4. Why NumPy Has More Bugs

**Primary reason**: NumPy uses more diverse Python 3.14 opcodes that are not yet implemented:

1. **`EXTENDED_ARG`** (numpy/ma/core.py): Large constant pools
2. **`DICT_UPDATE`** (numpy/_expired_attrs_2_0.py): Dict merging syntax
3. **`CONTAINS_OP`** (benchmarks/asv_pip_nopep517.py): `in` operator optimization
4. **`BUILD_STRING`** (doc/neps/conf.py): f-string assembly
5. **`LOAD_FAST_BORROW`** (benchmarks/benchmarks/bench_ufunc_strides.py): Performance optimization

**Secondary reason**: More NameError bugs (8 vs pandas' 1) - extensive use of `globals()`, `__name__` checks in module initialization.

### 5. Comparative Analysis: Why Pandas/Ansible Are Lower

**Pandas** (6%, 6 bugs):
- **Simpler module structure**: Fewer nested imports, less dynamic code generation
- **Heavy conditional imports** (4/6 bugs): Detectable as ImportError, not opcode issues
- **No unimplemented opcodes**: Pandas code is more "vanilla" Python

**Ansible** (6%, 6 bugs):
- **Even more conditional imports** (5/6 bugs): Designed for multi-environment portability
- **Defensive coding**: Extensive try/except around imports to handle missing dependencies

**Scikit-learn** (7%, 7 bugs):
- **Middle ground**: Some unimplemented opcodes (2) + ImportErrors (3)
- Still lower than numpy's 31% opcode gap

## Root Cause: False Positives from Opcode Gap

NumPy's high bug rate is **artificially inflated by implementation incompleteness**, not genuine semantic bugs:

- 5/16 (31%) of numpy bugs are **unimplemented opcodes** → **False positives**
- 8/16 (50%) are NameError from incomplete symbolic execution environment
- Only ~2/16 (12.5%) are potential true semantic issues (TypeError)

**After filtering opcode gaps**: Numpy's "true" bug rate would be ~11/16 = **68.75%** → effective **11% bug rate**, comparable to httpie (10.2%).

## Validation: 100% Module-Init Bugs

**All 16 numpy bugs** occur in `<module>` frame (module initialization phase), consistent with:
- Import-time code execution
- Global variable initialization
- Dynamic feature detection

This is **semantically correct behavior**: module initialization in symbolic execution with incomplete opcodes/environment.

## Recommendations

### 1. Immediate: Implement Missing Opcodes (Priority Order)

Based on tier 2 impact:

1. **`EXTENDED_ARG`**: Critical for large constant pools (numpy)
2. **`CONTAINS_OP`**: Common optimization for `in` operator
3. **`DICT_UPDATE`**: Dict merge syntax (`{**d1, **d2}`)
4. **`BUILD_STRING`**: f-string assembly (common in docs/config)
5. **`LOAD_FAST_BORROW`**: Performance optimization (less critical)

Implementing these 5 opcodes would eliminate **5 numpy bugs** → **11/100 = 11% bug rate**.

### 2. Enhance Symbolic Execution Environment

Add proper mocking for:
- `globals()` → return empty dict with `__name__`, `__file__`, `__doc__`
- `__name__` → always available as string constant
- `locals()` → return current frame locals

This would eliminate ~50% of NameError bugs.

### 3. Update False Positive Tracking

Current tier 2 metrics should distinguish:
- **Semantic bugs**: True PANIC/TYPE_CONFUSION/BOUNDS
- **Opcode gaps**: Unimplemented opcodes (implementation limitation)
- **Environment gaps**: Missing builtins/globals (execution harness limitation)

### 4. No Numpy-Specific Investigation Needed

Numpy's high bug rate is **explainable** and **addressable** through general improvements:
- Not a code quality issue (pandas/scikit-learn use similar patterns)
- Not an unusual structural pattern
- Simply hitting more edge cases of current implementation

## Conclusion

NumPy has highest tier 2 bug rate because it uses **more advanced/optimized Python features** that expose gaps in the current opcode coverage. This is a **tooling maturity issue**, not a code quality issue.

**After addressing opcode gaps + environment mocking**: Expected numpy bug rate would drop to **~7-11%**, comparable to scikit-learn/httpie.

**Action**: Proceed with opcode implementation (EXTENDED_ARG, CONTAINS_OP, etc.) rather than repo-specific investigation.

---

## Appendix: NumPy Bug File List

1. tools/get_submodule_paths.py - NameError
2. numpy/_globals.py - NameError
3. numpy/matlib.py - NameError
4. numpy/exceptions.py - NameError
5. numpy/_expired_attrs_2_0.py - DICT_UPDATE
6. benchmarks/asv_pip_nopep517.py - CONTAINS_OP
7. doc/preprocess.py - NameError
8. doc/postprocess.py - NameError
9. doc/neps/conf.py - BUILD_STRING
10. doc/source/user/plots/meshgrid_plot.py - TypeError
11. doc/source/user/plots/matplotlib3.py - TypeError
12. benchmarks/benchmarks/bench_ufunc_strides.py - LOAD_FAST_BORROW
13. benchmarks/benchmarks/bench_io.py - ImportError
14. numpy/core/multiarray.py - NameError
15. numpy/core/_multiarray_umath.py - NameError
16. numpy/ma/core.py - EXTENDED_ARG

All 16 bugs: Module initialization phase, 100% PANIC or TYPE_CONFUSION.
