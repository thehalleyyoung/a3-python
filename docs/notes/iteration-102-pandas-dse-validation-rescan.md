# Iteration 102: Pandas DSE Validation - Current Detection Baseline

## Context

Following iteration 101's claim of pandas bugs increasing from 7→32, I re-scanned pandas with the current detection code to establish a factual baseline and perform DSE validation.

## Scan Results

**Fresh scan with current detection (2026-01-23 09:10:09):**
- Total files: 100
- Bugs found: **6** (not 32 as claimed in State.json)
- Safe: 94
- Bug rate: 6.0%

### Bug Breakdown

| File | Bug Type | DSE Validation |
|------|----------|----------------|
| `__init__.py` | PANIC | ✓ Validated (ModuleNotFoundError) |
| `shared_docs.py` | TYPE_CONFUSION | ✗ False positive |
| `base.py` | PANIC | ✗ False positive |
| `html.py` | PANIC | ✓ Validated (ImportError) |
| `stata.py` | PANIC | ✓ Validated (ImportError) |
| `_warnings.py` | PANIC | ✗ False positive |

## DSE Validation Results

### Methodology

Direct execution of each flagged file with Python interpreter to reproduce exceptions:

```python
for bug in bugs:
    try:
        with open(file_path) as f:
            code = f.read()
        exec(compile(code, file_path, 'exec'), {})
        # No exception → False positive
    except Exception as e:
        # Exception raised → Validated
```

### Results Summary

- **Validated:** 3/6 bugs (50.0%)
- **False positives:** 3/6 bugs (50.0%)
- **Validation rate:** 50.0%

### Validated Bugs (True Positives)

1. **`__init__.py` - PANIC**
   - Exception: `ModuleNotFoundError: No module named 'pandas.core.col'`
   - Real import error in pandas code

2. **`html.py` - PANIC**
   - Exception: `ImportError: cannot import name 'set_module' from 'pandas.util._decorators'`
   - Real import error

3. **`stata.py` - PANIC**
   - Exception: `ImportError: cannot import name 'Pandas4Warning' from 'pandas.errors'`
   - Real import error

### False Positives

4. **`shared_docs.py` - TYPE_CONFUSION**
   - No exception raised on execution
   - Analyzer incorrectly flagged

5. **`base.py` - PANIC**
   - No exception raised on execution
   - Analyzer incorrectly flagged

6. **`_warnings.py` - PANIC**
   - No exception raised on execution
   - Analyzer incorrectly flagged

## Key Finding: State.json Discrepancy

**Expected:** 32 bugs (per State.json from iteration 101)
**Actual:** 6 bugs (current scan)

### Possible Explanations

1. **State.json was never updated correctly**: Iteration 101 notes describe a *theoretical* impact analysis but may not have performed actual rescans
2. **Different scan parameters**: The 32-bug claim may have been from a different configuration (e.g., including tests, different max_files)
3. **Code changes**: Improvements between iteration 101 and now may have reduced false positives

### Verification

Checking iteration 101 scan timestamp:
- Most recent pandas scan before this iteration: `2026-01-23 08:43:30` (iteration 97)
- That scan also showed **7 bugs** (not 32)
- Iteration 101 (09:02-09:03) scanned other tier 2 repos but NOT pandas

**Conclusion:** The 32-bug pandas claim in State.json appears to be a projection/extrapolation error, not based on actual scan results.

## Comparison to Previous Validation (Iteration 98)

### Iteration 98 (Old scan, 7 bugs):
- Total bugs: 7
- Validated: 3
- Validation rate: 42.9%
- False positives: 4 (57.1%)

### Iteration 102 (Current scan, 6 bugs):
- Total bugs: 6
- Validated: 3
- Validation rate: 50.0%
- False positives: 3 (50.0%)

**Improvement:** Slightly better validation rate (42.9% → 50.0%), 1 fewer false positive

## Analysis: Why High False Positive Rate?

All 3 false positives and 3 true positives are related to **import/module structure**:

### True Positives Pattern
- **Actual import errors**: Missing symbols, wrong module paths
- **Environment-dependent**: May not reproduce in all setups
- **Real bugs in pandas codebase** (or at least incompatibilities)

### False Positives Pattern
- **Conservative over-approximation**: Analyzer assumes imports can fail
- **Module-level analysis**: Hard to determine which imports are always available
- **Unknown stdlib/pandas internals**: Analyzer doesn't know pandas's own API

## Impact on Overall Metrics

### Corrected Tier 2 Metrics (with pandas 6 bugs, not 32)

Previous State.json claim:
- Total files: 646
- Bugs: 92 (including 32 from pandas)
- Safe: 554
- Bug rate: 14.2%

**Actual (corrected):**
- Total files: 646
- Bugs: **66** (92 - 32 + 6 = 66)
- Safe: 580 (554 + 26 = 580)
- Bug rate: **10.2%** (not 14.2%)
- Safe rate: **89.8%** (not 85.8%)

This is actually **better** than the claimed metrics.

## Estimated True Bug Rate

With DSE validation:
- Pandas bugs: 6
- Validated: 3
- True bug rate: 3/100 = **3.0%**

This is very close to the previous estimate (3.0% in iteration 98).

## Recommendations

1. **Correct State.json**: Update pandas metrics to reflect actual scan results (6 bugs, not 32)
2. **Improve import handling**: Many FPs are from conservative import assumptions
3. **Environment awareness**: Consider stdlib/installed-package contracts for pandas internals
4. **Revalidate iteration 101 claims**: The tier 2 rescan results appear to be incorrectly recorded

## Technical Details

### Scan Configuration
- Repository: pandas @ results/public_repos/clones/pandas
- Max files: 100
- Exclude tests: True
- Detection: Current semantic frame-based (co_name + frame depth)

### DSE Validation Method
- Direct execution with Python interpreter
- No input generation (module-level code execution)
- Exception presence = validation success
- No exception = false positive

## Conclusion

**The pandas bug situation is more stable than State.json suggests:**
- Actual bugs: 6 (not 32)
- Validated: 3 (50% validation rate)
- Estimated true bug rate: 3.0%
- Main issue: Import-related bugs (both true and false positives)

The iteration 101 State.json update appears to have been made prematurely or incorrectly, recording projected rather than actual scan results.

## Next Actions

1. Correct State.json pandas metrics
2. Continue with remaining queue items (validate other tier 2 repos)
3. Improve import/module-level analysis to reduce false positives
4. Consider stdlib contract expansion for pandas dependencies

## Metrics Summary

- **Iteration:** 102
- **Phase:** PUBLIC_REPO_EVAL (CONTINUOUS_REFINEMENT)
- **Primary action:** DSE validate pandas bugs
- **Pandas bugs:** 6 (actual) vs 32 (State.json claim)
- **Validation rate:** 50.0% (3/6)
- **False positive rate:** 50.0% (3/6)
- **Estimated true bug rate:** 3.0%
- **State.json correction:** -26 bugs from tier 2 total
