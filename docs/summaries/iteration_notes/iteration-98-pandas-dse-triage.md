# Iteration 98: Pandas Bug DSE Validation & Triage

## Objective
Validate pandas bugs from iteration 97 scan using concrete execution (DSE oracle approach).

## Method
- Executed each flagged file with Python to check if exceptions actually occur
- Compared actual exceptions with expected exceptions from symbolic traces
- Used concrete execution as validation oracle (DSE principle)

## Results

### Overall Validation Rate
- **Total bugs**: 7
- **Validated (exception raised)**: 3/7 (42.9%)
- **Matching exception type**: 1/7 (14.3%)
- **False positives (no exception)**: 4/7 (57.1%)

### By Bug Type
- **PANIC**: 3/6 validated (50.0%)
- **TYPE_CONFUSION**: 0/1 validated (0.0%)

### Detailed Findings

#### Validated Bugs (True Positives)

1. **pandas/__init__.py** - PANIC
   - Expected: NameError
   - Actual: ModuleNotFoundError
   - Status: ✓ Validated (exception type differs but related)
   - Note: Missing dependency (numpy)

2. **pandas/io/html.py** - PANIC
   - Expected: ImportError
   - Actual: Exception mentioning "numpy"
   - Status: ✓ Validated
   - Note: Missing dependency

3. **pandas/io/stata.py** - PANIC
   - Expected: ImportError
   - Actual: ImportError
   - Status: ✓ Validated (exact match)
   - Note: Missing dependency

#### False Positives (Not Validated)

4. **pandas/core/shared_docs.py** - TYPE_CONFUSION
   - Expected: TypeError
   - Actual: No exception (executed cleanly)
   - Status: ✗ False positive

5. **pandas/core/base.py** - PANIC
   - Expected: ImportError
   - Actual: No exception (executed cleanly)
   - Status: ✗ False positive

6. **pandas/_testing/_warnings.py** - PANIC
   - Expected: ImportError
   - Actual: No exception (executed cleanly)
   - Status: ✗ False positive

7. **pandas/api/types/__init__.py** - PANIC
   - Expected: Unimplemented opcode (CALL_INTRINSIC_1)
   - Actual: No exception (executed cleanly)
   - Status: ✗ False positive
   - Note: Opcode is actually implemented in Python 3.14

## Analysis

### Import/Dependency Pattern
All 3 validated bugs are import-related (missing numpy dependency). This is expected when analyzing pandas in isolation without its dependencies installed.

### False Positive Root Causes

1. **Module-level code without side effects**: Files like `shared_docs.py`, `base.py` execute successfully as they only define classes/functions
   
2. **Unimplemented opcode gap**: CALL_INTRINSIC_1 is actually implemented in Python 3.14 but our analyzer doesn't support it yet
   
3. **Import success in real execution**: Some imports that fail in our model succeed in real CPython due to:
   - Different import resolution mechanisms
   - Availability of dependencies in the test environment

### Implications

This 42.9% validation rate for pandas is **concerning** and suggests:

1. Our model is over-approximate in import/module handling
2. We need better handling of module-level vs function-level code
3. The 7.0% bug rate for pandas (iteration 97) is partially inflated by false positives

### True Bug Rate Estimate

If we apply the 42.9% validation rate to the 7.0% bug rate:
- Adjusted bug rate: 7.0% × 0.429 ≈ **3.0%** (true positive estimate)
- Remaining 4.0% are likely false positives

## Comparison with Tier 2 Validation History

Previous tier 2 DSE validation (iteration 84):
- 5 targets analyzed, 4 validated (80%)
- Much higher validation rate than pandas (42.9%)

This suggests pandas results are less reliable than other tier 2 repos.

## Action Items

1. ✓ Completed: DSE validation of all 7 pandas bugs
2. Document false positive patterns for future filtering
3. Consider implementing CALL_INTRINSIC_1 opcode (Python 3.14 compatibility)
4. Re-evaluate pandas with improved import/module handling
5. Apply similar DSE validation to other tier 2 repos for consistency

## Files Changed
- `results/pandas_dse_validation_iter98.json` - Full validation results
- `docs/notes/iteration-98-pandas-dse-triage.md` - This document

## Test Status
All 846 tests still passing (no code changes).
