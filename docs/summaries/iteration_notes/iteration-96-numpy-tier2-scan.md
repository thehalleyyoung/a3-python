# Iteration 96: Numpy Tier 2 Scan

## Objective
Expand tier 2 evaluation by scanning numpy, a fundamental scientific computing library (~27k stars).

## Actions Taken

1. **Added numpy to tier 2 repos**
   - Updated `pyfromscratch/evaluation/repo_list.py` to include numpy
   - Cloned numpy repository from https://github.com/numpy/numpy

2. **Scanned 100 numpy files with module-init filtering**
   - Used existing scanner infrastructure
   - Applied module-init phase detection and filtering

## Results

### Numpy Scan Summary
- **Total files**: 100
- **BUG**: 21 (21.0%)
- **SAFE**: 79 (79.0%)
- **UNKNOWN**: 0
- **ERROR**: 0

### Bug Type Distribution
- **PANIC**: 19 (90.5% of bugs) - mostly NameError/ImportError
- **TYPE_CONFUSION**: 2 (9.5% of bugs)

### Module-Init Filtering Impact
- **Filtered**: 21 findings (module initialization phase artifacts)
- **Not filtered**: 79 findings (actual function/class-level code)

### Key Observations

1. **Best SAFE Rate in Tier 2**: Numpy achieved 79.0% SAFE rate, significantly better than other tier 2 repos:
   - numpy: 79.0% SAFE (21.0% BUG)
   - httpie: 58.4% SAFE (41.6% BUG)
   - ansible: 62.0% SAFE (38.0% BUG)
   - django: 59.0% SAFE (41.0% BUG)
   - black: 26.2% SAFE (73.8% BUG)
   - scikit-learn: 23.0% SAFE (77.0% BUG)

2. **Bug Pattern**: Most bugs (90.5%) are PANIC type, primarily from import-time code execution issues (NameError, ImportError).

3. **Quality Indicator**: Numpy's high SAFE rate suggests:
   - Well-structured codebase with clean module boundaries
   - Less aggressive module-level execution
   - Better separation of initialization from functional code

4. **Type Confusion Instances**: Only 2 TYPE_CONFUSION bugs found, both in documentation plot examples:
   - `doc/source/user/plots/meshgrid_plot.py`
   - `doc/source/user/plots/matplotlib3.py`

### Tier 2 Aggregate Metrics (Now 6 repos)
- **Total files**: 550
- **Average BUG rate**: ~40.0% (across all repos)
- **Numpy impact**: Brings down average BUG rate due to high SAFE rate
- **Range**: 21.0% (numpy) to 77.0% (scikit-learn)

## Technical Notes

1. **Scanner Stability**: All 100 files analyzed successfully with no ERROR states.

2. **Module-Init Filtering Working**: The filtering correctly identifies and marks 21 findings as module-init artifacts.

3. **No UNKNOWN Results**: All files produced definitive BUG or SAFE verdicts.

## Next Steps

1. Consider scanning additional tier 2/3 repos (tensorflow, sympy, pandas)
2. Triage a sample of numpy bugs with DSE validation
3. Investigate why numpy has such a high SAFE rate compared to other tier 2 repos
4. Expand stdlib contracts based on numpy patterns (if any new patterns found)

## Files Changed
- `pyfromscratch/evaluation/repo_list.py`: Added numpy to TIER_2_REPOS
- `docs/notes/iteration-96-numpy-tier2-scan.md`: This file
- `results/iteration_96_numpy_scan.log`: Scan output
- `results/public_repos/scan_results/numpy_*.json`: Detailed results

## Tests
All existing tests continue to pass (846 tests).
