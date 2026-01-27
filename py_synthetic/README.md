# py_synthetic - Synthetic Bug Detection Test Suite

A synthetic dataset for evaluating the PythonFromScratch static analyzer. Contains Python programs with planted bugs and ground truth annotations.

## Summary

| Category | Files | Bugs | Safe | F1 Score |
|----------|-------|------|------|----------|
| Standalone | 34 | 30 | 4 | 1.0000 |
| Multi-file | 10 | 8 | 2 | 1.0000 |
| **Combined** | **44** | **38** | **6** | **1.0000** |

## Bug Types Covered

- **DIV_ZERO** (10 standalone + 2 multi-file): Division/modulo by zero
- **BOUNDS** (10 standalone + 4 multi-file): Array/list index out of bounds  
- **NULL_PTR** (8 standalone + 2 multi-file): None dereference
- **ASSERT_FAIL** (2 standalone): Assertion violation
- **SAFE** (4 standalone + 2 multi-file): Correctly guarded code

## Directory Structure

```
py_synthetic/
├── standalone/           # Single-file test cases
│   ├── div_zero_*.py     # Division by zero bugs
│   ├── bounds_*.py       # Bounds checking bugs
│   ├── null_ptr_*.py     # None dereference bugs
│   ├── assert_*.py       # Assertion failures
│   ├── ground_truth.json # Expected results
│   └── evaluate.py       # Evaluation script
│
├── multifile/            # Multi-file test programs
│   ├── calc/             # Calculator program
│   ├── userdb/           # User database program
│   ├── config/           # Config parser program
│   ├── stack/            # Stack/queue program
│   ├── safemath/         # Safe math utilities (no bugs)
│   ├── ground_truth.json # Expected results
│   └── evaluate.py       # Evaluation script
│
├── evaluate_all.py       # Combined evaluation
├── combined_results.json # Latest evaluation results
└── README.md             # This file
```

## Running Evaluations

### Run all tests:
```bash
cd /path/to/PythonFromScratch
venv/bin/python py_synthetic/evaluate_all.py
```

### Run standalone tests only:
```bash
venv/bin/python py_synthetic/standalone/evaluate.py
```

### Run multi-file tests only:
```bash
venv/bin/python py_synthetic/multifile/evaluate.py
```

## Evaluation Metrics

- **Precision**: True Positives / (True Positives + False Positives)
- **Recall**: True Positives / (True Positives + False Negatives)
- **F1 Score**: 2 × Precision × Recall / (Precision + Recall)

A bug is counted as a **True Positive** if:
1. The analyzer reports any bug type (not SAFE)
2. The ground truth expects a bug

Note: The analyzer may detect a different bug type than expected (e.g., PANIC instead of BOUNDS). This is still counted as a True Positive since a bug was detected.

## Latest Results

```
COMBINED TOTALS:
  True Positives:  38
  False Positives: 0
  False Negatives: 0
  True Negatives:  6
  Errors:          0
  Precision: 1.0000
  Recall:    1.0000
  F1 Score:  1.0000
```
