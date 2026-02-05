# Synthetic Suite Ground Truth Validation Infrastructure

## Overview

This document describes the ground truth validation infrastructure for the PythonFromScratch analyzer. The synthetic test suite provides labeled test cases for all 20 bug types to enable precise measurement of analyzer performance.

## Files Created

### 1. Ground Truth Manifest
**File:** `tests/synthetic_suite/GROUND_TRUTH_MANIFEST.json`

A comprehensive JSON manifest containing expected results for all 200 test files (10 per bug type).

**Structure:**
```json
{
  "metadata": { ... },
  "bug_types": {
    "ASSERT_FAIL": {
      "tp_01_unconditional_assert_false.py": {
        "expected": "BUG",
        "bug_type": "ASSERT_FAIL",
        "reason": "...",
        "unsafe_line": "..."
      },
      "tn_01_always_true_condition.py": {
        "expected": "SAFE",
        "reason": "..."
      },
      ...
    },
    ...
  }
}
```

**Key fields:**
- `expected`: "BUG" or "SAFE" (the ground truth verdict)
- `bug_type`: Which bug class this tests (for BUG cases)
- `reason`: Human-readable explanation of why this verdict is correct
- `unsafe_line`: The specific line that triggers the bug (for BUG cases)

### 2. Validation Script
**File:** `scripts/validate_synthetic_suite.py`

Compares analyzer output against ground truth and computes metrics.

**Usage:**
```bash
python scripts/validate_synthetic_suite.py \
  --results results/synthetic_suite_results.json \
  --manifest tests/synthetic_suite/GROUND_TRUTH_MANIFEST.json \
  --verbose
```

**Outputs:**
- Overall metrics (precision, recall, accuracy, F1)
- Per-bug-type breakdown
- List of all discrepancies (false positives and false negatives)
- Pass/fail verdict

**Exit codes:**
- 0: All tests passed (perfect match)
- 1: Discrepancies found

### 3. Suite Runner
**File:** `scripts/run_synthetic_suite.py`

Runs the analyzer on all 200 test files and saves results in JSON format.

**Usage:**
```bash
python scripts/run_synthetic_suite.py \
  --suite tests/synthetic_suite \
  --output results/synthetic_suite_results.json \
  --verbose
```

**Output format:**
```json
{
  "metadata": {
    "timestamp": "...",
    "total_files": 200,
    "suite_directory": "..."
  },
  "results": {
    "tests/synthetic_suite/BOUNDS/tp_01_list_index_out_of_range.py": {
      "verdict": "BUG",
      "bug_type": "BOUNDS",
      "counterexample": { ... },
      "paths_explored": 5,
      "error": null
    },
    ...
  }
}
```

## Workflow

### Complete Validation Cycle

1. **Run analyzer on all tests:**
   ```bash
   python scripts/run_synthetic_suite.py \
     --output results/synthetic_suite_results.json
   ```

2. **Validate results:**
   ```bash
   python scripts/validate_synthetic_suite.py \
     --results results/synthetic_suite_results.json
   ```

3. **Review discrepancies:**
   - Check the validation output for false positives/negatives
   - Review the specific test files flagged
   - Determine if the issue is:
     - Analyzer bug (most likely → fix the symbolic model)
     - Ground truth mislabel (rare → update manifest)

4. **Fix and iterate:**
   - Fix analyzer bugs (semantic model issues, not heuristics)
   - Re-run both scripts
   - Repeat until 100% accuracy achieved

## Metrics Definitions

### Confusion Matrix Terms

- **True Positive (TP):** Analyzer says BUG, ground truth says BUG ✓
- **True Negative (TN):** Analyzer says SAFE, ground truth says SAFE ✓
- **False Positive (FP):** Analyzer says BUG, ground truth says SAFE ✗
- **False Negative (FN):** Analyzer says SAFE, ground truth says BUG ✗
- **Unknown (UNK):** Analyzer returns UNKNOWN (conservative, acceptable)

### Performance Metrics

```
Precision = TP / (TP + FP)
  → Of all bugs reported, what fraction are real?
  → Target: 1.0 (no false alarms)

Recall = TP / (TP + FN)
  → Of all real bugs, what fraction did we find?
  → Target: 1.0 (no missed bugs)

Accuracy = (TP + TN) / Total
  → Overall correctness
  → Target: 1.0

F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
  → Harmonic mean of precision and recall
  → Target: 1.0
```

## Test Coverage

### 20 Bug Types × 10 Tests Each = 200 Total

Each bug type has:
- **5 True Positives:** Known buggy code that MUST be detected
- **5 True Negatives:** Safe code that MUST NOT be flagged

### Bug Type Breakdown

1. **INTEGER_OVERFLOW** - ctypes/array overflow at native boundary
2. **DIV_ZERO** - Division/modulo by zero
3. **FP_DOMAIN** - Math domain errors (sqrt negative, log zero, etc.)
4. **USE_AFTER_FREE** - Resource use after close/del
5. **DOUBLE_FREE** - Multiple close() calls on same resource
6. **MEMORY_LEAK** - Unbounded growth/circular references
7. **UNINIT_MEMORY** - Use before assignment
8. **NULL_PTR** - None dereference (method call, subscript, etc.)
9. **BOUNDS** - Index out of range, missing dict key
10. **DATA_RACE** - Shared mutable state without synchronization
11. **DEADLOCK** - Circular lock acquisition
12. **SEND_SYNC** - Non-thread-safe object shared across threads
13. **NON_TERMINATION** - Infinite loops, unbounded recursion
14. **PANIC** - Unhandled exception propagation
15. **ASSERT_FAIL** - Assert statement failure
16. **STACK_OVERFLOW** - Recursion exceeding stack limit
17. **TYPE_CONFUSION** - Wrong type passed to operation
18. **ITERATOR_INVALID** - Collection modified during iteration
19. **INFO_LEAK** - Secret data leaked to logs/errors
20. **TIMING_CHANNEL** - Secret-dependent timing differences

## Anti-Cheating Constraints

The analyzer **MUST NOT:**
- Parse test file names/paths as signals
- Hardcode behaviors specific to this test suite
- Use regex/pattern matching on source text as the decider
- Rely on comments/docstrings/variable names

Every BUG/SAFE verdict **MUST** come from:
- Bytecode-level symbolic execution
- Z3 constraint solving
- Barrier certificate proofs
- Semantic unsafe predicates

## Expected Quality Bar

### Target Metrics (Phase: SYNTHETIC_SUITE)
- Precision: **1.0** (no false positives)
- Recall: **1.0** (no false negatives)
- Accuracy: **1.0** (all verdicts correct)

### UNKNOWN Handling
- UNKNOWN is acceptable (conservative approximation)
- But track ratio: too many UNKNOWNs indicate weak model
- Target: <10% unknown rate on synthetic suite

### When Discrepancies Occur

**Decision tree:**
1. Is the ground truth label correct?
   - Check the test code and reasoning
   - Verify against Python semantics
   - If wrong: update `GROUND_TRUTH_MANIFEST.json`

2. If ground truth is correct:
   - The analyzer has a semantic model bug
   - **Do not add heuristics**
   - Fix the symbolic execution, unsafe predicates, or barrier synthesis
   - Re-run validation

3. Common analyzer issues:
   - Missing bytecode opcode handlers
   - Incorrect exception semantics
   - Over-approximate unknown call models (false positives)
   - Under-approximate unknown call models (false negatives)
   - Barrier synthesis too weak (UNKNOWN instead of SAFE)

## Integration with State.json

The validation results should be recorded in `State.json`:

```json
{
  "progress": {
    "evaluation": {
      "synthetic_suite": true,
      "last_validation": {
        "timestamp": "...",
        "precision": 1.0,
        "recall": 1.0,
        "accuracy": 1.0,
        "f1_score": 1.0,
        "false_positives": 0,
        "false_negatives": 0,
        "unknowns": 15
      }
    }
  }
}
```

## Next Steps After Validation

Once synthetic suite passes (100% accuracy):
1. Move to `PUBLIC_REPO_EVAL` phase
2. Clone real-world Python projects
3. Scan for bugs
4. Triage findings (true positives vs false positives)
5. Fix any false positives by improving semantics
6. Document true positives in `TRUE_POSITIVES_<repo>.md`

## Files Reference

- Manifest: `tests/synthetic_suite/GROUND_TRUTH_MANIFEST.json`
- Runner: `scripts/run_synthetic_suite.py`
- Validator: `scripts/validate_synthetic_suite.py`
- Suite README: `tests/synthetic_suite/README.md`
- Results (gitignored): `results/synthetic_suite_results.json`
