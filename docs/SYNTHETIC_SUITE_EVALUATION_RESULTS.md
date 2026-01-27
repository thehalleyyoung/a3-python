# Synthetic Suite Evaluation Results

**Date**: 2026-01-23  
**Iteration**: 199  
**Suite Size**: 200 tests (100 true positives, 100 true negatives) across 20 bug types

## Executive Summary

The synthetic suite validation revealed a **critical semantic gap** in the analyzer:

- **Recall: 0.0%** - The analyzer detected 0 out of ~95 true bugs
- **Precision: 0.0%** - When it did report bugs (2 cases), both were false positives  
- **Accuracy: 48.9%** - Only correct on true negatives (93/190 analyzed files)

## Root Cause Analysis

The analyzer is **not analyzing function bodies** that are called from module-level code. All test files follow this pattern:

```python
def buggy_function():
    assert False  # BUG HERE
    return 42

if __name__ == "__main__":
    result = buggy_function()  # Bug is in the function, not at module level
```

The analyzer appears to:
1. Only analyze module-level bytecode
2. Return SAFE with a constant barrier (barrier value 5.0) when no bugs are found at module level
3. Never enter function bodies to check for bugs within them

## Specific Examples

### False Negative #1: ASSERT_FAIL
**File**: `ASSERT_FAIL/tp_01_unconditional_assert_false.py`  
**Expected**: BUG (ASSERT_FAIL)  
**Actual**: SAFE  
**Issue**: Function contains `assert False` which is never reached by analyzer

### False Negative #2: DIV_ZERO  
**File**: `DIV_ZERO/tp_01_direct_literal.py`  
**Expected**: BUG (DIV_ZERO)  
**Actual**: SAFE  
**Issue**: Function contains `x / 0` which is never analyzed

## Per-Bug-Type Breakdown

All 19 bug types showed the same pattern:
- **True Positives**: 0 (0%)
- **True Negatives**: 4-5 (50%)  
- **False Negatives**: 5 per type (100% of bugs missed)
- **False Positives**: 0-1 (rare, only in INFO_LEAK and PANIC)

## Required Fixes (Semantic, Not Heuristic)

To fix this fundamental issue, the analyzer must:

1. **Interprocedural Analysis**: When analyzing `if __name__ == "__main__"` block, follow function calls into their bodies
2. **Entry Point Detection**: Identify all reachable code from module entry points
3. **Call Graph Construction**: Build a call graph and analyze all reachable functions
4. **Proper Unsafe Region Checks**: Check unsafe predicates within function scopes, not just module scope

## Anti-Cheating Validation

The current approach is **not cheating** (no text patterns, no heuristics), but it's also **not working**. The analyzer:
- ✅ Uses Z3 and symbolic execution (correct approach)
- ✅ Returns barrier certificates (correct approach)
- ❌ But only analyzes module-level code (semantic gap)
- ❌ Never reaches the actual bug locations in function bodies

## Next Actions

1. **CRITICAL FIX**: Implement interprocedural analysis to enter function bodies
2. **Entry Point Handling**: Properly handle `if __name__ == "__main__"` as an analysis entry point
3. **Call Graph**: Build call graph and analyze all reachable functions from entry points
4. **Re-run Suite**: After fix, re-run synthetic suite and expect recall close to 100%

## Notes

- The 2 false positives (INFO_LEAK, PANIC) suggest some module-level code is being analyzed
- The 93 true negatives confirm the barrier certificate mechanism works for SAFE cases
- This is a **semantic correctness issue**, not a precision/heuristic issue
- Fix must preserve the Z3/barrier-certificate approach (no regex/AST heuristics)
