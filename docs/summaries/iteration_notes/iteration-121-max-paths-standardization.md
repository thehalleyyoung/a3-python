# Iteration 121: max_paths Configuration Standardization

**Date**: 2026-01-23  
**Status**: Complete  
**Test Status**: All 907 tests passing

## Issue

Discrepancy between `Analyzer.__init__` default `max_paths` and the scanner's `analyze_file` function:
- `Analyzer.__init__`: max_paths=500 (default)
- `analyze_file()`: max_paths=2000 (scanner default)

This meant CLI usage (via `analyze()`) explored fewer paths than the scanner, leading to inconsistent results and potentially more UNKNOWN verdicts for CLI users.

## Root Cause

The `Analyzer` class was initialized with max_paths=500 as a conservative default from early iterations. Later, the scanner function `analyze_file()` increased its default to 2000 for better coverage on public repos, but the `Analyzer.__init__` default was never updated.

## Fix

Changed `Analyzer.__init__` default from max_paths=500 to max_paths=2000:

```python
def __init__(
    self,
    max_paths: int = 2000,  # Changed from 500
    max_depth: int = 2000,
    timeout_ms: int = 10000,
    verbose: bool = False
):
```

## Impact

1. **CLI consistency**: CLI now explores same number of paths as scanner by default
2. **Barrier synthesis soundness**: More paths explored before declaring UNKNOWN or attempting SAFE proof
3. **No test breakage**: All 907 tests still pass (one pre-existing test bug fixed in test_unpack_sequence_fix.py)

## Secondary Fix

Fixed pre-existing bug in `tests/test_unpack_sequence_fix.py`:
- Tests were calling `analyze(code, filename=...)` with wrong signature
- Fixed to use `analyze(filepath)` with tempfile approach
- All 5 tests now pass correctly

## Semantic Justification

This is a configuration change, not a semantics change. The analyzer behavior remains identical; we're just exploring more paths by default. This aligns with the barrier-certificate soundness requirement: we must explore enough of the state space before claiming SAFE or giving up with UNKNOWN.

The change maintains the invariant that max_paths can still be overridden by callers who need different limits.

## Files Changed

- `pyfromscratch/analyzer.py`: Updated Analyzer.__init__ default
- `tests/test_unpack_sequence_fix.py`: Fixed test signature bug
- `docs/notes/iteration-121-max-paths-standardization.md`: This file

## Queue Update

Removed completed action:
- ✅ "CONTINUOUS_REFINEMENT: Standardize max_paths across CLI and scanner (currently 500 vs 2000)"

This was a duplicate in the queue (appeared twice), so removed both instances.
