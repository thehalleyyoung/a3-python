# DSE-Based Barrier Analysis Refactoring

**Date**: January 30, 2026  
**Iteration**: 613  
**Goal**: Remove all ad-hoc heuristics and use proper Z3/DSE-based barrier analysis

---

## Summary

This refactoring removes name-based heuristics from bug detection and replaces them with proper Z3-backed DSE (Dynamic Symbolic Execution) and barrier certificate synthesis.

### Key Principle

From `barrier-certificate-theory.tex`:
- **Safety** is `B(s) >= 0` where `B` incorporates guards
- A bug is only real if Z3 **proves** the unsafe state is reachable
- If DSE finds no bugs AND barrier synthesis succeeds → **SAFE proof**

---

## Changes Made

### 1. Removed Ad-Hoc Heuristics from crash_summaries.py

**Before** (ad-hoc heuristics):
```python
NEVER_NONE_NAMES = frozenset({'self', 'cls', 'os', 'sys', 'np', 'pd', ...})
PATH_RELATED_NAMES = frozenset({'path', 'dir', 'folder', ...})

def _is_safe_divisor_pattern(self, node):
    if any(s in attr for s in ['count', 'size', 'num', 'batch_size']):
        return True  # HEURISTIC - unsound!
```

**After** (principled approach):
```python
# REMOVED: NEVER_NONE_NAMES, PATH_RELATED_NAMES
# Use:
# 1. SymbolicVM with Z3 for reachability checking
# 2. GuardDataflowAnalysis for guard propagation through CFG
# 3. Type annotations for nullability
# 4. Barrier certificate synthesis for safety proofs
```

### 2. Created DSE-Based Bug Detector

New file: `dse_bug_detector.py`

```python
def analyze_function_with_dse(code, func_name, file_path, max_steps=100):
    """
    Proper DSE approach:
    1. Run SymbolicVM.explore_bounded() 
    2. Check each path with check_unsafe_regions()
    3. Report only Z3-verified reachable bugs
    """
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=max_steps)
    
    for path in paths:
        result = check_unsafe_regions(path.state, path.trace)
        if result:
            # Bug is Z3-verified reachable!
            bugs.append(result)
```

### 3. Deprecated Heuristic-Based Analyzer Files

Renamed to `deprecated_*`:
- `analyze_with_guards.py` → `deprecated_analyze_with_guards.py`
- `analyze_repos_fast.py` → `deprecated_analyze_repos_fast.py`
- `quick_scan.py` → `deprecated_quick_scan.py`
- `analyze_fps.py` → `deprecated_analyze_fps.py`

### 4. Added DSE Verification to InterproceduralBugTracker

New method in `interprocedural_bugs.py`:
```python
def verify_bugs_with_dse(self, bugs, max_steps=100):
    """
    Verify bugs using DSE with Z3-backed symbolic execution.
    
    Returns:
        (confirmed_bugs, refuted_bugs, unknown_bugs)
    """
    for func_name, func_bugs in bugs_by_function.items():
        vm = SymbolicVM()
        paths = vm.explore_bounded(func_code, max_steps=max_steps)
        
        reachable_bug_types = set()
        for path in paths:
            result = check_unsafe_regions(path.state, path.trace)
            if result:
                reachable_bug_types.add(result.get('bug_type'))
        
        # Classify: confirmed if DSE found it, refuted if DSE exhaustively explored
```

New method:
```python
def find_all_bugs_with_dse_verification(self, max_dse_steps=100):
    """Full pipeline: summary-based detection + DSE verification"""
    bugs = self.find_all_bugs()
    confirmed, refuted, unknown = self.verify_bugs_with_dse(bugs)
    return confirmed + unknown  # Drop refuted (likely FPs)
```

### 5. Added --dse-verify CLI Option

In `cli.py`:
```bash
pyfromscratch myproject/ --interprocedural --dse-verify --max-dse-steps 100
```

### 6. Updated Analyzer.analyze_project_interprocedural

New parameters:
```python
def analyze_project_interprocedural(
    self,
    root_path: Path,
    entry_points: Optional[List[str]] = None,
    dse_verify: bool = False,      # NEW
    max_dse_steps: int = 100,      # NEW
)
```

New helper method:
```python
def _verify_bugs_with_dse(self, results, context, max_steps):
    """
    For each bug found, run SymbolicVM and check if Z3 proves reachability.
    """
    for ep_name, bug_types in results['bugs_by_entry_point'].items():
        vm = SymbolicVM(solver_timeout_ms=5000)
        paths = vm.explore_bounded(func_info.code_object, max_steps=max_steps)
        
        reachable_bug_types = set()
        for path in paths:
            result = check_unsafe_regions(path.state, path.trace)
            if result:
                reachable_bug_types.add(result.get('bug_type'))
        
        # Keep only Z3-verified bugs
        verified_for_ep = [bt for bt in bug_types if bt in reachable_bug_types]
```

---

## What's Acceptable vs Not Acceptable

### ACCEPTABLE: Sensitivity Inference for Security Bugs

```python
def infer_sensitivity_from_name(var_name):
    """Infer if a variable is sensitive (password, api_key, etc.)"""
    if 'password' in name_lower:
        return SourceType.PASSWORD
```

This is **acceptable** because:
- It **adds** taint labels for security analysis
- The Z3/DSE then **verifies** if tainted data reaches dangerous sinks
- It matches CodeQL's behavior for cleartext detection

### ACCEPTABLE: Barrier Synthesis Template Hints

```python
if any(hint in var_name.lower() for hint in ['i', 'iter', 'count']):
    yield loop_range_barrier(var_extractor, max_iter)
```

This is **acceptable** because:
- It **guides** barrier template generation
- Z3 **verifies** the barrier is actually inductive
- Incorrect hints just waste synthesis time, don't cause unsoundness

### NOT ACCEPTABLE: Bug Suppression Based on Names

```python
# DON'T DO THIS
if 'count' in node.id.lower():
    return  # Skip DIV_ZERO check - WRONG!

# DON'T DO THIS
if obj.id in NEVER_NONE_NAMES:
    return  # Skip NULL_PTR check - WRONG!
```

This is **not acceptable** because:
- It **hides** real bugs based on naming assumptions
- No Z3/DSE verification of the assumption
- Leads to false negatives

---

## Architecture

```
                    ┌─────────────────────┐
                    │   SymbolicVM (Z3)   │
                    │  explore_bounded()  │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │ check_unsafe_regions│
                    │  (UNSAFE_PREDICATES)│
                    └─────────┬───────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌─────────┐     ┌─────────┐     ┌─────────┐
        │ DIV_ZERO│     │ NULL_PTR│     │  BOUNDS │
        │ div_by_ │     │ none_   │     │  index_ │
        │ zero_   │     │ misuse_ │     │  error_ │
        │ reached │     │ reached │     │  reached│
        └─────────┘     └─────────┘     └─────────┘

Each predicate is checked by Z3 on the symbolic path condition!
```

---

## Usage

### Full DSE-Verified Analysis

```bash
# Single file with DSE
python -m pyfromscratch myfile.py --verbose

# Project with interprocedural + DSE verification
python -m pyfromscratch myproject/ --interprocedural --dse-verify

# Using the standalone DSE detector
python dse_bug_detector.py --repo Qlib --max-steps 50
```

### Programmatic API

```python
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker

tracker = InterproceduralBugTracker.from_project(Path("myproject"))

# Fast: summary-based (may have FPs)
bugs = tracker.find_all_bugs()

# Accurate: with DSE verification
bugs = tracker.find_all_bugs_with_dse_verification(max_dse_steps=100)
```

---

## Testing

To verify the refactoring works:

```bash
# Run tests
cd /Users/halleyyoung/Documents/PythonFromScratch
pytest tests/test_unsafe_div_zero.py -v

# Test on pygoat
python -m pyfromscratch external_tools/pygoat --interprocedural --dse-verify
```

---

## Files Modified

1. `pyfromscratch/semantics/crash_summaries.py`
   - Removed `NEVER_NONE_NAMES`, `PATH_RELATED_NAMES`
   - Removed `_is_safe_divisor_pattern`
   - Updated `visit_Attribute` to use type annotations instead of name matching

2. `pyfromscratch/semantics/interprocedural_bugs.py`
   - Added `verify_bugs_with_dse()` method
   - Added `find_all_bugs_with_dse_verification()` method
   - Added `_find_code_object()` helper

3. `pyfromscratch/analyzer.py`
   - Added `dse_verify` and `max_dse_steps` parameters to `analyze_project_interprocedural()`
   - Added `_verify_bugs_with_dse()` helper method

4. `pyfromscratch/cli.py`
   - Added `--dse-verify` option
   - Added `--max-dse-steps` option

5. `dse_bug_detector.py` (new)
   - Standalone DSE-based bug detector
   - `analyze_function_with_dse()`
   - `analyze_with_barrier_synthesis()`
   - `analyze_interprocedural_with_dse()`

6. Deprecated files (renamed with `deprecated_` prefix)
   - `deprecated_analyze_with_guards.py`
   - `deprecated_analyze_repos_fast.py`
   - `deprecated_quick_scan.py`
   - `deprecated_analyze_fps.py`
