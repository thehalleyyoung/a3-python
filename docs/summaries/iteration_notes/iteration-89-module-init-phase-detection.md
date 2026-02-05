# Iteration 89: Module-Init Phase Detection Flag for Import-Heavy Traces

## Objective

Add module-init phase detection to flag traces with heavy imports in early execution. This helps triage potential false positives in import-time code where incomplete import modeling may cause spurious bug reports.

## Problem

From tier 2 comparative analysis (iteration 85), import-heavy traces were identified as a source of potential false positives:
- Many tier 2 repos have extensive module-level imports (django, scikit-learn, black)
- Import-time execution involves complex stdlib contract interactions
- Bugs in module-init phase may reflect incomplete import context modeling rather than real application bugs
- Need a way to flag these traces for manual triage/refinement

## Solution

Implemented semantic module-init phase detection based on:
1. **Import count tracking**: Count IMPORT_NAME opcodes during execution
2. **Early execution heuristic**: Check if imports occur in early bytecode offsets (< 200)
3. **Threshold heuristic**: Flag as module-init if 3+ imports in early execution

Detection logic in `symbolic_vm.py`:
- Increment `state.import_count` on each IMPORT_NAME opcode
- Set `state.module_init_phase = True` if import_count >= 3 and offset < 200
- These flags persist through path exploration and counterexample extraction

## Implementation Details

### Changes Made

1. **SymbolicMachineState** (`pyfromscratch/semantics/symbolic_vm.py`):
   - Added `module_init_phase: bool = False` field
   - Added `import_count: int = 0` field
   - Updated `copy()` method to preserve these fields

2. **IMPORT_NAME opcode handler** (`pyfromscratch/semantics/symbolic_vm.py`):
   - Increment `state.import_count` on each IMPORT_NAME
   - Check heuristic: `frame.instruction_offset < 200 and state.import_count >= 3`
   - Set `state.module_init_phase = True` if heuristic matches

3. **Counterexample metadata** (`pyfromscratch/unsafe/registry.py`):
   - `check_unsafe_regions()` now adds `module_init_phase` and `import_count` to all counterexamples
   - This metadata flows through the entire analysis pipeline

4. **Display formatting** (`pyfromscratch/analyzer.py`):
   - `_format_counterexample()` now shows a warning for module-init traces:
     ```
     ⚠ MODULE-INIT PHASE: Trace has 5 imports in early execution
       (Potential FP: bug may be in import-time code, needs import context)
     ```

5. **Public repo scanning** (`pyfromscratch/evaluation/scanner.py`, `pyfromscratch/analyzer.py`):
   - Added `module_init_phase` and `import_count` fields to `Finding` and `BugFinding` dataclasses
   - Metadata propagated from counterexamples through to scan results

## Testing

Created comprehensive test suite in `tests/test_module_init_detection.py`:

1. **test_module_init_phase_detection**:
   - Code with 5 module-level imports → module_init_phase=True
   - Verified import_count >= 3

2. **test_no_module_init_phase_for_normal_code**:
   - Code with no imports → module_init_phase=False
   - Verified import_count=0

3. **test_module_init_phase_with_late_imports**:
   - Imports inside functions (late in execution) → may or may not flag
   - Test verifies metadata exists, agnostic to verdict

All 828 tests pass (3 new tests added).

## Semantics Faithfulness

This feature is **pure metadata annotation** — it does not change:
- The symbolic execution semantics
- The unsafe predicates
- The BUG/SAFE/UNKNOWN decision logic
- Any path condition or reachability computation

The detection is a **triage heuristic** for human review, explicitly labeled as such in output. It follows the anti-cheating rule: the semantic model still decides BUG/SAFE/UNKNOWN; this flag only helps prioritize which findings to investigate first.

## Next Steps (from State.json queue)

1. ✅ **DONE**: Add module-init phase detection flag for import-heavy traces (this iteration)
2. **NEXT**: Investigate SAFE proof synthesis gap in tier 2 (50.9% vs tier 1 100%)
3. **THEN**: Scan additional tier 2 repo (tensorflow, numpy, or sympy) for broader coverage
4. **THEN**: Expand opcode coverage for any tier 2 UNKNOWN patterns (currently 0%)

## Use Cases

When scanning public repos, findings with `module_init_phase=True` should be:
1. **Triaged with extra context**: Check if the bug is actually reachable in application code (not just at import time)
2. **DSE validated**: Run concolic execution to confirm concrete reachability
3. **Import contracts refined**: If FP, the root cause is likely a missing/imprecise stdlib contract for import machinery

This flag helps prioritize refinement efforts: module-init FPs → stdlib contract expansion (not app code bugs).

## Metrics

- **Heuristic parameters**:
  - Import threshold: 3 IMPORT_NAME opcodes
  - Offset threshold: 200 bytecode instruction offsets
  - Both are conservative (favor flagging too many, not too few)

- **Expected tier 2 impact**:
  - Django, scikit-learn, ansible have extensive imports at module level
  - Black has heavy AST imports
  - Httpie has moderate imports
  - Expect 10-30% of tier 2 BUG findings to be flagged as module-init

- **No false negatives**: This flag is only for triage; it never suppresses BUG findings, only annotates them

## Anti-Cheating Confirmation

- ✅ No regex/pattern matching on source text
- ✅ No heuristics used as BUG/SAFE decider (only metadata for human triage)
- ✅ Semantic detection based on bytecode opcode counts and instruction offsets
- ✅ Explicit labeling as "potential FP" heuristic (not a proof)
- ✅ DSE validation still required for concrete repro
- ✅ No impact on barrier synthesis or unsafe predicates

## Iteration Summary

- **Status**: Complete
- **Changes**: 5 files modified (symbolic_vm.py, registry.py, analyzer.py, scanner.py, test_unsafe_send_sync.py)
- **New files**: 1 test file (test_module_init_detection.py)
- **Tests**: 828 passed (3 new, 0 broken)
- **Bug types**: No change (still 20 implemented and validated)
- **Phase**: PUBLIC_REPO_EVAL (continuing refinement)
- **Anti-cheating**: ✓ Compliant (pure metadata, no decision impact)
