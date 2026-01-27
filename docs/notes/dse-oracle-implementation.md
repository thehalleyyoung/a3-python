# DSE (Dynamic Symbolic Execution) Oracle - Implementation Notes

## Overview

DSE is implemented as a **refinement oracle** for the PythonFromScratch barrier certificate verifier. It serves two critical purposes while maintaining soundness.

## Key Principle: Under-Approximate Oracle

**DSE can prove feasibility but NEVER infeasibility.**

- ✅ When DSE finds concrete inputs: The trace IS realizable
- ❌ When DSE fails: We know NOTHING (timeout, incomplete theory, or actually infeasible)

## Implementation Components

### 1. ConcreteExecutor (`pyfromscratch/dse/concolic.py`)

Executes Python bytecode with concrete inputs and records execution traces.

**Features:**
- Uses `sys.settrace()` to record bytecode offsets
- Captures stdout/stderr
- Records exceptions vs normal returns
- Max-steps limit to prevent infinite loops

**Not used for:**
- Proving safety (no proof = no SAFE claim)
- Shrinking over-approximations

### 2. TraceValidator

Attempts to realize symbolic paths by finding concrete inputs.

**Process:**
1. Take path condition (Z3 constraints)
2. Solve with Z3 to get model
3. Extract concrete input values
4. Execute code with concrete inputs
5. Compare concrete trace to expected symbolic trace

**Result types:**
- `realized`: Found concrete inputs, trace matches
- `failed`: Couldn't find inputs (does NOT mean infeasible!)
- `error`: Internal DSE failure

### 3. DSEResult

Structured result containing:
- Status (realized/failed/error)
- Concrete input (if found)
- Concrete trace (execution record)
- Metadata (Z3 model, timing)

## Usage in Bug Detection

### For BUG Reports

When symbolic execution finds a counterexample:

1. Extract path condition from symbolic trace
2. Use DSE to realize it with concrete inputs
3. Attach concrete repro to bug report
4. Include: input values, execution trace, exception/assertion

**Example:**
```python
# Symbolic: found path to assert False
# DSE: realizes with input x=5
# Report: "BUG: AssertionError reachable with input x=5"
```

### For Contract Refinement

DSE can witness behaviors for refinement suggestions:

```python
observed = dse.witness_behavior("unknown_f", inputs)
suggestion = validator.attempt_refinement("unknown_f", observed)
```

**Critical:** Suggestions require **independent justification** (source code, spec, or bounded exhaustive testing). Never auto-refine based on DSE alone.

## Soundness Constraints

### Never Do

❌ Report SAFE because DSE couldn't find counterexample
❌ Shrink `may_raise` because DSE didn't raise
❌ Shrink `may_write` because DSE didn't mutate
❌ Claim trace is spurious because DSE failed

### Always Do

✅ Use DSE to produce concrete repros for BUG reports
✅ Document when DSE fails (trace divergence, timeout)
✅ Keep contracts as over-approximations
✅ Only refine with independent justification

## Anti-Cheating Enforcement

DSE helps prevent cheating by requiring:

1. **Concrete witness for BUG**: Can't claim BUG without realizable trace
2. **Proof for SAFE**: DSE success/failure never justifies SAFE claim
3. **Conservative refinement**: Observed behaviors don't shrink contracts automatically

## Test Coverage

18 tests in `tests/test_dse.py`:

- **ConcreteExecutor tests (4)**: Basic execution, exceptions, tracing, limits
- **TraceValidator tests (5)**: Path solving, satisfiability, concrete extraction
- **Refinement oracle tests (3)**: Witnessing, suggestions, soundness
- **Bug integration tests (3)**: Repros for assert/div-zero, metadata
- **Principle tests (3)**: Under-approximate oracle, no SAFE without proof, over-approximation

All 236 tests pass after DSE integration.

## Phase Completion

DSE_ORACLE phase exit criteria met:

✅ DSE attempts to realize candidate traces (path conditions → concrete inputs)
✅ DSE produces concrete repro steps for bugs (DSEResult with trace)
✅ DSE used only as oracle (not proof of absence)

## Next Steps

With DSE complete, the analyzer can now:

1. Produce high-quality bug reports with concrete repros
2. Safely suggest contract refinements (with human validation)
3. Identify where symbolic semantics are too coarse

Next phase: **BARRIERS_AND_PROOFS** - implement inductive invariants and barrier certificates for SAFE verdicts.
