# RustFromScratch Workflow Discipline

Summary of implementation discipline from `RustFromScratch/continuous_checker_workflow.py` 
and `SEMANTIC_GAPS_TO_FIX.md`.

## 1. Stateful Continuous Improvement

The workflow is designed to run **repeatedly** (hundreds/thousands of times) in a loop.

Key principle: **State.json is the single source of truth**
- No memory between runs except repo contents + State.json
- Must read State.json at start, update at end
- Queue-driven: `queue.next_actions` is the deterministic "what to do next" list
- Never "start over" - always resume from State.json

## 2. Moving Parts Architecture

Explicit list of system components tracked in State.json.

For Python version (from prompt):
1. Frontend / program loading (bytecode compilation, source span mapping)
2. CFG + exceptional edges
3. Concrete bytecode machine (oracle harness for differential testing)
4. Symbolic state / heap model (Z3)
5. Symbolic execution / BMC
6. Unsafe region library (20 bug types)
7. Unknown call model + contract language
8. DSE (refinement oracle)
9. Barrier / invariant / ranking layer
10. Evaluation harness (synthetic + public repos)

Each feature must point to which moving part it belongs to.

## 3. Anti-Cheating Constraints

From `SEMANTIC_GAPS_TO_FIX.md` (Rust version tracked 80% accuracy on hard tests):

**Root cause of false negatives:**
"We make optimistic assumptions for patterns but pessimistic assumptions for Z3, 
leading to inconsistent reasoning."

**Fixed bugs (examples of what NOT to do):**
- ❌ Pattern-matching `arr[0]` as "safe" without checking array emptiness
- ❌ Assuming library functions (like `swap`) check bounds (must model contracts)
- ❌ Trusting function parameters without explicit checks
- ❌ Marking structure-matching code as SAFE when semantics has bug

**Correct approach:**
- Patterns are **necessary but not sufficient** for safety
- If pattern matches but Z3 finds counterexample: **trust Z3**
- Library calls need explicit contracts (over-approximating relations)
- No "looks safe" heuristics

## 4. Testing Methodology

**Three tiers of evaluation:**

1. **Micro-tests (5-20 lines)**: Target one semantic corner
   - BUG programs (must detect)
   - NON-BUG programs (must not flag)
   - Each bug type needs ≥10 BUG + ≥10 NON-BUG tests

2. **Synthetic realistic (50-200 lines)**: Plausible program structure
   - Label the "bug line"
   - Include intentional non-bugs

3. **Public repos**: Real-world code
   - Clone curated repo list
   - Scan in batches
   - Triage findings with model traces + DSE repro
   - **Fix false positives by improving semantics/contracts/proofs, NOT by adding text heuristics**

## 5. False Positive/Negative Tracking

Track in State.json:
- `progress.evaluation.false_positives`: List of SAFE programs incorrectly flagged
- `progress.evaluation.false_negatives`: List of BUG programs missed

Every FP/FN must lead to:
- Root cause analysis (semantic gap identified)
- Fix in the model (not a heuristic)
- Regression test added

## 6. Per-Run Procedure (from prompt §"Per-run procedure")

Every invocation must:
1. Read State.json
2. Mark run as `running` with timestamp
3. Re-check anti-cheating rule
4. Choose **exactly one** primary action from queue (or repopulate if empty)
5. Execute end-to-end: implement + tests + fix breakage
6. Update State.json: increment iteration, record results, update progress flags, update queue
7. Stop (don't start second large task in same run)

If tests failing at start: **primary action is fix the failures** (model-based).

## 7. Quality Bar (from prompt §"Quality bar")

For any bug detector, must be able to answer with code pointers:
- What is the exact semantic unsafe region (machine state predicate)?
- What is the exact transition relation used?
- Where is the Z3 query that proves reachability / inductiveness?
- Where is the extracted witness trace, and how to replay it concretely?

If you cannot answer these: **you are not doing the project** - stop and fix the model.
