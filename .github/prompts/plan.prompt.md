# PythonFromScratch: Overnight Plan Executor (CodeQL Parity + SOTA Precision)

You are being invoked repeatedly (possibly thousands of times) by `copilot-cli` in a loop (e.g., `while True:`). You have **no reliable memory** between invocations except the repository contents. Therefore you must be **stateful via `State.json`** and you must make **small, end-to-end, test-validated improvements** each run.

This prompt is an alternative to `.github/prompts/python-semantic-barrier-workflow.prompt.md`.
It is **not** a rewrite of the mission (we still require semantics-faithful BUG/SAFE/UNKNOWN), but it changes the overnight “what do I do next?” policy to **execute the implementation plan** in:

- `docs/CODEQL_PARITY_SOTA_MATH_PLAN.md`

The goal is to steadily close the precision gap vs CodeQL (starting with PyGoat), with emphasis on:
- **intraprocedural precision** (SOTA dataflow/abstract interpretation),
- **interprocedural precision** (IDE/IFDS-style transport),
- and **framework/sanitizer modeling** (guarded relational summaries + mandatory fallback).

---

# Non‑negotiables (repeat every run)

## 1) Resume via `State.json`

- You **MUST** read `State.json` at repo root at the start of every run.
- You **MUST** decide what to do next based on `State.json` (do not “start over”).
- You **MUST** write back to `State.json` at the end of every run (even on failure), so the next run resumes correctly.
- If `State.json` is missing, create it (see schema below).
- If `State.json` is invalid JSON, repair it **without discarding progress** (salvage what you can from git/history/logs and from the file contents).

## 2) Anti‑cheating rule (hard ban)

It is easy to “cheat” by implementing detectors that pass local tests but are not semantics-grounded. You must not do that.

**Every bug report and every safety claim must be justified by the Python→Z3 semantics model**, plus:
- sound over-approximations (abstract interpretation / dataflow),
- relational summaries with justified guards and **mandatory conservative fallback**,
- optional concolic/DSE diagnostics that **never decide SAFE**.

### Forbidden
- Regex/pattern matching on source as the decider (“if contains `eval(` then BUG”, etc.).
- Using comments/docstrings/variable names as the deciding signal.
- Returning SAFE because no bug was found.
- Removing the havoc fallback because “DSE didn’t observe it”.
- Re-running CodeQL for PyGoat (use the precomputed results).

### Allowed (when implemented soundly)
- CFG/dataflow/abstract interpretation over bytecode with explicit exceptional edges.
- Summary-based or IDE/IFDS-style interprocedural dataflow.
- Contracts/models as **relations** `R_f` with guards and mandatory fallback.
- Z3-based reachability/witnesses, and Z3-checked proof artifacts for SAFE.
- DSE/concolic only for witness generation, trace validation, or contract widening.

## 3) “While True” survival constraints

Each run must be:
- **Small**: aim for one coherent work item (one script, one refactor, one new test bundle, one bug fix).
- **End-to-end**: implement + validate (tests) + update docs/state.
- **Non-destructive**: avoid large rewrites, mass formatting, or deleting big folders unless explicitly required by the plan.

If you get blocked (missing info, unclear design, failing unrelated tests), do not stall:
- write a short note under `docs/notes/`,
- update `State.json.queue.blocked` with what’s blocked and why,
- pick the next best actionable task.

---

# Required reading inputs (minimal per run)

You must at least consult:

1. `State.json` (always)
2. `docs/CODEQL_PARITY_SOTA_MATH_PLAN.md` (only the section relevant to your chosen task)
3. `checkers_lacks.md` and `results/pygoat_codeql/CODEQL_RESULTS_SUMMARY.md` when working on parity

Do **not** repeatedly re-read the whole 1k-line plan every run. Read the parts you need to execute the next action.

---

# State.json (schema + migration)

## Location
`State.json` at repo root.

## Invariants
- Must remain valid JSON.
- Must be forward-compatible: add fields, don’t delete or rename existing ones without a migration note.
- Must be updated at end of every run, including failures/timeouts.

## Minimal schema (extend as needed)

If missing, create:

```json
{
  "schema_version": 1,
  "iteration": 0,
  "target_python": "3.14",
  "last_run": {
    "started_at": null,
    "finished_at": null,
    "status": "never_run",
    "summary": "",
    "changed_files": [],
    "tests_ran": [],
    "tests_status": "unknown"
  },
  "plan_executor": {
    "active_plan_doc": "docs/CODEQL_PARITY_SOTA_MATH_PLAN.md",
    "phase": "PHASE0_PARITY_TOOLING",
    "milestones": {
      "parity_diff_tooling": false,
      "intraprocedural_engine_unified": false,
      "ide_transport_baseline": false,
      "framework_models_minimal": false,
      "proof_pilot": false
    },
    "parity": {
      "codeql_dataset": {
        "pygoat_sarif": "results/pygoat_codeql/pygoat-codeql-results.sarif",
        "pygoat_csv": "results/pygoat_codeql/pygoat-codeql-results.csv"
      },
      "last_diff_artifact": null,
      "last_run_at": null,
      "miss_buckets_top": []
    }
  },
  "queue": {
    "next_actions": [],
    "blocked": [],
    "backlog": []
  }
}
```

## Migration policy

If `State.json` already exists:
- Preserve all existing keys.
- Add `plan_executor` and/or missing subkeys if absent.
- Do not change the meaning of existing `phase` fields from other prompts; use `plan_executor.phase` for this prompt’s phase machine.

---

# The per-run algorithm (do this every invocation)

## Step 0 — Load and start bookkeeping

1. Read `State.json`.
2. Set `last_run.started_at` to now and `last_run.status` to `"running"`.
3. Increment `iteration` by 1 at the **end** of the run (only after updating the rest).

## Step 1 — Choose exactly one task

Selection rules (in priority order):

1. If `State.json.queue.next_actions` is non-empty:
   - Pick the first action you can complete end-to-end.
2. Else:
   - Refill `queue.next_actions` from `docs/CODEQL_PARITY_SOTA_MATH_PLAN.md` (Section “Suggested iteration-level roadmap” and phase checklists).
   - Prefer Phase 0 tasks until `plan_executor.milestones.parity_diff_tooling` is true.
3. If everything is blocked:
   - Pick a small unblocker: add a missing test, fix a schema mismatch, or write a note that clarifies a design decision.

**Do not** pick tasks that require human interaction (e.g., “ask user which repo to scan”) in an overnight loop. Choose something self-contained.

## Step 2 — Execute the task end-to-end

For the chosen task:

1. Identify the exact files/modules you will touch.
2. Implement the smallest correct change that advances the plan.
3. Add/update tests so the change is non-regressable.
4. Run the most relevant tests:
   - If you changed core analysis: run unit tests + at least one targeted integration run.
   - Prefer `python3 -m pytest` (or existing test command in repo).
5. Update docs if needed:
   - plan progress, parity results artifacts, or implementation notes.

## Step 3 — Update State.json (always)

At the end of the run:

1. Fill `last_run.finished_at`.
2. Set `last_run.status` to `"success"` or `"failure"`.
3. Set `last_run.summary` to a short, concrete description:
   - what changed,
   - what tests ran,
   - what’s next.
4. Populate:
   - `last_run.changed_files`
   - `last_run.tests_ran`
   - `last_run.tests_status`
5. Update `plan_executor.phase` and milestones if you hit exit criteria.
6. Update `queue.next_actions`:
   - remove the completed item,
   - append discovered follow-ups,
   - move blocked items to `queue.blocked` with a reason.
7. Increment `iteration`.

---

# Phase machine (plan execution)

This prompt’s phase is tracked in `State.json.plan_executor.phase`.

## Phase `PHASE0_PARITY_TOOLING`

**Goal:** make parity measurable and reproducible (without re-running CodeQL).

Exit criteria:
- A script exists that:
  - parses CodeQL SARIF/CSV into a normalized finding schema,
  - parses our results into the same schema,
  - emits a diff artifact: agreement, CodeQL-only, our-only,
  - buckets misses into root causes,
  - writes outputs under `results/` deterministically.
- `plan_executor.milestones.parity_diff_tooling = true`

Recommended tasks:
- Add `scripts/parity_diff.py` (or similar) + tests.
- Add `results/pygoat_parity/` output conventions.
- Update `checkers_lacks.md` (or create a v2 doc) to separate “missing detector” vs “not firing”.

**Hard rule:** do not run CodeQL. Use:
- `results/pygoat_codeql/pygoat-codeql-results.sarif`
- `results/pygoat_codeql/pygoat-codeql-results.csv`

## Phase `PHASE1_INTRAPROC_ENGINE`

**Goal:** close the biggest CodeQL advantage: sophisticated intraprocedural analysis.

Exit criteria:
- One canonical intraprocedural security engine exists and is used by `Analyzer.security_scan()` (or a clear equivalent).
- The engine has tests for:
  - local taint propagation through assignments/containers/strings,
  - sanitizer-in-branch behavior (bounded partitioning or equivalent),
  - sink checks driven by `(τ, κ, σ)` rules.
- `plan_executor.milestones.intraprocedural_engine_unified = true`

Recommended tasks:
- Refactor to route security scanning through a dataflow-style intraprocedural fixpoint engine (worklist + join).
- Expand opcode coverage for security idioms.
- Implement bounded partitioning keyed by sanitizer/taint facts.
- Add witness skeleton reconstruction for explainability (optional concolic validation).

## Phase `PHASE2_IDE_TRANSPORT`

**Goal:** interprocedural taint precision comparable to CodeQL defaults.

Exit criteria:
- A baseline IDE/IFDS-style transport exists (call/return matching, recursion handling).
- Summaries are derived from bytecode/dataflow results (not AST-only heuristics).
- `plan_executor.milestones.ide_transport_baseline = true`

Recommended tasks:
- Build a stable ICFG representation (function+offset nodes).
- Implement call/return label transport and a conservative call-to-return fallback for unknown callees.
- Add minimal context sensitivity (1-CFA) only where parity diff shows it matters.

## Phase `PHASE3_MODELS_FRAMEWORKS`

**Goal:** close the model gap (framework + sanitizer libraries) without cheating.

Exit criteria:
- Minimal Django/Flask request source models exist as guarded relational cases + fallback.
- ORM/SQL parameterization models update κ correctly when provable.
- At least one “fallback stays reachable when guard not provable” test per major model.
- `plan_executor.milestones.framework_models_minimal = true`

## Phase `PHASE4_PROOF_PILOT`

**Goal:** integrate proof artifacts for at least one non-trivial security property (opt-in).

Exit criteria:
- One pilot CHC/PDR or barrier proof path exists for a small module/property under trusted models.
- SAFE outputs contain a reproducible proof artifact.
- `plan_executor.milestones.proof_pilot = true`

---

# Default commands (use repo-local tooling; prefer python3)

Use `python3` (this repo may not have a `python` shim).

Examples:
- Run tests: `python3 -m pytest`
- Run CLI analysis (adjust CLI subcommand to actual interface):
  - `python3 -m pyfromscratch.cli ...`

Do not install new dependencies overnight unless the plan explicitly requires it and the repo already vendors them.

---

# Output discipline (what you report in each run)

At the end of each run, output in docs/ a short human-readable summary:
- what you implemented,
- what tests you ran and their status,
- which State.json fields you updated,
- what the next queued action is.

Never claim parity improvements without a regenerated diff artifact in `results/`.

If you have completed everything in the plan and have nothing in the queue, choose a new python repository to analyze and add it to the backlog in `State.json.queue.backlog`.  Then analyze its CodeQL results and create a new parity plan document under `docs/` for it.  **Make sure to check if our checker produces any False Positives or False Negatives on the new repository before claiming improvements over codeql, and, especially if there's a False positive, add each exact location of such an error and why you believe its a false positive.  Report any True positives not caught by codeql in {test_repo}_positives.md, along with details about them that could be added to a bug report.  Iterate for as many iterations as needed before every False Positive is resolved in this repo before starting on another one.**