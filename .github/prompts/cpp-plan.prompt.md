# PythonFromScratch: Overnight Plan Executor (C++ Parity + SOTA Precision)

You are being invoked repeatedly (possibly thousands of times) by `copilot-cli` in a loop (e.g., `while True:`). You have **no reliable memory** between invocations except the repository contents. Therefore you must be **stateful via `State.json`** and you must make **small, end-to-end, test-validated improvements** each run.

This prompt is a C++-focused analogue of `.github/prompts/plan.prompt.md`.
It is also an alternative to `.github/prompts/cpp-semantic-barrier-workflow.prompt.md` (mission-focused rather than plan-executor-focused):

- same “overnight executor” discipline,
- but targeting **C++** bug finding/proving (including C++-unique hazards like UB, lifetimes, provenance, exception/terminate rules, and the C++ concurrency memory model),
- and **not** relying on any Python-only benchmark or Python-language-specific analysis logic.

This prompt’s “what do I do next?” policy is to execute the implementation plan in:

- `docs/CPP_CODEQL_PARITY_SOTA_MATH_PLAN.md`

The goal is to steadily close the precision gap vs CodeQL’s C/C++ query pack on a chosen C++ target (selected in `State.json.cpp_plan_executor.parity.target`), with emphasis on:

- **intraprocedural precision** (CFG + alias/points-to + ranges + lifetime/provenance),
- **interprocedural precision** (summaries / IDE/IFDS-style transport),
- and **library modeling** (guarded relational summaries + mandatory conservative fallback).

---

# Non‑negotiables (repeat every run)

## 1) Resume via `State.json`

- You **MUST** read `State.json` at repo root at the start of every run.
- You **MUST** decide what to do next based on `State.json` (do not “start over”).
- You **MUST** write back to `State.json` at the end of every run (even on failure), so the next run resumes correctly.
- This prompt is **C++-scoped**: persist state under `State.json.cpp_plan_executor` and `State.json.cpp_queue` so you do not overwrite Python-specific progress tracked elsewhere in `State.json`.
- If `State.json` is missing, create it (see schema below).
- If `State.json` is invalid JSON, repair it **without discarding progress** (salvage what you can from the file contents and git history).

## 2) Anti‑cheating rule (hard ban)

It is easy to “cheat” by implementing detectors that pass local tests but are not semantics-grounded. You must not do that.

**Every bug report and every safety claim must be justified by the C++→Z3 semantics model**, plus:

- sound over-approximations (abstract interpretation / dataflow / alias analysis),
- relational summaries with justified guards and **mandatory conservative fallback**,
- optional concolic/DSE diagnostics that **never decide SAFE**.

Concrete grounding anchors in this repo:

- `barrier-certificate-theory.tex` (reachability + barrier certificates)
- `cpp-barrier-certificate-theory.md` (C++ adaptation: UB as unsafe, lifetimes/provenance, exception/terminate)
- `docs/cpp_z3_semantics_core.py` (a runnable Z3 core semantics model to embed/extend)

### Forbidden

- Regex/pattern matching on source as the decider (“if contains `strcpy(` then BUG”, etc.).
- Using comments/identifiers/file names as deciding signals.
- Returning SAFE because no bug was found.
- Removing the havoc fallback because “dynamic testing didn’t observe it”.
- Re-running CodeQL in the overnight loop as the scoring oracle (parity is measured against **precomputed** CodeQL outputs committed under `results/`).

### Allowed (when implemented soundly)

- CFG construction with explicit exceptional/terminate edges (as applicable to your IR).
- Sound intraprocedural analysis with an explicit lattice + transfer functions (including ranges, init bits, typestate).
- Alias/points-to analysis as a sound over-approximation (conservative is fine; unsound is not).
- Summary-based interprocedural analysis with conservative unknown-call fallback.
- Contracts/models as **relations** `R_f(pre, post)` with guards and mandatory fallback.
- Z3-based reachability (BMC/CHCs) and Z3-checked proof artifacts for SAFE.
- DSE/concolic/sanitizers only for witness generation, trace validation, or contract widening.

## 3) “While True” survival constraints

Each run must be:

- **Small**: aim for one coherent work item (one script, one refactor, one test bundle).
- **End-to-end**: implement + validate (tests) + update docs/state.
- **Non-destructive**: avoid large rewrites, mass formatting, or deleting big folders unless explicitly required by the plan.

If blocked (missing info, unclear design, failing unrelated tests), do not stall:

- write a short note under `docs/notes/`,
- update `State.json.cpp_queue.blocked` with what’s blocked and why,
- pick the next best actionable task.

---

# Required reading inputs (minimal per run)

You must at least consult:

1. `State.json` (always)
2. `docs/CPP_CODEQL_PARITY_SOTA_MATH_PLAN.md` (only the section relevant to your chosen task)
3. When working on parity:
   - `State.json.cpp_plan_executor.parity.codeql_dataset` (paths under `results/`)
   - the current parity diff artifact under `results/` (if it exists)

Do **not** repeatedly re-read a whole plan every run. Read only what you need to execute the next action.

---

# State.json (schema + migration)

## Location

`State.json` at repo root.

## Invariants

- Must remain valid JSON.
- Must be forward-compatible: add fields, don’t delete or rename existing ones without a migration note.
- Must be updated at end of every run, including failures/timeouts.
- This prompt must not clobber Python-mode fields; it should only update `cpp_plan_executor` and `cpp_queue` (and may add missing subkeys).

## Minimal schema (extend as needed)

If missing, create:

```json
{
  "schema_version": 1,
  "cpp_plan_executor": {
    "schema_version": 1,
    "iteration": 0,
    "last_run": {
      "started_at": null,
      "finished_at": null,
      "status": "never_run",
      "summary": "",
      "changed_files": [],
      "tests_ran": [],
      "tests_status": "unknown"
    },
    "active_plan_doc": "docs/CPP_CODEQL_PARITY_SOTA_MATH_PLAN.md",
    "phase": "PHASE0_PARITY_TOOLING",
    "platform_contract": {
      "cpp_standard": "c++20",
      "abi": "x86_64-sysv",
      "os": "linux",
      "assumptions": []
    },
    "milestones": {
      "parity_diff_tooling": false,
      "ir_core_semantics": false,
      "intraprocedural_engine_unified": false,
      "ide_transport_baseline": false,
      "stdlib_models_minimal": false,
      "proof_pilot": false
    },
    "parity": {
      "target": {
        "name": null,
        "language": "cpp",
        "repo": null,
        "commit": null
      },
      "codeql_dataset": {
        "sarif": null,
        "csv": null
      },
      "last_diff_artifact": null,
      "last_run_at": null,
      "miss_buckets_top": []
    }
  },
  "cpp_queue": {
    "next_actions": [],
    "blocked": [],
    "backlog": []
  }
}
```

## Migration policy

If `State.json` already exists:

- Preserve all existing keys.
- Add `cpp_plan_executor` and/or missing subkeys if absent.
- Do not change the meaning of existing `phase` fields from other prompts; use `cpp_plan_executor.phase` for this prompt’s phase machine.

---

# The per-run algorithm (do this every invocation)

## Step 0 — Load and start bookkeeping

1. Read `State.json`.
2. Ensure `cpp_plan_executor` and `cpp_queue` exist (migrate if needed).
3. Set `cpp_plan_executor.last_run.started_at` to now and `cpp_plan_executor.last_run.status` to `"running"`.
4. Increment `cpp_plan_executor.iteration` by 1 at the **end** of the run (only after updating the rest).

## Step 1 — Choose exactly one task

Selection rules (in priority order):

1. If `State.json.cpp_queue.next_actions` is non-empty:
   - Pick the first action you can complete end-to-end.
2. Else:
   - Refill `cpp_queue.next_actions` from `docs/CPP_CODEQL_PARITY_SOTA_MATH_PLAN.md` (iteration roadmap + phase checklists).
   - Prefer Phase 0 tasks until `cpp_plan_executor.milestones.parity_diff_tooling` is true.
3. If everything is blocked:
   - Pick a small unblocker: add a missing unit test, fix a schema mismatch, or write a note that clarifies a design decision.

**Do not** pick tasks that require human interaction in an overnight loop. Choose something self-contained.

## Step 2 — Execute the task end-to-end

For the chosen task:

1. Identify the exact files/modules you will touch.
2. Implement the smallest correct change that advances the plan.
3. Add/update tests so the change is non-regressable.
4. Run the most relevant tests:
   - If you changed core analysis: run unit tests + at least one targeted integration run.
   - Prefer the repo’s existing harness; if none exists, add a minimal one in-repo.
5. Update docs if needed:
   - plan progress, parity diff artifacts, implementation notes.

## Step 3 — Update State.json (always)

At the end of the run:

1. Fill `cpp_plan_executor.last_run.finished_at`.
2. Set `cpp_plan_executor.last_run.status` to `"success"` or `"failure"`.
3. Set `cpp_plan_executor.last_run.summary` to a short, concrete description:
   - what changed,
   - what tests ran,
   - what’s next.
4. Populate:
   - `cpp_plan_executor.last_run.changed_files`
   - `cpp_plan_executor.last_run.tests_ran`
   - `cpp_plan_executor.last_run.tests_status`
5. Update `cpp_plan_executor.phase` and milestones if you hit exit criteria.
6. Update `cpp_queue.next_actions`:
   - remove the completed item,
   - append discovered follow-ups,
   - move blocked items to `cpp_queue.blocked` with a reason.

---

# Phase machine (plan execution)

This prompt’s phase is tracked in `State.json.cpp_plan_executor.phase`.

## Phase `PHASE0_PARITY_TOOLING`

**Goal:** make parity measurable and reproducible **without re-running CodeQL**.

Exit criteria:

- A script exists that:
  - parses CodeQL SARIF/CSV into a normalized finding schema,
  - parses our results into the same schema,
  - emits a diff artifact: agreement, CodeQL-only, our-only,
  - buckets misses into root causes,
  - writes outputs under `results/` deterministically.
- `cpp_plan_executor.milestones.parity_diff_tooling = true`

Recommended tasks:

- Add `scripts/cpp_parity_diff.py` (or similar) + tests.
- Add `results/<target>_parity/` output conventions.
- Add a “root-cause buckets” doc under `docs/` (missing model vs alias imprecision vs lifetime modeling vs etc.).

## Phase `PHASE1_IR_AND_INTRAPROC`

**Goal:** close the biggest advantage: sophisticated intraprocedural analysis over a faithful C++ execution substrate.

Exit criteria:

- A canonical intraprocedural engine exists and is used by the C++ analysis entrypoint.
- The engine has tests for:
  - range reasoning (`i < n`, `n*sizeof(T)` overflow patterns),
  - pointer provenance + bounds + alignment checks,
  - byte-level init tracking (uninitialized reads/leaks),
  - exception/terminate edges where relevant.
- `cpp_plan_executor.milestones.intraprocedural_engine_unified = true`

Recommended tasks:

- Implement or refine a small C++ core IR and CFG conventions (including exceptional/terminate edges).
- Add transfer functions for the core semantics used by bug predicates in `cpp-barrier-certificate-theory.md`.
- Add a minimal alias/points-to abstraction that is explicitly conservative.

## Phase `PHASE2_IDE_TRANSPORT`

**Goal:** interprocedural precision comparable to CodeQL defaults.

Exit criteria:

- A baseline IDE/IFDS-style transport exists (call/return matching, recursion handling).
- Summaries are derived from IR/dataflow results (not source-pattern heuristics).
- `cpp_plan_executor.milestones.ide_transport_baseline = true`

Recommended tasks:

- Build a stable ICFG representation (function + program-point nodes).
- Implement call/return label transport and a conservative call-to-return fallback for unknown callees.
- Add minimal context sensitivity only where parity diff shows it matters.

## Phase `PHASE3_STDLIB_MODELS`

**Goal:** close the model gap (stdlib + libc + common third-party APIs) without cheating.

Exit criteria:

- Minimal models exist as guarded relational cases + fallback for:
  - libc memory/string APIs (`memcpy`, `memmove`, `strcpy`, `strlen`, …),
  - allocation/deallocation (`new/delete`, `malloc/free`, new[]/delete[]),
  - common container/view invalidation patterns (epochs for `vector`, `string`, `string_view`, `span`).
- At least one “fallback stays reachable when guard not provable” test per major model.
- `cpp_plan_executor.milestones.stdlib_models_minimal = true`

## Phase `PHASE4_PROOF_PILOT`

**Goal:** integrate proof artifacts for at least one non-trivial C++ property (opt-in).

Exit criteria:

- One pilot proof path exists for a small module/property under trusted models:
  - CHC/PDR, or
  - inductive invariant / barrier certificate checked by Z3.
- SAFE outputs contain a reproducible proof artifact.
- `cpp_plan_executor.milestones.proof_pilot = true`

---

# Default commands (use repo-local tooling)

Run the repo’s existing tests and scripts; do not add new dependencies overnight unless the plan explicitly requires it.

Examples (adjust to what exists in-repo):

- Run tests: use the repository’s existing test runner (`ctest`, `ninja test`, `meson test`, etc.)
- Run parity diff tooling: run the script under `scripts/` with explicit input/output paths under `results/`

---

# Output discipline (what you report in each run)

At the end of each run, write a short human-readable summary under `docs/notes/`:

- what you implemented,
- what tests you ran and their status,
- which `State.json.cpp_plan_executor` / `State.json.cpp_queue` fields you updated,
- what the next queued action is.

Never claim parity improvements without a regenerated diff artifact in `results/`.

If you have completed everything in the C++ plan and have nothing in the queue:

1. Choose a new **C++** repository or test suite target and add it to `State.json.cpp_queue.backlog`.
2. Add (or import) its precomputed CodeQL outputs under `results/<target>_codeql/`.
3. Create a new parity plan doc under `docs/` for that target.
4. Before claiming improvements, triage false positives/negatives and record them explicitly with file:line locations.
