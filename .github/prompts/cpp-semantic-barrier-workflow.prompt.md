# CPPFromScratch: Stateful, Continuous C++ Semantics + Barrier-Certificate Verifier

You are being invoked repeatedly (possibly thousands of times) by `copilot-cli` in a loop (`while True:`). You have **no reliable memory** between invocations except the repository contents. Therefore:

## Non‑negotiable requirement: resume via `State.json`

- You **MUST** read `State.json` at the repo root at the start of every run.
- You **MUST** decide what to do next based on `State.json` (do not "start over").
- You **MUST** write back to `State.json` at the end of every run (even on failure), so the next run resumes correctly.
- The same prompt must be usable from any point in the process: `State.json` is the single source of truth.

If `State.json` is missing, create it using the schema in this prompt. If it exists but is invalid JSON, repair it *without discarding progress* (salvage what you can from git/history/logs).

---

# The mission (do not dilute this)

Build a *precise, execution‑faithful* semantic model of **C++** (as a programming language **plus** a concrete platform contract), and restate the "bug = reachable unsafe region" worldview in **barrier‑certificate** terms:

- Reference theory: `barrier-certificate-theory.tex` (20 bug types, barrier conditions, Z3 roles).
- C++ adaptation: `cpp-barrier-certificate-theory.md` (UB-as-unsafe, lifetimes/provenance, exceptions/terminate, concurrency notes).
- Full Z3 model (seed, evolve conservatively): `docs/cpp_z3_semantics_core.py` (a runnable Z3 transition system for a useful C++ core).
- Implementation style exemplar: `RustFromScratch/` (continuous improvement workflow, anti‑cheating stance, testing methodology, stateful iteration).

C++ adds two big complications that you must make explicit and model honestly:

1. **Undefined behavior (UB)** exists and is pervasive.
2. **Evaluation order and compilation-time semantics** introduce nondeterminism that you must represent (or conservatively over-approx).

Your stance must be explicit and persistent in `State.json`:

- Fix a target standard mode: e.g. `c++20`, and record it (`target_cpp`).
- Fix a **platform contract** (ABI + OS + key assumptions) and record it (`platform_contract`).
- Model defined behavior precisely for your chosen core.
- Treat **UB as an explicit unsafe region** (and optionally model post‑UB as unconstrained “chaos” if needed for soundness).

## The core deliverable

A program analysis toolchain that, given C++ code (or a C++‑aware lowered IR), can produce one of:

1. **BUG**: a *model‑checked reachable* unsafe state (with a concrete counterexample trace / witness), OR
2. **SAFE**: a *proof* (barrier certificate / inductive invariant) that the unsafe region is unreachable, OR
3. **UNKNOWN**: neither proof nor counterexample (this is allowed; never lie).

No "looks buggy" heuristics. No regex‑based detectors. No AST smell checks masquerading as verification. The tool must be grounded in the **C++→Z3 heap/transition/barrier** model.

## Required reading (to understand the target)

- `barrier-certificate-theory.tex`
  - Minimum: the "Summary: Complete Coverage of 20 Bug Types" section (bug list + the barrier/invariant shape).
  - Capture: the basic relationship between bugs, Z3, and barrier certificate theory; the 20 bug type names and how they work; and the "no proof = no safety guarantee" posture.
- `cpp-barrier-certificate-theory.md`
  - Minimum: machine state definition, reachability framing, UB-as-unsafe, unknown calls as relations, and the C++‑unique hazard taxonomy.
  - Capture: pointer provenance + lifetimes + init-bits, terminate/noexcept paths, and the soundness rule `Sem_f ⊆ R_f`.
- `docs/cpp_z3_semantics_core.py`
  - Minimum: how the transition relation is written as `Step(σ,σ')` and how unsafe is represented (UB flag and predicates).
  - Capture: pointer representation, allocation/lifetime tags, and how OOB/UAF/uninit/overflow/exception edges become first‑class predicates.
- `RustFromScratch/`
  - Minimum: `RustFromScratch/continuous_checker_workflow.py`, `RustFromScratch/barrier_refinement_orchestrator.py`, and `RustFromScratch/SEMANTIC_GAPS_TO_FIX.md`.
  - Capture: the workflow discipline (stateful phases) and the explicit anti‑cheating constraints.
- `docs/CPP_CODEQL_PARITY_SOTA_MATH_PLAN.md`
  - Minimum: the "non‑negotiables" and the iteration roadmap.
  - Special instruction: **make sure everything you do works interprocedurally** (or records what blocks interprocedural reasoning) and always append the next interprocedural step to `State.json.queue.next_actions`.

Write your summaries into small markdown files (e.g., under `docs/notes/`) and list them in `State.json.knowledge.notes_files`.

---

# Absolute anti‑cheating rule (repeat to yourself every run)

It is easy to "cheat" by implementing superficial recognizers that pass local tests but do not generalize. You must not do that.

**Every bug report and every safety claim must be justified strictly by the C++ Z3 heap/transition/barrier theory model** (plus clearly labeled, explicitly unsound optional hints that never decide BUG/SAFE).

## Forbidden approaches (hard ban)

- Regex/pattern matching on source text as the *decider* ("if `strcpy(` then bug", etc.).
- Using comments/identifiers/file paths/test names as deciding signals.
- Hardcoding behaviors for known repos or tests.
- Returning "SAFE" because you didn't find a counterexample (absence of evidence is not proof).
- Declaring a counterexample "spurious" purely because concrete execution didn't reproduce it (dynamic runs are under‑approximate).
- Treating UB as benign ("it works on my machine") or "compiler-dependent but ok".
- Treating a data race as benign: **in C++, a data race is UB**.
- Using sanitizers/DSE failures to shrink unknown-call behaviors without independent justification.

## Allowed approaches (must be semantics‑faithful)

- A C++‑aware operational semantics (elaborated AST / CFG / IR) with explicit control edges for:
  - normal flow,
  - exceptional flow (unwind, landing pads),
  - terminate edges (`noexcept`, uncaught exception, destructor throw during unwind).
- Symbolic execution with Z3 path conditions (bounded reachability).
- Abstract interpretation *with a stated lattice* and sound transfer functions:
  - integer ranges,
  - pointer bounds (incl. one‑past),
  - alias/points‑to over‑approx,
  - lifetime/provenance typestates,
  - init‑bit tracking.
- Barrier certificates / inductive invariants checked by Z3 (or SOS later).
- Contract modeling for unknown calls as **over‑approximating relations**; refinement only when justified (`Sem_f ⊆ R_f` preserved).
- Concolic/DSE/sanitizers only for witness generation/validation and contract widening (never to justify SAFE).

---

# Dual‑mode requirement: pure symbolic vs concolic‑assisted

Everything you build must work in **two modes**:

## Mode A: Pure static/symbolic (no concrete execution)

- This is the baseline and must always work.
- Unknown inputs and unknown library calls must be modeled **soundly** via over‑approximation:
  - unknown values are nondeterministic symbols,
  - unknown calls are relations `R_f` that may return/throw/mutate according to a justified contract (or a conservative fallback).
- This mode must be usable for untrusted code and for “do not execute” workflows.
- CLI (illustrative): `cppfromscratch analyze your_file.cpp --no-concolic`

## Mode B: Concolic‑assisted refinement (more precise witnesses)

- This mode may execute the program concretely and must be **optional**.
- Use it only to improve *witness quality* and *debuggability*, never to justify SAFE:
  - validate symbolic counterexamples via replay,
  - run with sanitizers (ASan/UBSan/MSan/TSan) to obtain concrete UB witnesses,
  - record concrete call observations for unknown libraries (selective tracing),
  - prioritize/refine library contracts when an UNKNOWN/BUG hinges on library behavior.
- The BUG/SAFE/UNKNOWN **verdict must not depend on concolic**:
  - BUG is decided by symbolic reachability of an unsafe region (optionally followed by validation),
  - SAFE is decided only by a proof artifact (barrier / inductive invariant),
  - concolic failures never imply infeasibility.
- Default CLI may run with concolic enabled; disable with `--no-concolic`.

## Implementation rule

Any feature that executes target code (DSE, selective concolic tracing, sanitizer runs, lockstep replay, hybrid witness generation) must be:

- guarded behind an `enable_concolic`/`--no-concolic` switch, and
- treated as “diagnostic / witness‑production only” (not a proof step).

---

# `State.json` (required persistent state)

## Location

`State.json` at the repository root.

## Invariants

- Must remain valid JSON.
- Must be forward‑compatible: when you add fields, keep old fields; never delete/rename without a migration note.
- Must be updated at the end of every run, including failures/timeouts.
- Must contain enough information to resume without rereading huge files every time.

## Minimal schema (extend as needed, but keep these keys)

```json
{
  "schema_version": 1,
  "phase": "BOOTSTRAP",
  "iteration": 0,
  "target_cpp": "c++20",
  "platform_contract": {
    "abi": "x86_64-sysv",
    "os": "linux",
    "assumptions": []
  },
  "last_run": {
    "started_at": null,
    "finished_at": null,
    "status": "never_run",
    "summary": "",
    "changed_files": [],
    "tests_ran": [],
    "tests_status": "unknown"
  },
  "knowledge": {
    "read_barrier_tex": false,
    "read_cpp_barrier_md": false,
    "read_cpp_z3_core": false,
    "studied_rustfromscratch_workflow": false,
    "notes_files": []
  },
  "progress": {
    "repo_scaffolded": false,
    "frontend": {
      "compile_db": false,
      "clang_frontend": false,
      "lowering_to_core_ir": false,
      "source_mapping": false
    },
    "ir_semantics": {
      "ir_defined": false,
      "implemented_ops": [],
      "exceptions": false,
      "terminate_edges": false,
      "raii_cleanup": false,
      "threads": false
    },
    "z3_symbolic": {
      "symbolic_state": false,
      "path_explorer": false,
      "bmc": false
    },
    "barriers": {
      "inductive_invariants": false,
      "barrier_templates": false,
      "ranking_functions": false,
      "contract_language": false
    },
    "bug_classes": {
      "implemented": [],
      "validated": []
    },
    "unknown_calls": {
      "mode": "havoc",
      "contracts": {}
    },
    "dse": {
      "implemented": false,
      "used_as_oracle": false,
      "sanitizers": {
        "asan": false,
        "ubsan": false,
        "msan": false,
        "tsan": false
      }
    },
    "evaluation": {
      "synthetic_suite": false,
      "cpp_codeql_comparison": {
        "completed": false,
        "target": null,
        "our_findings": [],
        "codeql_findings": [],
        "agreement": [],
        "our_lacks": [],
        "codeql_lacks": []
      },
      "public_repos": {
        "cloned": [],
        "scanned": []
      },
      "false_positives": [],
      "false_negatives": []
    }
  },
  "queue": {
    "next_actions": [],
    "blocked": []
  }
}
```

### How to use `queue.next_actions`

`queue.next_actions` is the deterministic "what to do next" list. Each run:

1. Pop the first action you can perform.
2. Do it end‑to‑end (implement + tests).
3. Append follow‑ups you discovered.
4. Write back the updated queue and progress.

If the queue is empty, you must repopulate it according to the phase logic below (do not idle).

---

# Phase machine (what to do next, forever)

You are building an analyzer that will *keep improving*. Organize work into phases; record current `phase` in `State.json`; advance only when exit criteria are met.

## Phase `BOOTSTRAP`

Goal: create a clean repo skeleton for the C++ semantic model + Z3 + tests + evaluation harness.

Exit criteria:
- A runnable CLI exists (even if tiny) that loads a C++ file (or a lowered IR artifact) and does *something deterministic*.
- A test runner exists and has at least one passing test.
- `State.json` is created and updated.

Immediately after BOOTSTRAP scaffolding exists, prioritize **library-specific semantics**:
- Implement relational call summaries (cases + required havoc fallback) for calls you can identify.
- Add as many libc/stdlib/STL summaries as possible (starting with high-frequency APIs).
- Reference: `docs/CPP_CODEQL_PARITY_SOTA_MATH_PLAN.md` and `cpp-barrier-certificate-theory.md` (unknown-call contract rules).

## Phase `SEMANTICS_CONCRETE`

Goal: a **concrete** stepper for your chosen C++ core abstract machine/IR, primarily for oracle comparison.

Exit criteria:
- For a curated subset of operations, the stepper's observable behavior matches a trusted oracle (compiler + runtime) on those programs (golden tests).
- You can print/serialize machine states for debugging.
- RAII cleanup and terminate/noexcept edges are represented explicitly (not hand-waved).

## Phase `SEMANTICS_SYMBOLIC`

Goal: a **symbolic** semantics over Z3 expressions (heap + frames + pointer provenance + init bits + exceptions/terminate) sufficient to express reachability queries.

Exit criteria:
- A bounded symbolic executor exists that can find a counterexample trace for at least one unsafe predicate (e.g., an OOB write or null deref).
- Sound defaults for unknown inputs exist (nondeterministic symbols).
- UB is modeled as an unsafe region predicate, not as “undefined but ignored”.

## Phase `UNSAFE_REGIONS_CORE`

Goal: encode unsafe regions for a first core subset of bug types (start with those entirely inside C++ semantics and high-signal UB).

Start set (suggested):
- `OOB_READ`, `OOB_WRITE`
- `NULL_DEREF`
- `USE_AFTER_FREE`, `DOUBLE_FREE`, `INVALID_FREE`
- `UNINIT_READ` (and uninitialized-byte leak/padding)
- `MISALIGNED_ACCESS`
- `SIGNED_OVERFLOW`, `SHIFT_UB`, `DIV_ZERO` (incl. `INT_MIN / -1`)
- `UNCAUGHT_EXCEPTION_TERMINATE`, `NOEXCEPT_VIOLATION_TERMINATE`, `DTOR_THROW_TERMINATE`
- `DATA_RACE` (UB) and `DEADLOCK` (liveness)

Exit criteria:
- Each implemented bug type has:
  - a machine‑state predicate `Unsafe_xxx(σ)` defined *semantically*,
  - at least 10 synthetic BUG tests + 10 synthetic NON‑BUG tests,
  - a counterexample trace extractor for BUG results,
  - and never reports SAFE without a proof artifact.

## Phase `UNKNOWN_CALLS_AND_CONTRACTS`

Goal: treat black‑box calls barrier‑theoretically (as relations) and refine them.

Exit criteria:
- Unknown calls are modeled as over‑approximations with explicit "may mutate heap / may throw / may allocate / may terminate" knobs.
- A contract format exists (even minimal) and is applied in the symbolic semantics.
- At least one refined contract is learned/added in a justified way (by reading source, by reading docs, or by bounded validation) and tracked in `State.json`.
- A growing library semantics pack exists: add as many library-specific summaries/contracts as feasible (libc, allocators, STL containers), each as an over-approx relation with recorded provenance.

## Phase `DSE_ORACLE`

Goal: dynamic symbolic execution (concolic) is implemented and used to validate candidate traces / guide refinement.

Exit criteria:
- Given a candidate counterexample trace (path constraints), concolic attempts to realize it on a compiled artifact and records success/failure + concrete inputs.
- Sanitizer outputs can be captured as concrete UB witnesses and mapped back to semantic predicates.
- Concolic results are used only to:
  - produce concrete repro steps for real bugs, or
  - identify *where* abstractions are too coarse (but never to prove infeasibility).
- The entire system remains correct and useful with concolic disabled (`--no-concolic`).

## Phase `BARRIERS_AND_PROOFS`

Goal: barrier certificates / inductive invariants are implemented as first‑class proof objects.

Exit criteria:
- A barrier template mechanism exists (start simple: linear/arithmetic templates).
- Inductiveness is checked by Z3 (for nondeterministic transitions too).
- At least one nontrivial SAFE proof is produced and verified end‑to‑end.

## Phase `FULL_20_BUG_TYPES`

Goal: cover the **20 bug types** from `barrier-certificate-theory.tex`, mapped into C++ semantics (and expanded with C++-native UB where needed).

Exit criteria:
- All 20 have:
  - semantic unsafe predicate,
  - reachability encoding,
  - tests (BUG + NON‑BUG),
  - evaluation metrics in `State.json`.

---

## Phase `CPP_CODEQL_COMPARISON` (NEW - REQUIRED BEFORE PUBLIC REPOS)

**Goal**: Run our checker on a pinned, real C++ target, compare findings with **pre-computed** CodeQL results, and identify gaps in both tools.

**IMPORTANT**: CodeQL analysis must be **precomputed** and committed under `results/<target>_codeql/`. **Do NOT re-run CodeQL** inside the overnight loop.

### Inputs you must establish (pinned and reproducible)

- **Target repo**: checked into `external_tools/<target>/` (submodule or vendored snapshot), or another pinned location recorded in `State.json.progress.evaluation.cpp_codeql_comparison.target`.
- **CodeQL results (PRE-COMPUTED)** under `results/<target>_codeql/`:
  - SARIF and/or CSV,
  - a short `CODEQL_RESULTS_SUMMARY.md` you maintain for triage.

### Step 1: Read pre-computed CodeQL results

Read `results/<target>_codeql/CODEQL_RESULTS_SUMMARY.md` and the raw SARIF/CSV.

### Step 2: Run our checker on the target

Run our checker (illustrative):

```bash
cppfromscratch analyze external_tools/<target>/ --recursive --output results/<target>-our-results.json
```

### Step 3: Compare findings and write `checkers_lacks_cpp.md`

For each finding, classify into categories:
- **AGREEMENT**: both tools flagged the same issue (same file + line + similar bug type)
- **OUR_ONLY**: our checker found it, CodeQL did not
- **CODEQL_ONLY**: CodeQL found it, our checker did not

For each discrepancy, determine the root cause:
1. **LACK_OF_BUG_TYPE**: the tool doesn't check for this bug category at all
2. **IMPRECISION**: the tool checks for it but missed this instance (false negative)
3. **DIFFERENT_SCOPE**: the bug type is out of scope for one tool
4. **FALSE_POSITIVE**: one tool incorrectly flagged something that isn't a bug

You MUST write findings to `checkers_lacks_cpp.md` in the repo root with this structure:

```markdown
# Checker Comparison: CPPFromScratch vs CodeQL on <target>

## Summary

| Metric | Count |
|--------|-------|
| Total C/C++ files analyzed | X |
| CodeQL findings | X |
| Our checker findings | X |
| Agreement (both found) | X |
| CodeQL-only | X |
| Our-only | X |

## Agreement (Both Tools Found)

| File | Line | Bug Type (Ours) | Bug Type (CodeQL) | Notes |
|------|------|-----------------|-------------------|-------|
| ... | ... | ... | ... | ... |

## Our Checker Lacks (CodeQL found, we missed)

### LACK_OF_BUG_TYPE - Bug categories we don't implement

| CodeQL Query ID | Bug Category | Example | Priority to Add |
|-----------------|--------------|---------|-----------------|
| ... | ... | file.cpp:123 | HIGH |

### IMPRECISION - We check for it but missed specific instances

| File | Line | Bug Type | Why We Missed | Fix Required |
|------|------|----------|---------------|--------------|
| ... | ... | ... | ... | ... |

## CodeQL Lacks (We found, CodeQL missed)

### LACK_OF_BUG_TYPE - Bug categories CodeQL doesn't check

| Our Bug Type | Description | Example |
|--------------|-------------|---------|
| ... | ... | file.cpp:45 |

### IMPRECISION - CodeQL checks for it but missed specific instances

| File | Line | Our Bug Type | Why CodeQL Missed |
|------|------|--------------|-------------------|
| ... | ... | ... | ... |

## Action Items for Our Checker

1. **HIGH PRIORITY**: Add bug types: [list from LACK_OF_BUG_TYPE]
2. **MEDIUM PRIORITY**: Fix imprecision in: [list]
3. **LOW PRIORITY**: Consider scope expansion for: [list]

## Notes on CodeQL Strengths/Weaknesses

- CodeQL excels at: [dataflow/taint/CFG scale, etc.]
- CodeQL misses: [proof artifacts, UB nuance, etc.]
- Our approach advantages: [formal reachability, counterexample traces, proof-carrying safety, etc.]
```

Exit criteria:
- Our checker run on `<target>` and results are stored under `results/`.
- `checkers_lacks_cpp.md` is written with a complete comparison.
- `State.json.progress.evaluation.cpp_codeql_comparison` updated with:
  - `completed: true`
  - `target: "<target>"`
  - `our_findings: [...]`
  - `codeql_findings: [...]`
  - `agreement: [...]`
  - `our_lacks: [...]`
  - `codeql_lacks: [...]`
- At least one follow-up action added to `queue.next_actions` to address a high-priority gap.

Why this phase matters:
- Establishes a baseline comparison with an industry-standard tool.
- Identifies concrete gaps to prioritize (models, alias precision, lifetime reasoning).
- Documents where we should not reinvent the wheel (if CodeQL’s taint tracking is mature, focus on what it can’t prove).

---

## Phase `PUBLIC_REPO_EVAL`

Goal: run on real repos, measure false positives/negatives, refine.

Exit criteria:
- A reproducible repo list and scanning pipeline exist.
- Findings are triaged with model traces + (optional) sanitizer repro.
- False positives lead to fixes in semantics/contracts/proofs, not heuristics.

## Phase `CONTINUOUS_REFINEMENT`

Goal: never stop improving; keep iterating overnight.

Behavior:
- Expand IR operation coverage.
- Expand C++ feature coverage (templates/TUs, exceptions, RAII, atomics).
- Expand contract library (libc + STL + common frameworks) with justified summaries.
- Expand and randomize synthetic test generation (avoid overfitting).
- Re-run parity comparisons periodically; track regressions.

---

# "Moving parts" (copy RustFromScratch's discipline)

Maintain an explicit list of moving parts in the codebase (and track completion in `State.json` as you go). This is not bureaucracy: it prevents the system from turning into ad‑hoc heuristics.

Suggested moving parts (C++ version of the RustFromScratch list):

1. **Frontend / program loading**
   - Compile database support (`compile_commands.json`) and target triple config.
   - Clang-based parser/AST integration (or equivalent) for C++.
   - Lowering to a core IR that preserves source spans (file/line/col) and semantics (including exceptional/terminate edges).
2. **CFG + exceptional/terminate edges**
   - Control-flow graph for the core IR.
   - Explicit unwind edges (`throw`/`catch`) and terminate edges (noexcept, uncaught exceptions, destructor throws).
   - RAII cleanup represented explicitly (destructor steps on unwind and on normal scope exit).
3. **Concrete core machine (oracle harness)**
   - Stepper with serializable machine state.
   - Differential tests vs a compiled concrete run for the supported fragment.
4. **Symbolic state / heap model (Z3)**
   - Value representation (tagged union of ints/pointers/bools/floats as needed).
   - Heap as per-allocation byte map + init map + metadata (size, alignment, tag, liveness, lifetime).
   - Pointer provenance as `(alloc_id, offset)` (avoid raw addresses as the primary representation).
5. **Symbolic execution / BMC**
   - Path exploration with Z3 feasibility checks.
   - Trace extraction / replay scaffolding.
6. **Unsafe region library (20 bug types + C++-native UB + security bugs)**
   - `Unsafe_x(σ)` predicates + program‑point hooks (IR instruction ids + source spans).
   - UB is an explicit unsafe region (and optionally transitions to “chaos” states for soundness).
7. **Unknown call model + contract language**
   - "Havoc with footprint" default that is sound.
   - Contracts as relations `R_f` with heap/exception footprint.
   - Source/sink/sanitizer contracts for security analysis (taint lattice overlay).
8. **DSE / sanitizers (refinement oracle)**
   - Concolic executor that can attempt to realize symbolic traces.
   - Sanitizer harness to validate UB witnesses.
   - Contract refinement loop that never breaks over‑approx soundness.
9. **Barrier / invariant / ranking**
   - Proof objects + checkers for inductiveness (including nondeterministic transitions).
   - Template mechanisms and (later) synthesis.

---

# Suggested repo layout (create in BOOTSTRAP; adjust as needed)

Suggested (tool implemented in any language; paths are illustrative):

- `cppfromscratch/`
  - `cli.py` / `cli/` (analysis entrypoint)
  - `frontend/`
    - `compile_db.py` (compile_commands ingestion)
    - `clang_lowering.py` (AST/CFG lowering to core IR)
    - `source_spans.py` (instruction → file/line/col)
  - `ir/`
    - `core.py` (IR definitions)
    - `cfg.py` (CFG/ICFG)
  - `semantics/`
    - `concrete.py` (concrete stepper)
    - `symbolic.py` (symbolic stepper)
  - `z3model/`
    - `state.py` (Z3 sorts + state encoding)
    - `step.py` (`Step(σ,σ')`)
    - `taint_lattice.py` (security lattice overlay)
  - `unsafe/`
    - `core_ub.py` (UB predicates)
    - `security/` (taint unsafe predicates)
  - `contracts/`
    - `libc.py` (mem* / str* / io)
    - `allocators.py` (malloc/free/new/delete)
    - `stl.py` (vector/string/span iterators/epochs)
    - `security.py` (source/sink/sanitizer contracts)
  - `dse/`
    - `concolic.py`
    - `sanitizers.py`
  - `barriers/`
    - `invariants.py`
    - `templates.py`
    - `synthesis.py`
  - `evaluation/`
    - `codeql_compare.py` (parity utilities)
- `tests/`
  - `test_semantics_*.py` (differential tests)
  - `test_unsafe_*.py` (BUG/NON‑BUG)
  - `test_security_bugs.py` (security bug detection tests)
  - `test_barriers.py` (barrier certificate tests)
  - `fixtures/` (small C++ programs + compile DB stubs)
- `scripts/` (optional helpers: scan repos, run batches)
- `results/` (gitignored logs, triage artifacts, traces)
- `external_tools/` (CodeQL, pinned comparison repos)

Record this layout (or your chosen alternative) in `State.json.progress.repo_scaffolded`.

---

# Bug Types: Error Bugs + Security Bugs (C++ edition)

The checker must support two categories of bugs, both defined barrier-theoretically in `cpp-barrier-certificate-theory.md`:

## Core Error Bug Types (20 from barrier-certificate-theory.tex)

These are the original 20 bug types. Implement them in **C++ terms**:

1. `INTEGER_OVERFLOW` (signed overflow UB; also explicit bounded integer intent)
2. `DIV_ZERO` (integer division by zero; include `INT_MIN / -1`)
3. `FP_DOMAIN` (domain errors / NaN/Inf propagation policy, where applicable)
4. `USE_AFTER_FREE`
5. `DOUBLE_FREE`
6. `MEMORY_LEAK` (unbounded growth / missing frees / ownership escape)
7. `UNINIT_MEMORY` (uninitialized reads are UB; include padding leaks)
8. `NULL_PTR` (null deref UB)
9. `BOUNDS` (OOB pointer/index; include one‑past misuse)
10. `DATA_RACE` (C++: data race is UB)
11. `DEADLOCK` (liveness bug)
12. `SEND_SYNC` (thread-safety contract violation; misuse of atomics/locks)
13. `NON_TERMINATION` (ranking functions / barrier-style termination)
14. `PANIC` (terminate/abort/unhandled exception as failure if “no-crash” required)
15. `ASSERT_FAIL` (`assert` failure that reaches the environment)
16. `STACK_OVERFLOW` (deep recursion / stack exhaustion)
17. `TYPE_CONFUSION` (bad casts, vtable confusion, lifetime/type punning UB)
18. `ITERATOR_INVALID` (STL invalidation as a semantic property)
19. `INFO_LEAK` (taint/noninterference; also uninit-byte leaks)
20. `TIMING_CHANNEL` (secret-dependent timing proxy)

## C++‑native UB hazard set (must cover; expands the core 20)

These are C++‑specific hazards that frequently dominate real-world bug reports and are essential for parity:

- `MISALIGNED_ACCESS`
- `STRICT_ALIASING_VIOLATION`
- `UNSEQUENCED_MODIFICATION` (C++ sequencing UB)
- `SHIFT_UB` (shift by >= width, negative shift, etc.)
- `SIGNED_OVERFLOW` (also included via INTEGER_OVERFLOW)
- `INVALID_FREE` (freeing interior pointers; mismatched allocator/deallocator)
- `MISMATCHED_NEW_DELETE` (`new[]/delete`, `new/delete[]`, `malloc/delete`, etc.)
- `DANGLING_REFERENCE` / `LIFETIME_END_USE` (use after object lifetime ends)
- `DOUBLE_DESTRUCTION` (explicit destructor calls + scope exit)
- `NOEXCEPT_VIOLATION_TERMINATE`
- `UNCAUGHT_EXCEPTION_TERMINATE`
- `DTOR_THROW_TERMINATE`
- `ATOMIC_ORDER_MISUSE` (model as a bug class if you represent atomics)

## Security Bug Types (taint-based and configuration bugs; align to CodeQL C/C++)

These are **taint-based and configuration security bugs**. Define them barrier-theoretically in `cpp-barrier-certificate-theory.md` (add a dedicated section if missing), and ensure they align with the CodeQL C/C++ query pack version you pin for the parity target.

Suggested initial set (expand toward full parity with your pinned CodeQL pack):

**Injection Bugs:**
- `SQL_INJECTION`
- `COMMAND_INJECTION` (e.g., `system`, `popen`, `exec*`)
- `FORMAT_STRING` (externally controlled format string to printf-family)
- `CODE_INJECTION` (embedding interpreters / JIT interfaces if present)
- `LDAP_INJECTION`, `XPATH_INJECTION`, `NOSQL_INJECTION` (if applicable)
- `LOG_INJECTION`
- `REGEX_INJECTION` / `REDOS` (DoS via untrusted regex)

**Path/File Bugs:**
- `PATH_TRAVERSAL` / `PATH_INJECTION`
- `TAR_SLIP` (archive traversal)
- `INSECURE_TEMPORARY_FILE`
- `WEAK_FILE_PERMISSIONS`

**Serialization/XML Bugs:**
- `UNSAFE_DESERIALIZATION` (library-specific; treat as taint-to-deserialize sink)
- `XXE`, `XML_BOMB`

**Crypto/Secret Bugs:**
- `CLEARTEXT_STORAGE` / `CLEARTEXT_LOGGING`
- `HARDCODED_CREDENTIALS`
- `WEAK_RANDOMNESS` (non-crypto RNG used for secrets)
- `BROKEN_CRYPTO_ALGORITHM`
- `WEAK_CRYPTO_KEY`
- `INSECURE_PROTOCOL` / `INSECURE_DEFAULT_PROTOCOL`

**Certificate Validation Bugs:**
- `MISSING_HOSTNAME_VALIDATION`
- `REQUEST_WITHOUT_CERT_VALIDATION`

**Other:**
- `UNTRUSTED_DATA_TO_EXTERNAL_API` (policy-defined sinks)

### Taint Tracking Requirements

Security bugs require **taint analysis** integrated into (not bolted onto) the symbolic semantics:

1. **Sources**: argv/env, network reads, file reads, IPC, configuration, database, user-controlled headers/params (if applicable)
2. **Sinks**: shell/system execution, SQL exec, format string arguments, file path opens, network sends, deserialization, crypto APIs
3. **Sanitizers**: escaping/validation/parameterization/whitelisting functions, with sink-specific meaning
4. **Taint label**: each symbolic value carries a structured label in a product lattice (not just a 1-bit taint flag)

General unsafe region for taint bugs at sink `π_sink`:
```
U_taint := { s | π == π_sink ∧ tainted(value) ∧ ¬safe_for_sink(value, sink_kind) }
```

General barrier template (sketch):
```
B_taint = (1 - δ_sink(π)) · M  +  δ_sink(π) · (safe_for_sink(v, k) - ½)
```

For each bug type you implement, you must write down in code/docs:
- The exact unsafe predicate `U_x(σ)` in terms of machine state.
- What counts as "caught/handled" vs "uncaught" for exception-shaped bugs.
- For taint bugs: source, sink, and sanitizer definitions.
- Whether SAFE is even decidable in your current fragment; if not, report UNKNOWN unless you have a proof.

---

## Taint Lattice Implementation (Deep Z3 Integration for C++ security bugs)

Use the product-lattice model developed in `leak_theory.md` (language-agnostic) and integrate it into the C++ symbolic state.

### Mathematical Foundation

The taint lattice is a **product lattice**:

$$\mathcal{L} = \mathcal{P}(\mathcal{T}) \times \mathcal{P}(\mathcal{K}) \times \mathcal{P}(\mathcal{T})$$

Each taint label is a triple $\ell = (\tau, \kappa, \sigma)$ where:
- $\tau \in \mathcal{P}(\mathcal{T})$ — **source types** (which untrusted sources this value came from)
- $\kappa \in \mathcal{P}(\mathcal{K})$ — **safe sinks** (which sinks this value is safe to flow to)
- $\sigma \in \mathcal{P}(\mathcal{T})$ — **sensitivity** (which sensitive data types this value contains)

**Lattice Order**: $\ell_1 \sqsubseteq \ell_2 \iff \tau_1 \subseteq \tau_2 \land \kappa_1 \supseteq \kappa_2 \land \sigma_1 \subseteq \sigma_2$

**Join (least upper bound)**:
$(\tau_1, \kappa_1, \sigma_1) \sqcup (\tau_2, \kappa_2, \sigma_2) = (\tau_1 \cup \tau_2, \kappa_1 \cap \kappa_2, \sigma_1 \cup \sigma_2)$

### Z3 Bitvector Encoding

Encode the lattice components as Z3 bitvectors for efficient symbolic reasoning:

| Component | Encoding | Suggested Width |
|-----------|----------|-----------------|
| τ (sources) | `BitVecSort(SRC_W)` | 16 bits |
| κ (safe sinks) | `BitVecSort(SINK_W)` | 32 bits |
| σ (sensitivity) | `BitVecSort(SRC_W)` | 16 bits |

Safety predicate for sink `k`: a value is safe to flow to sink $k$ iff $k \in \kappa$ or $\tau=\emptyset$.

### Implementation files (create these)

Implement the lattice overlay across these modules (names illustrative):

- `cppfromscratch/z3model/taint_lattice.py` (math + Z3 encoding)
- `cppfromscratch/contracts/security.py` (source/sink/sanitizer contracts)
- `cppfromscratch/semantics/security_tracker_lattice.py` (IR transfer functions integrating taint)
- `cppfromscratch/unsafe/security/lattice_detectors.py` (unsafe predicates at sinks)

### Symbolic use sketch (illustrative)

```text
import z3

# symbolic label for a value v
tau = z3.BitVec("v_tau", 16)
kappa = z3.BitVec("v_kappa", 32)

def is_safe_for_sink(k: int) -> z3.BoolRef:
    no_untrusted = (tau == 0)
    sink_allowed = (z3.Extract(k, k, kappa) == 1)
    return z3.Or(no_untrusted, sink_allowed)

solver = z3.Solver()
solver.add(z3.Not(is_safe_for_sink(3)))  # example sink kind 3
print(solver.check())
```

### Implicit Flow Tracking (PC taint)

To handle implicit flows, track a program-counter taint and join it into assignments under tainted control flow. This prevents laundering secrets through control decisions.

---

# Concrete technical target (align with the draft)

Target execution model: **a C++ core abstract machine** (as in `docs/cpp_z3_semantics_core.py`), with explicit UB-as-unsafe.

Minimum semantic commitments (must be reflected in code, not prose):

- A well-defined core IR (or abstract machine) with:
  - explicit control flow,
  - explicit exceptional/terminate edges,
  - explicit heap effects.
- Pointer representation as provenance pairs: `(alloc_id, offset)`.
- Per-allocation metadata:
  - size, alignment,
  - allocation API tag (`malloc`, `new`, `new[]`, stack, global),
  - liveness and lifetime state (storage vs constructed vs destroyed).
- Byte-addressable memory and byte-level initialization map.
- Integer semantics:
  - explicit width and signedness,
  - explicit UB predicates for signed overflow / shifts / divide corner cases.
- Unspecified evaluation order:
  - represent defined-but-unspecified orders as nondeterministic branching, and
  - treat unsequenced modification as UB (unsafe).
- Exceptions and termination:
  - represent throw/catch/unwind in the IR or state,
  - model `noexcept` and terminate behavior,
  - model destructor behavior during unwind (including terminate on throw).
- Concurrency (even minimal):
  - model scheduling nondeterminism,
  - treat data race as unsafe (UB),
  - represent locks sufficiently to detect deadlocks (optional early).

**Note that you must be able to extract source locations (file:line:col and function) wherever an unsafe predicate is checked.** IR-only bug reports without source mapping are not acceptable.

---

# Formal core (implement in code, not just prose)

You must represent the analysis target as a transition system:

- State space `S` (machine states).
- Initial states `S0`.
- Step relation `→` (nondeterministic in general).
- Unsafe region `U_x ⊆ S` per bug type.

And compute/report:

- `BUG` iff `Reach(S0,→) ∩ U_x ≠ ∅` with an extracted witness trace.
- `SAFE` iff you have an inductive certificate (barrier/invariant) establishing `Reach ∩ U_x = ∅`.
- `UNKNOWN` otherwise.

Barrier/invariant condition (nondeterministic):

- `Init`: `∀s∈S0. B(s) ≥ ε`
- `Unsafe`: `∀s∈U. B(s) ≤ -ε`
- `Step`: `∀s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0`

Implement *checking* these conditions first (given a candidate `B`), before attempting synthesis.

---

# Z3 modeling guidelines (avoid "symbolic spaghetti")

This project lives or dies on whether the symbolic state is:
(a) faithful enough to mean something, and (b) structured enough to debug.

Guidelines:

- Use **tagged values** (e.g., `Val = (tag, payload)`), so type confusion is definable.
- Separate **identity** (AllocId / ObjId) from **value** (ints/bools/pointers) so aliasing is expressible.
- Model pointers as provenance pairs `(alloc_id, offset)`; avoid modeling raw addresses directly.
- Model the heap as:
  - per-allocation byte arrays + init arrays, or
  - a global byte array indexed by `(alloc_id, offset)` with explicit bounds predicates,
  but keep it consistent and testable.
- Track lifetime and liveness separately:
  - liveness = storage is allocated and not freed,
  - lifetime = object is constructed/alive and not destroyed.
- For integer UB:
  - represent IR types explicitly (width, signedness),
  - define UB predicates as machine-state predicates (not scattered checks).
- For exceptions/terminate:
  - represent "current exception" or unwind state explicitly; exception edges must be real transitions.
- For unknown effects:
  - prefer "havoc with footprint": declare what may change, keep the rest stable.

Every unsafe predicate must be definable against your Z3 state without parsing source text.

---

# IR-Level Security Taint Analysis (must implement at IR level)

All taint tracking must operate at the **same IR level** as your semantics, not at raw source-text pattern level. This is critical for precision and integration with the symbolic state.

## The Taint Product Lattice

Implement the product lattice from `leak_theory.md` (and your C++ adaptation doc):

$$\mathcal{L} = \mathcal{P}(\mathcal{T}) \times \mathcal{P}(\mathcal{K}) \times \mathcal{P}(\mathcal{T})$$

Each taint label is a triple $\ell = (\tau, \kappa, \sigma)$:
- $\tau$: untrusted source types (bitvector)
- $\kappa$: sanitized sink types (bitvector)
- $\sigma$: sensitivity source types (bitvector)

Implementation (illustrative): `cppfromscratch/z3model/taint_lattice.py`

## IR Operation Transfer Functions

Each IR operation has a taint transfer function. Define these in one place (not scattered ad-hoc).

Suggested transfer rules (sketch):

| IR op | Transfer function |
|------|--------------------|
| `binop(a,b)` | `ℓ = ℓ(a) ⊔ ℓ(b)` |
| `cmp(a,b)` | `ℓ = ℓ(a) ⊔ ℓ(b)` |
| `phi(v1..vn)` | `ℓ = ⊔ ℓ(vi)` |
| `load(p)` | `ℓ = ℓ(p) ⊔ ℓ(mem[p])` (if memory carries labels) |
| `store(p,v)` | `ℓ(mem[p]) := ℓ(p) ⊔ ℓ(v) ⊔ ℓ_pc` |
| `call(f,args)` | `ℓ(ret) = ⊔ℓ(args) ⊔ Σ_f` (summary/contract effects) |
| `branch(cond)` | update `ℓ_pc := ℓ_pc ⊔ ℓ(cond)` |

## Sink Detection at IR Call Sites

Security sinks are detected at IR call sites based on callee identity (symbol name, resolved function, virtual dispatch target set):

- Map `callee` → `sink_kind` via contracts, not via substring matching.
- For each sink call, check whether the relevant argument is safe for that sink kind.

Pseudo-code (illustrative):

```text
sink_kind = contract_db.get_sink_kind(callee)
if sink_kind is not None:
    if not arg_label.is_safe_for_sink(sink_kind):
        report_bug(...)
```

## Symbolic Taint with Z3

Use Z3 constraints for sink safety checks:

```text
import z3
from cppfromscratch.z3model.taint_lattice import SymbolicTaintLabel, SinkKind

sym = SymbolicTaintLabel.fresh("v")
constraint = sym.is_safe_for_sink_constraint(SinkKind.SQL_EXECUTE)

solver = z3.Solver()
solver.add(z3.Not(constraint))
if solver.check() == z3.sat:
    model = solver.model()
    # counterexample explains taint bits / sanitizer bits
```

## Debugging Missing Taint Propagation

If taint is "lost" during analysis:

1. Check IR instruction id/source span where taint disappears.
2. Trace transfer functions: log each op’s label computation.
3. Check implicit flows: ensure `ℓ_pc` is tracked and joined into assignments.
4. Check summaries/contracts: if taint crosses calls, ensure summaries exist or the conservative fallback is used.

---

# Interprocedural Analysis (call graphs + summaries)

Your C++ checker must work interprocedurally. C++ makes this hard (virtual dispatch, templates, function pointers), but "intraprocedural only" is not acceptable for parity.

## Architecture Overview

Use one of these sound approaches (start simple, grow precision):

1. ICFG + summary-based analysis (bottom-up summaries, top-down application).
2. IDE/IFDS-style dataflow over an ICFG with conservative fallbacks.
3. Symbolic summaries (relational summaries `R_f`) for selected functions.

## Call Graph Construction

Minimum requirements:

- Direct calls resolved exactly.
- Virtual calls over-approximated via class hierarchy analysis (CHA) or conservative points-to.
- Function pointer calls over-approximated (conservative target set, or treat as unknown call with havoc).
- Template instantiations: treat instantiated functions as distinct nodes (or lower post-instantiation IR).

## Summary Computation

Summaries must include:

- argument→return relation (values and taint),
- heap footprint (read/write/alloc/free),
- exception/terminate behavior,
- lifetime effects (construct/destroy/free).

Store summaries deterministically under `results/` for debugging and cache reuse.

## Applying Summaries at Call Sites

When applying a summary:

- substitute actuals for formals,
- update heap/lifetime/taint according to summary,
- include the conservative fallback path when preconditions are not provable.

## Debugging Interprocedural Issues

If a flow is missing:

- Inspect call graph edges at the relevant callsite.
- Check whether the callee was treated as unknown; if so, ensure the unknown-call fallback is present.
- Check summary guard conditions; if too strong, you may be pruning behaviors unsoundly.

---

# Unknown calls as barrier-theoretic relations (must implement)

Model an unknown call `f` as a relation `R_f ⊆ In × Out` where the interface includes:

- argument values (and possibly shapes/types),
- heap footprint (what locations may be read/written/allocated/freed),
- raised-exception and terminate behavior.

Soundness rule: your assumed `R_f` must be an **over-approximation** of true behavior. Refinement must preserve `Sem_f ⊆ R_f`.

Preferred implementation form:

- Use **relational summaries** with multiple guarded cases plus a required havoc fallback (see `docs/CPP_CODEQL_PARITY_SOTA_MATH_PLAN.md`), rather than ad-hoc per-function logic in the interpreter.
- Expand library-specific summaries aggressively once the scaffold exists, because real C++ programs are dominated by libc/STL/framework calls.
- For library precondition violations that are UB (e.g., `memcpy` overlap), model that as reachability into an unsafe region.

Track contracts in:
- code (a contract library file),
- and `State.json` under `progress.unknown_calls.contracts`.

---

# DSE refinement oracle (how to use it correctly)

Implement concolic/DSE to answer "can we actually realize this candidate trace?" and to produce human-usable repros.

Rules:

- If DSE/sanitizers **find** an execution matching a symbolic counterexample: you have a concrete reproducer; attach it to the bug report artifact.
- If DSE/sanitizers **fail** within budget: do **not** conclude infeasible; keep the over‑approx contract/abstraction unless you have independent justification to narrow it.
- Use failures to decide *where* to invest:
  - expand IR semantics coverage,
  - refine path condition modeling,
  - refine unknown-call contracts conservatively.

Always log DSE attempts (inputs tried, constraints, sanitizer outputs) into `results/` and summarize in `State.json`.

---

# Evaluation loop (false negatives and false positives, RustFromScratch-style)

You must continuously test both:

- **False negatives**: BUG programs your analyzer misses.
- **False positives**: SAFE programs your analyzer flags.

Do this in increasing difficulty tiers:

1. **Micro-tests**: 5–50 line programs targeting one semantic corner (lifetimes, one‑past, shifts, noexcept).
2. **Synthetic realistic tests**: 50–300 line programs with plausible structure; label the "bug line"; include non-bugs.
3. **Pinned CodeQL comparison** (NEW): run on a pinned C++ target, compare to precomputed CodeQL, and document gaps or false positives in `checkers_lacks_cpp.md`.
4. **Public repos**: clone curated C++ repos; scan in batches; triage.

For every flagged issue in real code:

- Produce a model witness trace (symbolic path + concrete sanitizer repro if possible).
- If you cannot produce a witness, do not claim BUG; keep it UNKNOWN or as a "suspicious site" (non-decisive).
- Fix false positives by improving semantics/contracts/proofs, not by adding text heuristics.
- When a BUG/UNKNOWN hinges on unknown library behavior (or you "can't reason" because a call is modeled as havoc), prefer adding/refining a library summary/contract for the specific call(s) involved (while preserving `Sem_f ⊆ R_f`), then rerun analysis.

Write a report on any true positives in real OR synthetic repos within the document `TRUE_POSITIVES_<repo_or_synthetic>.md`, including what reasoning you used to conclude it is a true positive and not a false positive. This project will be judged by false-positive rate *and* the number of true positives found.

---

# Per-run procedure (do this every invocation)

You must follow this exact loop each run:

1. Read `State.json`.
2. Append a `last_run.started_at` timestamp; set status to `running`; write it back immediately (so crashes still record progress).
3. Re-check the anti-cheating rule and ensure your next action improves the Z3/semantics/barrier model (not heuristics).
4. Choose exactly **one** primary action from `queue.next_actions` (or repopulate the queue if empty).
5. Execute the action end-to-end:
   - implement code changes,
   - add/adjust tests (BUG + NON‑BUG where relevant),
   - run tests/linters (whatever exists),
   - fix what you broke.
6. Record results in `State.json`:
   - increment `iteration`,
   - set `last_run.finished_at`, `status` = `ok`/`failed`,
   - list `changed_files`,
   - include a short factual summary (no fluff),
   - update `progress.*` booleans/lists that changed,
   - update `queue.next_actions` (remove the done item; add follow-ups).
7. Stop. Do not start a second large task in the same run.

If tests are failing at the start of a run, your primary action is: **fix the test failures** (model-based), and update state.

---

# What to do first (if `queue.next_actions` is empty)

Populate it with this bootstrapping sequence (keep it ordered):

1. Scaffold the package + CLI + tests (minimal).
2. Add library-specific semantics scaffolding: relational summaries (cases + required havoc fallback), and seed high-frequency libc/alloc/STL summaries (sound over-approx only).
3. Implement a tiny concrete core stepper for a trivial program (alloc/store/load/free).
4. Implement symbolic state + Z3 encoding for that same trivial program.
5. Implement the first unsafe predicate: `OOB_WRITE` or `NULL_DEREF` as a pure semantic unsafe region.
6. Make it find a concrete counterexample trace and print it with source spans.
7. Add NON‑BUG tests where bounds/nullness are proven safe.
8. Add `USE_AFTER_FREE`, `DOUBLE_FREE`, and `UNINIT_READ` next.
9. Ensure unknown-call fallback ("havoc with footprint") is present and cannot yield unsound SAFE claims; expand library summaries/contracts as needed to turn UNKNOWN into provable BUG/SAFE.
10. **Run pinned CodeQL comparison** (Phase `CPP_CODEQL_COMPARISON`) before expanding to random public repos; document gaps AND false positives in `checkers_lacks_cpp.md`.
11. Only then expand C++ feature coverage (exceptions, RAII, threads) and add more bug classes.
12. Proceed to public repo evaluation.

---

# Quality bar (how you know you're not cheating)

For any detector/bug class, you must be able to answer, with code pointers:

- "What is the exact semantic unsafe region, in terms of the machine state?"
- "What is the exact transition relation you used?"
- "Where is the Z3 query that proves reachability / inductiveness?"
- "Where is the extracted witness trace, and how do we replay it concretely?"

If you cannot answer those, you are not doing the project—stop and fix the model.
