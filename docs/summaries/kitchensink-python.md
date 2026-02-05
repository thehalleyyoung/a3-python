# Kitchen-Sink Verification Pipeline for PythonFromScratch (Portfolio → Barrier Theory → Certificate/Counterexample)

This document adapts `docs/kitchensink.md` to **PythonFromScratch** as specified by `python-barrier-certificate-theory.md`.

Goal: increase the number of **non-timeout** outcomes (a checkable **SAFE** proof artifact or a validated **BUG** witness) by turning the current single-pass analyzer into a **staged, portfolio-driven orchestrator** where every technique is either:

- a producer of *barrier-theoretic information* (reduces / conditions the search), or
- a certifier (barrier certificate) or witness validator (concrete replay / DSE).

“Non-timeout” here means: fewer `UNKNOWN` results caused by Z3 timeouts, path explosion (hitting `max_paths`), or spending the whole budget in one hard subroutine (e.g., a single inductiveness query).

---

## 0) Core Principle: Per-Unsafe-Region Results (not one monolithic verdict)

The `docs/kitchensink.md` architecture is per-unsafe-region. For PythonFromScratch, the analogous “unsafe regions” are:

- the 20 core bug types (e.g., `DIV_ZERO`, `BOUNDS`, `ASSERT_FAIL`, …), and
- the security bug types (e.g., `SQL_INJECTION`, `COMMAND_INJECTION`, …).

### Why this increases non-timeout yield

One global query (e.g., `U = OR(all bugs)`) is typically much harder than `U_bug` per bug-type / per sink.

So the pipeline should aim to return:

- **BUG** for at least one region when a witness exists and can be validated, and/or
- **SAFE** for as many regions as possible (even if some regions remain `UNKNOWN`).

Keep the current CLI behavior (single exit code) by default, but internally compute (and optionally print) a table:

```
bug_type   verdict   artifact
DIV_ZERO   SAFE      invariant/barrier
BOUNDS     BUG       validated trace
...        UNKNOWN   (reason + partial artifacts)
```

This alone converts many “overall UNKNOWN” runs into “mostly SAFE + a small residual UNKNOWN set”, which is operationally a big win.

---

## 1) The Two-Semantics Hybrid Contract (Python-specific “glue”)

`python-barrier-certificate-theory.md` frames the hybrid model as:

1. **Symbolic transition system** `PTS_R` where unknown/library calls are modeled by **relations** `R_f` (contracts).
2. **Concolic traces** used to validate existential claims (bugs) and to *detect* when contracts are unsound (too narrow).
3. **A contract library** with provenance/trust levels.

The orchestrator should treat these as first-class artifacts and enforce:

- **SAFE is universal:** proofs must hold over `PTS_R`, and the contract set used must be attached to the proof.
- **BUG is existential:** symbolic counterexamples are hypotheses; report BUG only when there is a concrete repro (or at least a concrete replay objective that succeeds).

This directly matches the “coupled CEGIS loops” idea in `docs/kitchensink.md`, with the Python-specific third loop: **contract refinement**.

---

## 2) The Artifact Store: What We Cache and Reuse

To avoid “timeout by redoing work”, the orchestrator should cache artifacts per `(program, entry_point, bug_type/sink)`:

### Program structure
- Bytecode, CFG, exceptional edges (where modeled), call graph
- Detected loops, loop headers, backedges (`pyfromscratch/barriers/program_analysis.py`)
- Resolved call targets (stable function IDs for contract lookup)

### Relevance reductions (slicing / COI)
- Per-bug-type **sink set** (candidate hazard sites)
- Per-sink backward slice: variables + instructions that can influence that sink
- Pruned entry points: only analyze functions that can reach a sink

### Over-approx information (for conditioning proofs)
- Abstract bounds / invariants (intervals, simple congruences, taint facts)
- Loop invariants and ranking functions (existing termination/invariant integrations)
- Contract assumptions currently in force (`R_f` cases + fallback)

### Under-approx evidence (for bugs + learning)
- BMC witnesses (symbolic traces) and their replay objectives
- Concrete traces (DSE/concolic) and call-interface observations
- ICE-style examples: `(good states)`, `(bad states)`, `(implications)` extracted from failures

### Solver artifacts
- “Frontier” states when path exploration hits `max_paths`
- Z3 models from failed inductiveness checks (counterexamples)
- Unsat cores / simplification hints (purely as scheduling signals, never for verdicts)

---

## 3) Execution Policy: Portfolio + Staged Deepening (don’t bet the run on one hard query)

The orchestrator should schedule many cheap attempts before expensive ones, and increase budgets only when there is evidence it might pay off.

### Suggested staged schedule (per bug type / sink)
1. **Structural reachability (CFG-only):** prove sink unreachable when call target is statically known and no path exists.
2. **Light BMC:** small `k` bounded search focused on the sink and immediate preconditions (fast BUG wins).
3. **Guided symbolic exploration:** prioritize paths that move toward the sink; stop early if a witness appears.
4. **Witness validation:** DSE/concolic replay of the best candidate trace.
5. **Invariant harvesting:** loop invariant / ranking synthesis, abstract bounds.
6. **Barrier synthesis (CEGIS + templates):** start low-degree, low-dimensional; only escalate when the program structure suggests it.
7. **Contract refinement (if blocked on unknown calls):** selective concolic to gather call-interface observations; widen unsound contracts; retry.

Key “kitchen sink” engineering rule to preserve what already works:

- Any new stage must be **additive** (it can produce artifacts or early exits), never silently change the semantics of existing checks.

---

## 4) High-Leverage Integration Ideas (Concrete, PythonFromScratch-shaped)

### 4.1 Replace “one huge unsafe predicate” with per-bug-type obligations

Current SAFE proof attempts that use `unsafe_predicate = OR(all bugs)` are structurally much harder than necessary.

Instead:
- Try to prove **SAFE(DIV_ZERO)**, **SAFE(BOUNDS)**, … independently.
- Keep the overall CLI verdict conservative (overall SAFE only if all are SAFE), but *report partial safeties*.

This also enables bug-type-specific templates and encodings (e.g., bounds barriers use length observers; div-zero uses denom constraints).

### 4.2 Add “control-flow-only” SAFE proofs as the first certifier

Many security bug types reduce to “sink not reachable in this module/function under conservative call resolution”.

Barrier-theoretic shape:
- Use an inductive invariant on `pc`/call-stack (discrete barrier) proving `pc != sink_pc` always.

Implementation idea:
- Build a conservative CFG over bytecode offsets for the current entry point.
- If a sink site is unreachable in this CFG, emit a proof artifact:
  - a small inductive invariant over `pc` (or a reachability certificate) + the call-resolution assumptions used.

This is cheap and yields lots of non-timeout SAFE results without touching Z3-heavy heap modeling.

### 4.3 Make bug-finding a targeted reachability query, not “explore everything”

For crash-style bugs (`DIV_ZERO`, `BOUNDS`, `ASSERT_FAIL`, …):
- Identify *hazard opcodes* (e.g., `BINARY_OP /`, `BINARY_SUBSCR`, `LOAD_ATTR` on possibly-None, `ASSERT_*` patterns).
- For each hazard site, run BMC to reach it and satisfy the unsafe condition.

This turns “path explosion” into “many small SAT queries” and improves BUG yield under a fixed budget.

For security bugs:
- Use interprocedural summaries to identify candidate flows and then run **trace-backed** symbolic checks only on the relevant functions/paths.

### 4.4 Integrate DSE/lockstep as a first-class witness validator (not an afterthought)

From `python-barrier-certificate-theory.md`:
- symbolic traces are hypotheses; concolic is for witness generation/validation.

Practical orchestration changes:
- Validate **early**: as soon as you have any plausible BUG trace, attempt replay within a small budget.
- Maintain a queue of “pending validation” traces; don’t waste the entire budget searching if one trace is already likely.

### 4.5 Turn barrier synthesis into a real CEGIS loop with reusable counterexamples

`pyfromscratch/barriers/cegis.py` exists; the missing piece is making the orchestrator:
- treat failed inductiveness checks as valuable artifacts,
- feed them into template selection / parameter synthesis,
- and reuse them across related bug types (e.g., bounds + null-ptr share “index/len” constraints).

Concrete performance wins (no semantic change):
- Short-circuit inductiveness checks: if Init fails, don’t run Unsafe/Step; if Unsafe fails, don’t run Step.
- Run cheap checks with low Z3 timeouts first; only increase timeouts for templates that passed Init+Unsafe.

### 4.6 Fix the “step relation too imprecise → no barriers ever” failure mode

Barrier synthesis needs a step relation `→_R` that is:
- sound (over-approximate),
- but not so unconstrained that Step becomes “B must hold for all states”.

PythonFromScratch already has a directionally-correct place to put this:
- `pyfromscratch/barriers/step_relation.py` (opcode encodings with havoc fallback).

Integration idea:
- Build the step relation from the *actual opcode set* reachable in the current slice/CFG.
- Encode only what you can model; keep a havoc fallback for the rest.
- Add strengthening invariants/bounds so that havoc doesn’t destroy all structure.

This is the core bridge from “symbolic execution explored some paths” to “barrier proof covers all paths”.

### 4.7 Make contract refinement the third loop (only when it’s the blocker)

Many `UNKNOWN` results will be “blocked on library behavior”.

Rather than globally “improving contracts”:
- Detect when a candidate BUG/SAFE attempt hinges on an unknown call’s return shape / exception behavior.
- Trigger selective concolic runs to gather call-interface observations.
- Use observations only to:
  - **widen** unsound contracts, and
  - prioritize which spec/source-derived cases to add.

Never narrow contracts based on “didn’t observe X”.

---

## 5) “Without Breaking What Already Works”: Compatibility Strategy

### Keep the current analyzer as a stable baseline

- Do not remove or reorder existing checks in `pyfromscratch/analyzer.py` without a feature flag.
- Add a new orchestrator entry point (e.g., `Analyzer.analyze_file_kitchensink(...)` or a separate module) that *calls into* existing components.

### Make changes monotone and opt-in

- Start with a `--kitchensink` CLI flag that enables the orchestrator; default behavior stays unchanged.
- Ensure any new SAFE result is backed by a checkable artifact (barrier/invariant) and includes explicit assumptions (contracts/call resolution).
- Ensure any new BUG result includes a concrete repro/trace (or is labeled as “candidate” if not yet validated).

### Preserve soundness boundaries

- Pure-symbolic mode (`--no-concolic`) must still work; concolic can improve witnesses but must not decide SAFE.
- Any “heuristic” is allowed only for **scheduling/prioritization**, not for verdicts.

---

## 6) Concrete Mapping to This Repo (Where Each Kitchen-Sink Module Lives)

### Frontend / structure
- Loader/compile: `pyfromscratch/frontend/loader.py`
- CFG/call graph: `pyfromscratch/cfg/call_graph.py`
- Program structure heuristics: `pyfromscratch/barriers/program_analysis.py`

### Over-approx producers
- Interprocedural security summaries: `pyfromscratch/semantics/sota_intraprocedural.py`, `pyfromscratch/semantics/sota_interprocedural.py`
- Loop invariants: `pyfromscratch/semantics/invariant_integration.py`
- Termination/ranking: `pyfromscratch/barriers/ranking_synthesis.py`, `pyfromscratch/semantics/termination_integration.py`

### Under-approx bug finding + validation
- Symbolic execution core: `pyfromscratch/semantics/symbolic_vm.py`
- Concolic/DSE: `pyfromscratch/dse/concolic.py`, `pyfromscratch/dse/selective_concolic.py`, `pyfromscratch/dse/lockstep.py`

### Contracts / unknown calls
- Contract schemas/stubs: `pyfromscratch/contracts/*`
- (Planned) relational summaries adapter per `python-barrier-certificate-theory.md`: add `pyfromscratch/contracts/relations.py`

### Certifier (barriers / invariants)
- Inductiveness: `pyfromscratch/barriers/invariants.py`
- Template enumeration: `pyfromscratch/barriers/synthesis.py`
- CEGIS loop: `pyfromscratch/barriers/cegis.py`
- Step relation encoding: `pyfromscratch/barriers/step_relation.py`

### Unsafe regions
- Registry: `pyfromscratch/unsafe/registry.py`
- Bug-type-specific predicates/extractors: `pyfromscratch/unsafe/*`

---

## 7) Minimal “Kitchen-Sink Orchestrator” Pseudocode (PythonFromScratch-shaped)

```text
for entry_point in entry_points:
  pre = preprocess(bytecode, cfg, call_graph)

  for bug_type in bug_types:
    artifacts = cache.get(entry_point, bug_type) || {}

    // Phase A: cheap SAFE wins
    if cfg_proves_sink_unreachable(pre, bug_type):
      emit SAFE(bug_type, proof=pc_invariant)
      continue

    // Phase B: bug-finding portfolio
    trace = bmc_find(pre, bug_type, artifacts, small_budget)
         || guided_symbolic_find(pre, bug_type, artifacts, medium_budget)
    if trace:
      if concolic_validate(trace, artifacts, small_budget):
        emit BUG(bug_type, validated_trace)
        continue
      else:
        artifacts += pending_validation(trace)

    // Phase C: harvest invariants/bounds (condition proofs + prune search)
    artifacts += interprocedural_summaries(pre)   // if relevant
    artifacts += invariant_synthesis(pre)
    artifacts += ranking_synthesis(pre)           // for termination-related obligations

    // Phase D: certify (barrier CEGIS with staged templates)
    for template_family in schedule_templates(pre, artifacts):
      result = cegis_synthesize(pre, bug_type, template_family, artifacts, budget)
      if result.SAFE:
        emit SAFE(bug_type, barrier=result.barrier)
        break
      artifacts += result.counterexamples

    if no verdict:
      emit UNKNOWN(bug_type, reason + artifacts summary)
```

---

## 8) What “Success” Looks Like (Measurable)

Track and regress-test these metrics on existing suites (synthetic + PyGoat):

- % of `(entry_point, bug_type)` with a non-UNKNOWN result under fixed wall-clock budget
- # of validated BUGs found per minute
- # of SAFE proofs produced (even if partial, per bug type)
- distribution of time spent by stage (to detect “one stage eats the budget”)
- top reasons for UNKNOWN (path explosion, Z3 timeout, unknown-call blocker, missing encoding)

The kitchen-sink design is working when:
- easy SAFE/BUG cases stop timing out,
- hard cases produce better diagnostics + reusable artifacts,
- and nothing regresses existing correctness/tests (baseline analyzer remains intact).

