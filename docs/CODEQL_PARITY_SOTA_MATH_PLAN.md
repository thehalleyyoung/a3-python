# SOTA Math Plan: Closing the Precision Gap vs CodeQL (PyGoat → Real Repos)

**Purpose.** This document turns our current approach (barrier-certificate reachability + leak theory) into an *actionable* plan for improving the specific areas where CodeQL currently beats us—especially **sophisticated intraprocedural analysis**—while keeping the project’s core non-negotiable: **BUG/SAFE/UNKNOWN grounded in the Python→Z3 transition system**, not pattern matching.

**Primary inputs (repo-local).**
- `python-barrier-certificate-theory.md` (execution-faithful bytecode machine; unknown calls as relations; contracts + DSE rules; multi-IR pipeline and “guards as facts”).
- `leak_theory.md` (security leaks as reachability; taint as a product lattice over `(τ, κ, σ)` with optional `τ_pc`).
- `checkers_lacks.md` (PyGoat comparison framing what CodeQL wins on; concrete “we missed due to interprocedural precision / sanitizer modeling / framework integration”).
- `results/pygoat_codeql/CODEQL_RESULTS_SUMMARY.md` (ground truth list of CodeQL findings used in that comparison).

**Important sanity note (doc drift).**
`checkers_lacks.md` claims we “lack” several CodeQL bug categories, while `docs/SECTION_11_IMPLEMENTATION.md` claims all 47 CodeQL Python security queries are implemented/mapped. Before we optimize precision, we should reconcile whether the gap is **(A) missing bug types**, **(B) implemented but not firing**, or **(C) firing but lower precision/recall**.

---

## 0) Non‑negotiables, scope, and working definitions

### 0.1 Non‑negotiables (anti‑cheating, translated to engineering constraints)

This plan assumes we keep the repo’s core constraints from `.github/prompts/python-semantic-barrier-workflow.prompt.md`:

- **No pattern matching deciders.** A detector may *use* syntactic information to identify candidate program points, but the verdict must come from semantics-grounded reachability (symbolic/abstract) and/or proof artifacts.
- **No “SAFE by absence.”** SAFE means a checked proof artifact (barrier / inductive invariant / CHC proof), not “we didn’t find a bug”.
- **Unknown calls must remain sound.** If we can’t justify excluding behaviors, the **havoc fallback stays reachable** (especially for SAFE proofs).
- **Concolic is witness-only.** DSE/concolic may help *produce* or *validate* counterexamples and widen contracts, but must never be what makes something SAFE.

### 0.2 Working definitions (so “precision” is measurable)

We will use these definitions throughout:

- **Intraprocedural precision**: within a single code object, track how values/taint flow through locals/stack/temporaries and across branches, loops, and exceptions.
- **Interprocedural precision**: track how values/taint move across calls with call/return matching, recursion handling, and limited context sensitivity.
- **Model precision**: how accurately our contracts capture framework/library semantics (sources/sinks/sanitizers), without sacrificing soundness.

### 0.3 What “CodeQL parity” means (and what it doesn’t)

We are not trying to clone CodeQL. We are trying to:

- **Match CodeQL’s recall** on the CodeQL Python security query set (at least the subset we claim to support), *on the same code snapshot*, starting with PyGoat.
- **Maintain soundness posture**: any SAFE claim is backed by a proof, and any BUG claim is backed by a semantics witness (symbolic reachability; optionally concolic validation).
- **Beat CodeQL where we’re differentiated**: semantic correctness bugs and proof artifacts.

### 0.4 Current code anchors (where the work lands)

These are the most relevant modules to touch or wrap:

- CFG + guards
  - `pyfromscratch/cfg/control_flow.py`: CFG w/ exceptional edges + dominance + loop info.
  - `pyfromscratch/cfg/dataflow.py`: guard dataflow (nonnull/type/div/bounds-style facts).
  - `pyfromscratch/cfg/call_graph.py`: AST-based call graph + call sites.
- Taint + contracts
  - `pyfromscratch/z3model/taint_lattice.py`: `(τ, κ, σ)` lattice + symbolic encoding.
  - `pyfromscratch/contracts/security_lattice.py`: contract lookup + source/sink/sanitizer behavior.
  - `pyfromscratch/semantics/security_tracker_lattice.py`: VM-integrated taint tracking.
- Intraprocedural / interprocedural plumbing (today)
  - `pyfromscratch/semantics/intraprocedural_taint.py`: intraprocedural taint via bytecode worklist.
  - `pyfromscratch/semantics/summaries.py`: AST summaries (note: appears drift-prone; audit needed).
  - `pyfromscratch/semantics/interprocedural_taint.py`: applies summaries at call sites during VM stepping.
  - `pyfromscratch/semantics/bytecode_summaries.py`: a “SOTA abstract interpretation” skeleton (currently partially overlapping with the above).
- Orchestration
  - `pyfromscratch/analyzer.py`: `security_scan()` currently uses symbolic stepping + summary application.
  - `pyfromscratch/frontend/entry_points.py`: entrypoint detection + tainted/sensitive parameter marking.

### 0.5 A required first deliverable: reconcile doc/code drift with a single source of truth

Before optimizing math, ensure our *claims* and *measurements* match the code:

- `checkers_lacks.md` vs `docs/SECTION_11_IMPLEMENTATION.md` vs `State.json` should agree on:
  - which CodeQL bug types are implemented,
  - which are validated,
  - and which are missing due to modeling vs analysis precision.

## 1) Where CodeQL is beating us (problem decomposition)

From `checkers_lacks.md` (and consistent with CodeQL’s overall architecture), the recurring wins are:

1. **Intraprocedural precision**
   - Flow-sensitive local propagation through assignments, temporaries, collections, string building, and branch structure.
   - Mature “dataflow to sink” modeling for language idioms (e.g., `x = y; z = f(x); sink(z)`), including framework patterns.

2. **Interprocedural precision**
   - More precise cross-function flows (call/return matching, recursion handling, call context), especially for taint tracking.
   - Better defaults when call targets are dynamic (conservative but still useful).

3. **Sanitizer & framework integration**
   - Large curated models for Django/Flask/ORMs and sanitizer libraries.
   - “Additional taint steps” that encode framework semantics (e.g., request objects, templating, ORM parameterization).

4. **Engineering maturity at scale**
   - Good performance on big codebases.
   - Stable behavior in the face of dynamic Python features.

Our goal isn’t to re-implement CodeQL; it’s to *import the math* that makes it precise and scalable, while remaining barrier-certificate-first.

---

## 2) The math we should adopt (SOTA-but-practical)

This section names the math tools and shows how they fit our theory (“exact semantics; analysis is a validated over-approximation on an interface”).

### 2.1 Multi-IR pipeline (bytecode exactness + analysis-friendly IR)

`python-barrier-certificate-theory.md` explicitly supports a pipeline:
- **Exact substrate:** Python bytecode abstract machine (authoritative transition relation).
- **Derived analysis IR(s):** stack-to-register **SSA-like** IR and/or symbolic trace IR.

Why SSA-like IR matters:
- Stack machines obscure expressions; SSA makes data dependencies explicit.
- Intraprocedural analysis (abstract interpretation, dataflow, CHCs) is significantly easier when values have names and use-def edges.
- Summaries as relations compose cleanly on SSA variables.

**Core obligation (soundness).** Any derived IR must be a validated over-approximation of the exact semantics *after projection to the analysis interface* (taint bits, guard facts, selected observers).

### 2.2 Abstract interpretation over a product domain (intraprocedural engine)

We should treat intraprocedural analysis as a **least-fixpoint computation** on a *finite-height* or *widened* lattice domain.

Recommended abstract state at a program point:

```
D = GuardFacts × Taint × Shape × (Optional: Numeric/String domains)
```

Concrete suggestions that align with existing code:
- **GuardFacts:** the “guards as facts” idea (`g_nonnull`, `g_type`, `g_bounds`, etc.), computed via CFG analysis and/or abstract interpretation.
- **Taint:** use `leak_theory.md`’s product lattice label `(τ, κ, σ)` plus optional `τ_pc` for implicit flows.
- **Shape (minimal):** alias sets / container shape / “may-contain-taint” summaries sufficient to avoid obvious false negatives at sinks.
- **Numeric (optional):** intervals/sign/zeroness for crash checks (already sketched in `pyfromscratch/semantics/bytecode_summaries.py`).
- **String (optional):** start with *taint-only string builder* (propagate taint through `format`, f-strings, concatenation). If needed later, introduce a regular-language domain.

Fixpoint computation:
- Use a **worklist algorithm** on the CFG (including exceptional edges) with widening only where needed (loops; numeric domains).
- Keep taint as finite-height (bitvectors) so it converges without widening.

This is the “math spine” behind mature intraprocedural precision.

### 2.3 Path sensitivity without path explosion (trace partitioning / disjunctive completion)

Full symbolic path enumeration is fragile and expensive. For security, we usually want *just enough* path sensitivity to distinguish:
- sanitized vs unsanitized,
- validated vs unvalidated,
- `None`-guarded vs unguarded,
- type-checked vs unchecked.

Two practical SOTA patterns:

1. **Selective disjunction (partitioning)**
   - Split abstract states on a small set of critical predicates (e.g., sanitizer bit for a sink type, or “value definitely tainted” vs “maybe tainted”).
   - Keep splits bounded: only partition on facts that dominate a sink or are demanded by a query.

2. **Predicate abstraction with refinement**
   - Start with a coarse predicate set (guards + taint bits).
   - If a report is too imprecise, refine by adding predicates (learned from counterexamples or CHC/PDR failures).

This gives CodeQL-like discrimination power without doing exponential symbolic execution.

### 2.4 Interprocedural taint the CodeQL way: IFDS/IDE (tabulation)

Our current “summaries as transformers” are good, but they are not the full story for precision.

For interprocedural dataflow, modern static analysis often uses:
- **IFDS** (Interprocedural Finite Distributive Subset) problems: facts propagated with call/return matching.
- **IDE** (Interprocedural Distributive Environment) problems: extends IFDS with values in a lattice (e.g., taint labels).

Why this matters:
- It naturally handles recursion with tabulation.
- It supports call-site sensitivity and precise call/return matching.
- It’s the canonical way to “be CodeQL-like” in interprocedural precision while remaining formal and analyzable.

How to map our leak theory to IFDS/IDE:
- Facts can be “a variable/value is tainted by source-set τ” and “sanitized-for set κ includes sink type k”.
- IDE is especially natural if we treat the label as the environment value.

This directly targets the gap called out in `checkers_lacks.md` (“Expand interprocedural tracking / better sanitizer modeling / framework integration”), because IFDS/IDE provides the transport; models provide the steps.

### 2.5 Relational summaries for unknown calls (guarded cases + mandatory fallback)

This is already in `python-barrier-certificate-theory.md`:
- Unknown/library calls must be relations `R_f` with a soundness intent `Sem_f ⊆ R_f`.
- Multiple guarded cases are allowed when the guard is provable (by dataflow/guards/spec).
- A **havoc fallback** must remain reachable unless we can justify excluding it.

This is the right place to put framework models and sanitizer behavior:
- Use *summary cases* to model “this function returns a request parameter” or “this call parameterizes SQL”.
- Use *footprint-aware havoc* to preserve soundness for heap mutation uncertainty.

### 2.6 Proof-layer: CHCs + PDR/IC3 as barrier synthesis assistants

Barrier certificates are our differentiator: we can prove SAFE.
But intraprocedural precision improvements often come from learning inductive facts.

SOTA approach that fits the barrier worldview:
- Encode the abstracted control/dataflow constraints as **Constrained Horn Clauses (CHCs)**.
- Use **PDR/IC3-style** invariant synthesis to learn inductive invariants/guards.
- Feed learned invariants back into:
  - the abstract interpreter as additional guard facts,
  - the summary system as stronger relational cases,
  - barrier synthesis templates where appropriate.

This gives a principled “learn better facts” loop without turning concolic execution into a proof step.

### 2.7 Target architecture (concrete code-level shape)

This section makes the plan implementable by naming the layers, APIs, and “what calls what”.

#### 2.7.1 Layering (what belongs where)

**Goal:** keep “exact semantics” and “analysis over-approximations” clearly separated so we can scale precision without accidentally cheating.

- **Exact semantics layer**
  - `pyfromscratch/semantics/symbolic_vm.py` (authoritative step relation for symbolic paths).
  - “Unknown calls” enter here as **relational summaries** with mandatory fallback.
- **Derived analysis layer (precision engines)**
  - *Intraprocedural:* a forward abstract interpreter over CFG that computes taint+guards to a fixpoint and reports sink violations.
  - *Interprocedural:* an IFDS/IDE-style engine that transports taint facts across call/return edges (with optional context sensitivity).
- **Model layer (framework + library semantics)**
  - Purely declarative: sources/sinks/sanitizers are specified as relations/transformers on `(τ, κ, σ)` plus optional guard facts and footprints.
  - Implemented as contracts/summary-cases, not as “special-cased detectors”.
- **Orchestration**
  - `pyfromscratch/analyzer.py` chooses which engine runs (security vs crash vs proof) and formats results (including SARIF).

#### 2.7.2 Proposed primary APIs (so we can swap engines without rewiring everything)

Even if we refactor internally, keep stable “front doors”:

1. **Security intraprocedural analysis**
   - Input: a `types.CodeType`, file path, qualified name, plus a “taint seed” describing how entry parameters get `(τ, σ)` and which sinks are checked.
   - Output: `List[SecurityViolation]` (or our existing counterexample dicts) plus optional “why” diagnostics (states at sink, witness skeleton).

2. **Security interprocedural analysis**
   - Input: project root (or file), entry points, contracts/models, context-sensitivity config.
   - Output: a set of `SecurityViolation` objects with call chains, plus a summary cache that can be reused by the intraprocedural engine.

3. **Proof artifact hooks**
   - Input: a safety query (“no unsafe sink reachable under these contracts”), plus an abstraction interface.
   - Output: SAFE proofs only when validated (barrier / inductive invariant / CHC proof), otherwise UNKNOWN.

#### 2.7.3 “One truth” about results and comparisons

To keep PyGoat parity honest:
- Normalize both CodeQL and our findings into a common schema (bug type, file, line, sink kind, source kind, and a short “flow explanation”).
- Store comparison artifacts under `results/` (or `docs/`) with deterministic filenames so the diff is machine-checkable.

---

## 3) Concrete plan of work (phased roadmap)

This roadmap is ordered to attack the biggest CodeQL advantage first (intraprocedural precision), while keeping the rest compositional.

### Phase 0 — Reconcile the truth (1 iteration)

**Goal:** remove ambiguity between “missing detectors” and “precision failures”.

Deliverables:
- A refreshed PyGoat run that produces:
  - our findings,
  - CodeQL findings,
  - agreement / misses,
  - and an explanation of *why* each miss happens (missing bug type vs analysis precision vs missing models).
- Update `checkers_lacks.md` accordingly (or generate a new “comparison v2” doc and link it).

#### Phase 0.1 Implementation checklist

- [ ] **Normalize the “ground truth” input**
  - Treat `results/pygoat_codeql/CODEQL_RESULTS_SUMMARY.md` as an *input summary*, but use the SARIF/CSV in `results/pygoat_codeql/` as the canonical machine-readable dataset.
  - Create/confirm a “normalized finding” record format used by both our results and CodeQL results:
    - `bug_type` (our taxonomy + CodeQL mapping)
    - `severity`
    - `file_path`, `line`, `col` (or best effort)
    - `sink_kind` (e.g., SQL_EXECUTE, LOGGING, COOKIE_SET)
    - `source_kind` (e.g., HTTP_PARAM, PASSWORD)
    - `sanitizer_kind` (if any)
    - `call_chain` (optional)

- [ ] **Run the same snapshot**
  - Ensure PyGoat version/commit used by CodeQL results matches the one we scan.
  - Record the commit hashes in the comparison doc so parity numbers are reproducible.

- [ ] **Generate a reproducible diff**
  - Add (or update) a script under `scripts/` that:
    1. parses CodeQL SARIF/CSV into normalized findings,
    2. parses our SARIF (or our internal results) into normalized findings,
    3. outputs: agreement set, CodeQL-only set, our-only set,
    4. groups misses by root cause bucket:
       - “missing model/contract”
       - “intraprocedural transport/precision”
       - “interprocedural transport/precision”
       - “call graph / entrypoint miss”
       - “reporting normalization mismatch”

- [ ] **Reconcile the drift explicitly**
  - Update `checkers_lacks.md` (or create a v2 doc) to separate:
    - *implementation coverage* (is the bug type/query implemented at all?)
    - *precision/recall* (was the instance missed?)
  - If `docs/SECTION_11_IMPLEMENTATION.md` claims implementation but parity shows misses, add a short root-cause note:
    - implemented but disabled,
    - implemented but unreachable due to modeling/entrypoint seeding,
    - implemented but not triggered due to intraprocedural gaps.

- [ ] **State tracking**
  - Update `State.json.progress.evaluation.pygoat_codeql_comparison` with:
    - a pointer to the latest comparison artifact (file path),
    - counts per bug type,
    - and “top 5” miss reasons (to guide Phase 1–3 work).

### Phase 1 — Intraprocedural precision engine (the core CodeQL gap)

**Goal:** a robust, scalable within-function analyzer that tracks `(τ, κ, σ)` and guards with CFG-aware fixpoints.

Work packages:
1. **SSA-like IR extraction**
   - Lower CPython bytecode stack effects into named temporaries (SSA-ish), preserving exception edges.
   - Keep the bytecode VM as source of truth; SSA is a derived analysis view.

2. **Single intraprocedural abstract interpreter**
   - Replace “two intraprocedural tracks” (symbolic VM vs separate intraprocedural taint) with a unified fixpoint engine for security flows:
     - Worklist iteration on CFG with join at merges.
     - Optional limited partitioning on key guards (sanitizer bits / sensitive-vs-untrusted).

3. **Guard facts as first-class analysis outputs**
   - Make guard inference and taint inference cooperate:
     - guarding on `if x is None:` refines nullability,
     - guarding on `if re.match(...)` refines “validated input” (modeled via κ bits or dedicated guard facts),
     - guarding on “parameterized query” refines κ for SQL sinks.

4. **Precision targets**
   - Correctly propagate taint through common idioms:
     - string concatenation, `format`, f-strings,
     - dictionary/list extraction and re-wrapping,
     - basic sanitization wrappers.

Success criteria (PyGoat):
- All CodeQL sinks we already “kinda support” should be detected even when the flow is purely local (source → locals → sink).

#### Phase 1.1 Architecture decision: unify “intraprocedural taint” into one engine

Today we effectively have multiple overlapping intraprocedural mechanisms:

- `pyfromscratch/semantics/intraprocedural_taint.py` (explicit bytecode worklist over locals + operand stack).
- `pyfromscratch/semantics/bytecode_summaries.py` (broader abstract domain; CFG integration; partially overlapping taint modeling).
- `pyfromscratch/semantics/security_tracker_lattice.py` (taint propagation embedded in the VM’s symbolic stepping).

**Implementation plan:** pick a single canonical intraprocedural security engine and make everything else a caller or a thin adapter.

Recommended choice for CodeQL-parity work:
- Keep the “dataflow style” engine (worklist + join) for security bugs, because it naturally matches CodeQL’s strengths and avoids path explosion.
- Keep SymbolicVM for:
  - crash bugs (where concrete reachability traces matter),
  - witness refinement (Mode B),
  - and later CHC/barrier proofs.

Concrete outcome:
- `Analyzer.security_scan()` should *not* be primarily a path enumerator. It should call the intraprocedural dataflow engine (and later the interprocedural engine).

#### Phase 1.2 Define the intraprocedural abstract state (minimal but sufficient)

At each program point (bytecode offset or CFG node), track:

- **Locals:** `local_idx -> TaintLabel`
- **Operand stack:** `stack_slot -> TaintLabel` (top-of-stack last)
- **Names/globals (optional, Phase 1+):** `name -> TaintLabel` for `LOAD_NAME/STORE_NAME` patterns
- **Guard facts (must-analysis):** the facts from `cfg/dataflow.py` (nonnull/type/bounds/div) used to justify using “trusted cases” and suppressing false alarms.
- **Optional container summary:** a conservative “container content taint” flag to avoid false negatives for `x[i]` and `for v in x`.

Key engineering requirements:
- Use the canonical `pyfromscratch/z3model/taint_lattice.TaintLabel` as the value label everywhere.
- Define an explicit `join_state()` for merging control-flow.
- Ensure the domain is finite-height for taint (bitmasks) so the analysis converges without widening.

#### Phase 1.3 Transfer functions: opcode-by-opcode coverage plan

We need an explicit, test-driven opcode coverage list for security flows. The goal is *not* to model Python perfectly, but to:
1) be sound (over-approx), and
2) cover the idioms CodeQL flags.

**Core stack/local plumbing (must be correct first):**
- `LOAD_FAST`, `STORE_FAST`, `LOAD_CONST`, `LOAD_GLOBAL`, `STORE_GLOBAL`
- `LOAD_ATTR`, `STORE_ATTR` (conservative)
- `BINARY_SUBSCR`, `STORE_SUBSCR`
- `BUILD_LIST`, `BUILD_TUPLE`, `BUILD_SET`, `BUILD_MAP`, `LIST_APPEND`, `MAP_ADD`
- `BINARY_ADD` (string concat + general join), `BINARY_OP` (3.11+ generalized binary ops)
- `RETURN_VALUE`

**Call modeling (this is where most CodeQL queries live):**
- `CALL`, `CALL_FUNCTION_EX`, plus the common call setup opcodes (`PUSH_NULL`, `PRECALL`, `KW_NAMES`) depending on the CPython version.

**String-building idioms (frequent in injection):**
- f-strings: `FORMAT_VALUE`, `BUILD_STRING`
- `.format(...)` calls: handled through `CALL` + attribute resolution
- percent formatting: `BINARY_MODULO` / `BINARY_OP` variant

**Branch/loop propagation (for path-ish precision):**
- Conditional jumps: ensure both edges are explored and merged.
- Loop back edges: ensure we iterate to a fixpoint and don’t “forget” taint introduced in the loop body.

**Minimal soundness rule for any unhandled opcode:**
- If an opcode produces a value we don’t model, treat it as `join(all_inputs)` for taint and keep κ conservative (typically intersect), rather than “clean”.

#### Phase 1.4 Calls: a concrete resolution + contract application strategy

CodeQL’s advantage is largely in “what counts as a source/sink/sanitizer”. We should implement a deterministic, layered resolution strategy at each `CALL`:

1. **Resolve a stable “callee identifier”** (best effort)
   - Direct calls: `foo(...)` → `"foo"`
   - Attribute calls: `obj.method(...)` → `"obj.method"` and `"method"` (both are useful keys)
   - Imported calls (best effort): use `cfg/call_graph.py` bindings if available to get a qualified name

2. **Apply models in priority order**
   1. **Trusted relational summary cases** (if we have them) for known library/framework functions.
   2. **Contract table** (`contracts/security_lattice.py`) for sources/sinks/sanitizers.
   3. **User-defined summary** (if the callee is in the current project and we have summaries).
   4. **Fallback:** `ret_label = join(args)` and conservatively drop sanitization unless justified.

3. **Sink checking**
   - Sink checks must be performed at the call site with the label(s) of the relevant argument(s).
   - The check uses the leak-theory rules:
     - injection sinks: unsafe if `τ != 0` and sink not in `κ`
     - sensitive sinks: unsafe if `σ != 0` and sink not in `κ`

4. **Sanitizer behavior**
   - Sanitizers should update `κ` for the returned value, not erase `τ`/`σ`.
   - The sanitizer must be sink-specific (context-dependent), per `leak_theory.md`.

#### Phase 1.5 Precision without explosion: bounded partitioning (“selective disjunction”)

We should add a controlled form of disjunction to avoid the classic precision failure:
“one path sanitizes, another doesn’t; join loses the distinction and we miss bugs or create FPs”.

Plan:
- Maintain up to `N` partitions per CFG node keyed by a small set of boolean predicates:
  - `is_untrusted = (τ != 0)`
  - `is_sensitive = (σ != 0)`
  - `is_sanitized_for_k = (k ∈ κ)` for the sink types that actually appear in the function
  - optionally `pc_taint != 0` (if we implement implicit flows)
- If partitions exceed `N`, merge the two “closest” partitions (heuristic) using join.

This is implementable, testable, and gives most of the benefit of path sensitivity for taint.

#### Phase 1.6 Witness generation (so BUG reports are explainable)

Dataflow engines don’t naturally produce a single execution trace. We still need:
- a *witness skeleton* for debugging and concolic replay, and
- a clear explanation for the user.

Plan:
- Track predecessors in the worklist:
  - For each `(node, partition_key)` store one predecessor edge that caused the last change.
  - When a sink violation is reported, backtrack predecessors to produce a path as a list of bytecode offsets (or blocks).
- Optionally feed this skeleton to SymbolicVM as a *guided replay objective* (Mode B) to produce concrete inputs.

#### Phase 1.7 Integration points (what to change in orchestrator)

Implementation changes should make the orchestration reflect the new engine:
- `pyfromscratch/analyzer.py`:
  - `security_scan()` should call the intraprocedural engine per function (seeded by entry parameters) instead of exploring symbolic paths.
  - Keep the old path-exploration mode behind a debug flag (useful for hard witnesses and for validating semantics).
- `pyfromscratch/frontend/entry_points.py`:
  - Use entrypoint detection to seed which parameters are untrusted/sensitive; avoid variable-name heuristics as a decider.
  - Treat “unknown entrypoints” conservatively (e.g., web handlers get τ on request-derived parameters).

#### Phase 1.8 Tests (make the intraprocedural engine impossible to “fake”)

Add a dedicated suite whose only way to pass is correct dataflow:

1. **Idiom tests (within one function)**
   - `source()` → local → sink
   - source → `x = y` chains (multiple locals)
   - source → container store → container load → sink
   - source → f-string / format / concat → sink
   - sanitizer inside a branch vs outside, ensuring partitioning keeps them distinct

2. **Negative tests**
   - sanitized flows should not report injection when κ covers the sink type
   - sensitive flows should only trigger on sensitive sinks

3. **Soundness tests**
   - If a sanitizer is not provably applied on all paths, the engine must still allow the unsafe path (no accidental SAFE-by-join).

Acceptance criteria:
- Close the “purely local” misses seen in PyGoat (and in synthetic cases designed to mimic PyGoat patterns).

### Phase 2 — Interprocedural transport upgrade (IFDS/IDE)

**Goal:** make cross-function dataflow as precise as CodeQL’s typical defaults.

Work packages:
1. **IFDS/IDE baseline for taint**
   - Facts represent taint label propagation across call/return with matching.
   - Start with 0-CFA (context-insensitive) + good call/return matching.

2. **Selective context sensitivity**
   - Add 1-CFA or limited object-sensitivity only where it affects security sinks (entrypoints + their reachable subgraph).

3. **Summary caching**
   - Use summaries as memoized results of IFDS/IDE propagation, not as the sole mechanism.
   - Summaries remain valuable for scale and for unknown calls (relational cases).

Success criteria:
- Eliminate “we missed due to interprocedural precision” cases in `checkers_lacks.md` (e.g., the command injection misses listed there).

#### Phase 2.1 Decide on IDE as the default (and keep IFDS as a special case)

Because our taint information is a lattice value `(τ, κ, σ)` (not just a boolean), **IDE** is the natural fit:
- IFDS: propagates finite “facts” (e.g., tainted/not-tainted).
- IDE: propagates facts *with a lattice value* (e.g., the full label), via distributive flow functions.

Implementation principle:
- Keep the *label algebra* in `z3model/taint_lattice.py` and `contracts/security_lattice.py`.
- Treat the interprocedural engine as “transport + composition”, not as the source of taint semantics.

#### Phase 2.2 Build an interprocedural control-flow graph (ICFG) we can tabulate on

We need a stable graph representation that supports call/return matching.

Plan:
- For each reachable function:
  - build a per-function CFG using `cfg/control_flow.py` (bytecode-level offsets).
- Build an ICFG “supergraph” with node IDs like:
  - `(func_qname, bytecode_offset)` or `(func_qname, block_id, instr_index)`
- Add edges:
  - **intra edges**: per-function CFG edges
  - **call edges**: call site → callee entry
  - **return edges**: callee exits → return site continuation
  - **call-to-return edges**: a conservative edge for “skipping” unknown callees (summary/fallback)

We can start with an AST-based call graph (`cfg/call_graph.py`) and incrementally improve call target resolution later.

#### Phase 2.3 Define the IDE fact domain for Python (what is a “variable” here?)

We need interprocedural facts that remain meaningful across call boundaries.

Minimum viable fact set for CodeQL parity:
- **Formals:** one fact per formal parameter slot (`param_i`)
- **Return:** one fact for return value (`ret`)
- **Call-site temporaries:** the value produced by the call (`call_result@offset`)

We can implement this without full SSA by:
- treating “the call result” as an abstract slot identified by `(call_site_offset, stack_slot_after_call)`, and
- treating “arguments” as stack slots at the call site just before the call.

However, to avoid fragile stack-slot reasoning, the Phase 2 plan should include a bridge step:
- implement a tiny “def-use” naming layer for call arguments/results:
  - `ArgSlot(call_site, arg_index)`
  - `RetSlot(call_site)`
This stays stable even as CPython bytecode details change.

#### Phase 2.4 Flow functions (what transforms labels along edges)

IDE requires flow functions `f_e : L -> L` along edges. For taint, most flow functions are:
- identity on “unchanged” facts, or
- join/meet with argument labels, or
- sanitizer updates to `κ`.

Plan for flow functions:

1. **Intra-procedural edges**
   - Reuse Phase 1’s intraprocedural transfer semantics:
     - from a point to its successor, compute how labels on live slots change.
   - For IDE, you can either:
     - encode these transfers as distributive functions on environments, or
     - treat Phase 1’s intraprocedural engine as producing per-node label environments that IDE queries at sinks.
   - For a first implementation, prefer the second: run Phase 1 per function to a fixpoint, then use IDE mainly for call/return transport.

2. **Call edges**
   - Map caller argument slots to callee formal parameters:
     - `label(param_i) := label(arg_i)` (with appropriate join for `*args/**kwargs` as conservative fallback).

3. **Return edges**
   - Map callee `ret` label to caller `RetSlot(call_site)`.

4. **Call-to-return edges (unknown or skipped callee)**
   - Apply the “havoc join” fallback from leak theory:
     - `label(ret) := join(labels(args))` and conservatively drop κ unless a trusted summary applies.

#### Phase 2.5 Context sensitivity (keep it surgical)

CodeQL gets big wins from mild context sensitivity. We should:

- Start with **0-CFA** (context-insensitive) and get correctness + parity improvements.
- Add **1-CFA** (last call site) only for functions that:
  - are reachable from entrypoints,
  - and can reach sinks,
  - and show significant precision loss in the parity diff.

Engineering strategy:
- Make context sensitivity a parameter of the tabulation engine, not baked into graph construction.
- Cache results by `(func_qname, context_key)` so analysis is incremental.

#### Phase 2.6 Summaries: keep them, but make them bytecode-derived (not AST-heuristic)

Our current summaries infrastructure has value but is vulnerable to drift and missed semantics.

Plan:
- Replace AST-only summary computation with summaries derived from the Phase 1 intraprocedural engine:
  - compute `param_i -> ret` dependency and `param_i -> sink_j` dependencies by tracking `param_sources` through the transfer functions.
- Use summaries as:
  - memoized accelerators inside IDE,
  - the interface for unknown/library relational summaries,
  - and the object we attach to bug reports (“why the taint flowed interprocedurally”).

Also, explicitly audit and fix drift in `pyfromscratch/semantics/summaries.py` (e.g., `sink_types` vs `sink_type` field mismatches).

#### Phase 2.7 Tests (interprocedural precision, minimally sufficient)

Add a suite that specifically fails unless call/return matching works:

- **Straight-line 2-hop flow**
  - `src()` in `a.py` returns tainted → `b.py` receives → sink
- **Sanitizer in helper**
  - `sanitize(x)` in another module adds κ; caller should not flag injection if sanitizer guaranteed
- **Recursion / mutual recursion**
  - ensure tabulation terminates and does not “forget” taint
- **Dynamic dispatch fallback**
  - a call whose target can’t be resolved must still be conservatively treated as unknown (no false SAFE)

### Phase 3 — Models: framework + sanitizers as relational summaries

**Goal:** close the “library modeling” gap without cheating.

Work packages:
1. **Django/Flask request sources**
   - Treat request extraction as source relations producing τ (untrusted) and sometimes σ (sensitive).

2. **ORM / SQL sinks and sanitizers**
   - Model “parameterized query APIs” as adding κ for SQL_EXECUTE sinks.
   - Model unsafe string formatting into SQL as NOT adding κ.

3. **Sanitizer library growth**
   - Add sanitizer contracts as cases with explicit κ updates (sink-specific).
   - Maintain a mandatory fallback when behavior is uncertain.

4. **Footprint-aware havoc**
   - For unknown calls that may mutate arguments, havoc only may-write locations to avoid unnecessary precision loss.

Success criteria:
- Framework-heavy taint flows in PyGoat match CodeQL’s recall, with acceptable FP rate.

#### Phase 3.1 Build a model inventory (what CodeQL is actually using in PyGoat)

Use the CodeQL finding list (`results/pygoat_codeql/*`) to enumerate the minimum model set needed for parity:

- **Sources**
  - Django request data: `request.GET`, `request.POST`, `request.FILES`, `request.COOKIES`
  - Flask request data: `request.args`, `request.form`, `request.values`, etc.
  - Environment and filesystem sources used in the codebase (as relevant)
- **Sinks**
  - SQL execution (raw execute paths)
  - Shell execution (os/system, subprocess)
  - `eval`/`exec`
  - filesystem path usage
  - SSRF sinks (requests / urllib)
  - logging sinks for sensitive data
  - cookie-setting sinks (insecure cookie flags; cookie injection)
- **Sanitizers**
  - parameterized query APIs
  - `shlex.quote` (shell)
  - `html.escape` (HTML)
  - URL/redirect validators (as needed)

The inventory should be written down as a checklist that maps directly to:
- a contract entry,
- a relational summary case, or
- an “additional taint step”.

#### Phase 3.2 Standardize model representation as “guarded cases + fallback”

To keep models usable for both dataflow engines and proof engines, represent each modeled function as:

- `id`: stable identifier(s) (qualified name, plus aliases/patterns)
- `cases[]`: guarded cases, each with:
  - `guard`: a predicate over available guard facts and argument shapes (must be provable by the analysis)
  - `effect`: how it transforms `(τ, κ, σ)` on outputs and/or which sink checks occur
  - optional `footprint`: may-read/may-write sets for heap impact (even if coarse)
- `fallback`: the conservative default (havoc + join) used when no guard is provable
- `provenance`: “trusted” (spec/source) vs “heuristic” (allowed only for bug-finding hints)

This is exactly the framework described in `python-barrier-certificate-theory.md` (§4.9–§4.11).

#### Phase 3.3 Django/Flask specifics (how to model request sources without cheating)

Avoid source-text heuristics like “variable named `request` means taint”.
Instead:

1. Model the framework *objects* and their accessors as contracts/relations:
   - Example: `request.GET.get(k)` returns τ containing `HTTP_PARAM`.
2. Implement “additional taint steps” as explicit relations:
   - Example: `QueryDict.__getitem__` and `.get()` are sources.
3. Attach these models via:
   - qualified name matching when possible (imports resolved),
   - attribute-chain identifiers (`request.GET.get`) as a fallback.

#### Phase 3.4 ORM/SQL modeling (what κ means in practice)

Most SQL parity issues come from distinguishing:
- safe parameterization (`cursor.execute("... %s", [x])`) vs
- unsafe string building (`cursor.execute("..."+x)`).

Model strategy:
- Treat parameterized query APIs as **sanitizers for SQL_EXECUTE** (add `SQL_EXECUTE` to κ under provable usage patterns).
- Treat plain string concatenation/formatting as taint-preserving (no κ added).

This requires the intraprocedural engine to:
- understand whether a `CALL` matches a known parameterized signature pattern, or conservatively not apply the sanitizer case.

#### Phase 3.5 Cookie and logging issues (σ-driven checks)

Some CodeQL findings are better described as “sensitive data misuse” than “untrusted injection”.

Plan:
- Use `σ` (sensitivity) in `leak_theory.md`:
  - **Cleartext logging/storage:** unsafe if `σ != 0` at logging/storage sinks and not declassified via κ.
- Seed `σ` from:
  - explicit sensitive sources (password reads, secrets),
  - and framework request fields known to hold credentials (when the model justifies it).

For insecure cookie flags / debug mode:
- Treat as reachability to a configuration sink state (e.g., a cookie set call missing Secure/HttpOnly; Flask app run with debug=True).
- Implement as semantics checks on call arguments/config objects, not pure string scanning.

#### Phase 3.6 Footprint-aware havoc (precision win without unsoundness)

When modeling unknown calls:
- havoc only the locations in the **may-write** footprint,
- keep other locations stable,
- and model allocation as fresh identities (if the engine tracks identities at all).

Even a coarse footprint model (“may mutate arg0; may write global X”) can dramatically reduce precision loss compared to full heap havoc.

#### Phase 3.7 Tests (model correctness and “fallback stays reachable”)

For every new model case:
- add at least one test where:
  - the case is required to avoid a false positive (precision),
  - and a sibling test where the guard is *not* provable, forcing the fallback and preserving soundness.

### Phase 4 — Proof-first integration (barriers + learned invariants)

**Goal:** preserve (and improve) SAFE proofs as precision grows.

Work packages:
- Use abstract interpretation results to propose barrier templates/guards (feature extraction).
- Encode hard cases as CHCs; apply PDR/IC3 to synthesize inductive invariants.
- Ensure “no concolic dependency”: concolic remains witness-only / contract-widening-only.

Success criteria:
- Fewer UNKNOWNs on “no bug” code when the property is provable from guards/invariants.

#### Phase 4.1 Decide what we will actually prove (and when)

For CodeQL-parity, most “wins” are BUG findings, not SAFE proofs. But we still want the proof pipeline because:
- it prevents “precision improvements” from accidentally becoming unsound,
- it lets us prove absence of certain classes in well-modeled code,
- and it’s the project’s differentiator.

Implementation plan:
- **BUG mode (default for parity):** dataflow engines find violations; SymbolicVM can produce/validate witnesses.
- **SAFE mode (opt-in initially):** only attempt proof for:
  - small functions (bounded CFG size),
  - well-modeled call sites (trusted summary cases),
  - and properties expressible on our current interface (taint/guards/observers).

#### Phase 4.2 CHC/PDR integration as a “learn missing guards” tool

When the intraprocedural engine is too imprecise (e.g., joins lose crucial information), use a CHC solver to synthesize invariants:

- Encode the abstracted transition system as CHCs:
  - relation symbols represent abstract states at program points,
  - Horn clauses encode transfers,
  - “bad” encodes reaching an unsafe sink state.
- Run PDR/IC3 (Spacer) to either:
  - produce an inductive invariant proving `bad` unreachable (SAFE), or
  - produce a counterexample trace (which we can feed into witness generation).

Crucially:
- any CHC abstraction must be a sound over-approx of the bytecode semantics on the chosen interface.

#### Phase 4.3 Feeding learned invariants back into dataflow

Treat learned invariants as:
- new guard facts (`g_validated`, `g_sanitized_for_sql`, etc.), or
- stronger summary guards for relational cases.

This gives a principled refinement loop:
1. run coarse analysis,
2. ask CHC solver for proof/counterexample,
3. add the missing predicates/guards,
4. rerun dataflow with better precision.

#### Phase 4.4 Proof artifact format (engineering requirement)

To avoid “silent SAFE”, every SAFE result should come with:
- the property statement (unsafe region definition),
- the invariant/barrier/CHC proof artifact (in a serialized form),
- and a Z3 verification log or at least a deterministic re-check path.

This should be stored under `results/` and referenced in the output summary.

---

## 4) Evaluation plan (benchmarks, metrics, ablations)

### 4.1 Benchmarks

1. **PyGoat parity suite**
   - One minimal test per CodeQL finding in `results/pygoat_codeql/`.
   - Keep these tests stable as a regression suite.

   Implementation detail:
   - Create a deterministic mapping from each CodeQL finding to a test case ID:
     - `CWE + query_id + file + line` (or SARIF ruleId if available).
   - Prefer **micro-tests** over importing PyGoat itself into tests:
     - extract the minimal code pattern into a small function that mimics the flow,
     - keep a comment linking back to the original PyGoat location for audit.
   - Maintain a “golden” expected results file (normalized findings) for the suite.

2. **Synthetic intraprocedural precision suite**
   - Patterns specifically designed to defeat naïve propagation:
     - aliasing (`a=b; c=a; sink(c)`),
     - container wrapping/unwrapping,
     - string building, f-strings, format chains,
     - sanitizer-inside-branch vs outside.

   Implementation detail:
   - Each pattern should come in triples:
     - **BUG**: tainted reaches sink
     - **SAFE**: same shape, but sanitized for the relevant sink
     - **UNKNOWN-expected (optional)**: requires a model we haven’t added yet; ensures we don’t “pretend SAFE”

3. **Small real repos (10–20)**
   - Diverse frameworks and idioms (Django, Flask, FastAPI, requests usage, etc.).
   - Compare against CodeQL on the same commit snapshots.

   Implementation detail:
   - Treat repo scans as “evaluation runs” with frozen dependencies:
     - record repo commit, our analyzer version, CodeQL version/query pack.
   - Store outputs in `results/<repo>/<timestamp>/` with:
     - our SARIF,
     - CodeQL SARIF,
     - normalized diff,
     - and summary metrics.

### 4.2 Metrics

For each bug category (and per repo):
- **Recall vs CodeQL**: `% of CodeQL findings we also find`.
- **Precision**: triaged true-positive rate on our findings (spot-check initially; later more systematic).
- **UNKNOWN rate**: how often we can’t decide in Mode A.
- **Performance**: wall-clock and memory vs LOC and call graph size.

Implementation detail (so metrics are stable):
- Define a canonical “match key” between CodeQL and our findings.
  - Start with `(bug_type, file_path, line)` and refine only if needed.
  - When line numbers differ due to formatting or extraction, allow a small window (±N lines) but record that as a “fuzzy match” separately.
- Track metrics separately for:
  - **taint-flow bugs** (SQL/command/code/path/SSRF/XXE/deserialization/etc.),
  - **sensitive-data bugs** (cleartext logging/storage),
  - **config bugs** (debug mode, insecure cookies, weak crypto).

### 4.3 Ablation studies (to ensure we’re improving for the right reasons)

Run the same suite with toggles:
- SSA-like IR on/off.
- Partitioning on/off (and partition budget).
- IFDS/IDE on/off (summaries-only baseline).
- Footprint-aware havoc on/off.

This tells us which math components actually move parity.

Implementation detail:
- Each ablation should emit:
  - parity diff,
  - runtime/memory,
  - and “top miss buckets”.
- Keep ablation toggles wired into CLI flags so we can run them in CI-style loops later.

---

## 5) Practical engineering notes (keep us honest)

### 5.1 “Anti-cheating” constraints translated to implementation

Allowed:
- bytecode/CFG-based reasoning,
- monotone dataflow / abstract interpretation,
- relational summaries with sound fallback,
- Z3-based reachability and proof checking,
- DSE only as witness/provenance refinement.

Forbidden:
- detectors whose deciding logic is source-text pattern recognition,
- SAFE by “no bug found”,
- removing havoc fallback because “DSE didn’t see it”.

### 5.2 What “success” looks like

We’ve “caught up” to CodeQL on taint when:
- PyGoat: near-total recall for CodeQL’s taint/config classes, and any misses are explainable by explicit design choices (e.g., deliberately excluding a query).
- Real repos: stable performance and predictable UNKNOWNs, with the ability to prove SAFE for some properties that CodeQL cannot.

---

## 6) Immediate next actions (short list)

1. **Reconcile** `checkers_lacks.md` vs `docs/SECTION_11_IMPLEMENTATION.md` by re-running the PyGoat comparison with current code and labeling gaps as:
   - missing detector,
   - interprocedural transport gap,
   - intraprocedural precision gap,
   - missing model (framework/sanitizer),
   - or expected limitation.
2. **Commit to one intraprocedural engine** for security flows (abstract interpretation on CFG + optional partitioning), with SSA-like lowering as the enabling step.
3. **Implement IFDS/IDE** for taint as the interprocedural backbone; keep summaries as caching and as the interface for unknown/library relations.

---

## 7) Suggested iteration-level roadmap (turn this plan into work items)

This is a concrete “what to do next” ordering. Treat iteration numbers as approximate; always update `State.json.queue.next_actions` as you go.

### 7.1 Phase 0: parity truth + tooling

1. **Parity diff tooling**
   - Add a normalized findings schema + a diff script (CodeQL SARIF/CSV vs our output).
2. **Comparison v2 doc**
   - Update `checkers_lacks.md` (or add a v2 doc) to separate:
     - “implemented but not firing” vs “missing model” vs “transport/precision”.

### 7.2 Phase 1: intraprocedural engine hardening (highest ROI)

3. **Canonical intraprocedural security engine**
   - Choose one engine and route `Analyzer.security_scan()` through it.
4. **Opcode coverage for security idioms**
   - Add string-building + container flow coverage with dedicated tests.
5. **Bounded partitioning**
   - Implement partitioning keyed by sanitizer/taint facts; add branch-sanitizer tests.
6. **Witness skeleton + optional concolic validation**
   - Provide explainable BUG traces without turning concolic into a decider.

### 7.3 Phase 2: interprocedural transport (close remaining misses)

7. **Bytecode-derived summaries**
   - Compute param→ret and param→sink dependencies from Phase 1 transfers.
8. **ICFG + IDE transport**
   - Implement call/return matching; start context-insensitive, add 1-CFA surgically.

### 7.4 Phase 3: models (framework/sanitizer parity)

9. **Django/Flask request sources**
   - Add relational cases/contracts for request extraction patterns found in PyGoat.
10. **ORM + sanitizers**
   - Add κ-updating models for parameterized SQL patterns; ensure fallback stays reachable.

### 7.5 Phase 4: proof integration (optional until parity stabilizes)

11. **CHC/PDR pilot**
   - Pick one small property (e.g., “no SQL injection sink in a small module under trusted models”) and implement a proof path.
12. **Refinement loop**
   - Feed learned invariants back into guards/models/partitioning.

---

## Appendix A: “Done means done” acceptance gates (per phase)

- **Phase 0 is done** when:
  - A diff script reproduces the parity numbers from a single command, and
  - every miss is bucketed with a root-cause label.
- **Phase 1 is done** when:
  - intraprocedural-only PyGoat flows match CodeQL recall for the same set of sinks (within a small tolerance), and
  - the new engine has a test suite that makes it hard to regress silently.
- **Phase 2 is done** when:
  - the specific interprocedural misses from the parity diff disappear (or are re-bucketed as “missing model”).
- **Phase 3 is done** when:
  - framework-heavy flows match CodeQL recall and FPs are explainable as either modeling gaps or conservative fallbacks.
- **Phase 4 is done** when:
  - SAFE proofs exist for at least one non-trivial security property on a real module under trusted models, and
  - the proof artifacts are reproducible and re-checkable.
