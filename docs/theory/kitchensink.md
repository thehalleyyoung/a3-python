# Kitchen-Sink Verification Pipeline (SOTA → Barrier Theory → Certificate/Counterexample)

This document defines the intended *end-to-end* LA-PTS verification architecture:

> **(Every SOTA checking approach we can run) → barrier-theoretic information → (barrier certificate OR exact counterexample).**

Barrier theory is the certifier. Everything else is an information generator that either:
- helps find a barrier, or
- helps find and validate a real counterexample.

---

## 1) Inputs and Outputs

### Input: LA-PTS instance
An LA-PTS instance provides:
- State variables `V` (with semantic types/hints when available)
- Control locations `L` and initial location `l0`
- Initial constraints `Init(x)`
- Transition relation `Trans(x, x')`
- Unsafe regions `Unsafe_i(x)` (per bug source / property)

### Output: per-unsafe-region verdicts
For each unsafe region `U`:
- **SAFE** with a *checkable* barrier certificate `B` (plus optional proof artifacts), or
- **BUG** with a *validated* counterexample trace `x0 → … → xk ∈ U`, or
- **UNKNOWN** only if resources are exhausted (with diagnostics + partial artifacts).

---

## 2) What Counts as “Barrier-Theoretic Information”?

Barrier synthesis is a hard global constraint problem. The rest of the stack exists to transform a raw LA-PTS into a smaller, structured, better-conditioned barrier search.

Barrier-theoretic information includes (not exhaustive):

1. **Relevant subspace**
   - variable relevance, cone-of-influence, slicing
2. **Reachable-set over-approximations**
   - sound bounds + inductive invariants per location
3. **Decomposition structure**
   - sparsity graphs, clique covers, contracts (assume/guarantee), concurrency reductions
4. **Templates and bases**
   - degree bounds, monomial bases, Newton polytope pruning, DSOS/SDSOS relaxations
5. **Samples and counterexamples**
   - reachable samples (BMC/DSE), ICE examples, barrier-condition counterexamples
6. **Strengthening lemmas**
   - interpolants, k-induction lemmas, PDR frames, transition invariants

The controlling question for every technique:

> Does it reduce the barrier search space, improve conditioning, or supply counterexamples that refine the search?

---

## 3) The Unifying Glue: Coupled CEGIS Loops

The architecture is easiest to understand as two coupled CEGIS loops sharing artifacts.

### A) Bug-finding loop (toward exact counterexample)
- Propose candidate reachability witnesses (BMC, DSE, guided search).
- If a candidate trace is found, **validate** it against the exact transition relation.
- If validated, return **BUG(trace)**.
- If spurious (from an abstraction), refine the abstraction and keep searching.

### B) Barrier-synthesis loop (toward certificate)
- Propose a barrier candidate from a parameterized template.
- Check barrier conditions using SMT/SOS encodings.
- If conditions fail, extract **witness counterexamples** (states or transitions).
- Add those witnesses as new constraints/examples; repeat.

Key synergy:

> Counterexamples are valuable both for bug discovery and for barrier refinement.

---

## 4) Execution Policy: Portfolio + Staged Deepening

The “kitchen sink” is not “run everything all the time”. It is:

1. **Portfolio scheduling**: run complementary methods with time budgets.
2. **Staged deepening**: cheap → expensive; local → global; under-approx → over-approx → certificate.
3. **Artifact reuse**: invariants, slices, decompositions, and learned constraints are cached and reused across unsafe regions.

---

## 5) Technique Taxonomy: How Each Feeds Barrier Theory

Each module produces artifacts; barrier synthesis consumes them.

### 5.1 Slicing / Relevance / Cone-of-Influence (reduces dimension)
**Artifacts**
- Reduced variable set `V_U`
- Reduced transitions `T_U` and constraints (reachability-preserving for `U`)

**Barrier impact**
- Smaller templates and smaller SOS/SMT problems.

### 5.2 Abstract Interpretation (sound bounds + fast pruning)
**Artifacts**
- Sound bounds/invariants: `Inv_abs(l, x)`
- Reachable-location pruning

**Barrier impact**
- Adds reachable-set restrictions and conditioning constraints to barrier obligations.

### 5.3 Loop Analysis / Summarization / Acceleration (structure extraction)
**Artifacts**
- Loop summaries or sound accelerations
- Modified/read variable sets, induction variable hints

**Barrier impact**
- Strengthens inductiveness checks; suggests separable templates.

### 5.4 Invariant Inference (Houdini, ICE, templates, interpolation)
**Artifacts**
- Inductive invariants `Inv(l, x)`
- ICE implication counterexamples and sample sets
- Predicate pools / lemmas

**Barrier impact**
- Invariants restrict where barrier conditions must hold; also serve as strengthening lemmas.

### 5.5 BMC / k-Induction / Interpolation (bugs + lemmas)
**Artifacts**
- Candidate counterexample traces (under-approx)
- Induction lemmas and interpolants

**Barrier impact**
- Traces provide reachable samples; interpolants/lemmas narrow barrier search.

### 5.6 CEGAR / PDR(=IC3) (global inductive invariants)
**Artifacts**
- Predicate abstraction refinements, blocked cubes, frames

**Barrier impact**
- Frames/lemmas become barrier side-conditions and can induce decompositions.

### 5.7 DSE / Symbolic Execution / Concolic Testing (exactness + samples)
**Artifacts**
- Concrete reachable states and path constraints
- Validated traces (bug witnesses)

**Barrier impact**
- Supplies rich data for ICE/data-driven candidate barriers and validates traces.

### 5.8 Concurrency + POR (state explosion control)
**Artifacts**
- Reduced interleavings; concurrency invariants/contracts

**Barrier impact**
- Shrinks both bug-finding and barrier-checking search spaces.

### 5.9 SOS / SDP / Sparse Polynomial Optimization (certificate engine)
**Artifacts**
- Barrier candidates + SOS/SDP proof artifacts (when used)

**Barrier impact**
- This is the primary synthesis engine; everything else makes it feasible.

---

## 6) Certification Contract: What a Barrier Must Prove

For barrier `B` and unsafe region `U`:

1. `Init(x) ⇒ B(x) ≥ ε`
2. `B(x) ≥ 0 ∧ Trans(x, x') ⇒ B(x') ≥ 0` (or stricter decrease)
3. `U(x) ⇒ B(x) < 0` (or `≤ -ε`)

In practice we strengthen obligations with inductive invariants:
- check only on reachable states: `Inv(l, x)`
- use per-location / compositional barriers as needed

---

## 7) “Delegates Compositionally”: The Orchestrator Contract

The orchestrator is a controller over producers and a consumer of their artifacts.

Artifacts are first-class:
- `Slice(V_U, T_U)`
- `Bounds(Inv_abs)`
- `Invariants(Inv, lemmas, predicates)`
- `LoopSummaries(Sigma)`
- `Samples(S+, S-, Implications)`
- `Decomposition(components, interfaces, sparsity graph)`
- `Traces(validated traces)`

Barrier synthesis consumes artifacts and returns:
- either a certificate, or
- a barrier-condition counterexample that is fed back into inference/ICE.

### Per-unsafe-region pseudocode
```text
artifacts = {}

// Phase 0: preprocess and reduce
artifacts += slice(pts, unsafe)
artifacts += preanalyze(pts_U, unsafe)

// Phase 1: harvest invariants and bounds (over-approx)
artifacts += abstract_interpret(pts_U, unsafe)
artifacts += loop_analyze_and_summarize(pts_U)
artifacts += invariant_infer(pts_U, unsafe)   // Houdini/ICE/templates/interpolants/PDR
artifacts += decompose(pts_U)                 // sparsity + assume/guarantee + concurrency hooks

// Phase 2: bug-finding portfolio (under-approx)
trace = bmc_find_bug(pts_U, unsafe, artifacts) || dse_find_bug(pts_U, unsafe, artifacts)
if trace and validate(trace): return BUG(trace)

// Phase 3: certify via barrier CEGIS
repeat with increasing budget:
  barrier = synthesize_barrier(pts_U, unsafe, artifacts)
  if barrier.valid: return SAFE(barrier)
  artifacts += barrier.counterexamples
  artifacts += refine_invariants_with_cex(ICE/Houdini, counterexamples)

return UNKNOWN(with diagnostics)
```

Composition comes from:
1. structural decomposition (assume-guarantee components, sparsity cliques, concurrency interfaces)
2. artifact composition (constraints and lemmas combined consistently)

---

## 8) Why This Works

Different techniques answer different questions:
- Under-approx (BMC/DSE): *Is there a real bug? Give me a witness.*
- Over-approx (AI/PDR): *Can we rule out regions? Give me invariants/bounds.*
- Learning (ICE/data-driven): *What separating surfaces fit observed behavior?*
- Optimization (SOS): *Can we produce a globally valid certificate?*

Barrier theory unifies them because it accepts inductive strengthening, counterexample refinement, decomposition, and yields a single checkable certificate when successful.

---

## 9) Engineering Rules (to keep the kitchen sink sane)

1. Never report a bug without validation (trace replay against exact semantics).
2. Cache artifacts (slices, invariants, decompositions) across unsafe regions.
3. Prefer dimension reduction over degree increase.
4. Use staged budgets (many small attempts > one huge solve).
5. Treat UNKNOWN as diagnosable (return partial artifacts + failing witnesses).

---

## 10) Mapping to This Project

Conceptual modules live under `src/solver/include/`:
- Slicing/relevance: `src/solver/include/slicing/*`
- Abstract interpretation: `src/solver/include/analysis/*`
- Loop analysis: `src/solver/include/analysis/loop_analysis.hpp`
- Invariant inference (Houdini/ICE): `src/solver/include/invariants/inference.hpp`
- BMC / k-induction: `src/solver/include/solver/bmc.hpp`
- CEGAR / PDR: `src/solver/include/solver/cegar.hpp`
- Barrier synthesis / SOS: `src/solver/include/solver/barrier.hpp`, `src/solver/include/solver/sos.hpp`, `src/solver/include/sparse/*`
- DSE / trace validation: `src/solver/include/dse/*`
- Compositional / concurrency: `src/solver/include/compositional/*`, `src/solver/include/concurrency/*`

This doc specifies how those modules are meant to be “glued together” so every technique is either:
- a producer of barrier-theoretic information, or
- part of producing a certified result (certificate or validated bug).

