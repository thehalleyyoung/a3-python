# KitchenSink++: 20 SOTA Papers + Polynomial Barrier Certificates (Full Integration Plan)

This document extends `docs/kitchensink.md` and `kitchensink-python.md` into a **KitchenSink++** roadmap: a portfolio of **state-of-the-art (SOTA)** verification techniques that act as *producers* of barrier-theoretic information and/or *engines* for finding either:

- a **validated counterexample** (BUG), or
- a **checkable proof artifact** (SAFE), preferably a **polynomial barrier certificate** (SOS/DSOS/SDSOS-backed when applicable).

The key design constraint (consistent with `python-barrier-certificate-theory.md`):

- **BUG is existential**: must come with a realizable witness (ideally concrete replay / concolic validation).
- **SAFE is universal**: must come with a proof artifact that quantifies over the (sound over-approximate) transition relation.
- Everything else is *glue* that reduces search space, improves conditioning, and supplies counterexamples/examples to drive refinement.

---

## 0) What “Full Integration” Means

“Full integration” is **not** “we cite these papers” or “we add one new solver call.”

It means each technique is wired into one of the coupled loops below, with:

1. **Artifact types** (states, traces, invariants, lemmas, contracts) represented explicitly,
2. **Caching + reuse** across bug types/sinks and across entry points,
3. **Staged budgets** and portfolio scheduling (cheap → expensive),
4. **Bridging to polynomial barriers** via:
   - extracting semialgebraic constraints from program semantics (or conservative abstractions),
   - feeding those constraints into SOS/DSOS/SDSOS relaxations,
   - returning a checkable certificate or an actionable counterexample.

---

## 1) The Coupled Loops (Bug-Finding ↔ Invariants/Barriers ↔ Contracts)

### Loop A — Bug-finding (under-approximate)
Goal: find *real* counterexamples fast.

Typical engines:
- BMC / k-BMC, path-guided symbolic execution, concolic replay.

Artifacts produced:
- candidate trace, replay objective, concrete witness inputs, minimal-depth counterexample.

### Loop B — Invariants / Barrier synthesis (over-approximate certifier)
Goal: prove *unreachability* of unsafe regions via inductive certificates.

Typical engines:
- IC3/PDR/CHC solvers (for discrete invariants),
- interpolation-based invariant discovery,
- ICE/Houdini/SyGuS/CEGIS (learning/synthesis),
- polynomial barrier certificates (SOS/DSOS/SDSOS), especially for numeric/affine/poly submodels.

Artifacts produced:
- inductive invariants, frames/lemmas, barrier certificate and proof checks, separating constraints.

### Loop C — Unknown-call / library-contract refinement (hybrid)
Goal: keep proofs sound while allowing bug witnesses to be realizable.

Typical engines:
- selective concolic execution,
- observational traces as *witnesses* and as *unsoundness detectors* (widening triggers),
- relational summaries/contracts with havoc fallback.

Artifacts produced:
- updated contracts `R_f`, call-interface observations, refined abstract transitions.

---

## 2) The 20 SOTA Papers (and Why Each Matters to Polynomial Barrier Theory)

Below is a curated list of 20 widely-cited “backbone” papers that (together) cover:

- reachability engines (BUG finding),
- invariant engines (SAFE proving),
- learning/synthesis loops (automation),
- polynomial optimization/barrier certificate machinery (proof artifacts).

Each entry includes: **what to integrate** and **how it strengthens polynomial barriers**.

---

### A. Polynomial barrier certificates and optimization backbone (9)

1) **Barrier certificates for hybrid systems**  
S. Prajna, A. Jadbabaie, G. J. Pappas. *Safety verification of hybrid systems using barrier certificates.* HSCC 2004.  
Integrate: the canonical barrier obligations (Init/Step/Unsafe) for nondeterministic transitions and hybrid-style reachability framing.  
Barrier synergy: defines the *shape* of the certificate contract.

2) **Worst-case + stochastic barrier framework**  
S. Prajna, A. Jadbabaie, G. J. Pappas. *A framework for worst-case and stochastic safety verification using barrier certificates.* IEEE TAC, 2007.  
Integrate: “proof under uncertainty” logic for nondeterministic/unknown calls; produce probability bounds when applicable (optional).  
Barrier synergy: makes contract uncertainty first-class while staying certificate-driven.

3) **SOS emptiness checking for safety**  
H. Yazarel, S. Prajna, G. J. Pappas. *S.O.S. for safety.* 2004 (IEEE).  
Integrate: reduce some safety conditions to emptiness of semialgebraic sets checked by SOS.  
Barrier synergy: turns inductiveness failures into polynomial constraints.

4) **SOSTOOLS (SOS programming toolbox; method paper)**  
S. Prajna, A. Papachristodoulou, P. A. Parrilo. *Introducing SOSTOOLS: A general purpose sum of squares programming solver.* 2002 (IEEE).  
Integrate: standardized SOS modeling patterns (Gram matrices, multipliers) and sparse/structured tricks.  
Barrier synergy: engineering playbook for scalable SOS constraints.

5) **Putinar Positivstellensatz**  
M. Putinar. *Positive polynomials on compact semi-algebraic sets.* Indiana Univ. Math. J., 1993.  
Integrate: principled positivity certificates using SOS + multipliers under compactness assumptions.  
Barrier synergy: the mathematical justification behind SOS barrier soundness.

6) **Parrilo (SOS via SDP; semialgebraic reasoning)**  
P. A. Parrilo. *Semidefinite programming relaxations for semialgebraic problems.* Math. Program., 2003 (and related thesis work, 2000).  
Integrate: SOS-as-SDP encoding patterns, Positivstellensatz-based certificates, structured relaxations.  
Barrier synergy: the core reduction from polynomial proof obligations to SDPs.

7) **Lasserre hierarchy (moments/SOS)**  
J.-B. Lasserre. *Global optimization with polynomials and the problem of moments.* SIAM J. Optim., 2001.  
Integrate: systematic degree-lift hierarchy; “increase degree, converge” schedules; extraction of certificates/counterexamples.  
Barrier synergy: disciplined staged deepening for polynomial barriers.

8) **Sparse SOS / correlative sparsity**  
M. Kojima, S. Kim, H. Waki. *Sparsity in sums of squares of polynomials.* Math. Program., 2005.  
Integrate: exploit variable-interaction graphs (cliques) to shrink SOS problems.  
Barrier synergy: make polynomial barriers scale to high-dimensional extracted models.

9) **DSOS/SDSOS (LP/SOCP inner approximations to SOS)**  
A. A. Ahmadi, A. Majumdar. *DSOS and SDSOS optimization: more tractable alternatives to sum of squares and semidefinite optimization.* 2017 (SIAM J. Appl. Algebra Geom., 2019).  
Integrate: fallback certifier when SDPs time out; fast “good enough” certificates with monotone strengthening.  
Barrier synergy: increases non-timeout SAFE yield (at cost of completeness), still checkable.

> Note: Items (8) and (9) are the two biggest “scale levers” for polynomial barriers: sparsity + LP/SOCP relaxations.

---

### B. Discrete/infinite-state safety engines that feed barriers (7)

10) **IC3 / PDR-style inductive reasoning (core idea)**  
A. R. Bradley. *SAT-Based Model Checking without Unrolling* (VMCAI 2011) + the IC3 tutorial lineage (“Understanding IC3”, etc.).  
Integrate: counterexamples-to-induction → lemma discovery; frames; property-directed strengthening.  
Barrier synergy: provides *discrete* inductive invariants / lemmas that restrict reachable states, conditioning polynomial barrier synthesis.

11) **Spacer / SMT-PDR for recursive programs (CHCs)**  
A. Komuravelli, A. Gurfinkel, S. Chaki. *SMT-based model checking for recursive programs.* CAV 2014.  
Integrate: CHC-solving view; procedure summaries; over/under approximations.  
Barrier synergy: yields strong inductive invariants over linear arithmetic that can be imported as constraints into polynomial barrier obligations (or used to choose degree/variables).

12) **CEGAR (counterexample-guided abstraction refinement)**  
E. Clarke, O. Grumberg, S. Jha, Y. Lu, H. Veith. *Counterexample-Guided Abstraction Refinement.* CAV 2000.  
Integrate: abstraction loops that stop wasting time on spurious counterexamples; refine only where needed.  
Barrier synergy: reduces the “unknown call / heap / path explosion” problem before polynomial barrier attempts.

13) **Predicate abstraction for software via SAT (precision + bit-level semantics)**  
E. Clarke, D. Kroening, N. Sharygina, K. Yorav. *Predicate Abstraction of ANSI-C Programs Using SAT.* FMSD 2004.  
Integrate: a precise Boolean abstraction construction when SMT is expensive; use SAT to build accurate abstraction relations.  
Barrier synergy: produces cleaner discrete abstractions that reduce spurious transitions; polynomial barriers become feasible on the residual numeric part.

14) **Boolean programs as a model + refinement process**  
T. Ball, S. Rajamani. *Boolean Programs: A Model and Process for Software Analysis.* MSR TR 2000.  
Integrate: convert complex semantics to a tractable Boolean program model for control-flow-heavy bugs.  
Barrier synergy: barrier synthesis can focus on numeric submodels while Boolean programs handle control invariants.

15) **Interpolation-based model checking (IMC)**  
K. L. McMillan. *Interpolation and SAT-Based Model Checking.* CAV 2003.  
Integrate: derive inductive approximations from unsat BMC queries; cache interpolants as lemmas.  
Barrier synergy: interpolants become strengthening lemmas (constraints) that shrink the polynomial barrier search space.

16) **Lazy abstraction with interpolants (IMPACT lineage)**  
K. L. McMillan. *Lazy Abstraction with Interpolants.* CAV 2006.  
Integrate: interpolate on single paths; avoid whole-program unroll blow-ups; converge via refinement.  
Barrier synergy: produces targeted lemmas around hard control-flow regions; polynomial barriers can ignore irrelevant control complexity.

---

### C. Learning / synthesis loops that generate invariants/barriers (4)

17) **ICE learning (examples + counterexamples + implications)**  
P. Garg, C. Löding, P. Madhusudan, D. Neider. *ICE: A Robust Framework for Learning Invariants.* CAV 2014.  
Integrate: treat failed inductiveness checks as implication constraints; learn invariants over a predicate/feature basis.  
Barrier synergy: ICE supplies constraints and candidate invariants that can be lifted into polynomial templates (monomials/features) and used as side conditions.

18) **Houdini (annotation inference via refutation)**  
C. Flanagan, K. R. M. Leino. *Houdini, an Annotation Assistant for ESC/Java.* 2001.  
Integrate: fast “candidate pool → refute → keep” invariant pruning; great as a cheap invariant harvester.  
Barrier synergy: Houdini-like pruning can choose small, stable predicate sets and variable bounds to condition SOS feasibility.

19) **Syntax-Guided Synthesis (SyGuS)**
R. Alur et al. *Syntax-Guided Synthesis.* FMCAD 2013.  
Integrate: grammar-constrained search for invariants/barriers (including polynomial templates, piecewise, max/min).  
Barrier synergy: provides a disciplined template language for polynomial barriers, avoiding brittle ad hoc template enumeration.

20) **Assume-guarantee reasoning (compositional decomposition)**
T. A. Henzinger, S. Qadeer, S. Rajamani. *You assume, we guarantee: Methodology and case studies.* CAV 1998.  
Integrate: component contracts; decompose proofs; reuse summaries across call sites; shrink transition relation.  
Barrier synergy: enables compositional polynomial barriers (per component) with smaller variable sets and local invariants.

---

## 3) How These Improve Bug Detection (When Implemented Fully)

Below are the concrete ways these techniques improve “BUG detection” (more true positives) and “non-timeout verification” (more SAFE proofs), specifically *in a barrier-certificate-first framework*.

### 3.1 More *real* BUGs (validated counterexamples)

1) **BMC-first scheduling finds shallow bugs quickly**  
BMC (plus incremental SAT/SMT) finds many real crash/security issues at small depth before symbolic exploration explodes.

2) **CEGAR + predicate abstraction reduce spurious witnesses**  
Instead of chasing infeasible paths, refinements eliminate spurious counterexamples, concentrating effort where a real bug might exist.

3) **Interpolation / IMPACT produce minimal, relevant constraints**  
When a candidate trace is infeasible, interpolants tell you *why*, producing refinements that avoid repeated dead ends.

4) **ICE provides data-driven invariant constraints to cut false paths**  
Implication examples (from failed inductiveness/feasibility checks) teach the system which regions are stable, reducing the number of explored paths needed to reach a real bug.

5) **Contract loop increases witness realizability**  
When unknown calls make a symbolic trace “too unconstrained,” selective concolic runs supply concrete witnesses or force contract widening.

Net effect: more **validated** BUG findings under the same time budget, especially in large repos.

### 3.2 More SAFE proofs (barriers that actually prove something)

Polynomial barriers fail in practice for two main reasons:

- (i) the transition relation is too unconstrained (“havoc makes everything reachable”), or  
- (ii) the polynomial optimization is too large (degree/variables explode).

The 20-paper stack addresses both:

1) **IC3/PDR/Spacer provide discrete inductive invariants** that restrict reachable control regions and numeric ranges.
2) **Interpolation and Houdini/ICE supply strengthening lemmas** that keep the SOS obligations well-conditioned.
3) **Sparsity-aware SOS + DSOS/SDSOS** keep solves within budget and expand the range of solvable models.
4) **Lasserre-style staged deepening** provides a principled “increase degree only when needed” schedule.
5) **Assume-guarantee decomposition** reduces dimension: smaller per-component barriers are tractable even when a global one is not.

Net effect: fewer “we explored some paths but cannot prove SAFE” outcomes.

### 3.3 Fewer UNKNOWNs (timeouts) via portfolio and monotone staging

The stack turns one hard query into many cheap ones:

- cheap BUG-finders (BMC) first,
- cheap invariants (Houdini/ICE over simple predicates) next,
- CHC/PDR engines for discrete invariants,
- then polynomial barriers with sparse/DSOS fallbacks.

Every stage either returns a verdict or produces artifacts that make the next stage cheaper.

---

## 4) “Full Implementation” in PythonFromScratch: What It Would Look Like

To genuinely “integrate” this SOTA stack with polynomial barrier theory in PythonFromScratch, the key implementation milestones are:

1) **Artifact-oriented orchestrator** (portfolio scheduling, caching, per-bug-type reporting).  
2) **Explicit transition-system extraction layers**:
   - discrete/control CHCs for IC3/PDR/Spacer,
   - affine/poly numeric submodels for SOS/DSOS.
3) **ICE/Houdini/SyGuS invariant front-end** producing:
   - bounds,
   - predicates,
   - polynomial template grammars (monomials, piecewise, max/min).
4) **SOS backends** with:
   - sparsity graphs (correlative sparsity from slicing/relevance),
   - DSOS/SDSOS fallback when SDP is too large,
   - proof object emission (certificate constraints).
5) **Concolic contract refinement** that is strictly widening-only for proof soundness.

Once all of these are in place, “more true positives on all test repos” comes from:

- faster access to real bugs (BMC + better witness validation),
- fewer spurious alarms (CEGAR/interpolants/contracts),
- more *provable* safe regions (PDR/ICE conditioning + scalable SOS).

---

## 5) Practical Evaluation Targets

KitchenSink++ should be measured with *budgeted* experiments:

- **TP rate**: validated BUG findings per repo under fixed wall-clock budget.
- **Non-timeout yield**: fraction of (entry point × bug type) producing BUG or SAFE, not UNKNOWN.
- **Witness quality**: % of BUGs with concrete replay inputs and minimized traces.
- **Proof quality**: % of SAFE results with explicit barrier artifacts and stated contract assumptions.

---

## 6) Reference Pointers (for implementation scoping)

- `docs/kitchensink.md`: portfolio + staged deepening + artifact reuse.
- `python-barrier-certificate-theory.md`: hybrid soundness rules (contracts + concolic).
- `kitchensink-python.md`: mapping of these ideas to the current PythonFromScratch architecture.
