# Barrier Certificates for an Exact Model of Python (Draft / Beginning)

This document starts a Python-focused analogue of `barrier-certificate-theory.tex`: we want a *precise, execution-faithful* semantic model of Python (as a PL), and then we want to restate the “bug = reachable unsafe region” worldview in barrier-certificate terms—*including black-box/unknown library calls treated barrier-theoretically*, with dynamic symbolic execution (DSE) used as a refinement oracle.

The immediate goal is to get far enough that “*`assert(False)` outside an exception handler is a bug*” is not a slogan but a formally stated reachability query against an exact Python semantics.

## 0. Scope and “Exactness”

### 0.1 Target language and implementation level

Python is not one thing:

- **The language reference** defines a surface language: tokenization/indentation, grammar, scoping, evaluation order, exceptions, the object model, etc.
- **CPython** is the dominant implementation with a specific execution model (frames, reference counting + cyclic GC, bytecode VM, exception tables, descriptor protocol details, etc.).

When we say **“exact model of Python”**, we need to fix a target. For this draft, the working target is:

- **Language:** Python 3.x as specified by the Python Language Reference.
- **Operational substrate:** CPython-style execution via bytecode *as an abstract machine*.

This does **not** mean “we ignore CPython quirks”—it means we choose an executable-level semantics (bytecode/abstract machine) whose behavior agrees with the reference on all defined behaviors, and then we explicitly account for CPython-relevant details when they influence bug definitions (e.g., refcounting finalizers, recursion limits, exact exception propagation, etc.).

### 0.2 What “exact” does and does not promise

“Exact” is about *semantic faithfulness*, not about tractability:

- We allow unbounded heaps, unbounded integers, dynamic dispatch, reflection, imports, etc., in the mathematical model.
- For analysis, we will later introduce *certified approximations* (semialgebraic over-approximations, predicate abstractions, path summarization, etc.) while keeping the **specification** exact.

## 1. Research Map: Semantic Representations of Python (PL Perspective)

The core question is: **what do we take as the semantic object** for Python?

### 1.1 Surface syntax → AST → core forms

Python’s semantics begins before execution: **tokenization** and **indentation** create block structure. The tokenizer inserts `INDENT`/`DEDENT` tokens based on whitespace, which is semantically relevant because it determines the parse tree. A PL-faithful model therefore needs at least:

- A *lexical layer* (strings → token stream with indentation tokens).
- A *parsing layer* (token stream → AST).
- A *binding layer* (AST → scope analysis; `global`/`nonlocal`; comprehension scopes; class body special scoping).

In many PL semantics, a pragmatic move is to desugar the surface into a smaller **core calculus**. For Python, desugarings include:

- `with` → `__enter__/__exit__` protocol + `try/finally` skeleton
- `for x in it:` → iterator protocol (`iter`, `next`, `StopIteration`)
- `async for`, `async with` → awaitable variants
- `match` → decision-tree evaluation (patterns + guards)
- `assert e, m` → conditional raise under `__debug__`

### 1.2 Operational semantics: small-step, big-step, and abstract machines

For “exactness” we want an **operational** account that matches real execution:

- **Small-step structural operational semantics (SOS):** explicit evaluation contexts; good for proofs; can be verbose for Python.
- **Big-step (natural) semantics:** compact; but exceptions, generators, and control operators complicate it.
- **Abstract machine semantics:** CEK/CESK-style, or a direct **bytecode VM** model; tends to match implementations and yields a clean notion of “program point” (PC) and “step”.

For barrier certificates, an abstract machine is attractive because it directly gives a **program transition system**.

### 1.3 Existing formalizations to reuse (and what to steal from each)

Several research lines matter here:

1. **“Python: The Full Monty” (Redex model).**
   - Value: a careful account of Python’s dynamic features in a mechanized semantics.
   - What we steal: scoping corner cases, attribute lookup, exceptions, control flow.
2. **K Framework Python semantics (and related mechanizations).**
   - Value: executable semantics + reachability tooling; good interface to symbolic execution and rewriting.
   - What we steal: a modular semantics structure and configuration/state layout.
3. **CPython bytecode semantics (implementation model).**
   - Value: the closest thing to a “machine model” you can barrier-analyze with explicit PCs.
   - What we steal: stack machine layout, exception propagation machinery, call frames, recursion behavior, and import semantics (at least at a summarized level).

The key design decision is: **AST-level semantics vs bytecode-level semantics**. AST-level is prettier; bytecode-level is closer to execution and makes “program points” concrete. This draft chooses bytecode-level as the canonical operational substrate, but we will keep an AST layer for specification and for mapping bug reports back to source.

### 1.4 “All aspects of Python” that a model must account for (eventually)

An “exact” Python model must cover at least the following semantic subsystems; we list them explicitly because barrier proofs will later need hooks/abstractions for each:

1. **Lexing/parsing/AST** (including indentation, f-strings).
2. **Name binding and scopes** (LEGB, `global`, `nonlocal`, comprehension scopes, class body scope).
3. **Expression evaluation order** and side effects (left-to-right sequencing, short-circuiting).
4. **The object model**: identity, mutability, aliasing, attribute lookup, descriptors, metaclasses.
5. **Call semantics**: positional/keyword args, defaults, `*args/**kwargs`, closures, generators/coroutines.
6. **Exceptions**: raise, propagation, chaining, finally, suppression, `except*`/exception groups (if modeled).
7. **Iteration protocols**: iterators, generator protocol, mutation-during-iteration behavior.
8. **Numeric tower**: unbounded `int`, IEEE `float`, `decimal`/`fractions` (if modeled), `__index__`.
9. **Imports and modules**: module objects, initialization, caching, side effects of import.
10. **Reflection and dynamic code**: `eval`, `exec`, `compile`, `getattr/setattr`, `__getattribute__`.
11. **Concurrency**: threads (GIL realities), `asyncio` semantics, synchronization primitives.
12. **FFI / native extension boundary**: `ctypes`, C extensions; where “memory bugs” can arise.

This is intentionally broad; we will start with a core executable subset and then grow coverage with certified approximations.

## 2. The Semantic Object We Will Barrier-Analyze: A Python Program Transition System

Barrier-certificate-theory.tex reduces verification to **reachability** in a transition system:

> Safety is: `Reach(P) ∩ Unsafe = ∅`.

We want the *same* story for Python, but with a transition system that matches Python execution.

### 2.1 Code objects and bytecode as the control-flow carrier

CPython executes **code objects** that contain:

- bytecode instructions
- constants table
- names table
- local variable layout
- free variable / cell variable layout
- (since Python 3.11+) exception tables describing handler ranges

We will treat a *code object* `C` as:

```
C = (Instr[0..N-1], Const, Names, VarLayout, FreeLayout, ExnTable, ...)
```

This gives a natural **program counter** `pc ∈ {0, …, N-1}`.

### 2.2 Machine state: the exact components we need (first cut)

Define the abstract machine state:

```
σ ::= (Threads, Heap, Globals, Builtins, ImportState, IO, Time, Flags)
```

To start (single-threaded core), we collapse `Threads` to one thread with a call stack.

#### Frames and the call stack

A **frame** records the current executing code object and its dynamic environment:

```
Frame = (C, pc, EvalStack, Locals, Cells, GlobalsRef, BuiltinsRef, BlockStack, CurrentException)
```

Where:

- `EvalStack` is the operand stack (list of object references).
- `Locals` is a mapping from local slots (or names) to object references.
- `Cells` holds closure cells (references to references).
- `BlockStack`/handler metadata represents active `try`/`except`/`finally` regions (or, in 3.11+, an interpretation of the exception table ranges as active handlers).
- `CurrentException` is either `None` or an exception triple `(exc_obj, cause, context)` plus traceback metadata.

The **call stack** is a list of frames `[F0, F1, …, Fk]` with `Fk` the current frame.

#### Heap and objects (exact, but structured)

The heap maps object identities to object records:

```
Heap : ObjId → Obj
Obj  : (TypeTag, Payload, AttrDict?, RefCount?, GCMeta?, ...)
```

We will not pretend that all of this is polynomial. Instead, we treat the heap as a *semantic structure* that later gets a *semialgebraic encoding interface* when we synthesize barriers.

### 2.3 Transition relation

Define a (possibly nondeterministic) **step relation**:

```
σ → σ'
```

which is induced by executing one bytecode instruction (or one “macro-step” like a call/return boundary if we choose).

This relation is nondeterministic for three reasons that we want to model explicitly (not sweep under the rug):

1. **Unknown inputs** (environment, command line, IO).
2. **Scheduling** if we include threads/async.
3. **Unknown/library code** when source is unavailable or intentionally abstracted.

Barrier certificates must be defined against **nondeterministic** transitions: “safe” means safe for *all* successor states permitted by the semantics (or by an assumed contract).

### 2.4 Reachability as the semantic core (least fixpoint)

Given a transition system `(S, S0, →)` (state space, initial states, step relation), define:

- `Post(X) = { s' | ∃ s ∈ X. s → s' }`
- `Reach = μR. (S0 ∪ Post(R))` (least fixpoint / transitive closure)

For a bug class with unsafe region `U ⊆ S`, the semantic notion of “bug exists” is:

```
Bug(U)  ⇔  Reach ∩ U ≠ ∅
Safe(U) ⇔  Reach ∩ U = ∅
```

This is the exact statement that barrier certificates are meant to prove.

### 2.5 Barrier certificates for nondeterministic Python execution

In the Rust document, barriers are presented as polynomial witnesses of safety. For Python we want the *same logical shape* but must accommodate nondeterminism (unknown calls, IO, scheduling). A convenient formulation is:

- Choose a real-valued function `B : S → ℝ`.
- Interpret the **candidate safe region** as `Safe_B = { s | B(s) ≥ 0 }`.

Then `B` is a (discrete-time) barrier certificate proving `Safe(U)` if:

1. **Initial safety:** `∀ s ∈ S0. B(s) ≥ ε` for some `ε > 0`
2. **Unsafe exclusion:** `∀ s ∈ U. B(s) ≤ -ε`
3. **Inductiveness (nondeterministic):** `∀ s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0`

This is the invariant-style view. It matches the reachability statement above: by (1)+(3), every reachable state stays in `Safe_B`; by (2), `Safe_B` is disjoint from `U`.

When we later restrict to *polynomial* `B` and semialgebraic encodings of `S`, (1)-(3) become constraints we can discharge via SOS/SMT/Positivstellensatz-style machinery (as in the Rust setup).

### 2.6 Quantitative reporting (confidence/risk) is a layer *on top* of reachability

The core deliverable is still a 3-valued outcome for a given unsafe region `U`: **BUG** (witnessed reachability), **SAFE** (proved unreachability), or **UNKNOWN**.

In practice we also want *ranking/triage metadata* that is:

- semantics-aligned (always refers to a specific `U` and a specific analysis semantics `PTS_R`),
- explicit about evidence (symbolic witness vs concrete witness vs proof), and
- stable under sound contract refinement (`Sem_f ⊆ R_f`), rather than ad-hoc multipliers.

Plan for a Z3-driven, OTMC-inspired quantitative layer (intervals + depth/stratification + explicit contract assumptions): `docs/OTMC_CONFIDENCE_Z3_PLAN.md`.

## 3. The `assert` Statement as a Reachability Bug (Not a Syntax Smell)

We pin down the user requirement early because it forces us to model:

- evaluation order
- exception raising
- exception handling context
- reachability (path feasibility)

### 3.1 Exact semantic meaning of `assert`

In Python, `assert` is a statement with semantics controlled by `__debug__` (optimized mode may erase asserts). The reference expansion is:

```
assert e
```

behaves like:

```
if __debug__:
    if not e:
        raise AssertionError
```

and with a message:

```
assert e, m
```

behaves like:

```
if __debug__:
    if not e:
        raise AssertionError(m)
```

So `assert(False)` is equivalent (under `__debug__ == True`) to raising `AssertionError` at that program point.

### 3.2 What exactly is “outside an exception handler”?

We want a *semantic* predicate, not a syntactic one.

Let `Raise(AssertionError)` be the transition that sets `CurrentException` to an `AssertionError` object and transfers control to exception-handling machinery. Let `Handle(AssertionError)` denote a handler transition that catches and clears that exception (possibly binding it, running a suite, and continuing).

Informally, we want to report a bug when:

> There exists a reachable state where `assert(False)` raises `AssertionError` and that exception is not caught by any dynamically enclosing handler (in the current frame or up the call stack), i.e. it reaches the top-level and terminates the program with an uncaught exception.

That corresponds to an **unsafe region** in the state space:

```
U_assert_uncaught = {
  σ | top_of_stack(σ).CurrentException is AssertionError
      and ExceptionWillPropagateOut(σ)
}
```

To make `ExceptionWillPropagateOut` *exact*, we need the semantic notion of the **active handler stack**. One faithful model is:

- Each frame carries a (dynamic) stack `Handlers` of active `try` regions.
- Each handler entry records a list of `except` clauses (class patterns) and handler PCs.
- When an exception is raised, the machine searches `Handlers` from innermost to outermost; if none match, it pops the frame and continues at the caller.

Define a semantic predicate `CaughtHereOrAbove(σ, exc)` that is true iff *some* handler on the current call stack will catch `exc` (according to Python’s exception matching rules). Then:

```
ExceptionWillPropagateOut(σ) :=
  not CaughtHereOrAbove(σ, top_of_stack(σ).CurrentException)
```

The core point is that “bugginess” is a **reachability property**:

```
BUG if Reach(σ0) ∩ U_assert_uncaught ≠ ∅
SAFE if Reach(σ0) ∩ U_assert_uncaught = ∅
```

So even for the syntactically obvious `assert False`, the right question is:

- Is the instruction **reachable**?
- If reachable, is the resulting `AssertionError` **caught** (locally or by callers)?
- Is the analysis mode assuming `__debug__ == True` (asserts active)?

### 3.3 Barrier-friendly formulation for `assert(False)`

In the Rust report, assertion failure is treated as an unsafe region guarded by path knowledge. For Python, we can similarly introduce:

- `pc_assert` = the bytecode index of the assert site (or its lowered raise site)
- `g_catch` = a guard that is `1` on paths where an `AssertionError` will be caught before escaping

Then a minimal “assert-uncaught” unsafe predicate is:

```
UnsafeAssert(σ) := (pc == pc_assert_fail) ∧ (__debug__ == True) ∧ (g_catch == 0)
```

The job of analysis is to compute whether `g_catch` can be `0` at the fail site on any feasible path. This is fundamentally a reachability + handler-analysis problem, and barrier certificates give us a way to *close loops* and handle unbounded control flow without mere bounded unrolling.

### 3.4 Three minimal test cases the model must classify correctly

**(A) Bug: reachable + uncaught**

```python
def f():
    assert False
f()
```

If asserts are enabled (`__debug__ == True`), `Reach ∩ U_assert_uncaught ≠ ∅` should hold.

**(B) Not a bug for ASSERT_FAIL: reachable + caught**

```python
try:
    assert False
except AssertionError:
    pass
```

Here the failing assertion is reachable, but `CaughtHereOrAbove` is true at the raise site, so this path should *not* witness `U_assert_uncaught`.

**(C) Not a bug for ASSERT_FAIL: unreachable**

```python
if False:
    assert False
```

Here the failing assertion site is not in `Reach` (under standard semantics), so it should not be reported.

## 4. Unknown Library Calls: Making DSE Barrier-Theoretic

Python programs are largely *glue code* over libraries. Any “exact model of Python” that ignores unknown library calls is not modeling Python-as-used.

### 4.1 The semantic problem

At a call site:

```
y = lib.f(x)
```

we often do not have source for `lib.f`, or we do not want to inline it. In a strict operational semantics, `lib.f` is still just Python code (or C extension code), but as analyzers we may treat it as **unknown**.

If we model it as fully nondeterministic, we get extreme conservatism and false positives:

```
CallUnknown_f : (σ, x) → (σ', y)   with almost no constraints
```

Yet if we assume a contract that is too strong, we get unsoundness.

### 4.2 Barrier-theoretic contracts: unknown calls as relations

We model an unknown call by a *summary relation* (a contract-as-relation):

```
R_f ⊆ InterfaceIn_f × InterfaceOut_f
```

where the interface includes not just argument/return values but also the heap footprint and raised-exception behavior (because Python calls can mutate globals, mutate arguments, and raise).

An analysis is sound if the real library behavior is contained in the assumed relation:

```
Sem_f ⊆ R_f
```

If we can certify this inclusion (or iteratively falsify and refine it), barrier proofs that assume `R_f` become sound for the real program.

### 4.3 DSE as a refinement oracle (CEGAR for contracts)

Dynamic symbolic execution (DSE) gives a way to *query the actual library* and to **validate counterexamples** produced under an abstract contract. The key soundness point is:

> For safety proofs, contracts for unknown calls must be **over-approximations** of the true behavior (`Sem_f ⊆ R_f`). Refinement must preserve this inclusion.

1. Start with a coarse contract `R_f^0` (e.g., “may return any int; may raise any Exception”).
2. Barrier-synthesize a proof. If it fails, obtain a counterexample trace that relies on some behavior of `f`.
3. Use DSE (concolic execution) to check whether that library behavior is realizable:
   - If realizable, we have a real bug (or at least a real failing execution).
   - If not found within a DSE budget, you **cannot** conclude it is unrealizable. For soundness you either:
     - keep the contract as-is (treat as “unknown”), or
     - refine only using constraints that are independently justified (proved from library code, proved by SMT for a bounded domain, or given by a trusted spec).
4. Repeat until either:
   - the unsafe trace becomes realizable (bug found), or
   - the barrier proof succeeds under the refined `R_f` (property proved).

This is the barrier-theoretic version of “havoc with constraints”: the barrier engine proposes an abstract adversarial behavior; DSE *tries to witness it*. When combined with validated contract constraints, this yields a CEGAR loop where:

- SMT/barriers provide **sound over-approximate** reasoning, and
- DSE provides **under-approximate** validation of candidate counterexamples and concrete debugging traces.

### 4.4 The core tension: “full symbolic program” meets black-box libraries

There are two different quantifier worlds in play:

- **Full symbolic model of the program** (our bytecode abstract machine): we want a transition relation `→` over machine states, so we can state and prove reachability properties with Z3 and barrier certificates.
- **Unknown library semantics**: at call sites, the true transition is induced by external code we do not model (Python code we didn’t inline, C extensions, OS effects, etc.).

If we treat unknown calls as *fully nondeterministic*, we preserve soundness but lose precision (many **UNKNOWN** or false-positive BUG candidates). If we assume overly-strong behavior, we can “prove” properties that are not true (unsound **SAFE**).

Concolic execution (DSE) is the missing piece, but it must be combined with the symbolic model in a way that respects:

1. **Soundness for proofs**: any proof must be valid for *all* real library behaviors, not just those observed dynamically.
2. **Existential validity for bugs**: any **BUG** must come with a realizable witness execution (a concrete repro), not just a symbolic trace that relied on an over-approximate contract.

The result is a disciplined hybrid workflow: **symbolic reasoning proposes**; **concolic execution witnesses**; **contracts are refined only with justified over-approximations**.

---

### 4.5 Three artifacts and two semantics (what we actually combine)

Think of the system as producing and consuming three artifacts:

1. **A symbolic transition system** `PTS_R = (S, S0, →_R)` where unknown calls are modeled by relations `R_f` (contracts). This is the system used for barrier proofs and symbolic counterexample generation.
2. **A concolic trace** `τ = (ι, ctrace, pctrace)` where:
   - `ι` is a concrete input/environment configuration (argv/env/filesystem stubs/time seeds),
   - `ctrace` is the concrete execution trace (events + concrete states), and
   - `pctrace` is the shadow symbolic path condition derived from the same run.
3. **A contract library** `R = {R_f}` with provenance and trust levels (spec/source-justified vs. default/havoc vs. “learned hints”).

And two “ground truths”:

- `Sem_prog`: the real program semantics (CPython + real libraries + OS).
- `Sem_f`: the real semantics of each external function call `f`.

The key invariant for *sound* analysis is still:

```
Sem_f ⊆ R_f
```

and therefore `Sem_prog ⊆ PTS_R` when all unknown calls are abstracted by their `R_f` relations.

Concolic execution does **not** replace this invariant; it helps us (a) produce concrete witnesses for existential claims, and (b) detect when a proposed or trusted contract is too strong (unsound), because reality exhibits behaviors outside `R_f`.

---

### 4.6 Selective concolic execution: symbolically model “our code”, concretely run libraries

The practical way to combine “full symbolic program model” with unknown libraries is **selective concolic execution**:

- Execute the program concretely on CPython.
- In parallel, run a “shadow” symbolic interpreter for the same bytecode steps in *our* code.
- When the concrete run calls into a library function whose semantics we do not model:
  - we let CPython execute it concretely (so the run continues),
  - we update the shadow symbolic state using a contract `R_f` if available, or a havoc relation otherwise,
  - and we record the concrete observation `(args_conc, ret_conc, exc_conc, footprint_conc)` as evidence.

This yields two kinds of constraints:

1. **Program-level path constraints**: branch decisions in our code become symbolic constraints on the program’s inputs/state.
2. **Call-interface observations**: concrete I/O of `f` gives us *samples* of `Sem_f` (under-approximate).

Crucially, without a contract that relates inputs to outputs, concolic execution can get “stuck” on library-dependent branches:

```python
y = lib.f(x)     # unknown relation between x and y
if y > 0:        # branch depends on y
    ...
```

If the shadow model treats `y` as unconstrained, solving for new `x` values cannot reliably control `y` (because the solver has no model of `lib.f`). This is why **contracts are not optional**: they are what makes concolic exploration *steerable* rather than merely observational.

So the hybrid stack is:

- concolic execution gives concrete traces and witnesses,
- symbolic execution + contracts gives steerability and proofs,
- and the contract refinement loop connects the two.

---

### 4.7 A disciplined hybrid loop: “symbolic propose” → “concolic witness” → “contract refine”

We want a loop that supports both bug finding and safety proofs without mixing their evidence incorrectly.

#### 4.7.1 Bug-finding loop (existential goal)

Goal: produce **BUG** only when there exists a concrete CPython execution reaching an unsafe region.

1. Run symbolic reachability in `PTS_R` to obtain a candidate counterexample trace `π` reaching `U` (unsafe region).
2. Extract from `π` a **concolic replay objective**:
   - the desired branch outcomes in our code,
   - and any required call-interface events (e.g., “this call must return a list of length ≥ 1”, “this call must not raise”, etc.) implied by the trace.
3. Attempt to realize the objective with concolic execution:
   - Solve the path constraints for program inputs (where possible).
   - Execute concretely; check whether the unsafe point is reached and the program state matches the symbolic intent.
4. If a concrete execution reaches unsafe: report **BUG** with the concrete repro and the symbolic witness trace.
5. If concolic cannot realize it within budget:
   - do **not** conclude infeasible,
   - classify as **UNKNOWN** (or “needs contract refinement”) and proceed to refinement work.

This respects the anti-cheating posture: *symbolic counterexamples are hypotheses*; only concrete replays certify a bug.

#### 4.7.2 Proof loop (universal goal)

Goal: produce **SAFE** only when we have a barrier/invariant proof for the *over-approximate* transition system that is known to cover reality.

1. Fix a contract set `R` with stated provenance (e.g., stdlib spec, source analysis).
2. Attempt to synthesize/check a barrier certificate `B` for `PTS_R`:
   - `Init`, `Step`, `Unsafe` conditions must quantify over the full relation `→_R` (including unknown-call relations).
3. If the proof succeeds: report **SAFE** and attach the proof artifact *plus* the contract assumptions used.
4. If the proof fails: use the counterexample model to guide either:
   - semantic model improvements (opcode/heap modeling), or
   - contract enrichment (adding sound over-approx constraints), or
   - reporting **UNKNOWN**.

Concolic execution can assist *search* (e.g., propose candidate invariants, validate counterexample traces), but it cannot justify contract narrowing that a proof depends on unless the narrowing is independently justified.

---

### 4.8 What can DSE legitimately “learn” about unknown libraries?

Because DSE is under-approximate, the only logically sound inferences are **widening** checks and **witness generation**:

#### 4.8.1 Sound uses (always allowed)

1. **Witness generation**:
   - If DSE finds a concrete repro, we can report **BUG**.
2. **Unsoundness detection for contracts** (widening trigger):
   - If a concrete run exhibits behavior not allowed by `R_f`, then `R_f` was too narrow (unsound).
   - Fix by *widening* `R_f` so that `Sem_f ⊆ R_f` becomes plausible again.
3. **Prioritization signals**:
   - Identify which call sites dominate UNKNOWN/FP results.
   - Identify which aspects matter (exceptions, return shapes, heap footprint).

#### 4.8.2 Unsound uses (allowed only as non-decisive hints)

1. **Narrowing by absence of evidence**:
   - “DSE didn’t see exception X, therefore X can’t happen” is invalid.
2. **Footprint restriction by observation**:
   - observing that `f` mutated only field `a` does not prove it cannot mutate `b`.

These can be used as *heuristics to guide where to read source/spec*, but must never be used to decide **SAFE**, and should not be used to eliminate BUG candidates without additional justification.

---

### 4.9 Bridging the gap: contracts as relational summaries, not ad-hoc stubs

The most robust way to make concolic + symbolic interplay work is to model calls as **relational summaries** with:

- multiple guarded cases (when we can *prove* the guard from program state), and
- a required havoc fallback (to preserve soundness when the guard/case is not justified).

This aligns with the “Elevation Plan” approach: make library semantics a first-class part of the transition system, so:

- the symbolic engine can steer exploration through library-dependent branches,
- counterexample traces can be replayed concretely with meaningful objectives,
- and barrier proofs can quantify over well-structured relations instead of opaque “do anything” steps.

The key subtlety is *when the fallback can be ruled out*:

- If a case is justified by spec/source (i.e., known to be an over-approx under its guard), then when the guard is provable on a path we may safely use the case without keeping havoc reachable.
- If a case is merely “learned” from DSE, then excluding havoc based on that case is unsound for proofs; such cases may still be useful as a bug-finding heuristic, but they must not be relied upon for **SAFE**.

This naturally suggests tracking contract provenance and enforcing a policy:

- proofs may only rely on trusted cases,
- bug-finding may use any cases, but must end in a concrete witness.

---

### 4.10 Handling heap effects under unknown calls (the hard part)

Unknown calls in Python are difficult primarily because they can:

- mutate arguments (aliasing),
- mutate globals/modules,
- allocate objects, and
- raise exceptions that alter control flow.

Concolic execution can observe *some* concrete mutations, but generalizing them into a symbolic post-state relation is nontrivial.

To make “full symbolic program” viable, the contract interface should expose at least:

- **Return/exception** behavior (what may be returned/raised, and under what preconditions),
- **Footprint** (what may be read/written/allocated),
- and ideally **shape facts** (e.g., “returns a list of length ≥ 0”, “returns a dict whose keys are a subset of …”).

When the exact heap post-state is unknown, a sound pattern is:

- havoc all locations in the may-write footprint,
- keep everything else stable,
- and model allocations via fresh object identities.

This is the “havoc with footprint” discipline: it is conservative but compositional and can be quantified over by barrier certificates.

---

### 4.11 Practical implementation plan (hybrid concolic + symbolic for unknown libs)

This is an implementation-oriented plan that still respects the theory constraints above:

1. **Define the call interface** used by both engines:
   - `(args, kwargs, receiver/self, globals footprint handles, exception channel)`.
2. **Instrument concolic runs** to emit structured call events:
   - inputs, outputs/exceptions, and a conservative footprint signal (e.g., “arg0 mutated”, “global X written”, “allocations occurred”).
3. **Make symbolic execution produce replay objectives**:
   - branch decisions + call-level constraints implied by the symbolic trace.
4. **Implement a replay driver**:
   - solve for program inputs where constraints are solver-visible,
   - otherwise use search/fuzzing around the concrete run to try to satisfy library-dependent objectives.
5. **Enforce contract provenance rules**:
   - DSE can widen contracts (unsoundness fixes) immediately,
   - narrowing requires spec/source justification,
   - learned cases without proof must keep a havoc fallback reachable for proofs.
6. **Close the loop with a “known-behavior suite”**:
   - curated snippets where the expected SAFE/BUG outcome is known,
   - focused on exercising library calls in realistic, composition-heavy patterns,
   - used to validate that added summaries improve precision without compromising soundness.

This workflow makes concolic and symbolic complementary:

- symbolic is the *proposal engine* (find candidate paths, build proof obligations),
- concolic is the *witness engine* (produce repros, sanity-check contracts),
- and contracts are the *bridge* that turns black-box behavior into a structured transition relation.

## 5. Bug Taxonomy Target: The Same 22 Bug Classes as Rust (Mapped to Python)

`barrier-certificate-theory.tex` frames bug finding as reachability into semialgebraic unsafe regions. The Rust report groups patterns but effectively targets **22 bug classes** (by splitting paired sections like overflow/underflow, race/deadlock, etc., and including cast overflow).

For Python, we keep the *shape* of the taxonomy but reinterpret each class through Python’s semantics (and, where relevant, the Python↔native boundary).

### 5.1 The 22 classes (names first, details next)

1. **INTEGER_OVERFLOW** (fixed-width overflow at FFI boundaries; `ctypes`, C extensions, `array`/`struct` casts)
2. **INTEGER_UNDERFLOW** (ditto; underflow / wrap)
3. **BUFFER_OVERFLOW** (native boundary; buffer protocol misuse; unsafe C extensions)
4. **ARRAY_OOB** (Python-level IndexError/KeyError/StopIteration misuse; also native OOB)
5. **USE_AFTER_FREE** (native boundary; lifetime bugs in extensions; unsafe capsule patterns)
6. **DOUBLE_FREE** (native boundary)
7. **DATA_RACE** (threaded Python + native releases of GIL; races on shared mutable state / external resources)
8. **DEADLOCK** (locks, conditions, async deadlocks)
9. **DIV_ZERO** (Python `//`, `/`, `%` raising `ZeroDivisionError` for numeric types; also domain-specific zeros)
10. **FP_DOMAIN** (e.g., `math.sqrt(-1.0)`; NaN/inf propagation constraints)
11. **NULL_DEREF** (`None` misuse; AttributeError/TypeError; also native null deref)
12. **UNINIT_MEMORY** (native boundary; reading uninitialized buffers; `ctypes` structs; unsafe `memoryview`)
13. **MEMORY_LEAK** (unbounded growth; reference cycles with finalizers; caches; native leaks)
14. **RESOURCE_LEAK** (files/sockets/locks not released; `with` protocol violations)
15. **ASSERT_FAIL** (reachable failing assert that is *not handled*)
16. **PANIC / UNHANDLED_EXCEPTION** (uncaught exceptions that violate a “no-crash” contract)
17. **INFO_LEAK** (taint flow: secrets to sinks)
18. **TIMING_CHANNEL** (secret-dependent timing via branches/loops/IO)
19. **STACK_OVERFLOW** (recursion limit / runaway recursion; `RecursionError` as failure mode)
20. **NON_TERMINATION** (infinite loops / non-terminating recursion)
21. **TYPE_CONFUSION** (dynamic type errors; misuse of protocols; wrong descriptor expectations)
22. **CAST_OVERFLOW** (narrowing conversions at boundaries: `int.to_bytes`, `struct.pack`, `numpy` dtypes, `ctypes` casts)

### 5.2 The promised “assert(False) outside a handler” check

This is the minimum concrete requirement we will enforce in the Python taxonomy:

- If there exists a reachable execution in which `assert False` is executed (with asserts enabled) and the resulting `AssertionError` is uncaught (propagates out of all handlers), then we report **ASSERT_FAIL**.
- If every execution either (a) never reaches the assert, or (b) catches the resulting `AssertionError` before it escapes, then the program is **safe for this property**.

The rest of the document will make this precise by defining:

1. `Reach` for the Python PTS
2. an exact “exception caught” predicate derived from handler tables / control stack
3. a barrier template that captures reachability + handler knowledge without bounded unrolling

### 5.3 Unsafe-region schemas (machine-state predicates; first-cut)

Below are *schematic* unsafe-region definitions in terms of the bytecode machine state. They are intentionally “interface-level”: they say what the unsafe condition *is*, not how to encode it semialgebraically yet.

Write `Top(σ)` for the current frame; `pc(σ)` for its program counter; and `Stack(σ)` for its evaluation stack (top at the right). Let `Val(o)` and `Type(o)` inspect heap objects.

1. **INTEGER_OVERFLOW:** `pc` at a boundary op (e.g., `struct.pack`, `ctypes` store) and `Val(x)` outside the target fixed-width range.
2. **INTEGER_UNDERFLOW:** same, but below the target min.
3. **BUFFER_OVERFLOW:** `pc` at native write with byte count `n` and target buffer size `ℓ`, with `n > ℓ`.
4. **ARRAY_OOB:** `pc` at `BINARY_SUBSCR` / `STORE_SUBSCR` and index `i` outside container bounds (or key missing if we treat `KeyError` similarly).
5. **USE_AFTER_FREE:** native boundary predicate: an object/handle `h` is used while its lifetime tag is “freed”.
6. **DOUBLE_FREE:** native boundary predicate: deallocation is invoked when lifetime tag already “freed”.
7. **DATA_RACE:** two threads `t1≠t2` reach overlapping critical sections accessing same location without a common lockset.
8. **DEADLOCK:** wait-for graph contains a cycle among held/requested locks.
9. **DIV_ZERO:** `pc` at a division/mod opcode, stack has `(a, d)` with numeric `d == 0`.
10. **FP_DOMAIN:** `pc` at a domain-restricted numeric op/call (e.g., `math.sqrt`) with argument outside domain and complex promotion not taken.
11. **NULL_DEREF:** `pc` at an attribute access/call expecting non-None receiver, with receiver `is None` (or native null deref).
12. **UNINIT_MEMORY:** native/buffer read occurs where initialization predicate for bytes/fields is false.
13. **MEMORY_LEAK:** along an unbounded run, heap size or refcounted-but-unreachable mass diverges (reachability + liveness style).
14. **RESOURCE_LEAK:** at function/module exit, a resource state machine is in “acquired” not “released” (files, sockets, locks).
15. **ASSERT_FAIL:** `pc` at assert-fail raise site with asserts enabled and `ExceptionWillPropagateOut(σ)` for `AssertionError`.
16. **PANIC / UNHANDLED_EXCEPTION:** `pc` at a raise site (any exception) with `ExceptionWillPropagateOut(σ)`.
17. **INFO_LEAK:** two runs differing only in secret input yield differing observable sink values (noninterference / taint).
18. **TIMING_CHANNEL:** two runs differing only in secret input yield differing observed time (or other timing proxy).
19. **STACK_OVERFLOW:** call stack depth exceeds recursion limit, or `RecursionError` raised and propagates out.
20. **NON_TERMINATION:** there exists an infinite execution (no terminal state), often witnessed by failure to synthesize a ranking/barrier.
21. **TYPE_CONFUSION:** dynamic dispatch selects an operation whose preconditions on `Type/Val` do not hold (often witnessed by `TypeError`/wrong descriptor path).
22. **CAST_OVERFLOW:** `pc` at narrowing cast boundary with value out of range (e.g., `int.to_bytes(length=k)` with `Val(x) ≥ 256^k`).

---

## 6. Representations: From Python Source to an Analyzable Transition System

Barrier certificates ultimately talk about a transition system `(S, S0, →)`. For Python, a key PL decision is *where to cut semantics*:

- **AST semantics** is closest to the language reference (cleaner for proving correctness of the model).
- **Bytecode semantics** is closest to the implementation (cleaner for defining “program point”, CFG edges, handler tables, call/return, etc.).

This document uses **bytecode-as-abstract-machine** as the operational semantics, and treats AST semantics as a specification layer plus a way to map results back to source.

### 6.1 A representation stack (the pipeline we certify)

We model a pipeline:

1. **Source** `P` (text)
2. `lex/parse` → **AST** `A`
3. `bind/desugar` → **Core AST** `A_core`
4. `compile` → **Code objects** `C` (bytecode + tables + exception table)
5. `cfg(C)` → **CFG with exceptional edges** `G = (V,E)`
6. `pts(G)` → **Program Transition System** `𝕋 = (S,S0,→)`

This pipeline itself has correctness obligations:

- The bytecode machine is faithful to the reference semantics for defined behavior.
- `cfg(C)` reflects actual control flow, including exception edges.
- The “program points” used in the analysis correspond to concrete instruction indices and are traceable to source spans.

Barrier synthesis is only as “exact” as these obligations.

### 6.2 The bytecode machine as a semantics carrier

At bytecode level, we get:

- **A concrete `pc`** (instruction index).
- A concrete **evaluation stack**.
- A concrete **exception machinery** (handler tables, unwinding).
- A concrete **call discipline** (frame push/pop, argument passing, return values).

These are exactly the ingredients that make reachability and “uncaught exception” predicates non-handwavy.

### 6.3 CFG extraction: normal and exceptional edges

For barrier analysis we want a CFG `G` whose nodes are *basic blocks* (ranges of bytecode with single entry, single exit under normal flow). Edges include:

- **Normal edges**: `JUMP`, `JUMP_IF_*`, fallthrough, `RETURN_VALUE`, etc.
- **Exceptional edges**: any instruction that may raise can transfer to a handler (or unwind).

Two non-negotiable Python realities:

1. “May raise” is pervasive: attribute access, arithmetic, iteration, calls, indexing, and user-defined special methods can all raise.
2. Exception handling is semantic, not syntactic: an `except` clause guards a *dynamic region* of execution; the raised exception must be matched against handler clauses.

So `cfg(C)` must expose exceptional control flow explicitly, because our unsafe regions for `ASSERT_FAIL`, `PANIC`, `DIV_ZERO`, `TYPE_CONFUSION`, etc. all depend on whether an exception is caught.

### 6.4 Program points: `pc` vs (block, offset)

There are two equivalent “program counter” representations:

- `pc ∈ {0,…,N-1}`: instruction index
- `(bb, off)`: basic block id + offset in block

For Z3 encodings, `pc` as an integer is convenient. For dominance/post-dominance and dataflow, block-level graphs are convenient. We will freely move between them via a mapping:

```
pc_to_bb : pc → bb
bb_entry_pc : bb → pc
```

### 6.5 Guards as representation-level facts (what the program knows)

Barrier-certificate-theory.tex emphasizes that *path-insensitive* “value-only” barriers are insufficient. For Python, this is even more true because “is safe” frequently means “some dynamic check happened earlier”.

We introduce **guard variables** `g` that summarize control/dataflow facts relevant to safety:

- `g_nonnull(x)`: program has established `x is not None` on the current path.
- `g_type(x,T)`: program has established `isinstance(x,T)` (or stronger).
- `g_div(d)`: program has established `d != 0` before a division site.
- `g_bounds(seq,i)`: program has established `0 ≤ i < len(seq)` (or equivalent).
- `g_catch(E)`: an exception of class `E` will be caught before escaping.
- `g_ctx(r)`: resource `r` is in a region protected by a context manager ensuring release.

Crucially: these guards are not magic—they are derived from **dataflow analysis** plus **control-flow structure** (dominance) plus **exception region structure**.

### 6.6 Alternative IRs (AST, SSA, symbolic traces) and why they matter

Bytecode is a good operational substrate, but it is not always the best analysis substrate. A practical Python barrier pipeline usually uses *multiple* representations, each optimized for a purpose:

1. **AST / Core AST.**
   - Best for: mapping back to source, reasoning about scoping (`global`/`nonlocal`), desugaring (`with`, comprehensions).
   - Pain points: dynamic dispatch and exception propagation still require an operational model; “program point” is less concrete.
2. **Bytecode + explicit stack effects.**
   - Best for: exact evaluation order; precise exception edges; concrete `pc`.
   - Pain points: stack machine style is awkward for algebraic invariants.
3. **Stack-to-register (SSA-like) IR.**
   - Best for: numeric reasoning (ranges, ranking functions, polynomial barriers), because expressions become explicit.
   - Caveat: SSA must be done on *object references*; to get value-level SSA you need to pick tracked projections (e.g., numeric value, length).
4. **Symbolic trace IR.**
   - Best for: DSE and counterexample explanation: a trace is a sequence of events (`LOAD_ATTR`, `CALL`, `RAISE`, …) with symbolic inputs/outputs.
   - Benefit: aligns with contracts as relations; easy to splice unknown-call summaries.

An “exact model” can live at the bytecode level, while barrier synthesis can run on a derived SSA-like IR over interface variables. The key correctness obligation is:

> The derived IR transition relation must be a validated over-approximation of the concrete bytecode transition relation *after projection to the interface*.

This is exactly the “validated over-approximation” pattern: concrete semantics → projected/abstracted semantics with a certificate of inclusion.

### 6.7 Python’s object model as relations (attribute lookup, descriptors, calls)

Many “common Python bugs” are not arithmetic; they are **object-model protocol violations**: missing attributes, wrong `__iter__`/`__next__`, non-callables called as functions, wrong descriptor behavior, etc. An exact semantic model must treat these protocols as *first-class relations* in the transition system.

#### 6.7.1 Attribute lookup (why it is semantically nontrivial)

In Python, `x.a` is not “read field `a`”. It is a multi-stage lookup with hooks:

1. Determine the type `T = type(x)`.
2. If `a` is a **data descriptor** in `T` (defines `__set__` or `__delete__`), it wins and runs `descr.__get__(x, T)`.
3. Otherwise, check `x.__dict__` (or slots) for an instance attribute `a`.
4. Otherwise, if `a` is a **non-data descriptor** in `T`, run its `__get__`.
5. Otherwise, if `a` exists in `T`’s dict, return it.
6. Otherwise, call `T.__getattr__` if defined, else raise `AttributeError`.

Crucially, descriptor `__get__` and `__getattr__` are arbitrary Python code: attribute access can allocate, mutate, call functions, and raise exceptions. So “attribute access” is an operational event, not a pure projection.

We model attribute access as a relation:

```
GetAttr : (Heap, x, name) → (Heap', v)   or   raises AttributeError
```

This relation is deterministic for a fixed heap and name *in the pure model*, but in practice it triggers arbitrary code and is therefore as hard as general execution.

#### 6.7.2 Call protocol

A call `f(args...)` similarly is a protocol:

- evaluate `f`
- evaluate arguments left-to-right (including `*args`, `**kwargs`)
- then perform a call:
  - if `f` is a function object, create a new frame with bound locals and run its code object
  - else, attempt `f.__call__` (which itself is attribute lookup + call)
  - if missing, raise `TypeError`

So we model calls at the interface as:

```
Call : (Heap, f, args, kwargs) → (Heap', ret)   or   raises TypeError / other
```

Unknown library calls are exactly “treat `Call` as a summary relation `R_f`”.

#### 6.7.3 Operator dispatch (`+`, `[]`, iteration) as protocols

Most “typechecking bugs” reduce to protocols:

- `x + y` uses `__add__`/`__radd__` and may raise `TypeError`.
- `x[i]` uses `__getitem__` and may raise `IndexError`/`KeyError`/`TypeError`.
- `for x in it` uses `iter(it)` then repeated `next(it)` and treats `StopIteration` as loop termination.

Each protocol is a relation with:

- preconditions (type/protocol support)
- possible exceptional outcomes
- heap effects (because special methods are arbitrary code)

This viewpoint matters for barrier certificates because it tells us what we can *soundly summarize*:

- We often cannot summarize full heap effects, but we can summarize **guard-relevant facts**:
  - “`x` is not None”
  - “`x` implements `__iter__`”
  - “`x` has attribute `a`”
  - “calling `f` does not raise `TypeError` on this path”

Those facts become guard bits and interface variables.

## 7. A Path-Sensitive Python Transition System (PTS)

### 7.1 State space with program counter and guards

We reuse the path-sensitive PTS pattern:

```
S_π = X × Π × G
```

but make `X` Python-shaped rather than “just reals”.

- `Π` is the set of program points (bytecode PCs or basic blocks).
- `G = {0,1}^m` is a vector of guard bits.
- `X` is the semantic store: frames, locals, heap, etc. (exact) or an interface summary (for analysis).

Write machine state as:

```
s = (x, π, g)
```

and transitions as:

```
(x, π, g) → (x', π', g')
```

where `π'` follows the CFG (including exceptional edges), `x'` follows bytecode semantics, and `g'` follows guard propagation rules.

### 7.2 Guard propagation semantics (examples we need for Python)

Guard propagation is the semantic bridge between “program structure” and “barriers”. We specify it as a family of updates `γ_e` indexed by CFG edges `e`.

#### Non-None guards

For a variable `v`:

```
γ_e(g_nonnull(v)) =
  1  if e is the true-branch of (v is not None)
  0  if e assigns v := None
  g_nonnull(v) otherwise
```

#### Type guards

For `isinstance(v, T)`:

```
γ_e(g_type(v,T)) =
  1  if e is the true-branch of isinstance(v,T)
  0  if e assigns v := <unknown> (kills the fact)
  g_type(v,T) otherwise
```

This intentionally models *knowledge*, not the runtime type itself. The runtime type lives in the heap/object model; the guard is a summarized fact derived from control flow.

#### Exception-catching guards (handler structure)

For a specific exception class `E` and a site `π`:

- `g_catch(E)` is `1` at `π` if, from `π`, any raised `E` will be caught by some dynamically enclosing handler before escaping.
- This can be approximated intraprocedurally by “this instruction is within a try-region that catches `E`”, but exactness requires also considering callers (interprocedural).

We model propagation with two components:

1. **Region membership:** whether `π` is within a handler-protected region for `E`.
2. **Call-summary effect:** whether exceptions are caught in callers (a summary for each function).

The “exact” definition is semantic (`CaughtHereOrAbove`); guard propagation is the analysis approximation used to build a barrier.

### 7.3 A Python path-sensitive barrier template (shape, not yet encoding)

Barriers are easiest to understand as “inductive safe regions”. For a bug class `U ⊆ S`, we want a function `B : S → ℝ` such that:

- `B ≥ 0` on all reachable states
- `B < 0` on all unsafe states

The path-sensitive form uses guard bits to distinguish “checked” from “unchecked”.

For example, for a “non-None required at site `π_deref`” property with a guard bit `g_nonnull(v)` and a runtime indicator `ν_v` (`ν_v=1` iff `v is not None`), a canonical *checked-vs-unchecked* barrier term is:

```
B_nonnull(v) = g_nonnull(v) · (ν_v - 1/2)  +  (1 - g_nonnull(v)) · M
```

where `M` is a large positive constant (a “don’t care yet” reward when unchecked but also not at a deref site). When we combine with a penalty for being at a deref site without the check, we obtain a barrier that separates safe and unsafe executions.

Python’s “exactness” wrinkle is that many `ν_v` and `θ_v` (type tag) facts are not polynomial in a raw heap model. We will address this by defining a semialgebraic **interface encoding** (next section) so that `ν_v`, `θ_v`, `len(seq)` etc. are explicit state variables (or summarized variables) available to `B`.

## 8. Semialgebraic Interface Semantics for Python States

Barrier synthesis wants a numeric state vector; Python states are structured and dynamic. The bridge is an *interface abstraction*:

```
α : (exact Python machine states) → (interface states)
```

An interface state contains the specific numeric and Boolean features needed to express and prove a property.

### 8.1 What the interface must support

To model the 22 bug classes, the interface needs:

- **Type tags** for relevant values (at least a finite partition: `None`, `int`, `float`, `bool`, `str`, `bytes`, `list`, `dict`, `tuple`, `callable`, user-object).
- **Numeric values** for integers/reals when they matter (including range bounds at cast/boundary sites).
- **Shape facts**: `len(seq)` for sequences, container membership facts, etc.
- **Alias/identity facts**: equality on object identities (at least a may-alias relation).
- **Exception class facts** at raise sites and handler sites.
- **Resource state machines** for `with`-managed resources, locks, files, sockets.
- **Control facts**: `π` and guard bits `g`.

The guiding principle from semialgebraic-semantics.tex is:

> *You only project down to an interface that is rich enough to state the safety property and to be inductive under the transitions you keep.*

### 8.2 Numeric carriers: ℤ, ℝ, and bitvectors

Python has:

- unbounded `int` (mathematically ℤ)
- IEEE-ish `float` (finite set with NaN/inf)

For barrier certificates, a common move is to:

- treat `int` as an `ℤ` variable for SMT feasibility and as an `ℝ` relaxation for polynomial reasoning
- treat `float` with a sound abstraction: either as a real with domain predicates (ignoring rounding) or as an IEEE bitvector model for bounded checks (more exact but heavier)

Because the user goal is “exact model of Python”, we separate:

1. **Semantic truth:** floats are IEEE binary64; ints are unbounded.
2. **Analysis encoding:** we may use reals for barriers, but we must either (a) certify over-approximation, or (b) restrict claims to the abstraction.

### 8.3 A concrete interface schema (first iteration)

For each tracked program variable `v`, introduce:

- `θ_v` a one-hot type tag vector (or an integer enum with constraints)
- `ν_v ∈ {0,1}` an “is-not-None” indicator (redundant with `θ_v` but convenient)
- `ι_v ∈ {0,1}` an “initialized” indicator for native/buffer views
- `x_v ∈ ℤ` and/or `r_v ∈ ℝ` a numeric carrier when `v` is numeric

For each tracked container `c`:

- `len_c ∈ ℤ, len_c ≥ 0`
- `shape_c` predicates (e.g., “is list/tuple/bytes”)

For exceptions:

- `exc ∈ ExcTag ∪ {None}` where `ExcTag` is a finite tag partition of exception classes (or a Z3 datatype)
- `g_catch(E)` guard bits for exception-catching knowledge

For control:

- `π ∈ Π`

For resources:

- `state_r ∈ {Init, Acquired, Released, Leaked}` (finite automaton state)
- `owner_r` or `held_by(t,ℓ)` for locks

Then an interface state is:

```
α(x) = (π, g, θ, ν, x, r, len, state, ...)
```

Barriers are polynomials (or piecewise-polynomials) over these interface variables.

### 8.4 Heap and objects: uninterpreted structure + tracked projections

We do not attempt to embed the full Python heap into a polynomial ring. Instead:

- Heap structure is kept in the *exact machine semantics*.
- The interface contains **tracked projections**: selected `θ_v`, `ν_v`, `len_v`, alias predicates, etc.
- Z3 handles the remaining symbolic heap reasoning when necessary via:
  - uninterpreted functions like `Attr(obj, name)` or `DictGet(d,k)`
  - arrays mapping object ids to fields
  - datatypes for object payload variants

This yields a *hybrid* approach:

- **SOS/polynomial** reasoning for numeric/guard invariants (barriers, ranking functions).
- **SMT** reasoning for discrete structure, type tags, case splits, and path feasibility.

### 8.5 Gluing + hiding: contracts and abstractions as compositional relations

The semialgebraic-semantics viewpoint is that every stage of “modeling Python” is a **relation**, and composition is just:

- **Glue (conjunction):** put two relations side-by-side by conjoining their constraints on shared variables.
- **Hide (projection):** existentially quantify intermediate variables (internal wires).

This matters because Python verification is inherently staged:

1. The bytecode step relation `Step_py` is already a relation on states.
2. Each unknown/library call site introduces a summary relation `R_f` on an interface.
3. Each abstraction step (stack-to-SSA, heap projection, float relaxation) introduces an approximate relation `Step_hat` that should over-approximate `Step_py` on the interface.

If we can validate (or explicitly assume) inclusions of the form:

```
Step_py ⊆ Step_hat
Sem_f   ⊆ R_f
```

then the composed whole-program relation is also over-approximated, and safety is monotone:

> Proving safety on the over-approximate relation is sound for the concrete relation.

This gives us a disciplined way to add “Python realism” (unknown calls, floats, OS effects) without losing the semantics thread: every approximation is either (a) validated, or (b) declared as an assumption whose scope is explicit.

## 9. The Role of Z3: Feasibility, BMC, and Hybrid Certification

Z3 plays three distinct roles:

1. **Path feasibility oracle** (symbolic execution / DSE): is this path condition satisfiable?
2. **Bounded model checking (BMC)**: does there exist a bug within `k` steps?
3. **Certificate checker / glue logic**: discharge boolean/discrete parts of the barrier conditions that are not purely polynomial.

### 9.1 BMC encoding of Python bytecode (skeletal form)

Fix a bound `k`. Introduce symbolic states `s_0,…,s_k` with:

- `pc_i : Int`
- `stack_i : Seq[ObjId]` (or a fixed-depth tuple if you bound stack depth)
- `locals_i : Name → ObjId` (or arrays for locals slots)
- `heap_i` as arrays/uninterpreted functions (often summarized)
- `exc_i` as a datatype/tag

Then encode:

```
Init(s_0) ∧ ∧_{i=0}^{k-1} Step(s_i, s_{i+1}) ∧ Unsafe(s_k)
```

If SAT, the model yields a concrete counterexample (witness values for the interface variables, plus enough structure to replay the bug).

### 9.2 Modeling exceptions and handlers in SMT

For the `assert(False)` requirement, the key is to model:

- the transition that raises `AssertionError` at a specific `pc`
- handler matching (`except AssertionError:` catches it)
- propagation out of frames when uncaught

An SMT-friendly pattern is:

- Represent exception class tags by an enumeration:

```
Exc = None | AssertionError | ZeroDivisionError | TypeError | ...
```

- Track `exc_i : Exc`.
- Define `WillCatchAt(pc, exc)` as a predicate derived from handler tables (intraprocedural) and/or summaries (interprocedural).

Then:

```
UnsafeAssert(s) :=
  (pc == pc_assert_fail) ∧ (__debug__ == True) ∧ (exc == AssertionError) ∧ ¬WillCatchAt(pc, exc)
```

This aligns exactly with the earlier semantic unsafe region; the only approximation is how we compute/encode `WillCatchAt`.

### 9.3 Modeling dynamic dispatch and type errors in SMT

Python operations like `x + y` are not simple arithmetic; they are dynamic dispatch:

1. compute `x.__add__(y)` (if present)
2. if returns `NotImplemented`, try `y.__radd__(x)`
3. if still not implemented, raise `TypeError`

In a bytecode-level symbolic executor, we can encode this with:

- `θ_x`, `θ_y` type tags (finite partition)
- uninterpreted functions representing magic methods when we treat user code as unknown
- case splits for built-in types

For a “typechecking bug” class, we typically define the unsafe region as **a reachable `TypeError` that is uncaught**, or (stronger) a reachable program point where a required type precondition is violated.

Z3 is the natural place to manage the combinatorial branching of dynamic dispatch; barriers are the natural place to summarize the “global shape” facts needed to prevent those errors.

### 9.4 Hybrid proof obligations: splitting the barrier conditions

The barrier conditions from §2.5/§7.3 can be separated:

- Purely **numeric** constraints (polynomial inequalities over reals/integers): good for SOS/DSOS/SDSOS.
- Purely **boolean/discrete** constraints (type tags, guards, handler membership): good for SMT.
- **Mixed** constraints: handled by introducing indicator variables and using SMT to case-split or by using mixed-integer polynomial techniques.

Operationally, a hybrid checker often does:

1. Use SMT to enumerate/over-approximate discrete cases (type tags, guards).
2. For each case, solve the numeric barrier subproblem (SOS) or check a template.
3. Use Z3 again to validate that the barrier is inductive over the abstracted step relation.

This is “barrier certificates with an SMT front-end”.

### 9.5 Two concrete Z3 sketches (assert reachability, typechecking at an op)

These are intentionally schematic: the point is to show the *shape* of the SMT problems we solve alongside barrier synthesis.

#### (A) `assert False` uncaught (bounded)

We model a tiny control skeleton with a single potential handler. Let:

- `pc` be either `ASSERT_SITE` or `EXIT`.
- `caught` be a Boolean indicating whether a handler catches `AssertionError`.

Then the unsafe condition is “at assert site and not caught”:

```smtlib
(declare-const pc Int)
(declare-const caught Bool)
(declare-const ASSERT_SITE Int)

; unsafe if we hit the failing assert and no handler catches it
(define-fun UnsafeAssert () Bool
  (and (= pc ASSERT_SITE) (not caught)))
```

In a real BMC encoding, `pc` and `caught` are indexed by time `i` and constrained by `Step(s_i,s_{i+1})`. SAT produces a concrete witness path.

#### (B) Typechecking at a numeric op site

Suppose at some `pc == ADD_SITE` we want `x` and `y` to be `int`. Use a finite type tag:

```smtlib
(declare-datatypes () ((Ty NoneTy IntTy FloatTy StrTy ObjTy)))
(declare-const pc Int)
(declare-const ADD_SITE Int)
(declare-const ty_x Ty)
(declare-const ty_y Ty)

(define-fun UnsafeAddType () Bool
  (and (= pc ADD_SITE) (or (not (= ty_x IntTy)) (not (= ty_y IntTy)))))
```

This “typechecking bug” is a reachability query: `Reach ∩ UnsafeAddType ≠ ∅`. Guards like `g_type(x,int)` appear as additional booleans constrained by control-flow (`isinstance` branches), letting the barrier enforce that the check dominates the operation.

### 9.6 Exceptions “exactly enough”: handler stacks, matching, finally, and suppression

If Python bugs are reachability into unsafe regions, then exception propagation is the connective tissue: many unsafe regions are “a bad exception escapes” or “a bad exception is raised at all”. An exact operational model must therefore make exceptions a *first-class control effect* rather than an annotation.

#### 9.6.1 An abstract machine view of exceptions

We extend the frame state from §2.2 with an explicit dynamic handler stack:

```
Frame = (C, pc, EvalStack, Locals, Cells, GlobalsRef, BuiltinsRef,
         Handlers, CurrentException)
```

where:

- `CurrentException` is either `None` or an exception object/tag plus metadata (cause/context/traceback).
- `Handlers` is a stack of *handler entries* representing dynamically active `try`/`except`/`finally` regions.

Semantically, raising an exception is a transition:

```
Raise(E): (…, CurrentException=None) → (…, CurrentException=E)
```

followed by unwinding/search transitions that either:

- transfer control to an appropriate handler (within the current frame), or
- pop the frame and propagate to the caller, or
- terminate the program at the top (uncaught).

This is the core reason “outside an exception handler” must be semantic: it depends on the dynamic `Handlers` stack, not merely syntax.

#### 9.6.2 Exception matching is itself a computation

In Python, `except T:` matches if the raised exception instance `e` satisfies `isinstance(e, T)` where `T` may be:

- a single exception class
- a tuple of classes

In the “exact model”, this is not a simple tag compare:

- the exception object is an instance with a dynamic MRO and potential metaclass behavior
- the matching relation is defined by the object model and class hierarchy

For analysis, we typically choose a finite abstraction:

- `ExcTag(e)` is a finite tag for the exception class (e.g., `AssertionError`, `TypeError`, …)
- matching becomes either:
  - exact on tags (if the tag partition refines subclassing), or
  - conservative (`ExcTag` is coarse, so matching is over-approximated).

This is one of the places where “validated over-approximation” is conceptually clean: if the match relation is over-approximated, then safety proofs about “no uncaught exception” remain sound (they are conservative).

#### 9.6.3 `finally` and “handler edges that run code”

`try/finally` and `with` introduce a key complexity: there are control-flow edges that must execute cleanup code on both the normal and exceptional paths.

Operationally:

- A `finally` region registers a cleanup continuation in `Handlers`.
- On both `return` and `raise`, control transfers to the cleanup code before continuing propagation.

For reachability, this means:

- a “bad exception escapes” property must allow intermediate states where the exception is present but will be *temporarily* masked or transformed by `finally` code.
- a “resource leak” property often hinges on `finally` ensuring a typestate transition to `Released`.

So, when we talk about `WillCatchAt(pc, exc)`, it is insufficient to treat `finally` as a boolean “caught”; it is a code region that may:

- handle (swallow) the exception
- re-raise it
- replace it (raise a different exception)
- always run and then resume propagation

#### 9.6.4 Exception suppression and chaining are part of the semantics

Python supports:

- exception chaining (`raise X from Y`)
- context (`__context__`, `__cause__`)
- suppression (`from None`)

For crash/no-crash properties, we usually care only about whether an exception escapes, not about its chain. For diagnostics and information-flow properties, chains may matter (e.g., leaking secrets in exception messages). The interface can therefore selectively track:

- `exc_tag` (class)
- optionally `exc_payload` summaries (message length, taint, numeric codes)

### 9.7 Computing and encoding `WillCatchAt`: region analysis + summaries + proof obligations

The document has used `WillCatchAt(pc, exc)` as if it were a primitive. This subsection makes it explicit as an *analysis artifact* that sits between exact semantics and barrier proofs.

#### 9.7.1 Three progressively stronger notions

It is useful to separate three predicates that people often conflate:

1. **Transfer-to-handler (`WillTransferToHandlerAt`)**  
   Structural: if an exception is raised at `pc`, control will jump to some handler entry in the current frame (not necessarily one that catches the type).
2. **Match (`WillMatchInHandlerAt`)**  
   Structural+type: there exists an enclosing `except` clause whose class pattern matches `exc`.
3. **Handle (`WillBeHandled`)**  
   Semantic: after executing handler code (and any `finally` code), the exception will not escape this frame/call stack.

For `ASSERT_FAIL` as “uncaught AssertionError”, we need (3). For some internal optimizations (e.g., pruning exploration), (1) and (2) are still very valuable.

#### 9.7.2 Intraprocedural extraction (what we can get from bytecode)

At the bytecode level we can derive:

- the **protected region intervals** for `try` blocks (which PCs are covered)
- handler entry PCs for exceptional control flow
- the handler code’s own CFG

From this we can build:

- `Region(pc)`: the innermost protected region containing `pc` (or none)
- exceptional edges: `pc ─exc→ handler_entry(pc)` for potentially-raising instructions

This yields an *exact* intraprocedural exceptional CFG skeleton.

#### 9.7.3 Interprocedural summaries for “uncaught”

Whether an exception is ultimately uncaught is interprocedural: even if a function does not catch `AssertionError`, its caller might.

A clean summary interface is:

```
MayRaise_f(E) : can f raise E (on some path)?
MustHandle_f(E) : if f raises E, is it guaranteed to be handled before escaping f's dynamic extent?
```

More commonly, we compute:

- `MayEscape_f(E)` — there exists an execution where `f` raises `E` and it escapes the call to `f`.

These summaries can be computed via fixpoints on the call graph, but Python’s dynamic call targets complicate this; unknown calls need contracts (§4) to be included in the summary computation.

#### 9.7.4 Proof obligation: the guard must over-approximate the semantic predicate

When we use guard bits like `g_catch(E)` inside a barrier, soundness relies on the guard being conservative in the right direction.

For a “no-uncaught-exception” safety property, the *dangerous* unsoundness is:

> setting `g_catch(E)=1` on a path where the exception can in fact escape.

So the safe direction is:

```
g_catch(E)=1  ⇒  WillBeHandled(E)
```

Equivalently, `g_catch` must under-approximate “handled”. Under-approximation preserves soundness of safety proofs but can cause false positives (because you fail to prove safety when it is actually safe).

This is exactly where SMT is helpful: on code patterns like

```python
try:
    assert False
except AssertionError:
    pass
```

you can prove the handler does not re-raise and thus justify `g_catch(AssertionError)=1` after the handler.

### 9.8 The barrier+SMT workflow as a CEGAR loop

Putting the parts together yields a practical “Python barrier checker” loop:

1. **Build an exact operational model skeleton** at the bytecode level (CFG + exceptional edges + call structure).
2. **Choose an interface** `α` (types, guards, numeric values, lengths, resource states) rich enough for the property.
3. **Over-approximate unknown calls** with contracts `R_f` on the interface.
4. **Try to find a bug quickly** with Z3 BMC on the interface model (bounded).
5. If no bug is found, **attempt to synthesize an inductive barrier** `B` (template + solve).
6. **Validate inductiveness** with SMT case-splitting over the discrete structure (guards, tags, PCs).
7. If validation fails, extract a counterexample state/transition:
   - refine the interface (add guard bits, track more variables), or
   - refine the abstraction/contract (stronger but validated assumptions), or
   - accept the found bug (if realizable).

This is CEGAR in the barrier world:

- the abstraction is the interface + contracts,
- the refinement is adding predicates/guards/contracts,
- the checker alternates between BMC counterexamples and inductive certificates.

## General Relational Semantics for Library Calls (Non‑Regex)

This plan stays within the system defined by:
- `.github/prompts/python-semantic-barrier-workflow.prompt.md` (stateful workflow + anti‑cheating + BUG/SAFE/UNKNOWN posture)
- `python-barrier-certificate-theory.md` (abstract machine reachability + unknown calls as relations with `Sem_f ⊆ R_f`)

Goal: upgrade the analyzer so **any** library/builtin function becomes “reasoning‑relevant” once its semantics are added in a *uniform, structural form* (not via source pattern matching). The `len`/bounds story becomes one instance of this general mechanism.

---

### 0. Non‑negotiables (anti‑cheating)

- Do **not** special‑case source patterns (`len(x)-1`, `x[len(x)]`, etc.).
- Do **not** use regex/AST smells/docstrings/test names as a decider.
- All “BUG” and “SAFE” outcomes must follow from the machine transition relation + Z3 checks. If we can’t prove it, return **UNKNOWN**.
- For unknown calls, preserve soundness: `Sem_f ⊆ R_f` (default `R_f` is havoc).

---

### 1. The general solution: treat *all* known calls as relational transitions

We want a single call semantics pipeline:

1. **Frontend** resolves a call target to a stable identifier (e.g. `"len"`, `"math.sqrt"`, `"pathlib.Path.exists"`).
2. The symbolic VM applies a **registered relational summary** for that identifier:
   - a relation over `(pre_state, args) → (post_state, ret, exc)` expressed in Z3‑checkable form,
   - with a sound default havoc case when the summary doesn’t apply.
3. The same pipeline works for:
   - builtins (`len`, `isinstance`, `sorted`, …),
   - stdlib (`math.sqrt`, `json.loads`, …),
   - third‑party libs (when summaries are provided),
   - methods/attributes (when resolution can identify them).

This is the structural “plug‑in point”: add semantics by adding a relation, not by changing the VM.

---

### 2. The “given form” for library semantics (what authors write)

Define a *declarative* summary format: **a set of cases** + a required fallback.

**SummarySpec(function_id)**:
- `cases: [Case]` (ordered or prioritized)
- `fallback: HavocCase` (always present; ensures soundness)

**Case** (one behavior mode):
- `guard(pre_state, args) -> z3.BoolRef` (when this case applies)
- `post(pre_state, args, fresh) -> (post_constraints, heap_updates, ret_value)` for normal return
- `raises: [RaiseCase]` (optional exceptional behaviors)

**RaiseCase**:
- `guard(pre_state, args) -> z3.BoolRef`
- `exception_type: str` (or an exception object summary)
- optional `heap_updates`

Design constraints:
- Cases may be *partial*: if `guard` can’t be established, the engine must keep fallback behaviors reachable.
- Summaries are allowed to be **over‑approximations** only (never “assume it doesn’t raise” unless justified by the spec and enforced by constraints).

Practical representation:
- Implement the summary format as Python objects/functions that *build Z3 constraints* (not as raw strings).
- Keep the existing `Contract` type as a coarse schema; add an adapter so simple `Contract`s can be interpreted as one or two trivial `Case`s (type/range only), while richer summaries use the full relational form.

---

### 3. One engine to apply any summary (no per-function special cases)

Files likely involved: `pyfromscratch/semantics/symbolic_vm.py`, `pyfromscratch/contracts/schema.py` (or a new `pyfromscratch/contracts/relations.py`).

Implement `apply_summary(function_id, state, args)`:
- Produce successor paths for:
  - each feasible normal-return case
  - each feasible exceptional case
  - the fallback havoc case (unless proven unreachable under the current `path_condition`)
- For each successor:
  - conjoin `path_condition ∧ case.guard ∧ post_constraints`
  - apply heap updates in a structured way (see §4)
  - set `(ret, exc)` appropriately

Soundness rule:
- If summaries are incomplete/uncertain, the fallback must remain reachable; this prevents “semantic optimism” that could lead to bogus SAFE.

Why this generalizes:
- Any library function becomes useful to downstream reasoning (bounds, null‑ptr, type confusion, etc.) when its summary adds the right constraints/facts into the state.

---

### 4. Make summaries able to talk about heap properties (observers + updaters)

To avoid “model‑peeking” (e.g., using `solver.model()` mid‑execution), summaries need symbolic heap accessors that are stable even when object identities are symbolic.

Introduce a small “heap observer/updater” interface usable from summaries:

- Observers (pure):
  - `SeqLen(obj_id) : Int`
  - `DictSize(obj_id) : Int` (optional)
  - `StrLen(obj_id) : Int` (optional)
  - `HasKey(dict_id, key) : Bool` (optional)
- Updaters (effects):
  - allocation: returns fresh `obj_id` with constraints (e.g., `SeqLen(new) == n`)
  - mutation: updates post‑state observers (functional‑heap style, e.g., `SeqLen'(lst) == SeqLen(lst) + 1`)

Implementation approach (plan-level):
- Encode observers as (possibly) uninterpreted functions in Z3 with “frame” versions to model mutation (`SeqLen_t` per time step or per heap snapshot).
- When the VM executes a heap‑creating opcode (BUILD_LIST/TUPLE, etc.), assert the corresponding observer constraints.
- When summaries mutate heap (e.g., `list.append`), express it by relating pre/post observer symbols, not by mutating Python dictionaries.

Success criterion:
- Any summary can express relationships like “return equals a heap-derived property” and “this call increases list length”, enabling structural proofs elsewhere.

---

### 5. Bounds example as an instance (no pattern matching)

With the general summary engine + heap observers:

- Add a `len` summary case:
  - guard: arg0 is LIST/TUPLE/STR/DICT
  - post: `ret == SeqLen(arg0)` (or the appropriate observer), `ret >= 0`
  - raises/fallback: if arg0 is generic OBJ, keep `TypeError/*` and heap effects reachable (via fallback)
- Update truthiness (`if x:`) to depend on observers (can be modeled as a “truthiness summary” for BOOL conversion, or as a VM intrinsic that uses the same observer API):
  - LIST/TUPLE/STR: `is_true(x) ↔ SeqLen(x) != 0`
- Update subscript to use the same observers:
  - bounds_ok uses `SeqLen(container)`; normalize negative indices; produce `bounds_violated` formula

Then Z3 can prove:
- `x[SeqLen(x)]` violates bounds (off-by-one)
- `x[SeqLen(x)-1]` is in-bounds under `SeqLen(x) > 0`
…without any special casing of `len(...)` syntax.

---

### 6. Validation (tests that enforce generality)

Add tests in a way that the only path to passing is “summary constraints compose with core semantics”:

1. Bounds tests (the motivating example), including variants that defeat pattern matching:
   - store `n = len(x)` then use `n-1` / `n`
   - alias `x` through another name
2. Summary-composition tests (general):
   - For each added summary, include at least one test where its postcondition is required to prove a downstream property.
   - Example patterns:
     - `math.sqrt(x)` summary adds `x >= 0` on non-exceptional path → should eliminate spurious FP_DOMAIN on guarded paths.
     - `dict.get(k, default)` summary constrains “no KeyError” → should prevent BOUNDS(KeyError) in guarded uses.
3. Soundness tests:
   - Ensure fallback remains reachable when guards aren’t provable (so we don’t accidentally “prove SAFE” by dropping havoc).




---

## 9.5. Interprocedural Analysis: Call Graphs, Function Summaries, and Cross-File Dataflow

The preceding sections focus on **intraprocedural** analysis: reasoning within a single function's bytecode. However, real Python programs are collections of modules, classes, and functions that call each other. To achieve precision on security properties (especially taint tracking for the 47 CodeQL bug types), we require **interprocedural analysis** that tracks dataflow across function boundaries and files.

### 9.5.1 The Interprocedural Problem

Consider a cross-function taint flow:

```python
# file: sources.py
def get_user_input():
    return request.GET.get('query')  # Source: HTTP_PARAM

# file: handlers.py
from sources import get_user_input
def process():
    data = get_user_input()          # Taint flows through call
    cursor.execute(data)              # Sink: SQL_EXECUTE → BUG!
```

An intraprocedural analysis of `process()` alone cannot determine that `data` is tainted—it only sees a call to `get_user_input()` returning some value. Without a **function summary** or **inlining**, the taint is lost.

### 9.5.2 Call Graph Construction

**Definition 9.5.1 (Static Call Graph).** A call graph $G_{call} = (V, E)$ where:
- $V$ is the set of all functions (code objects) in the program
- $E \subseteq V \times V$ where $(f, g) \in E$ iff $f$ contains a call site that may invoke $g$

For Python, call graph construction is **approximate** due to:
1. **First-class functions**: `f = some_func; f(x)` requires points-to analysis
2. **Dynamic dispatch**: `obj.method()` requires type analysis
3. **Reflection**: `getattr(obj, name)()` is generally undecidable
4. **Imports**: `from module import func` requires module resolution

**Definition 9.5.2 (Call Site).** A call site $\pi_c$ is a program point (bytecode offset) containing a `CALL_FUNCTION*` instruction. Each call site has:
- A **callee expression** (the function being called)
- **Arguments** (positional and keyword)
- A **return continuation** (where control resumes after the call)

**Definition 9.5.3 (Call Graph Over-Approximation).** A sound call graph satisfies:
$$\forall \text{ execution } \tau, \forall \text{ call event } (f, \pi_c, g) \in \tau: (f, g) \in E$$

That is, every actual call in any execution is represented by an edge.

### 9.5.3 Function Summaries as Taint Transformers

Rather than inlining all functions (which doesn't scale and may not terminate for recursion), we compute **function summaries** that abstract each function's effect on taint.

**Definition 9.5.4 (Taint Summary).** For function $f$ with parameters $\vec{p} = (p_1, \ldots, p_n)$ and return value $r$, a taint summary is a transformer:
$$\Sigma_f^{\tau} : \mathcal{L}^n \to \mathcal{L}$$
mapping input taint labels to output taint label, where $\mathcal{L} = \mathcal{P}(\mathcal{T}) \times \mathcal{P}(\mathcal{K}) \times \mathcal{P}(\mathcal{T})$ is the taint product lattice.

**Concrete form**: The summary is a tuple $(\tau_{ret}, \kappa_{ret}, \sigma_{ret})$ computed as:
$$\tau_{ret} = \bigcup_{i: p_i \text{ flows to } r} \tau_{p_i}$$
$$\kappa_{ret} = \bigcap_{i: p_i \text{ flows to } r} \kappa_{p_i}$$
$$\sigma_{ret} = \bigcup_{i: p_i \text{ flows to } r} \sigma_{p_i}$$

**Example**: For `def identity(x): return x`, the summary is:
$$\Sigma_{identity}^{\tau}(\ell_x) = \ell_x$$

**Example**: For `def sanitize(x): return html.escape(x)`, the summary is:
$$\Sigma_{sanitize}^{\tau}((\tau, \kappa, \sigma)) = (\tau, \kappa \cup \{HTML\_RENDER\}, \sigma)$$

### 9.5.4 Barrier Summaries for Interprocedural Safety

Beyond taint, we need summaries that preserve barrier certificate reasoning.

**Definition 9.5.5 (Barrier Summary).** A barrier summary for function $f$ is a transformer:
$$\Sigma_f^B : (B_{pre}, \vec{x}_{args}, \vec{g}_{pre}) \mapsto (B_{post}, x_{ret}, \vec{g}_{post})$$
encoding how calling $f$ transforms the barrier value and guard state.

The barrier summary must satisfy **inductiveness through calls**:
$$B_{pre}(s) \geq 0 \land s \xrightarrow{call\ f} s' \implies B_{post}(s') \geq 0$$

**Theorem 9.5.1 (Compositional Barrier Soundness).** If each function $f$ in the call graph has a sound barrier summary $\Sigma_f^B$, and the main entry point has $B_{init} \geq \epsilon > 0$, then the composed program satisfies:
$$\forall s \in Reach: B(s) \geq 0$$

where $B$ is the piecewise barrier defined by applying summaries at each call site.

### 9.5.5 Summary Computation Algorithm

Summaries are computed **bottom-up** in the call graph (from leaves to roots).

**Algorithm: ComputeTaintSummaries**
```
Input: Call graph G = (V, E), source/sink/sanitizer contracts
Output: Summary map Σ: V → TaintSummary

1. Compute SCCs of G (handle recursion)
2. Process SCCs in reverse topological order:
   For each SCC C:
     If C is a single non-recursive function f:
       Σ[f] ← AnalyzeFunction(f, Σ)
     Else (recursive SCC):
       Σ[C] ← FixpointIteration(C, Σ)
3. Return Σ

AnalyzeFunction(f, Σ):
   // Intraprocedural dataflow with call site handling
   For each parameter p:
     label[p] ← symbolic fresh label ℓ_p
   For each instruction in f:
     If instruction is CALL g at site π_c:
       arg_labels ← [label[arg] for arg in call_args]
       If g has summary Σ[g]:
         ret_label ← apply Σ[g] to arg_labels
       Else if g is source/sink/sanitizer:
         ret_label ← apply contract
       Else:
         ret_label ← ⊔(arg_labels)  // Sound over-approximation
       label[ret_var] ← ret_label
     Else:
       // Standard intraprocedural transfer
   return (dependencies from params to return)
```

### 9.5.6 Cross-File Module Resolution

Python's import system requires resolving module dependencies to build a complete call graph.

**Definition 9.5.6 (Module Graph).** The module graph $G_{mod} = (M, I)$ where:
- $M$ is the set of all modules (`.py` files or packages)
- $I \subseteq M \times M$ where $(m_1, m_2) \in I$ iff $m_1$ imports from $m_2$

**Import Resolution Algorithm**:
1. Parse each Python file to extract `import` and `from ... import` statements
2. Resolve relative imports using package structure
3. Build module graph edges
4. For each imported name, track the binding chain to its definition

**Cross-file dataflow** then follows imported bindings:
```python
# file: utils.py
def helper(x):
    return x.upper()  # Returns string with same taint as x

# file: main.py  
from utils import helper
data = request.GET['q']      # τ = {HTTP_PARAM}, κ = ∅
result = helper(data)         # Apply Σ_helper: τ = {HTTP_PARAM}, κ = ∅
eval(result)                  # Sink: CODE_EVAL → BUG!
```

### 9.5.7 Entry Point Analysis

A common gap is failing to analyze code reachable from entry points.

**Definition 9.5.7 (Entry Points).** Entry points are the roots of reachability:
1. **Module-level code**: Statements at the top level of each module
2. **`if __name__ == "__main__":`** blocks
3. **Framework entry points**: Flask routes (`@app.route`), Django views, pytest tests
4. **Callbacks**: Functions passed to libraries (e.g., `map(f, ...)`, event handlers)

**Analysis must**:
1. Identify all entry points
2. Compute call graph reachability from entry points
3. Analyze all reachable functions (not just module-level code)

### 9.5.8 Handling Recursion and Mutual Recursion

Recursive functions require fixpoint computation.

**Definition 9.5.8 (Recursive Summary).** For a strongly connected component $C = \{f_1, \ldots, f_k\}$ in the call graph:

Initialize: $\Sigma_i^{(0)} = \bot$ (no taint flows through)

Iterate:
$$\Sigma_i^{(n+1)} = F_i(\Sigma_1^{(n)}, \ldots, \Sigma_k^{(n)})$$

where $F_i$ is the transfer function for $f_i$ using current summaries for other functions in $C$.

Terminate when: $\Sigma^{(n+1)} = \Sigma^{(n)}$ (fixpoint reached)

**Theorem 9.5.2 (Fixpoint Existence).** On the taint lattice $\mathcal{L}$, the summary lattice $\mathcal{L}^n \to \mathcal{L}$ is finite-height, so Kleene iteration terminates.

### 9.5.9 Context Sensitivity

For precision, summaries can be **context-sensitive**: different calling contexts get different summaries.

**Definition 9.5.9 (k-CFA Context).** A context $\gamma$ is the sequence of the last $k$ call sites:
$$\gamma = (\pi_{c_1}, \ldots, \pi_{c_k})$$

Context-sensitive summaries: $\Sigma_f^\gamma$ indexed by context.

**Tradeoff**: More precision but exponential blowup. For taint analysis, **1-CFA** (one level of call-site sensitivity) often suffices.

### 9.5.10 Taint Lattice Integration with Interprocedural Analysis

The product taint lattice $\mathcal{L} = \mathcal{P}(\mathcal{T}) \times \mathcal{P}(\mathcal{K}) \times \mathcal{P}(\mathcal{T})$ integrates with interprocedural analysis as follows:

**At call sites** (applying summary $\Sigma_g$):
$$\ell_{ret} = \Sigma_g(\ell_{arg_1}, \ldots, \ell_{arg_n})$$

**For unknown functions** (havoc with footprint):
$$\ell_{ret} = (\bigcup_i \tau_i, \bigcap_i \kappa_i, \bigcup_i \sigma_i)$$

**For sources/sinks/sanitizers** (contract application):
- Source $f$: $\ell_{ret} = (2^{source\_type}, 0, 0)$ or $(0, 0, 2^{source\_type})$ for sensitive
- Sanitizer $f$: $\ell_{ret} = (\tau_{in}, \kappa_{in} \cup sinks\_protected, \sigma_{in})$
- Sink $f$: Check $\neg Safe_k(\ell_{arg})$ for violation

### 9.5.11 Implementation Architecture

The interprocedural analysis infrastructure consists of:

1. **Call Graph Builder** (`pyfromscratch/cfg/call_graph.py`):
   - Parse all Python files in project
   - Extract function definitions and call sites
   - Build edges with callee resolution
   - Handle dynamic dispatch conservatively

2. **Module Resolver** (`pyfromscratch/frontend/module_resolver.py`):
   - Resolve import statements
   - Track name bindings across modules
   - Handle relative imports and packages

3. **Summary Computer** (`pyfromscratch/semantics/summaries.py`):
   - Bottom-up SCC traversal
   - Fixpoint iteration for recursive SCCs
   - Cache and reuse summaries

4. **Interprocedural Taint Tracker** (`pyfromscratch/semantics/interprocedural_taint.py`):
   - Extend `LatticeSecurityTracker` with summaries
   - Apply summaries at call sites
   - Propagate taint across function boundaries

5. **Entry Point Detector** (`pyfromscratch/frontend/entry_points.py`):
   - Identify all program entry points
   - Framework-specific patterns (Flask, Django, pytest)
   - Compute reachable functions

### 9.5.12 Comparison with CodeQL's Approach

CodeQL performs **interprocedural dataflow analysis** with:
- Static call graph construction
- Context-sensitive taint tracking
- "Additional taint steps" for framework-specific patterns

Our approach differs in:
1. **Barrier certificates**: We can prove SAFE, not just find bugs
2. **Z3 integration**: Symbolic constraints on taint, not just boolean propagation
3. **Summary-based**: Compositional reasoning for scalability
4. **DSE validation**: Concrete witness generation for bugs

**Alignment goal**: Detect the same 47 bug types that CodeQL finds, but with:
- Formal SAFE proofs when bugs are absent
- Counterexample traces with symbolic/concrete values
- Sound over-approximation guarantees


## 10. Bug-by-bug: Python Bug Classes as Barrier Certificates (First Detailed Pass)

This section mirrors the Rust “bug-by-bug” treatment, but the Python version has two distinctive emphases:

1. **Type + exception structure is first-class.** Many “bugs” are reachable unhandled exceptions.
2. **Unknown code is the norm.** Library calls must be modeled relationally and refined via DSE/CEGAR.

In each bug class below we specify:

- `Safe_X`: the semantic safety property.
- An unsafe region `U_X ⊆ S`.
- Guard variables and guard propagation patterns.
- A barrier template shape that separates `Reach` from `U_X`.

### 10.1 ASSERT_FAIL: reachable failing assert that is uncaught

**Safety property.**

```
Safe_assert := no reachable uncaught AssertionError caused by assert
```

**Unsafe region.** At the lowered raise site (or the bytecode region implementing `assert`):

```
U_assert := { (x,π,g) | π == π_assert_fail ∧ __debug__ ∧ exc == AssertionError ∧ g_catch(AssertionError)=0 }
```

**Guard propagation.**

- `g_catch(AssertionError)` becomes `1` in regions covered by an `except AssertionError` handler (intraprocedurally), and becomes `1` after calls whose summaries guarantee they catch it (interprocedurally).

**Barrier template (interface-level).**

Introduce a site-indicator `δ_assert(π)` which is `1` iff `π == π_assert_fail` (or a polynomial surrogate like `-(π-π0)^2` in a one-hot encoding).

One conceptual barrier shape is:

```
B_assert = (1 - δ_assert(π)) · M  +  δ_assert(π) · (g_catch(AssertionError) - 1/2)
```

so that at the assert-fail site:

- if caught, `g_catch=1` ⇒ `B_assert ≥ 0`
- if uncaught, `g_catch=0` ⇒ `B_assert < 0`

The inductiveness condition reduces to: “if `B_assert ≥ 0` now, then after any step (including exceptional steps), `B_assert ≥ 0`”. Proving that relies on correctness of the `g_catch` propagation and the CFG/handler edges.

### 10.2 PANIC / UNHANDLED_EXCEPTION: uncaught exception as the general crash property

Python has no “panic” primitive, but it does have uncaught exceptions. Many real systems treat any uncaught exception as a crash. So:

**Unsafe region.**

```
U_uncaught := { s | exc ≠ None ∧ ExceptionWillPropagateOut(s) }
```

This subsumes `ASSERT_FAIL` as a special case.

**Barriers.**

You can either:

- Prove *no uncaught exception* (very strong), or
- Prove *no uncaught exception of certain classes* (e.g., `ZeroDivisionError`, `TypeError`, `AssertionError`) while allowing others.

This is naturally parameterized by an allowed set `AllowedExc`.

### 10.3 TYPE_CONFUSION / TYPECHECKING FAILURE: type precondition violation as reachability

Python is dynamically typed, so “typechecking bugs” show up as:

- a reachable `TypeError`/`AttributeError`/`ValueError` that is uncaught, or
- a violation of an *intended protocol* (e.g., treating a non-iterable as iterable) even if caught later (bug depends on spec)

We define a **typechecking bug class** as a reachability property against a type precondition.

#### 10.3.1 Example: numeric addition expects ints

Suppose we claim: at program point `π_add`, variables `x` and `y` are always `int`.

**Unsafe region.**

Let `θ_x_int` be the indicator that `x` is an int at `π_add`. Then:

```
U_type_add := { s | π == π_add ∧ (θ_x_int·θ_y_int == 0) }
```

This is a purely “type tag” unsafe region.

**Guards.**

Introduce `g_type(x,int)` and `g_type(y,int)` from earlier checks. Then a path-sensitive barrier uses guards:

```
B_type_add =
  (1-δ_add(π))·M
  + δ_add(π)·(g_type(x,int)·g_type(y,int) - 1/2)
```

This encodes “if we’re at the add site, we must have proven the types”.

#### 10.3.2 Runtime `TypeError` as the exception-flavored version

Alternatively, define the unsafe region as “this operation raises `TypeError` and it is uncaught”:

```
U_typeerror_uncaught := { s | exc == TypeError ∧ ExceptionWillPropagateOut(s) }
```

This is weaker (it allows type mismatch if it doesn’t raise) but aligns with real crash behavior.

### 10.4 NULL_DEREF: `None` misuse as a guard+type property

Python’s “null dereference” is usually `AttributeError: 'NoneType' object has no attribute ...` or `TypeError: 'NoneType' object is not callable`, etc.

At an attribute access site `π_attr`, define:

```
U_none_attr := { s | π == π_attr ∧ ν_recv == 0 }
```

where `ν_recv=1` iff receiver is not None.

The path-sensitive barrier uses `g_nonnull(recv)` computed from `if recv is not None:` checks, `assert recv is not None`, or successful pattern matches / exception logic.

### 10.5 DIV_ZERO: ZeroDivisionError as a numeric + exception property

At a division site, the unsafe event is raising `ZeroDivisionError` (for numeric types that behave that way). A minimal unsafe region is:

```
U_div0 := { s | π == π_div ∧ d == 0 ∧ (g_div(d) == 0) }
```

If you instead define the bug as “uncaught ZeroDivisionError”, combine with `g_catch(ZeroDivisionError)` similarly to `ASSERT_FAIL`.

### 10.6 FP_DOMAIN: domain restrictions and Python’s split semantics

Python’s numeric domain story is subtle:

- `(-1.0)**0.5` produces a complex number (no exception) due to complex promotion.
- `math.sqrt(-1.0)` raises `ValueError` because the `math` module stays in reals.

So FP domain bugs are often **library-call domain** bugs, not core-language bugs.

We model a domain-restricted primitive as having a precondition `Dom_f(x)` and an exceptional outcome if violated.

At a call site `π_call`:

```
U_fpdom := { s | π == π_call ∧ call_target == f ∧ ¬Dom_f(arg) ∧ g_dom(f,arg)==0 }
```

Here `g_dom` is a guard bit set by earlier checks (e.g., `if x >= 0:` before `math.sqrt(x)`).

Unknown-library-call handling (§4) is central here: if `f` is unknown, we treat `Dom_f` as part of the contract and refine it with DSE.

### 10.7 ARRAY_OOB: IndexError / KeyError / StopIteration as boundedness properties

Python’s “out of bounds” is exception-based:

- `seq[i]` may raise `IndexError`
- `d[k]` may raise `KeyError`
- `next(it)` may raise `StopIteration`

Whether these are “bugs” depends on spec:

- In many systems, an uncaught `IndexError` is a crash.
- In iterator protocol, `StopIteration` is expected inside loops but a bug if it escapes certain contexts.

We treat the generic pattern as:

```
U_oob := { s | π == π_subscr ∧ (i < 0 ∨ i ≥ len(seq)) ∧ g_bounds(seq,i)==0 }
```

and optionally conjoin “uncaught exception”.

### 10.8 RESOURCE_LEAK: with-protocol and typestate barriers

Resource leaks in Python are naturally modeled as a typestate automaton:

```
Init → Acquired → Released
```

An unsafe region might be “function exit with state == Acquired”.

Let `π_exit` denote return/exit points, and `state_r` the resource state:

```
U_leak := { s | π ∈ ExitPoints ∧ state_r == Acquired }
```

Guard bits like `g_ctx(r)` represent being within a `with`-protected region. A barrier can encode that either:

- `with` ensures `Released` on all paths (strong), or
- in a hybrid setting, `with` sets `g_ctx` and the barrier enforces that `state_r` cannot be `Acquired` at exit unless `g_ctx` is false (and then penalize).

### 10.9 STACK_OVERFLOW: recursion depth as a barrier/ranking property

Python has a recursion limit and raises `RecursionError` rather than consuming the process stack in pure Python. But from a “crash property” viewpoint, `RecursionError` is like stack overflow.

Let `d` be the call stack depth. Unsafe region:

```
U_stack := { s | d > D_max }
```

A simple barrier is:

```
B_stack = D_max - d
```

If you treat `RecursionError` propagation as the failure mode, combine with `g_catch(RecursionError)`.

### 10.10 NON_TERMINATION: ranking functions in a Python CFG

Non-termination is a liveness property, but the standard barrier/ranking technique applies:

- Identify loops.
- Synthesize a ranking function `ρ` that decreases on each loop iteration and is bounded below.

At bytecode level, the loop head is a set of PCs. If you can produce:

```
ρ(x') ≤ ρ(x) - ε    whenever control goes around the loop
```

then termination follows (modulo fairness in nondeterministic choices).

### 10.11 Native-boundary bugs: overflow, UAF, double-free, uninitialized memory, buffer overflow

Several of the Rust bug classes live naturally at the Python↔native boundary:

- C extensions and `ctypes` can overflow fixed-width integers.
- Buffers can be mis-sized.
- Lifetimes can be violated (UAF/double-free).
- Uninitialized native memory can be exposed.

The Python barrier story here is:

1. Treat the native boundary as an unknown call/relation.
2. Expose explicit interface variables for sizes, lifetimes, and initialization flags.
3. Prove that the interface never enters an unsafe region.

Example: buffer write with `n` bytes to capacity `ℓ`:

```
U_buf = { s | π == π_write ∧ n > ℓ ∧ g_bounds(buf,n)==0 }
```

Example: use-after-free:

```
U_uaf = { s | π == π_use(h) ∧ alive(h) == 0 }
```

Here `alive(h)` is an interface predicate updated by allocation/free operations (in Python, these updates occur inside the native code relation).

### 10.12 Concurrency: race and deadlock as reachability in a multi-thread PTS

If we include threads, the state includes per-thread frames and a scheduler step.

- **Data race:** reachable state where two threads access same location concurrently without a protecting lockset.
- **Deadlock:** reachable state where all threads are blocked and the wait-for graph has a cycle.

Barrier certificates can still apply, but the state space is larger:

```
S = (x_1,…,x_T, Locks, Scheduler, ...)
```

and transitions interleave thread steps. Guard bits track locksets and ownership.

### 10.13 CAST_OVERFLOW: narrowing conversions and fixed-width boundaries

Python itself has unbounded integers, so “cast overflow” is typically a *boundary* phenomenon: converting an unbounded `int` into a fixed-width representation (bytes, structs, array elements, C integers).

Common sites:

- `int.to_bytes(length=k, ...)` (raises `OverflowError` if out of range)
- `struct.pack(fmt, x)` where `fmt` specifies a bounded integer (raises `struct.error` on range violation)
- `array('B').append(x)`-style element range checks (implementation-dependent but conceptually bounded)
- `ctypes` or C extension argument marshalling (may wrap, saturate, or error depending on API)

#### 10.13.1 Generic model

Treat a cast as a partial function with a numeric precondition:

```
cast_{[L,U]} : ℤ ⇀ ℤ
defined iff  L ≤ x ≤ U
```

Unsafe region at a cast site `π_cast`:

```
U_cast := { s | π == π_cast ∧ (x < L ∨ x > U) ∧ g_cast(x,[L,U])==0 }
```

where `g_cast` is a guard bit set by earlier range checks, or by proofs about `x`.

#### 10.13.2 Barrier template (polynomial range barrier)

Reuse the classic range polynomial:

```
P_range(x) = (x - L) · (U - x)
```

Then a path-sensitive barrier term is:

```
B_cast = (1-δ_cast(π))·M  +  δ_cast(π)·(g_cast · P_range(x) + (1-g_cast)·M')
```

At the cast site, if the guard is set, `P_range(x) ≥ 0` implies safety; if the guard is not set, we penalize reaching the cast without proof of range.

This mirrors the Rust `Cast Overflow` section but becomes practically important in Python because it is the main way fixed-width overflow enters Python programs.

### 10.14 INTEGER_OVERFLOW / INTEGER_UNDERFLOW: when “unbounded int” meets bitwidth

Pure Python integer arithmetic does not overflow. But “integer overflow” is still a meaningful bug class in Python when the *semantic intent* is fixed-width arithmetic or when values are stored into fixed-width containers/FFI.

Two faithful modeling options:

1. **Bitvector semantics at the boundary** (exact for fixed-width): represent the casted value as a Z3 bitvector `(_ BitVec w)` and encode the conversion semantics precisely (wrap, saturate, or error).
2. **Range-precondition semantics** (portable safety): represent the boundary op as requiring `L ≤ x ≤ U` and treat violation as unsafe (exception/crash/UB depending on target).

For barrier certificates, (2) gives a polynomial surface; (1) gives exact bit-precise checking with SMT.

Unsafe region mirrors §10.13, split into two classes:

```
U_overflow  := { s | π == π_bound ∧ x > U ∧ g_range==0 }
U_underflow := { s | π == π_bound ∧ x < L ∧ g_range==0 }
```

You can either:

- prove both are unreachable (full range safety), or
- prove the boundary code *handles* them (they raise and are caught), which reduces to `PANIC/UNHANDLED_EXCEPTION` patterns.

### 10.15 MEMORY_LEAK: unbounded growth as a quantitative safety property

Memory leaks in Python are usually not “forgot to free” (the GC frees unreachable objects), but **unbounded retention**:

- global caches without eviction
- reference cycles involving finalizers (`__del__`) that are not collected
- data structure growth due to logic bugs
- native leaks in extensions

To make this barrier-friendly, we choose a *memory measure* `μ(s)` on states.

Examples (interface-level):

- `μ = HeapSize` (number of heap objects)
- `μ = BytesAllocated` (if tracked)
- `μ = LiveExternalHandles` (files, sockets, native buffers)

Then there are two common verification styles:

#### 10.15.1 Bounded-memory safety (invariant style)

Fix a budget `B`. Safety property:

```
Safe_mem(B) := ∀ reachable s. μ(s) ≤ B
```

Unsafe region:

```
U_mem := { s | μ(s) > B }
```

Barrier:

```
B_mem(s) = B - μ(s)
```

Inductiveness requires showing `μ(s') ≤ μ(s) + Δ` for each step, and that the program’s structure prevents cumulative drift past `B` (often via loop invariants).

#### 10.15.2 Leak-as-nontermination in the complement (cycle growth)

If the program has a reachable cycle that strictly increases `μ`, then there exists an execution with unbounded growth. This is “non-termination” of the measure:

```
μ(s_{t+T}) ≥ μ(s_t) + 1   on a cycle
```

Detecting this is dual to ranking functions: instead of finding a decreasing `ρ`, we find an increasing witness. For proving absence, we aim to synthesize an invariant that bounds `μ`.

### 10.16 INFO_LEAK: noninterference via product programs or taint barriers

Information-flow security is naturally a **two-run** property. Let inputs be split into secret `S` and public `P`, and let observables (sinks) be `Obs(s)`.

Noninterference says:

```
P same, S different  ⇒  Obs same
```

#### 10.16.1 Product-program semantics (exact but heavier)

Construct a *paired* transition system over `S×S`:

```
ŝ = (s, s~)
```

with synchronized steps (or stuttering) and shared public inputs. Unsafe region:

```
U_leak := { (s,s~) | PubInputsEqual(s,s~) ∧ Obs(s) ≠ Obs(s~) }
```

Then an ordinary (one-run) barrier over paired states can prove noninterference by showing `Reach ∩ U_leak = ∅`.

Z3 is the natural engine for finding counterexample pairs (it’s a relational reachability query). Barriers become the way to close loops and avoid bounded unrolling in the paired system.

#### 10.16.2 Taint-style barrier (efficient and compositional)

Introduce a taint bit `τ(v) ∈ {0,1}` indicating whether a value may depend on secrets. Propagate taint through operations:

- `τ(z) := τ(x) ∨ τ(y)` for `z = op(x,y)`
- `τ(Attr(x,name)) := τ(x)` (plus optional dependence on `name`)
- `τ(call f(x))` depends on a contract for `f`

Unsafe region at a sink (print, log, network write) `π_sink`:

```
U_taint := { s | π == π_sink ∧ τ(v_sink) = 1 }
```

Barrier:

```
B_taint = 1 - τ(v_sink)
```

This is “barrier certificates over a discrete semiring” in spirit; the inductiveness check is a dataflow proof.

### 10.17 TIMING_CHANNEL: cost semantics + secret sensitivity

Timing channels are also two-run properties, but the observable is time (or a proxy like step count).

Define a cost model:

- `T(s)` is accumulated cost so far.
- Each step updates `T' = T + cost(instr, state)`.

Unsafe region in paired semantics:

```
U_time := { (s,s~) | PubInputsEqual ∧ T(s) ≠ T(s~) }
```

You can attack this two ways:

1. **Product-program + Z3** to find a violating pair (bounded or with loop summarization).
2. **Guarded constant-time barrier**: introduce a guard `g_const` meaning “this region is constant time w.r.t. secrets”, then enforce that any secret-dependent branch resets `g_const=0`. At a “timing-sensitive boundary” (cryptographic op), require `g_const=1`.

Interface-level barrier sketch:

```
B_time = (1-δ_boundary(π))·M  +  δ_boundary(π)·(g_const - 1/2)
```

This mirrors the Rust timing-channel template, but Python’s timing model is noisier (VM dispatch, allocator effects, GC, OS scheduling). The “exact model” story therefore requires explicitly stating what timing observable we mean (instruction count? wall clock? syscall trace?) and what nondeterminism is allowed.

### 10.18 ITERATOR_INVALID: versioned containers and mutation-during-iteration

Rust has “iterator invalidation” as a bug class in unsafe/FFI contexts (or via interior mutability). Python has its own analogue: **mutation during iteration** and **iterator/state mismatch**.

There are two broad phenomena:

1. **Safe detection**: Python raises a `RuntimeError` in some cases (notably dict/set “changed size during iteration”).
2. **Silent semantic drift**: list iteration while mutating can skip or repeat elements without raising.

Whether this is a “bug class” depends on the program spec. To mirror Rust’s iterator-invalidation style, we define the bug as “an iterator observes a container in a different structural version than the one it was created for” (even if Python doesn’t always throw).

#### 10.18.1 Interface state: container version counters

For each tracked container `c`, introduce:

- `ver_c ∈ ℤ` a monotonically increasing “structural modification count”.

For each iterator `it` produced from `c`, introduce:

- `src_it` an identity link to its source container
- `ver_it ∈ ℤ` the captured version at iterator creation

Update rules (schematic):

- On iterator creation `it = iter(c)`:
  - `src_it := c`
  - `ver_it := ver_c`
- On structural mutation of `c` (insert/delete/resize):
  - `ver_c := ver_c + 1`

#### 10.18.2 Unsafe region

At a `next(it)` site `π_next` where `it` is an iterator over `c=src_it`:

```
U_iter :=
  { s | π == π_next ∧ (ver_it ≠ ver_c) ∧ g_iter_ok(it)==0 }
```

Here `g_iter_ok` is a guard bit that can be set by a proof/analysis that no structural mutations of `c` occur along the path between iterator creation and the `next` call.

#### 10.18.3 Barrier template

A direct “difference” penalty works:

```
B_iter = (1-δ_next(π))·M  +  δ_next(π)·(g_iter_ok - 1/2)  -  λ·(ver_it - ver_c)^2
```

Interpretation:

- If the program proves the container is not mutated (`g_iter_ok=1`), the barrier is positive at `next`.
- If not, and versions diverge, the negative quadratic term drives `B_iter` below 0.

This is a clean example of “Python bugs that are not exceptions by default”: we can define the unsafe region as a semantic mismatch rather than a thrown error.

### 10.19 UNINIT_MEMORY: initialization predicates at buffer boundaries

Pure Python does not expose uninitialized memory, but Python programs cross into:

- C extensions
- `ctypes`
- buffer protocol / `memoryview`

where uninitialized reads can occur.

#### 10.19.1 Interface state: initializedness flags

For each tracked buffer `b`, introduce an initializedness predicate. Two common granularities:

1. **Coarse:** `ι_b ∈ {0,1}` meaning “entire buffer initialized”.
2. **Segmented:** `ι_{b,j} ∈ {0,1}` per block/field/byte-range (more precise, more expensive).

We also track:

- `len_b ∈ ℤ, len_b ≥ 0`

#### 10.19.2 Unsafe region

At a read site `π_read` of `n` bytes from offset `off`:

```
U_uninit :=
  { s | π == π_read ∧ (ι_b(off, n) == 0) }
```

If you model Python-level behavior, the manifestation might be “reads arbitrary data” rather than a thrown exception. If you model crash properties, you can treat `U_uninit` as unsafe directly.

#### 10.19.3 Barrier template (coarse)

With coarse `ι_b`:

```
B_uninit = (1-δ_read(π))·M  +  δ_read(π)·(ι_b - 1/2)
```

This is structurally identical to `ASSERT_FAIL`’s “guard at a site” pattern, but the guard is an initialization predicate rather than a catch predicate.

### 10.20 BUFFER_OVERFLOW: capacity constraints as range barriers (native boundary)

Buffer overflow is primarily a native-boundary bug for Python, but it is still barrier-shaped: you are proving a length/index precondition at a site.

#### 10.20.1 Interface variables

At a write site:

- `n ∈ ℤ, n ≥ 0` bytes to write
- `cap ∈ ℤ, cap ≥ 0` buffer capacity
- `off ∈ ℤ, off ≥ 0` offset

Safe condition:

```
0 ≤ off ∧ 0 ≤ n ∧ off + n ≤ cap
```

Unsafe region at `π_write`:

```
U_buf :=
  { s | π == π_write ∧ (off + n > cap) ∧ g_bounds(buf,off,n)==0 }
```

#### 10.20.2 Barrier template

Use the simple linear slack:

```
slack = cap - (off + n)
```

and:

```
B_buf = (1-δ_write(π))·M  +  δ_write(π)·(g_bounds·slack + (1-g_bounds)·M')
```

If `g_bounds=1`, then `slack ≥ 0` implies safety.

### 10.21 USE_AFTER_FREE / DOUBLE_FREE: lifetime tags at the Python↔native boundary

Use-after-free and double-free are again boundary bugs, but their semantics can be expressed in the same typestate/guard language as resources and iterators.

#### 10.21.1 Interface: allocation status and aliasing

For each tracked native handle/object `h`:

- `alive_h ∈ {0,1}` (1 allocated, 0 freed)
- optionally `rc_h ∈ ℤ` if reference-counted externally

Operations update `alive_h`:

- `alloc(h)` sets `alive_h := 1`
- `free(h)` sets `alive_h := 0`

#### 10.21.2 Unsafe regions

Use-after-free at a use site `π_use`:

```
U_uaf := { s | π == π_use ∧ alive_h == 0 }
```

Double-free at a free site `π_free`:

```
U_df := { s | π == π_free ∧ alive_h == 0 }
```

These are extremely “barrier-friendly”: they are discrete predicates at a site.

#### 10.21.3 Barrier templates

At use site:

```
B_uaf = (1-δ_use(π))·M  +  δ_use(π)·(alive_h - 1/2)
```

At free site:

```
B_df = (1-δ_free(π))·M  +  δ_free(π)·(alive_h - 1/2)
```

These look identical, because the unsafe condition is “alive is false at the critical site”.

The difference is in how `alive_h` is updated: in Python, these updates occur inside unknown/native code relations. Contract refinement (§4/§9.8) is essential: you must specify whether a library function may free a handle, may return aliases, etc.

### 10.22 DATA_RACE: locksets, the GIL, and “logical races”

Python threads complicate “data race” because:

- the GIL serializes bytecode execution in CPython (reducing low-level memory races in pure Python)
- but races still exist at the level of program logic (non-atomic read-modify-write sequences)
- and C extensions can release the GIL, reintroducing true concurrent memory access

To keep the taxonomy compatible with the Rust story, we define `DATA_RACE` at the interface level as “two threads access a shared location with at least one write, without a protecting lockset, in overlapping time”.

#### 10.22.1 Interface: shared locations and locksets

Introduce:

- `Loc` a set (or finite abstraction) of shared locations
- for each thread `t`:
  - `LockSet_t ⊆ Locks` (locks currently held)
  - `Access_t ∈ {None, Read(ℓ), Write(ℓ)}` current access event (abstract)
  - `Time_t ∈ ℤ` a logical timestamp / step count

#### 10.22.2 Unsafe region

Let `Overlaps(Time_t1, Time_t2)` be true when accesses are concurrent in the model (for cooperative scheduling, this may be a window; for preemptive, it can be “interleavings exist”).

Unsafe condition:

```
U_race :=
  { s | ∃ t1≠t2, ℓ.
        Access_t1 is Write(ℓ) ∧ Access_t2 is (Read(ℓ) or Write(ℓ))
        ∧ Overlaps(Time_t1, Time_t2)
        ∧ (LockSet_t1 ∩ LockSet_t2 == ∅) }
```

This is structurally identical to lockset-based race detection in other settings, but the “Overlaps” notion depends on whether you model GIL release points as enabling true concurrency.

#### 10.22.3 Barrier shape

Race-freedom is often proved by an invariant that a shared location is always accessed under a particular lock. This becomes a guard:

- `g_lock(ℓ, L)` meaning “location ℓ is protected by lock L”.

Then at each access site, enforce `L ∈ LockSet_t`. This is a guard-at-site barrier like earlier:

```
B_race =
  Σ_{access sites} δ_site(π) · ( [L ∈ LockSet_t] - 1/2 )  +  (1-δ_site)·M
```

The discrete membership `[L ∈ LockSet_t]` is handled by SMT; the barrier is “mostly boolean”, which is fine—the barrier framework is about inductive exclusion of unsafe regions, not only about reals.

### 10.23 DEADLOCK: wait-for cycles as reachability

Deadlock is also a reachability property:

- some state where threads are blocked and the wait-for graph contains a cycle.

#### 10.23.1 Interface: wait-for graph

Track:

- `H_t ⊆ Locks`: locks held by thread `t`
- `W_t ∈ Locks ∪ {None}`: lock thread `t` is currently waiting for (if blocked)

Define a directed edge `t → t'` if `W_t ∈ H_{t'}`. Deadlock exists if this graph has a cycle and all threads in the cycle are blocked.

#### 10.23.2 Unsafe region

```
U_deadlock := { s | WaitForGraphHasCycle(s) }
```

#### 10.23.3 Barrier idea

Deadlock-freedom can be proved by a global lock ordering:

- a strict partial order `≺` on locks,
- invariant: each thread acquires locks in increasing order.

Encode the invariant with a per-thread “max lock rank held”:

- `rank(L) ∈ ℤ`
- `maxrank_t ∈ ℤ`

Update:

- on acquiring `L`: require `rank(L) > maxrank_t`, then set `maxrank_t := rank(L)`

Unsafe region corresponds to acquiring out of order (or requesting out of order). A barrier is:

```
B_deadlock = Σ_t (maxrank_t - next_rank_t)
```

where `next_rank_t` is the rank of the lock requested. If all requests respect ordering, the barrier remains nonnegative; any out-of-order request drives it negative and witnesses a potential deadlock cycle.

This mirrors classic deadlock prevention: lock ordering is the barrier certificate.

---

## 11. Security Bug Classes: Complete CodeQL Coverage with Barrier-Theoretic Definitions

The previous sections covered "crash bugs" (assertion failures, exceptions, resource errors) and memory/concurrency bugs. Modern static analysis (e.g., CodeQL, Semgrep, Pyright+security rules) also targets **security vulnerabilities**—bugs where untrusted input reaches a sensitive sink.

This section provides **barrier-theoretic definitions for every security bug class in CodeQL's Python security queries** (47 total queries across 28 CWE categories). Each bug is expressed using taint bits, unsafe regions, and barrier templates.

### 11.0 Complete CodeQL Python Security Query List

The following is the complete list of security queries from CodeQL's `codeql/python-queries` package (v1.2.1):

| Query File | CWE | Query ID | Description |
|------------|-----|----------|-------------|
| SqlInjection.ql | CWE-089 | py/sql-injection | SQL query built from user-controlled sources |
| CommandInjection.ql | CWE-078 | py/command-line-injection | Uncontrolled command line |
| UnsafeShellCommandConstruction.ql | CWE-078 | py/shell-command-constructed-from-input | Shell command from library input |
| CodeInjection.ql | CWE-094 | py/code-injection | eval/exec of user input |
| PathInjection.ql | CWE-022 | py/path-injection | Uncontrolled data in path expression |
| TarSlip.ql | CWE-022 | py/tarslip | Arbitrary file write during tarfile extraction |
| ReflectedXss.ql | CWE-079 | py/reflective-xss | Reflected cross-site scripting |
| Jinja2WithoutEscaping.ql | CWE-079 | py/jinja2/autoescape-false | Jinja2 with autoescape=False |
| HeaderInjection.ql | CWE-113 | py/http-response-splitting | HTTP response splitting |
| FullServerSideRequestForgery.ql | CWE-918 | py/full-ssrf | Full SSRF |
| PartialServerSideRequestForgery.ql | CWE-918 | py/partial-ssrf | Partial SSRF |
| UnsafeDeserialization.ql | CWE-502 | py/unsafe-deserialization | Deserialization of user-controlled data |
| Xxe.ql | CWE-611 | py/xxe | XML external entity expansion |
| XmlBomb.ql | CWE-776 | py/xml-bomb | XML internal entity expansion (billion laughs) |
| LdapInjection.ql | CWE-090 | py/ldap-injection | LDAP query injection |
| XpathInjection.ql | CWE-643 | py/xpath-injection | XPath query injection |
| NoSqlInjection.ql | CWE-943 | py/nosql-injection | NoSQL injection |
| RegexInjection.ql | CWE-730 | py/regex-injection | Regex injection |
| ReDoS.ql | CWE-730 | py/redos | Inefficient regex (exponential backtracking) |
| PolynomialReDoS.ql | CWE-730 | py/polynomial-redos | Polynomial ReDoS on untrusted data |
| UrlRedirect.ql | CWE-601 | py/url-redirection | URL redirection from remote source |
| CleartextStorage.ql | CWE-312 | py/clear-text-storage-sensitive-data | Cleartext storage of sensitive data |
| CleartextLogging.ql | CWE-312 | py/clear-text-logging-sensitive-data | Cleartext logging of sensitive data |
| HardcodedCredentials.ql | CWE-798 | py/hardcoded-credentials | Hard-coded credentials |
| WeakCryptoKey.ql | CWE-326 | py/weak-crypto-key | Weak cryptographic key |
| BrokenCryptoAlgorithm.ql | CWE-327 | py/weak-cryptographic-algorithm | Broken/weak crypto algorithm |
| WeakSensitiveDataHashing.ql | CWE-327 | py/weak-sensitive-data-hashing | Weak hashing for sensitive data |
| InsecureProtocol.ql | CWE-327 | py/insecure-protocol | Insecure SSL/TLS version |
| InsecureDefaultProtocol.ql | CWE-327 | py/insecure-default-protocol | Default SSL/TLS may be insecure |
| InsecureCookie.ql | CWE-614 | py/insecure-cookie | Missing Secure/HttpOnly/SameSite |
| CookieInjection.ql | CWE-020 | py/cookie-injection | Cookie from user input |
| CSRFProtectionDisabled.ql | CWE-352 | py/csrf-protection-disabled | CSRF protection disabled |
| FlaskDebug.ql | CWE-215 | py/flask-debug | Flask debug mode in production |
| StackTraceExposure.ql | CWE-209 | py/stack-trace-exposure | Stack trace exposed to user |
| LogInjection.ql | CWE-117 | py/log-injection | Log injection |
| BadTagFilter.ql | CWE-116 | py/bad-tag-filter | Bad HTML filtering regex |
| IncompleteHostnameRegExp.ql | CWE-020 | py/incomplete-hostname-regexp | Incomplete hostname regex |
| IncompleteUrlSubstringSanitization.ql | CWE-020 | py/incomplete-url-substring-sanitization | Incomplete URL sanitization |
| OverlyLargeRange.ql | CWE-020 | py/overly-large-range | Overly permissive regex range |
| InsecureTemporaryFile.ql | CWE-377 | py/insecure-temporary-file | Insecure temp file creation |
| WeakFilePermissions.ql | CWE-732 | py/overly-permissive-file | Overly permissive file permissions |
| BindToAllInterfaces.ql | CVE-2018-1281 | py/bind-socket-all-network-interfaces | Binding socket to all interfaces |
| MissingHostKeyValidation.ql | CWE-295 | py/paramiko-missing-host-key-validation | SSH host key not validated |
| RequestWithoutValidation.ql | CWE-295 | py/request-without-cert-validation | Request without certificate validation |
| PamAuthorization.ql | CWE-285 | py/pam-auth-bypass | PAM authorization bypass |
| UntrustedDataToExternalAPI.ql | CWE-020 | py/untrusted-data-to-external-api | Untrusted data to external API |
| ExternalAPIsUsedWithUntrustedData.ql | CWE-020 | py/count-untrusted-data-external-api | Frequency of untrusted data to APIs |

### 11.1 Taint Analysis as Barrier Certificates: The General Framework

Security bugs share a common pattern:

1. **Sources**: program points where untrusted data enters (HTTP parameters, user input, environment variables, file contents, etc.)
2. **Sinks**: program points where data flows to a sensitive operation (SQL query, shell command, file path, HTML output, etc.)
3. **Sanitizers**: operations that "clean" data, removing the taint (escaping, validation, type conversion)

#### 11.1.1 Interface state: taint bits

For each tracked value `v`, introduce taint bits:

```
τ(v) ∈ {0, 1}   (0 = trusted, 1 = tainted/untrusted)
σ(v) ∈ {0, 1}   (0 = not sensitive, 1 = sensitive data like passwords)
```

Taint propagation rules:

- **Source**: at source site `π_src`, any value `v` derived from external input gets `τ(v) := 1`
- **Sensitive source**: password fields, API keys get `σ(v) := 1`
- **Propagation**: for operations `z = op(x, y)`, typically `τ(z) := τ(x) ∨ τ(y)` and `σ(z) := σ(x) ∨ σ(y)`
- **Sanitizer**: at sanitizer site `π_san`, if value `v` passes validation, `τ(v) := 0`

#### 11.1.2 General unsafe region for taint bugs

At a sink site `π_sink` with sink value `v`:

```
U_taint := { s | π == π_sink ∧ τ(v) == 1 ∧ g_sanitized(v) == 0 }
```

#### 11.1.3 Barrier template

```
B_taint = (1 - δ_sink(π)) · M  +  δ_sink(π) · (g_sanitized(v) + (1 - τ(v)) - 1/2)
```

---

### 11.2 SQL_INJECTION (CWE-089): py/sql-injection

**Description**: SQL query built from user-controlled sources allows malicious SQL code execution.

**Sources**: `request.GET[k]`, `request.POST[k]`, `request.args.get(k)`, `input()`, form data, URL parameters.

**Sinks**:
```python
cursor.execute(query)           # sqlite3, psycopg2, mysql-connector
cursor.executemany(query, ...)
Model.objects.raw(query)        # Django
engine.execute(query)           # SQLAlchemy
connection.execute(text(query)) # SQLAlchemy
```

**Sanitizers**: Parameterized queries `cursor.execute("SELECT * FROM t WHERE id=%s", (user_id,))`, ORMs with proper escaping.

**Unsafe region**:
```
U_sqli := { s | π == π_sql_execute ∧ τ(query_string) == 1 ∧ ¬Parameterized(call) }
```

**Barrier**: `B = δ_sql · (Parameterized + (1-τ(query)) - ½)`

---

### 11.3 COMMAND_INJECTION (CWE-078): py/command-line-injection

**Description**: Externally controlled strings in command line allow malicious command execution.

**Sinks**:
```python
os.system(cmd)
subprocess.call(cmd, shell=True)
subprocess.Popen(cmd, shell=True)
subprocess.run(cmd, shell=True)
os.popen(cmd)
```

**Sanitizers**: `shlex.quote()`, using list form `subprocess.call([prog, arg1, arg2])` without `shell=True`.

**Unsafe region**:
```
U_cmdi := { s | π == π_shell ∧ τ(cmd) == 1 ∧ shell_enabled ∧ g_escaped(cmd) == 0 }
```

**Barrier**: `B = δ_shell · (g_escaped + (1-τ) + ¬shell_enabled - ½)`

---

### 11.4 UNSAFE_SHELL_COMMAND_CONSTRUCTION (CWE-078): py/shell-command-constructed-from-input

**Description**: Shell command constructed from library input (not just direct user input).

Same pattern as COMMAND_INJECTION but sources include library inputs.

---

### 11.5 CODE_INJECTION (CWE-094): py/code-injection

**Description**: Interpreting unsanitized user input as code via eval/exec.

**Sinks**:
```python
eval(code_string)
exec(code_string)
compile(code_string, ...)
__import__(module_name)
```

**Unsafe region**:
```
U_code := { s | π == π_eval ∧ τ(code_string) == 1 }
```

**Note**: There is rarely a valid sanitizer for arbitrary code execution—this is critical severity.

**Barrier**: `B = δ_eval · ((1-τ(code)) - ½)`

---

### 11.6 PATH_INJECTION (CWE-022): py/path-injection

**Description**: Accessing paths influenced by users allows access to unexpected files (path traversal).

**Sinks**:
```python
open(filepath, mode)
pathlib.Path(filepath).read_text()
os.remove(filepath)
shutil.copy(src, dst)
send_file(filepath)  # Flask
```

**Sanitizers**:
```python
os.path.basename(user_input)
os.path.realpath(path).startswith(allowed_dir)
werkzeug.utils.secure_filename(filename)
```

**Unsafe region**:
```
U_path := { s | π == π_file_op ∧ τ(filepath) == 1 ∧ g_path_validated(filepath) == 0 }
```

---

### 11.7 TAR_SLIP (CWE-022): py/tarslip

**Description**: Extracting tarfile with malicious member paths can overwrite arbitrary files.

**Sinks**:
```python
tarfile.extractall()
tarfile.extract(member)
```

**Unsafe region**:
```
U_tarslip := { s | π == π_tar_extract ∧ τ(tar_source) == 1 ∧ ¬PathValidated(member) }
```

---

### 11.8 REFLECTED_XSS (CWE-079): py/reflective-xss

**Description**: Writing user input directly to web page allows XSS attacks.

**Sinks**:
```python
HttpResponse(user_input)
return render_template_string(user_input)
response.write(user_input)
```

**Sanitizers**: `django.utils.html.escape()`, `markupsafe.escape()`, template auto-escaping.

**Unsafe region**:
```
U_xss := { s | π == π_html_response ∧ τ(content) == 1 ∧ ¬AutoEscaped(context) ∧ g_escaped(content) == 0 }
```

---

### 11.9 JINJA2_AUTOESCAPE_FALSE (CWE-079): py/jinja2/autoescape-false

**Description**: Using Jinja2 templates with `autoescape=False` enables XSS.

**Unsafe region**:
```
U_jinja := { s | π == π_jinja_env ∧ autoescape == False ∧ τ(template_input) == 1 }
```

---

### 11.10 HEADER_INJECTION (CWE-113): py/http-response-splitting

**Description**: User input in HTTP headers with newlines enables response splitting.

**Sinks**:
```python
response['X-Header'] = user_input
response.headers['Location'] = url
```

**Unsafe region**:
```
U_header := { s | π == π_set_header ∧ τ(header_value) == 1 ∧ ContainsNewline(header_value) }
```

---

### 11.11 FULL_SSRF (CWE-918): py/full-ssrf

**Description**: Full URL controlled by user in server-side request.

**Sinks**:
```python
requests.get(url)
urllib.request.urlopen(url)
httpx.get(url)
```

**Unsafe region**:
```
U_ssrf := { s | π == π_http_request ∧ τ(full_url) == 1 ∧ g_url_validated(url) == 0 }
```

---

### 11.12 PARTIAL_SSRF (CWE-918): py/partial-ssrf

**Description**: Part of URL (path, query) controlled by user in server-side request.

Same structure but lower severity since base URL is fixed.

---

### 11.13 UNSAFE_DESERIALIZATION (CWE-502): py/unsafe-deserialization

**Description**: Deserializing user-controlled data with unsafe deserializers allows RCE.

**Sinks**:
```python
pickle.loads(data)
pickle.load(file)
yaml.load(data)  # Without Loader=SafeLoader
yaml.unsafe_load(data)
marshal.loads(data)
```

**Safe alternatives**: `yaml.safe_load()`, `json.loads()`.

**Unsafe region**:
```
U_deser := { s | π == π_deserialize ∧ τ(data) == 1 ∧ DeserializerIsUnsafe(func) }
```

---

### 11.14 XXE (CWE-611): py/xxe

**Description**: XML parsing with external entity expansion allows reading arbitrary files.

**Sinks**:
```python
xml.etree.ElementTree.parse(file)
lxml.etree.parse(file)
xml.dom.minidom.parse(file)
```

**Sanitizers**: `defusedxml` library, disabling external entities.

**Unsafe region**:
```
U_xxe := { s | π == π_xml_parse ∧ τ(xml_input) == 1 ∧ ExternalEntitiesEnabled(parser) }
```

---

### 11.15 XML_BOMB (CWE-776): py/xml-bomb

**Description**: XML with internal entity expansion (billion laughs attack) causes DoS.

**Unsafe region**:
```
U_xmlbomb := { s | π == π_xml_parse ∧ τ(xml_input) == 1 ∧ EntityExpansionUnlimited(parser) }
```

---

### 11.16 LDAP_INJECTION (CWE-090): py/ldap-injection

**Description**: User input in LDAP filter or DN allows LDAP injection.

**Sinks**:
```python
ldap.search_s(base_dn, scope, filter_str)
ldap3.Connection.search(search_base, search_filter)
```

**Unsafe region**:
```
U_ldap := { s | π == π_ldap_search ∧ (τ(filter) == 1 ∨ τ(dn) == 1) ∧ g_ldap_escaped == 0 }
```

---

### 11.17 XPATH_INJECTION (CWE-643): py/xpath-injection

**Description**: User input in XPath expression allows query manipulation.

**Sinks**:
```python
tree.xpath(xpath_expr)
tree.find(xpath_expr)
lxml.etree.XPath(xpath_expr)
```

**Unsafe region**:
```
U_xpath := { s | π == π_xpath ∧ τ(xpath_expr) == 1 }
```

---

### 11.18 NOSQL_INJECTION (CWE-943): py/nosql-injection

**Description**: User input in NoSQL query operators allows query manipulation.

**Sinks**:
```python
collection.find(query)      # MongoDB/PyMongo
collection.find_one(query)
db.command(query)
```

**Unsafe region**:
```
U_nosql := { s | π == π_nosql ∧ τ(query) == 1 ∧ QueryContainsOperators(query) }
```

---

### 11.19 REGEX_INJECTION (CWE-730): py/regex-injection

**Description**: User input as regex pattern without escaping enables ReDoS.

**Sinks**:
```python
re.match(pattern, string)
re.search(pattern, string)
re.compile(pattern)
```

**Sanitizer**: `re.escape(user_input)`.

**Unsafe region**:
```
U_regex := { s | π == π_regex ∧ τ(pattern) == 1 ∧ g_regex_escaped(pattern) == 0 }
```

---

### 11.20 REDOS (CWE-730): py/redos

**Description**: Regex with exponential backtracking causes DoS (not taint-based—static pattern analysis).

**Unsafe region** (static):
```
U_redos := { s | π == π_regex ∧ HasExponentialBacktracking(pattern) }
```

---

### 11.21 POLYNOMIAL_REDOS (CWE-730): py/polynomial-redos

**Description**: Polynomial-time regex on untrusted input.

**Unsafe region**:
```
U_polyredos := { s | π == π_regex ∧ τ(input_string) == 1 ∧ HasPolynomialBacktracking(pattern) }
```

---

### 11.22 URL_REDIRECT (CWE-601): py/url-redirection

**Description**: Open redirect via user-controlled URL.

**Sinks**:
```python
redirect(url)
HttpResponseRedirect(url)
response.headers['Location'] = url
```

**Sanitizers**: Relative URL only, allowlist check.

**Unsafe region**:
```
U_redirect := { s | π == π_redirect ∧ τ(url) == 1 ∧ IsExternalURL(url) ∧ g_url_validated == 0 }
```

---

### 11.23 CLEARTEXT_STORAGE (CWE-312): py/clear-text-storage-sensitive-data

**Description**: Sensitive data stored without encryption.

**Uses sensitivity taint `σ(v)` instead of untrusted taint `τ(v)`.**

**Sinks**: Database writes, file writes, cache stores.

**Unsafe region**:
```
U_cleartext_store := { s | π == π_store ∧ σ(value) == 1 ∧ ¬Encrypted(value) }
```

---

### 11.24 CLEARTEXT_LOGGING (CWE-312/532): py/clear-text-logging-sensitive-data

**Description**: Sensitive data logged without encryption.

**Sinks**:
```python
logging.info(msg)
logging.debug(msg)
print(msg)
logger.warning(msg)
```

**Unsafe region**:
```
U_cleartext_log := { s | π == π_log ∧ σ(logged_value) == 1 }
```

---

### 11.25 HARDCODED_CREDENTIALS (CWE-798): py/hardcoded-credentials

**Description**: Credentials hard-coded in source code (not taint-based—static pattern).

**Unsafe region** (static):
```
U_hardcoded := { s | π == π_credential_use ∧ IsStringLiteral(credential) ∧ LooksLikeSecret(credential) }
```

---

### 11.26 WEAK_CRYPTO_KEY (CWE-326): py/weak-crypto-key

**Description**: Cryptographic key size below minimum secure size.

**Unsafe region** (static):
```
U_weak_key := { s | π == π_keygen ∧ key_size < MinSecureSize(algorithm) }
```

---

### 11.27 BROKEN_CRYPTO_ALGORITHM (CWE-327): py/weak-cryptographic-algorithm

**Description**: Use of broken/weak encryption algorithms (DES, RC4, etc.).

**Unsafe region** (static):
```
U_weak_algo := { s | π == π_encrypt ∧ algorithm ∈ {DES, RC4, Blowfish_small_key, ECB_mode} }
```

---

### 11.28 WEAK_SENSITIVE_DATA_HASHING (CWE-327): py/weak-sensitive-data-hashing

**Description**: Using MD5/SHA1/SHA256 (non-KDF) for password hashing.

**Sinks**:
```python
hashlib.md5(password)
hashlib.sha1(password)
hashlib.sha256(password)  # Without PBKDF2/bcrypt/scrypt wrapper
```

**Safe alternatives**: `bcrypt`, `argon2`, `scrypt`, `PBKDF2`.

**Unsafe region**:
```
U_weak_hash := { s | π == π_hash ∧ σ(input) == 1 ∧ algorithm ∈ {MD5, SHA1, SHA256_raw} }
```

---

### 11.29 INSECURE_PROTOCOL (CWE-327): py/insecure-protocol

**Description**: Using insecure SSL/TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1).

**Unsafe region** (static):
```
U_insecure_tls := { s | π == π_ssl_context ∧ protocol ∈ {SSLv2, SSLv3, TLSv1, TLSv1_1} }
```

---

### 11.30 INSECURE_DEFAULT_PROTOCOL (CWE-327): py/insecure-default-protocol

**Description**: Using `ssl.wrap_socket()` without specifying protocol.

**Unsafe region** (static):
```
U_default_tls := { s | π == π_wrap_socket ∧ ¬SpecifiedProtocol(call) }
```

---

### 11.31 INSECURE_COOKIE (CWE-614): py/insecure-cookie

**Description**: Cookie without Secure, HttpOnly, or proper SameSite attributes.

**Unsafe region** (static):
```
U_cookie := { s | π == π_set_cookie ∧ (¬SecureFlag ∨ ¬HttpOnlyFlag ∨ SameSite==None) }
```

---

### 11.32 COOKIE_INJECTION (CWE-020): py/cookie-injection

**Description**: Cookie value constructed from user input (cookie poisoning).

**Unsafe region**:
```
U_cookie_inject := { s | π == π_set_cookie ∧ τ(cookie_value) == 1 }
```

---

### 11.33 CSRF_PROTECTION_DISABLED (CWE-352): py/csrf-protection-disabled

**Description**: CSRF protection disabled or weakened.

**Unsafe region** (static):
```
U_csrf := { s | π == π_csrf_setting ∧ csrf_verification == False }
```

---

### 11.34 FLASK_DEBUG (CWE-215): py/flask-debug

**Description**: Flask running with debug=True exposes Werkzeug debugger (RCE).

**Unsafe region** (static):
```
U_flask_debug := { s | π == π_flask_run ∧ debug == True }
```

---

### 11.35 STACK_TRACE_EXPOSURE (CWE-209): py/stack-trace-exposure

**Description**: Stack trace information exposed to external user.

**Sinks**: HTTP responses, error pages, API responses.

**Unsafe region**:
```
U_stacktrace := { s | π == π_response ∧ StackTraceFlowsTo(content) }
```

---

### 11.36 LOG_INJECTION (CWE-117): py/log-injection

**Description**: User input in log entries enables log forging.

**Sinks**:
```python
logging.info(user_input)
logger.warning(f"User: {user_input}")
```

**Unsafe region**:
```
U_log_inject := { s | π == π_log ∧ τ(logged_value) == 1 ∧ ContainsNewline(logged_value) }
```

---

### 11.37 BAD_TAG_FILTER (CWE-116): py/bad-tag-filter

**Description**: HTML tag filtering via regex is error-prone and bypassable.

**Unsafe region** (static regex analysis):
```
U_bad_tag := { s | π == π_regex_replace ∧ LooksLikeHtmlFilter(pattern) ∧ IsBypassable(pattern) }
```

---

### 11.38 INCOMPLETE_HOSTNAME_REGEXP (CWE-020): py/incomplete-hostname-regexp

**Description**: Hostname regex with unescaped dot matches more than intended.

**Unsafe region** (static):
```
U_hostname := { s | π == π_hostname_check ∧ HasUnescapedDot(pattern) }
```

---

### 11.39 INCOMPLETE_URL_SUBSTRING_SANITIZATION (CWE-020): py/incomplete-url-substring-sanitization

**Description**: URL validation via substring matching is bypassable.

**Unsafe region** (static):
```
U_url_substr := { s | π == π_url_check ∧ UsesSubstringMatching(check) }
```

---

### 11.40 OVERLY_LARGE_RANGE (CWE-020): py/overly-large-range

**Description**: Regex character range matches more than intended (e.g., `[A-z]` includes special chars).

**Unsafe region** (static):
```
U_large_range := { s | π == π_regex ∧ HasOverlyLargeRange(pattern) }
```

---

### 11.41 INSECURE_TEMPORARY_FILE (CWE-377): py/insecure-temporary-file

**Description**: Using `tempfile.mktemp()` or `os.tmpnam()` creates race condition.

**Sinks**:
```python
tempfile.mktemp()
os.tmpnam()
os.tempnam()
```

**Safe alternative**: `tempfile.mkstemp()`, `tempfile.NamedTemporaryFile()`.

**Unsafe region** (static):
```
U_temp := { s | π == π_temp_file ∧ func ∈ {mktemp, tmpnam, tempnam} }
```

---

### 11.42 WEAK_FILE_PERMISSIONS (CWE-732): py/overly-permissive-file

**Description**: File created with world-readable or world-writable permissions.

**Unsafe region** (static):
```
U_perms := { s | π == π_chmod ∧ (world_read(mode) ∨ world_write(mode)) }
```

---

### 11.43 BIND_TO_ALL_INTERFACES (CVE-2018-1281): py/bind-socket-all-network-interfaces

**Description**: Socket bound to 0.0.0.0 or :: accepts traffic from any interface.

**Unsafe region** (static):
```
U_bind := { s | π == π_socket_bind ∧ host ∈ {"0.0.0.0", "", "::", "::0"} }
```

---

### 11.44 MISSING_HOST_KEY_VALIDATION (CWE-295): py/paramiko-missing-host-key-validation

**Description**: SSH connection with AutoAddPolicy accepts any host key (MITM vulnerability).

**Sinks**:
```python
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.set_missing_host_key_policy(paramiko.WarningPolicy())
```

**Unsafe region** (static):
```
U_hostkey := { s | π == π_set_policy ∧ policy ∈ {AutoAddPolicy, WarningPolicy} }
```

---

### 11.45 REQUEST_WITHOUT_CERT_VALIDATION (CWE-295): py/request-without-cert-validation

**Description**: HTTPS request with certificate validation disabled.

**Sinks**:
```python
requests.get(url, verify=False)
urllib3.PoolManager(cert_reqs='CERT_NONE')
```

**Unsafe region** (static or taint):
```
U_no_cert := { s | π == π_https_request ∧ verify == False }
```

---

### 11.46 PAM_AUTHORIZATION_BYPASS (CWE-285): py/pam-auth-bypass

**Description**: Using `pam_authenticate` without `pam_acct_mgmt` allows bypassing account restrictions.

**Unsafe region** (static):
```
U_pam := { s | π == π_pam_auth ∧ ¬FollowedByAcctMgmt(call) }
```

---

### 11.47 UNTRUSTED_DATA_TO_EXTERNAL_API (CWE-020): py/untrusted-data-to-external-api

**Description**: Untrusted data passed to external APIs without sanitization.

**General taint check for unmodeled APIs.**

**Unsafe region**:
```
U_external := { s | π == π_external_call ∧ τ(arg) == 1 ∧ ¬Sanitized(arg) }
```

---

### 11.48 Summary: Security Bug Classes as Barrier Certificates

All 47 CodeQL security queries can be expressed using the barrier framework:

| Category | Bug Pattern | Taint Type | Barrier Shape |
|----------|-------------|------------|---------------|
| **Injection (SQL, Cmd, Code, LDAP, XPath, NoSQL)** | τ at query/command sink | Untrusted | `δ_sink · (Parameterized + (1-τ) - ½)` |
| **Path Traversal** | τ at file operation | Untrusted | `δ_file · (g_path_valid + (1-τ) - ½)` |
| **XSS** | τ at HTML output | Untrusted | `δ_html · (g_escaped + (1-τ) - ½)` |
| **SSRF** | τ at HTTP client | Untrusted | `δ_request · (g_url_valid + (1-τ) - ½)` |
| **Deserialization** | τ at deserializer | Untrusted | `δ_deser · ((1-UnsafeDeser) + (1-τ) - ½)` |
| **XXE/XML Bomb** | τ at XML parser | Untrusted | `δ_xml · ((1-EntitiesEnabled) + (1-τ) - ½)` |
| **Cleartext Storage/Logging** | σ at storage/log sink | Sensitive | `δ_sink · ((1-σ) + Encrypted - ½)` |
| **Weak Crypto** | Algorithm at crypto call | N/A (static) | `δ_crypto · (StrongAlgo - ½)` |
| **Insecure Config** | Configuration value | N/A (static) | `δ_config · (SecureSetting - ½)` |
| **Regex DoS** | Pattern complexity | Untrusted | `δ_regex · ((1-τ_input) + SafePattern - ½)` |

### 11.49 Implementation: Taint Tracking in the Symbolic VM

To detect all 47 security bug classes, the symbolic VM must:

1. **Track taint bits** for all symbolic values:
   - `τ(v)` for untrusted data (user input, external sources)
   - `σ(v)` for sensitive data (passwords, API keys, PII)

2. **Model sources** (framework-specific):
   ```python
   # Django source contract
   def request_GET_getitem(request, key):
       value = fresh_symbol()
       τ[value] = True  # Mark as untrusted
       return value
   
   # Password field source
   def form_cleaned_data_password(form):
       value = fresh_symbol()
       σ[value] = True  # Mark as sensitive
       return value
   ```

3. **Propagate taint through operations**:
   ```python
   def symbolic_binop(op, x, y):
       result = z3_op(op, x, y)
       τ[result] = Or(τ[x], τ[y])
       σ[result] = Or(σ[x], σ[y])
       return result
   ```

4. **Model sanitizers** (clear taint):
   ```python
   def symbolic_escape(v):
       result = fresh_symbol()
       # Taint cleared by escaping
       τ[result] = False
       σ[result] = σ[v]  # Sensitivity preserved
       return result
   ```

5. **Check unsafe predicates at sinks**:
   ```python
   def check_sink(sink_type, value, call_info):
       if sink_type == "SQL_EXECUTE":
           if not is_parameterized(call_info):
               emit_unsafe_check(
                   And(τ[value], Not(g_sanitized[value])),
                   bug_type="SQL_INJECTION",
                   cwe="CWE-089"
               )
       elif sink_type == "LOG":
           emit_unsafe_check(
               σ[value],
               bug_type="CLEARTEXT_LOGGING",
               cwe="CWE-532"
           )
       # ... etc for all 47 types
   ```

---

## 12. Roadmap (what to add next)

The next expansions will:

1. Make the handler/exception model fully explicit (a formal `CaughtHereOrAbove` and a concrete `WillCatchAt` extraction from bytecode exception tables).
2. Give a concrete Z3 encoding for a small Python bytecode fragment that proves/rejects `ASSERT_FAIL` on the three minimal examples in §3.4.
3. Turn the 22 bug schemas into a uniform “property interface” (`UnsafeRegion` objects) analogous to the Rust checker’s `BugType` list.
4. Detail contract refinement for unknown library calls with DSE traces, and show how counterexample models become DSE queries.


## References / starting points

This draft is intentionally synthesis-oriented, but the “exact model” goal depends on (a) the Python reference semantics and (b) existing mechanizations we can borrow from.

- Python Language Reference (anchor points we’ll cite repeatedly):
  - Execution model (names/scopes): https://docs.python.org/3/reference/executionmodel.html
  - Expressions (evaluation order): https://docs.python.org/3/reference/expressions.html#evaluation-order
  - Simple statements (`assert`): https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement
  - The data model (attribute lookup, descriptors, etc.): https://docs.python.org/3/reference/datamodel.html
  - Compound statements (`try`, `with`, etc.): https://docs.python.org/3/reference/compound_stmts.html
- Politz et al., *Python: The Full Monty* (OOPSLA 2013): mechanized semantics with wide Python feature coverage.
- Dwight Guth, *A Formal Semantics of Python 3.3* (K Framework): executable semantics + rewriting-based reachability.
- K Framework (general): https://kframework.org/
- CrossHair (symbolic execution with contracts for Python): https://crosshair.readthedocs.io/
