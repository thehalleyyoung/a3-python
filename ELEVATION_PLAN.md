# Elevation Plan: General Relational Semantics for Library Calls (Non‑Regex)

This plan stays within the system defined by:
- `.github/prompts/python-semantic-barrier-workflow.prompt.md` (stateful workflow + anti‑cheating + BUG/SAFE/UNKNOWN posture)
- `python-barrier-certificate-theory.md` (abstract machine reachability + unknown calls as relations with `Sem_f ⊆ R_f`)

Goal: upgrade the analyzer so **any** library/builtin function becomes “reasoning‑relevant” once its semantics are added in a *uniform, structural form* (not via source pattern matching). The `len`/bounds story becomes one instance of this general mechanism.

---

## 0. Non‑negotiables (anti‑cheating)

- Do **not** special‑case source patterns (`len(x)-1`, `x[len(x)]`, etc.).
- Do **not** use regex/AST smells/docstrings/test names as a decider.
- All “BUG” and “SAFE” outcomes must follow from the machine transition relation + Z3 checks. If we can’t prove it, return **UNKNOWN**.
- For unknown calls, preserve soundness: `Sem_f ⊆ R_f` (default `R_f` is havoc).

---

## 1. The general solution: treat *all* known calls as relational transitions

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

## 2. The “given form” for library semantics (what authors write)

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

## 3. One engine to apply any summary (no per-function special cases)

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

## 4. Make summaries able to talk about heap properties (observers + updaters)

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

## 5. Bounds example as an instance (no pattern matching)

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

## 6. Validation (tests that enforce generality)

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

## 7. Workflow integration (as required by the system prompt)

- Add a note in `docs/notes/` describing:
  - the summary format (“cases + fallback”), and how it preserves `Sem_f ⊆ R_f`
  - the heap observer/updater API and why it avoids model‑peeking
  - how adding a summary improves proofs without heuristics
- Add a `State.json.queue.next_actions` item like:
  - `CONTINUOUS_REFINEMENT: relational summaries engine + heap observers`
- Run the full test suite; if a property can’t be proved under the summary+core semantics, report **UNKNOWN** rather than inventing rules.
