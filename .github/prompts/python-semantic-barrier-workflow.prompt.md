# PythonFromScratch: Stateful, Continuous Python Semantics + Barrier-Certificate Verifier

You are being invoked repeatedly (possibly thousands of times) by `copilot-cli` in a loop (`while True:`). You have **no reliable memory** between invocations except the repository contents. Therefore:

## Non‑negotiable requirement: resume via `State.json`

- You **MUST** read `State.json` at the repo root at the start of every run.
- You **MUST** decide what to do next based on `State.json` (do not "start over").
- You **MUST** write back to `State.json` at the end of every run (even on failure), so the next run resumes correctly.
- The same prompt must be usable from any point in the process: `State.json` is the single source of truth.

If `State.json` is missing, create it using the schema in this prompt. If it exists but is invalid JSON, repair it *without discarding progress* (salvage what you can from git/history/logs).

---

# The mission (do not dilute this)

Build a *precise, execution‑faithful* semantic model of Python (as a programming language), and restate the "bug = reachable unsafe region" worldview in **barrier‑certificate** terms:

- Reference theory: `barrier-certificate-theory.tex` (20 bug types, barrier conditions, Z3 roles).
- Python adaptation: `python-barrier-certificate-theory.md` (bytecode‑machine semantics, unknown calls as relations, DSE as refinement oracle).
- Implementation style exemplar: `RustFromScratch/` (continuous improvement workflow, anti‑cheating stance, testing methodology, stateful iteration).

## The core deliverable

A program analysis toolchain that, given Python code, can produce one of:

1. **BUG**: a *model‑checked reachable* unsafe state (with a concrete counterexample trace / witness), OR
2. **SAFE**: a *proof* (barrier certificate / inductive invariant) that the unsafe region is unreachable, OR
3. **UNKNOWN**: neither proof nor counterexample (this is allowed; never lie).

No "looks buggy" heuristics. No regex‑based detectors. No AST smell checks masquerading as verification. The tool must be grounded in the **Python→Z3 heap/transition/barrier** model.

## Required reading (to understand the target)

- `barrier-certificate-theory.tex`
  - Minimum: the "Summary: Complete Coverage of 20 Bug Types" section (bug list + the barrier/invariant shape).
  - Capture: the basic relationship between bugs, z3, and barrier certificate theory, the 20 bug type names and how they work, and the "no proof = no safety guarantee" posture.
- `python-barrier-certificate-theory.md`
  - Minimum: machine state definition, reachability framing, unknown calls as relations, and the DSE-as-oracle refinement rules.
  - Capture: the bytecode-as-abstract-machine target and the soundness rule `Sem_f ⊆ R_f`.
- `RustFromScratch/`
  - Minimum: `RustFromScratch/continuous_checker_workflow.py`, `RustFromScratch/barrier_refinement_orchestrator.py`, and `RustFromScratch/SEMANTIC_GAPS_TO_FIX.md`.
  - Capture: the workflow discipline (stateful phases) and the explicit anti‑cheating constraints.
- `CODEQL_PARITY_SOTA_MATH_PLAN.md` for some additions to the code to improve interprocedural taint tracking - **make sure everything you do works for interprocedural analysis, and iterate on that/get as far as you can and add the next step towards that at the end in State.json**.

Write your summaries into small markdown files (e.g., under `docs/notes/`) and list them in `State.json.knowledge.notes_files`.

---

# Absolute anti‑cheating rule (repeat to yourself every run)

It is easy to "cheat" by implementing superficial recognizers that pass local tests but do not generalize. You must not do that.

**Every bug report and every safety claim must be justified strictly by the Python Z3 heap/transition/barrier theory model** (plus clearly labeled, explicitly unsound optional hints that never decide BUG/SAFE).

## Forbidden approaches (hard ban)

- Regex/pattern matching on source text as the *decider* ("if `assert False` then bug", "if `/ 0` then bug", etc.).
- Using comments/docstrings/variable names/file paths/test names as signals.
- Hardcoding behaviors for known repos or tests.
- Returning "SAFE" because you didn't find a counterexample (absence of evidence is not proof).
- Declaring a counterexample "spurious" purely because DSE failed to find it (DSE is under‑approximate).

## Allowed approaches (must be semantics‑faithful)

- Bytecode/CFG construction + explicit exceptional edges.
- Symbolic execution with Z3 path conditions (bounded reachability).
- Abstract interpretation *with a stated lattice* and sound transfer functions.
- Barrier certificates / inductive invariants checked by Z3 (or SOS later).
- Contract modeling for unknown calls as **over‑approximating relations**; refinement only when justified.
- DSE as a **refinement oracle** (concretize/validate traces), never as a proof of absence.

---

# Dual‑mode requirement: pure symbolic vs concolic‑assisted

Everything you build must work in **two modes**:

## Mode A: Pure static/symbolic (no concrete execution)

- This is the baseline and must always work.
- Unknown inputs and unknown library calls must be modeled **soundly** via over‑approximation:
  - unknown values are nondeterministic symbols,
  - unknown calls are relations `R_f` that may return/raise/mutate according to a justified contract (or a conservative fallback).
- This mode must be usable for untrusted code and for “do not execute” workflows.
- CLI: `python -m pyfromscratch.cli your_file.py --no-concolic`

## Mode B: Concolic‑assisted refinement (more precise witnesses)

- This mode may execute the program concretely and must be **optional**.
- Use it only to improve *witness quality* and *debuggability*, never to justify SAFE:
  - validate symbolic counterexamples (DSE),
  - record concrete call observations for unknown libraries (selective concolic tracing),
  - replay a concrete path inside `SymbolicVM` (oracle‑guided replay / lockstep diagnostics),
  - prioritize/validate library contracts when an UNKNOWN/BUG hinges on library behavior.
- The BUG/SAFE/UNKNOWN **verdict must not depend on concolic**:
  - BUG is decided by symbolic reachability of an unsafe region (optionally followed by validation),
  - SAFE is decided only by a proof artifact (barrier / inductive invariant),
  - concolic failures never imply infeasibility.
- Default CLI runs with concolic enabled; disable with `--no-concolic`.

## Implementation rule

Any feature that executes target code (DSE, selective concolic tracing, lockstep replay, hybrid witness generation) must be:
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
  "target_python": "3.11",
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
    "read_python_barrier_md": false,
    "studied_rustfromscratch_workflow": false,
    "notes_files": []
  },
  "progress": {
    "repo_scaffolded": false,
    "bytecode_semantics": {
      "implemented_opcodes": [],
      "exceptions": false,
      "function_calls": false,
      "imports": false,
      "generators": false,
      "async": false
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
      "used_as_oracle": false
    },
    "evaluation": {
      "synthetic_suite": false,
      "pygoat_codeql_comparison": {
        "completed": false,
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

Goal: create a clean repo skeleton for the Python semantic model + Z3 + tests + evaluation harness.

Exit criteria:
- A runnable CLI exists (even if tiny) that loads a Python file and does *something deterministic*.
- A test runner exists (pytest/unittest) and has at least one passing test.
- `State.json` is created and updated.

Immediately after BOOTSTRAP scaffolding exists, prioritize **library-specific semantics**:
- Implement relational call summaries (cases + required havoc fallback) for calls you can identify.
- Add as many builtin/stdlib/library summaries as possible (starting with high-frequency APIs).
- Reference: `ELEVATION_PLAN.md` and the "Elevation Plan: General Relational Semantics for Library Calls (Non‑Regex)" section in `python-barrier-certificate-theory.md`.

## Phase `SEMANTICS_CONCRETE`

Goal: a **concrete** bytecode machine stepper (faithful to Python 3.11+ where possible), primarily for oracle comparison.

Exit criteria:
- For a curated subset of bytecode instructions, the stepper's observable behavior matches CPython on those programs (golden tests).
- You can print/serialize machine states for debugging.

## Phase `SEMANTICS_SYMBOLIC`

Goal: a **symbolic** semantics over Z3 expressions (heap + frames + operand stack + exceptions) sufficient to express reachability queries.

Exit criteria:
- A bounded symbolic executor exists that can find a counterexample trace for at least one unsafe predicate (e.g., unhandled `assert False`).
- Sound defaults for unknown inputs exist (nondeterministic symbols).

## Phase `UNSAFE_REGIONS_CORE`

Goal: encode unsafe regions for a first core subset of bug types (start with those entirely inside Python semantics).

Start set (suggested):
- `ASSERT_FAIL`, `PANIC`(unhandled exception), `DIV_ZERO`, `BOUNDS`, `NULL_PTR`(None misuse), `STACK_OVERFLOW`, `TYPE_CONFUSION`.

Exit criteria:
- Each implemented bug type has:
  - a machine‑state predicate `Unsafe_xxx(σ)` defined *semantically*,
  - at least 10 synthetic BUG tests + 10 synthetic NON‑BUG tests,
  - a counterexample trace extractor for BUG results,
  - and never reports SAFE without a proof artifact.

## Phase `UNKNOWN_CALLS_AND_CONTRACTS`

Goal: treat black‑box calls barrier‑theoretically (as relations) and refine them.

Exit criteria:
- Unknown calls are modeled as over‑approximations with explicit "may mutate heap / may raise / may return anything" knobs.
- A contract format exists (even minimal) and is applied in the symbolic semantics.
- At least one refined contract is learned/added in a justified way (by reading source, or by bounded validation) and tracked in `State.json`.
- A growing library semantics pack exists: add as many library-specific summaries/contracts as feasible (builtins, stdlib, common third-party), each as an over-approx relation with recorded provenance.

## Phase `DSE_ORACLE`

Goal: dynamic symbolic execution (concolic) is implemented and used to validate candidate traces / guide refinement.

Exit criteria:
- Given a candidate counterexample trace (path constraints), DSE attempts to realize it on CPython and records success/failure + concrete input.
- DSE results are used only to:
  - produce concrete repro steps for real bugs, or
  - identify *where* abstractions are too coarse (but never to prove infeasibility).
- The entire system remains correct and useful with concolic disabled (`--no-concolic`): concolic only affects optional witness/diagnostic artifacts.

## Phase `BARRIERS_AND_PROOFS`

Goal: barrier certificates / inductive invariants are implemented as first‑class proof objects.

Exit criteria:
- A barrier template mechanism exists (start simple: linear/arithmetic templates).
- Inductiveness is checked by Z3 (for nondeterministic transitions too).
- At least one nontrivial SAFE proof is produced and verified end‑to‑end.

## Phase `FULL_20_BUG_TYPES`

Goal: cover the **20 bug types** from `barrier-certificate-theory.tex`, mapped into Python semantics (and native boundary where applicable).

Exit criteria:
- All 20 have:
  - semantic unsafe predicate,
  - reachability encoding,
  - tests (BUG + NON‑BUG),
  - evaluation metrics in `State.json`.

---

## Phase `PUBLIC_REPO_EVAL`

Goal: run on real repos, measure false positives/negatives, refine.

Exit criteria:
- A reproducible repo list and scanning pipeline exist.
- Findings are triaged with model traces + (optional) DSE repro.
- False positives lead to fixes in semantics/contracts/proofs, not heuristics.

## Phase `CONTINUOUS_REFINEMENT`

Goal: never stop improving; keep iterating overnight.

Behavior:
- Expand bytecode opcode coverage.
- Expand Python feature coverage (generators, async, imports, descriptors).
- Expand contract library (stdlib + common libs) with justified summaries.
- Expand and randomize synthetic test generation (avoid overfitting).
- Re-run public-repo evaluation periodically; track regressions.

---

# "Moving parts" (copy RustFromScratch's discipline)

Maintain an explicit list of moving parts in the codebase (and track completion in `State.json` as you go). This is not bureaucracy: it prevents the system from turning into ad‑hoc heuristics.

Suggested moving parts (Python version of the RustFromScratch list):

1. **Frontend / program loading**
   - Source loader (files, modules).
   - Compilation to code objects / bytecode (target Python version pinned).
   - Source span mapping (bytecode offset → file/line/col).
2. **CFG + exceptional edges**
   - Control‑flow graph for bytecode, including exception table edges (3.11+).
   - Basic block builder; dominators optional later.
3. **Concrete bytecode machine (oracle harness)**
   - Stepper with serializable machine state.
   - Differential tests vs CPython for the supported fragment.
4. **Symbolic state / heap model (Z3)**
   - Value representation (tagged union).
   - Heap representation (ObjId → object record), plus "external handle/resource" model.
   - Frame/stack representation.
5. **Symbolic execution / BMC**
   - Path exploration with Z3 feasibility checks.
   - Trace extraction / replay scaffolding.
6. **Unsafe region library (20 bug types + 47 security bug types)**
   - `Unsafe_x(σ)` predicates + program‑point hooks (bytecode offsets / call sites).
   - **Security lattice detectors** for all 47 CodeQL security bug types with Z3 constraints.
7. **Unknown call model + contract language**
   - "Havoc" default that is sound.
   - Contracts as relations `R_f` with heap/exception footprint.
   - **Source/sink/sanitizer contracts** for security analysis with lattice integration.
8. **DSE (refinement oracle)**
   - Concolic executor that can attempt to realize symbolic traces.
   - Contract refinement loop that never breaks over‑approx soundness.
9. **Barrier / invariant / ranking layer**
   - Inductive invariants checked by Z3.
   - Ranking functions for termination.
   - Barrier templates + synthesis loop (start simple; grow).
   - **Security barrier certificates** for proving absence of taint flows.
10. **Taint lattice layer (NEW)**
    - Product lattice L = P(T) × P(K) × P(T) with Z3 bitvector encoding.
    - 16 source types, 32 sink types, 29 sanitizer types.
    - Implicit flow tracking via PC taint.
    - Integration with symbolic VM for deep analysis.
11. **Evaluation harness**
   - Synthetic program generator (BUG and NON‑BUG, diverse).
   - Public repo crawler + scan runner + triage pipeline.
   - Metrics and regression tracking (false positives/negatives, unknowns).

Every time you add a feature, you must be able to point to which moving part it belongs to.

---

# Suggested repo layout (create in BOOTSTRAP; adjust as needed)

Create a Python-first structure (keep `RustFromScratch/` as reference only):

- `pyfromscratch/` (package root)
  - `__init__.py`
  - `cli.py` (entrypoint: analyze a file/module)
  - `frontend/` (load/compile/bytecode utilities)
  - `cfg/` (CFG + exception edges)
  - `semantics/`
    - `concrete_vm.py` (debuggable stepper for subset)
    - `symbolic_vm.py` (Z3-backed symbolic stepper)
    - `state.py` (machine state dataclasses; (de)serialization)
    - `security_tracker.py` (original security tracker)
    - `security_tracker_lattice.py` (**NEW**: deep lattice integration with VM)
  - `z3model/`
    - `values.py` (tagged values)
    - `heap.py`
    - `constraints.py`
    - `taint.py` (basic taint tracking)
    - `taint_lattice.py` (**NEW**: full product lattice L = P(T) × P(K) × P(T) with Z3 bitvectors)
  - `unsafe/`
    - `registry.py` (list of bug classes; mapping to predicates)
    - `assert_fail.py`, `div_zero.py`, ... (one per bug class)
    - `security/`
      - `lattice_detectors.py` (**NEW**: 47 unsafe region predicates for CodeQL bug types)
  - `contracts/`
    - `stdlib.py` (over-approx contracts; start tiny)
    - `format.md` or `schema.py` (contract schema)
    - `security.py` (original security contracts)
    - `security_lattice.py` (**NEW**: source/sink/sanitizer contracts with lattice integration)
  - `dse/`
    - `concolic.py`
  - `barriers/`
    - `invariants.py`
    - `templates.py`
    - `synthesis.py`
  - `evaluation/`
    - `pygoat_compare.py` (PyGoat/CodeQL comparison utilities)
- `tests/`
  - `test_semantics_*.py` (differential tests)
  - `test_unsafe_*.py` (BUG/NON‑BUG)
  - `test_security_bugs.py` (security bug detection tests)
  - `test_barriers.py` (barrier certificate tests)
  - `test_taint_lattice.py` (**NEW**: 31 tests for lattice implementation)
  - `fixtures/` (small Python programs)
- `scripts/` (optional helpers: scan repos, run batches)
- `results/` (gitignored logs, triage artifacts, traces)
- `external_tools/` (CodeQL, PyGoat, other comparison tools)
  - `codeql/` (CodeQL CLI + queries)
  - `pygoat/` (OWASP PyGoat vulnerable app)

Record this layout (or your chosen alternative) in `State.json.progress.repo_scaffolded`.

---

# Bug Types: Error Bugs + Security Bugs (67 total)

The checker must support two categories of bugs, both defined barrier-theoretically in `python-barrier-certificate-theory.md`:

## Core Error Bug Types (20 from barrier-certificate-theory.tex)

These are the original 20 bug types. Implement them in Python terms:

1. `INTEGER_OVERFLOW` (Python↔native boundary / fixed-width intent)
2. `DIV_ZERO`
3. `FP_DOMAIN`
4. `USE_AFTER_FREE` (native boundary / handles / capsules)
5. `DOUBLE_FREE` (native boundary)
6. `MEMORY_LEAK` (unbounded growth / unreachable retention)
7. `UNINIT_MEMORY` (native boundary / uninitialized buffers)
8. `NULL_PTR` (None misuse + native null deref boundary)
9. `BOUNDS` (IndexError/KeyError/iterator protocol misuse; semantic)
10. `DATA_RACE` (threads + external state; include GIL-release caveat)
11. `DEADLOCK` (locks/conditions/async deadlocks)
12. `SEND_SYNC` (thread-safety contract violation)
13. `NON_TERMINATION` (ranking functions / barrier-style termination)
14. `PANIC` (unhandled exception / "no-crash" contract violation)
15. `ASSERT_FAIL` (assertion failure that propagates out)
16. `STACK_OVERFLOW` (runaway recursion / RecursionError as failure)
17. `TYPE_CONFUSION` (dynamic dispatch/type errors violating expected protocol)
18. `ITERATOR_INVALID` (collection mutation invalidation)
19. `INFO_LEAK` (taint / noninterference to sinks)
20. `TIMING_CHANNEL` (secret-dependent timing proxy)

## Security Bug Types (47 from CodeQL Python queries, now in python-barrier-certificate-theory.md §11)

These are **taint-based and configuration security bugs** covering ALL CodeQL Python security queries. See `python-barrier-certificate-theory.md` §11 for full barrier-theoretic definitions including sources, sinks, sanitizers, unsafe regions, and barrier templates:

**Injection Bugs:**
- `SQL_INJECTION` (CWE-089) - py/sql-injection
- `COMMAND_INJECTION` (CWE-078) - py/command-line-injection
- `UNSAFE_SHELL_COMMAND_CONSTRUCTION` (CWE-078) - py/shell-command-constructed-from-input
- `CODE_INJECTION` (CWE-094) - py/code-injection
- `LDAP_INJECTION` (CWE-090) - py/ldap-injection
- `XPATH_INJECTION` (CWE-643) - py/xpath-injection
- `NOSQL_INJECTION` (CWE-943) - py/nosql-injection
- `LOG_INJECTION` (CWE-117) - py/log-injection
- `REGEX_INJECTION` (CWE-730) - py/regex-injection

**Path/File Bugs:**
- `PATH_INJECTION` (CWE-022) - py/path-injection
- `TAR_SLIP` (CWE-022) - py/tarslip
- `INSECURE_TEMPORARY_FILE` (CWE-377) - py/insecure-temporary-file
- `WEAK_FILE_PERMISSIONS` (CWE-732) - py/overly-permissive-file

**Web/XSS Bugs:**
- `REFLECTED_XSS` (CWE-079) - py/reflective-xss
- `JINJA2_AUTOESCAPE_FALSE` (CWE-079) - py/jinja2/autoescape-false
- `HEADER_INJECTION` (CWE-113) - py/http-response-splitting
- `URL_REDIRECT` (CWE-601) - py/url-redirection
- `COOKIE_INJECTION` (CWE-020) - py/cookie-injection
- `INSECURE_COOKIE` (CWE-614) - py/insecure-cookie
- `CSRF_PROTECTION_DISABLED` (CWE-352) - py/csrf-protection-disabled
- `FLASK_DEBUG` (CWE-215) - py/flask-debug
- `STACK_TRACE_EXPOSURE` (CWE-209) - py/stack-trace-exposure

**SSRF/Network Bugs:**
- `FULL_SSRF` (CWE-918) - py/full-ssrf
- `PARTIAL_SSRF` (CWE-918) - py/partial-ssrf
- `BIND_TO_ALL_INTERFACES` (CVE-2018-1281) - py/bind-socket-all-network-interfaces

**Serialization/XML Bugs:**
- `UNSAFE_DESERIALIZATION` (CWE-502) - py/unsafe-deserialization
- `XXE` (CWE-611) - py/xxe
- `XML_BOMB` (CWE-776) - py/xml-bomb

**Crypto/Secret Bugs:**
- `CLEARTEXT_STORAGE` (CWE-312) - py/clear-text-storage-sensitive-data
- `CLEARTEXT_LOGGING` (CWE-312/532) - py/clear-text-logging-sensitive-data
- `HARDCODED_CREDENTIALS` (CWE-798) - py/hardcoded-credentials
- `WEAK_CRYPTO_KEY` (CWE-326) - py/weak-crypto-key
- `BROKEN_CRYPTO_ALGORITHM` (CWE-327) - py/weak-cryptographic-algorithm
- `WEAK_SENSITIVE_DATA_HASHING` (CWE-327) - py/weak-sensitive-data-hashing
- `INSECURE_PROTOCOL` (CWE-327) - py/insecure-protocol
- `INSECURE_DEFAULT_PROTOCOL` (CWE-327) - py/insecure-default-protocol

**Certificate Validation Bugs:**
- `MISSING_HOST_KEY_VALIDATION` (CWE-295) - py/paramiko-missing-host-key-validation
- `REQUEST_WITHOUT_CERT_VALIDATION` (CWE-295) - py/request-without-cert-validation

**Regex DoS Bugs:**
- `REDOS` (CWE-730) - py/redos
- `POLYNOMIAL_REDOS` (CWE-730) - py/polynomial-redos

**Validation/Sanitization Bugs:**
- `BAD_TAG_FILTER` (CWE-116) - py/bad-tag-filter
- `INCOMPLETE_HOSTNAME_REGEXP` (CWE-020) - py/incomplete-hostname-regexp
- `INCOMPLETE_URL_SUBSTRING_SANITIZATION` (CWE-020) - py/incomplete-url-substring-sanitization
- `OVERLY_LARGE_RANGE` (CWE-020) - py/overly-large-range

**Other:**
- `PAM_AUTHORIZATION_BYPASS` (CWE-285) - py/pam-auth-bypass
- `UNTRUSTED_DATA_TO_EXTERNAL_API` (CWE-020) - py/untrusted-data-to-external-api

### Taint Tracking Requirements

Security bugs require **taint analysis** in the symbolic VM:

1. **Sources**: HTTP parameters, user input, environment variables, file content
2. **Sinks**: SQL execute, shell commands, file operations, HTML output, etc.
3. **Sanitizers**: Escaping functions, type conversions, parameterized queries
4. **Taint bits**: Each symbolic value carries `τ(v) ∈ {0,1}` (untrusted) and optionally `σ(v) ∈ {0,1}` (sensitive)

General unsafe region for taint bugs at sink `π_sink`:
```
U_taint := { s | π == π_sink ∧ τ(value) == 1 ∧ g_sanitized(value) == 0 }
```

General barrier template:
```
B_taint = (1 - δ_sink(π)) · M  +  δ_sink(π) · (g_sanitized + (1 - τ(v)) - ½)
```

For each bug type you implement, you must write down in code/docs:
- The exact unsafe predicate `U_x(σ)` in terms of machine state.
- What counts as "caught/handled" vs "uncaught" for exception-shaped bugs.
- For taint bugs: source, sink, and sanitizer definitions.
- Whether SAFE is even decidable in your current fragment; if not, report UNKNOWN unless you have a proof.

---

## Taint Lattice Implementation (Deep Z3 Integration for 47 Security Bug Types)

The full mathematical taint lattice model from `leak_theory.md` is now implemented with deep Z3 integration. This provides **barrier-theoretic proofs** for all 47 CodeQL security bug types.

### Mathematical Foundation

The taint lattice is a **product lattice**:

$$\mathcal{L} = \mathcal{P}(\mathcal{T}) \times \mathcal{P}(\mathcal{K}) \times \mathcal{P}(\mathcal{T})$$

Each taint label is a triple $\ell = (\tau, \kappa, \sigma)$ where:
- $\tau \in \mathcal{P}(\mathcal{T})$ — **source types** (which untrusted sources this value came from)
- $\kappa \in \mathcal{P}(\mathcal{K})$ — **safe sinks** (which sinks this value is safe to flow to)
- $\sigma \in \mathcal{P}(\mathcal{T})$ — **sensitivity** (which sensitive data types this value contains)

**Lattice Order**: $\ell_1 \sqsubseteq \ell_2 \iff \tau_1 \subseteq \tau_2 \land \kappa_1 \supseteq \kappa_2 \land \sigma_1 \subseteq \sigma_2$

**Join (least upper bound)**: $(\tau_1, \kappa_1, \sigma_1) \sqcup (\tau_2, \kappa_2, \sigma_2) = (\tau_1 \cup \tau_2, \kappa_1 \cap \kappa_2, \sigma_1 \cup \sigma_2)$

### Z3 Bitvector Encoding

The lattice components are encoded as Z3 bitvectors for efficient symbolic reasoning:

| Component | Encoding | Width |
|-----------|----------|-------|
| τ (sources) | `BitVecSort(16)` | 16 bits (16 source types) |
| κ (safe sinks) | `BitVecSort(32)` | 32 bits (32 sink types) |
| σ (sensitivity) | `BitVecSort(16)` | 16 bits (same as sources) |

**Safety predicate for sink `k`**: A value is safe to flow to sink $k$ iff $k \in \kappa$:
```
safe_for_sink(v, k) := (v.kappa & (1 << k)) != 0
```

In Z3: `Extract(k, k, symbolic_label.kappa) == 1`

### Implementation Files

The taint lattice is implemented across these modules:

#### Core Lattice Model: `pyfromscratch/z3model/taint_lattice.py`

The mathematical model with Z3 encoding:

- **`SourceType(IntEnum)`**: 16 source types (HTTP_PARAM, USER_INPUT, ENVIRONMENT, PASSWORD, API_KEY, FILE_CONTENT, DATABASE, NETWORK, COOKIE, SESSION, HEADER, URL, COMMAND_LINE, DESERIALIZED, RANDOM, EXTERNAL)
- **`SinkType(IntEnum)`**: 32 sink types (SQL_EXECUTE, COMMAND_SHELL, CODE_EVAL, LOG_OUTPUT, FILE_WRITE, NETWORK_SEND, HTTP_RESPONSE, REDIRECT, HEADER_SET, COOKIE_SET, HTML_RENDER, XPATH_QUERY, LDAP_QUERY, NOSQL_QUERY, REGEX_COMPILE, DESERIALIZE, CRYPTO_KEY, CRYPTO_HASH, FILE_PATH, TEMP_FILE, PERMISSIONS, URL_FETCH, XML_PARSE, PICKLE_LOADS, SECRET_STORAGE, TEMPLATE_RENDER, EXTERNAL_API, HOST_VALIDATION, URL_VALIDATION, PORT_BIND, PAM_AUTH, DENIAL_OF_SERVICE)
- **`SanitizerType(IntEnum)`**: 29 sanitizer types mapping to sink protection
- **`TaintLabel`**: Concrete label with `(tau, kappa, sigma)` as integers
- **`SymbolicTaintLabel`**: Z3 bitvector version for symbolic reasoning
- **`PCTaint / SymbolicPCTaint`**: Implicit flow tracking (control-flow taint)
- **`CODEQL_BUG_TYPES`**: Dictionary of 47 `SecurityBugType` definitions with CWE mappings
- **`SANITIZER_TO_SINKS`**: Mapping from sanitizer types to the sinks they protect
- **`create_unsafe_region_constraint()`**: Z3 constraint for bug detection
- **`create_barrier_certificate()`**: Barrier function generation for security proofs

**Key Functions**:
```python
# Create taint label from source
label = TaintLabel.from_source(SourceType.HTTP_PARAM)

# Check if safe for sink
is_safe = label.is_safe_for_sink(SinkType.SQL_EXECUTE)

# Apply sanitizer
sanitized = label.apply_sanitizer(SanitizerType.SQL_ESCAPE)

# Symbolic Z3 operations
sym_label = SymbolicTaintLabel.from_source_symbolic("v", SourceType.USER_INPUT)
constraint = sym_label.create_sink_safety_constraint(SinkType.CODE_EVAL)
```

#### Security Contracts: `pyfromscratch/contracts/security_lattice.py`

Library function contracts with lattice integration:

- **`SourceContract`**: Defines source functions (e.g., `request.GET.get()` → HTTP_PARAM)
- **`SinkContract`**: Defines sink functions (e.g., `cursor.execute()` → SQL_EXECUTE)
- **`SanitizerContract`**: Defines sanitizer functions (e.g., `escape()` → HTML_ESCAPE)
- **40+ source contracts**: HTTP, environment, file, network, database, sensitive data sources
- **70+ sink contracts**: Injection sinks, cleartext exposure, crypto operations
- **30+ sanitizer contracts**: Escaping, validation, parameterization

**Contract Application**:
```python
# Apply source taint from contract
label = apply_source_taint(contract, existing_label)

# Check sink safety from contract  
is_unsafe, missing_sanitizers = check_sink_taint(contract, label)

# Apply sanitizer from contract
sanitized = apply_sanitizer(contract, label)

# Symbolic versions for Z3
sym_label = apply_source_taint_symbolic(contract, sym_label)
sym_sanitized = apply_sanitizer_symbolic(contract, sym_label)
```

#### Deep VM Integration: `pyfromscratch/semantics/security_tracker_lattice.py`

The `LatticeSecurityTracker` class provides deep integration with the symbolic VM:

- **`value_labels: Dict[int, TaintLabel]`**: Concrete taint per value ID
- **`symbolic_labels: Dict[int, SymbolicTaintLabel]`**: Symbolic taint per value ID
- **`pc_taint / pc_taint_stack`**: Implicit flow tracking for control flow
- **`taint_constraints`**: Z3 constraints for barrier certificate synthesis
- **`sanitization_guards`**: Guard variables for barrier generation

**VM Hooks**:
- `handle_call_pre(func_name, args)`: Apply source/sink contracts before calls
- `handle_call_post(func_name, result)`: Propagate taint to return values
- `handle_binop/handle_unop(op, operands)`: Taint propagation through operations
- `enter_branch(condition)/exit_branch()`: Implicit flow tracking
- `create_barrier_for_sink(sink_type)`: Generate barrier certificate for security proof

**Usage in SymbolicVM**:
```python
# The VM automatically uses LatticeSecurityTracker
from pyfromscratch.semantics.security_tracker_lattice import LatticeSecurityTracker

vm = SymbolicVM(code_obj)  # LatticeSecurityTracker is integrated

# After analysis, check for security violations
for sink_type, violation_data in vm.security_tracker.check_all_sinks():
    if violation_data['is_unsafe']:
        print(f"Security bug: {sink_type} - {violation_data['reason']}")
```

#### Unsafe Region Predicates: `pyfromscratch/unsafe/security/lattice_detectors.py`

47 unsafe region predicates for all CodeQL bug types:

- **`UnsafeRegionPredicate`**: Dataclass defining the Z3 predicate for each bug type
- **`create_lattice_detector(bug_type)`**: Factory function to create detector
- **`SECURITY_DETECTORS`**: Registry mapping bug type names to predicates
- Backward-compatible `is_unsafe_*` functions for each bug type

**Unsafe Region Definition**:
```python
# For SQL injection: value reaches SQL_EXECUTE sink while unsafe
unsafe_sql = UnsafeRegionPredicate(
    name="SQL_INJECTION",
    cwe="CWE-089",
    sources={SourceType.HTTP_PARAM, SourceType.USER_INPUT, ...},
    sinks={SinkType.SQL_EXECUTE},
    sanitizers={SanitizerType.SQL_ESCAPE, SanitizerType.SQL_PARAMETERIZE},
    predicate=lambda label: (
        label.has_taint_from_any(unsafe_sources) and
        not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
    )
)
```

### Barrier Certificate Generation

For each security bug type, the system can generate a barrier certificate that proves the program is safe:

$$B_{taint}(s) = \begin{cases}
M & \text{if } \pi \neq \pi_{sink} \\
(1 - \delta_{unsafe}(s)) - \frac{1}{2} & \text{if } \pi = \pi_{sink}
\end{cases}$$

Where $\delta_{unsafe}(s) = 1$ iff the value is tainted and unsanitized for the sink.

**Implementation**:
```python
from pyfromscratch.z3model.taint_lattice import create_barrier_certificate

# Create barrier for SQL injection safety
barrier = create_barrier_certificate(
    label=symbolic_label,
    sink_type=SinkType.SQL_EXECUTE,
    at_sink=is_at_sink_variable
)

# Verify inductiveness with Z3
solver = z3.Solver()
solver.add(Not(barrier_inductive_condition))
if solver.check() == unsat:
    print("SAFE: Barrier certificate verified")
```

### Implicit Flow Tracking (PC Taint)

The system tracks taint through control flow for detecting implicit information leaks:

```python
# When entering a branch on tainted condition
tracker.enter_branch(tainted_condition)

# All values assigned in the branch inherit PC taint
# This prevents laundering sensitive data through control flow

# When exiting the branch
tracker.exit_branch()
```

### Test Coverage

The implementation is validated by 31 dedicated tests in `tests/test_taint_lattice.py`:

- TaintLabel creation and operations
- SymbolicTaintLabel Z3 encoding
- Sink safety checks (both concrete and symbolic)
- Sanitizer application
- Lattice join operations
- Z3 constraint generation
- Barrier certificate verification

Run tests: `pytest tests/test_taint_lattice.py -v`

### Integration with Existing Security Tests

The lattice implementation is fully integrated with the existing security test suite:
- 29 tests in `tests/test_security_bugs.py`
- 34 tests in `tests/test_barriers.py`

Total: **94 security/barrier tests passing**

---

# Concrete technical target (align with the draft)

Target execution model: **Python 3.11 bytecode as an abstract machine** (as in `python-barrier-certificate-theory.md`).

Minimum semantic commitments (must be reflected in code, not prose):

- Deterministic evaluation order (operand stack behavior, call protocol).
- Exceptions and handler tables (3.11+ exception table ranges).
- Frames: locals/cells/globals/builtins, operand stack, instruction pointer.
- Heap/object model sufficient for:
  - None, bool, int, float, str (start),
  - lists/dicts/tuples (soon),
  - user objects + attribute lookup (later),
  - plus a representation of "external resources/handles" for leak/UAF boundary modeling.
- Nondeterminism surfaces:
  - unknown inputs (argv/env/io),
  - unknown library calls,
  - scheduling (if/when modeling threads/async).

---

**Note that you must be able to extract the function name (and ideally more context) wherever an unsafe predicate is checked, to report bugs precisely - just describing bytecode is totally insufficient.**

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

- Use **tagged values** (e.g., `Value = (tag, payload)`), so type confusion is definable.
- Separate **identity** (ObjId) from **value** (ints/bools) so aliasing is expressible.
- Model the heap as:
  - a functional map (Z3 Array) from ObjId → ObjRecord, or
  - uninterpreted functions with explicit "updated heap" versions,
  but keep it consistent.
- For Python ints: start with mathematical integers (`IntSort`) and only introduce boundedness at explicit boundary operations/contracts.
- For exceptions: represent "current exception" in the machine state explicitly; exception edges must be real transitions.
- For unknown effects: prefer "havoc with footprint": declare what may change, keep the rest stable.

Every unsafe predicate must be definable against your Z3 state without parsing source text.

---

# Bytecode-Level Taint Analysis (must implement at bytecode level)

All taint tracking must operate at the **bytecode level**, not AST level. This is critical for precision and integration with the symbolic VM.

## The Taint Product Lattice

Implement the product lattice from `python-barrier-certificate-theory.md` §9.5.3:

$$\mathcal{L} = \mathcal{P}(\mathcal{T}) \times \mathcal{P}(\mathcal{K}) \times \mathcal{P}(\mathcal{T})$$

Each taint label is a triple $\ell = (\tau, \kappa, \sigma)$:
- $\tau$: untrusted source types (16-bit bitvector)
- $\kappa$: sanitized sink types (32-bit bitvector)  
- $\sigma$: sensitivity source types (16-bit bitvector)

**Implementation**: `pyfromscratch/z3model/taint_lattice.py`

## Bytecode Opcode Transfer Functions

Each bytecode opcode has a taint transfer function. These are defined in `taint_lattice.BytecodeTaintTransfer`:

| Opcode | Transfer Function |
|--------|-------------------|
| `BINARY_ADD/SUB/MUL/...` | `[[binop]](ℓ₁, ℓ₂) = ℓ₁ ⊔ ℓ₂` |
| `BINARY_SUBSCR` | `[[subscr]](ℓ_container, ℓ_index) = ℓ_container ⊔ ℓ_index` |
| `STORE_FAST/NAME` | `[[store]](ℓ_value) = ℓ_value ⊔ ℓ_pc` (implicit flow) |
| `LOAD_FAST/NAME` | `[[load]](var) = ℓ_var` |
| `CALL` | `[[call]](ℓ_func, [ℓ_args]) = ⊔{ℓ_args} ⊔ Σ_callee` |
| `COMPARE_OP` | `[[compare]](ℓ₁, ℓ₂) = ℓ₁ ⊔ ℓ₂` |
| `POP_JUMP_IF_*` | Updates `ℓ_pc` for implicit flow tracking |
| `FORMAT_VALUE` | `[[format]](ℓ_value, ℓ_fmt) = ℓ_value ⊔ ℓ_fmt` |
| `BUILD_STRING/LIST/...` | `[[build]]([ℓ₁,...,ℓₙ]) = ⊔{ℓᵢ}` |
| `UNPACK_SEQUENCE` | `[[unpack]](ℓ_seq, n) = [ℓ_seq, ..., ℓ_seq]` |

## Sink Detection at Bytecode Level

Security sinks are detected at `CALL` instructions. The mapping is in `taint_lattice.FUNCTION_TO_SINK` and `MODULE_FUNCTION_TO_SINK`:

```python
# At CALL opcode, check if callee is a sink
from pyfromscratch.z3model.taint_lattice import get_sink_for_call, SinkType

sink = get_sink_for_call(func_name, module_name)
if sink is not None:
    # Check if argument is tainted and unsanitized
    if not arg_label.is_safe_for_sink(sink):
        report_bug(...)
```

## Symbolic Taint with Z3

For symbolic analysis, use `SymbolicTaintLabel` with Z3 bitvectors:

```python
from pyfromscratch.z3model.taint_lattice import SymbolicTaintLabel, SymbolicBytecodeTaintTransfer
import z3

# Create symbolic label
sym_label = SymbolicTaintLabel.fresh("v")

# Create constraint for sink safety
constraint = sym_label.is_safe_for_sink_constraint(SinkType.SQL_EXECUTE)

# Check if bug is reachable
solver = z3.Solver()
solver.add(z3.Not(constraint))  # Unsafe condition
if solver.check() == z3.sat:
    model = solver.model()  # Counterexample
```

## Debugging Taint Analysis

### Debugging Intraprocedural Taint

```bash
# Run taint analysis with debug output
venv/bin/python -c "
from pyfromscratch.z3model.taint_lattice import BytecodeTaintTransfer, TaintLabel, SourceType

# Create test labels
http = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, 'request.args')
clean = TaintLabel.clean()

# Trace through operations
result = BytecodeTaintTransfer.subscript(clean, http)
print(f'After subscript: tau={bin(result.tau)}, tainted={result.has_untrusted_taint()}')
print(f'Sources: {result.get_untrusted_sources()}')
print(f'Provenance: {result.provenance}')
"
```

### Debugging Missing Taint Propagation

If taint is "lost" during analysis:

1. **Check bytecode offset**: Print the bytecode offset where taint disappears
   ```python
   import dis
   dis.dis(func)  # See bytecode with offsets
   ```

2. **Trace transfer functions**: Add logging to `BytecodeTaintTransfer` methods

3. **Check implicit flows**: If taint flows through control flow, ensure `PCTaint` is being tracked

4. **Check function summaries**: For cross-function flows, ensure summary is computed

### Common Issues

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Taint disappears at call | Missing function summary | Add summary or use havoc |
| False negative at sink | Sink not recognized | Add to `FUNCTION_TO_SINK` |
| Taint on wrong values | Wrong bytecode semantics | Check operand stack model |
| No implicit flow | PCTaint not updated | Track branch conditions |

---

# Interprocedural Analysis (call graphs + summaries)

Interprocedural analysis is required for cross-function taint tracking. This implements `python-barrier-certificate-theory.md` §9.5.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Interprocedural Analysis                      │
├─────────────────────────────────────────────────────────────────┤
│ 1. Call Graph (cfg/call_graph.py)                               │
│    - Parse all Python files                                      │
│    - Extract FunctionInfo + CallSite                             │
│    - Build edges with callee resolution                          │
├─────────────────────────────────────────────────────────────────┤
│ 2. Entry Points (frontend/entry_points.py)                       │
│    - __main__ blocks                                             │
│    - Framework routes (@app.route, Django views)                 │
│    - Pytest test functions                                       │
├─────────────────────────────────────────────────────────────────┤
│ 3. Taint Summaries (semantics/summaries.py)                      │
│    - Bottom-up SCC traversal                                     │
│    - Fixpoint iteration for recursive functions                  │
│    - TaintSummary = (param_to_return, side_effects, sink_checks) │
├─────────────────────────────────────────────────────────────────┤
│ 4. Interprocedural Tracker (semantics/interprocedural_taint.py)  │
│    - Apply summaries at CALL instructions                        │
│    - Track taint across module boundaries                        │
│    - Report cross-function violations                            │
└─────────────────────────────────────────────────────────────────┘
```

## Call Graph Construction

Build the call graph from bytecode (not AST) using `CALL*` instruction analysis:

```python
from pyfromscratch.cfg.call_graph import build_call_graph_from_directory

# Build call graph for entire project
call_graph = build_call_graph_from_directory(Path("/path/to/project"))

# Inspect results
for func_name, func_info in call_graph.functions.items():
    print(f"{func_name}: {len(func_info.call_sites)} call sites")
    for site in func_info.call_sites:
        print(f"  → {site.callee_name} at line {site.line_number}")
```

## Summary Computation

Summaries are computed bottom-up in topological order:

```python
from pyfromscratch.semantics.summaries import SummaryComputer

computer = SummaryComputer(
    call_graph,
    source_contracts={...},
    sink_contracts={...},
    sanitizer_contracts={...}
)
summaries = computer.compute_all()

# Inspect a summary
summary = summaries.get("handlers.process")
print(f"param_to_return: {summary.param_to_return}")  # Which params flow to return
print(f"returns_tainted: {summary.returns_tainted}")
print(f"sink_checks: {summary.sink_checks}")  # Sinks accessed with which params
```

## Applying Summaries at Call Sites

At each `CALL` instruction in the symbolic VM:

```python
def handle_call(self, callee_name: str, args: List[SymbolicValue]):
    # Check for known summary
    summary = self.interprocedural_context.get_summary(callee_name)
    
    if summary is not None:
        # Apply the summary to get return taint
        arg_labels = [self.get_taint_label(arg) for arg in args]
        ret_label = summary.apply(arg_labels)
        
        # Check for sink violations in the callee
        for sink_check in summary.sink_checks:
            param_idx, sink_type = sink_check
            if not arg_labels[param_idx].is_safe_for_sink(sink_type):
                self.report_violation(...)
    else:
        # Unknown function: conservative join of all args
        ret_label = label_join_many([self.get_taint_label(a) for a in args])
    
    return ret_label
```

## Debugging Interprocedural Analysis

### Debugging Call Graph Issues

```bash
# Visualize call graph
venv/bin/python -c "
from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pathlib import Path

cg = build_call_graph_from_directory(Path('pyfromscratch'))
print(f'Functions: {len(cg.functions)}')
print(f'Edges: {sum(len(f.call_sites) for f in cg.functions.values())}')

# Check specific function
if 'handlers.process' in cg.functions:
    info = cg.functions['handlers.process']
    print(f'Call sites in handlers.process:')
    for site in info.call_sites:
        print(f'  {site.callee_name} at {site.file_path}:{site.line_number}')
"
```

### Debugging Missing Edges

If a call is not in the graph:

1. **Check bytecode**: The `CALL*` instruction must be present
   ```python
   import dis
   dis.dis(func)
   ```

2. **Check callee resolution**: Dynamic calls may not resolve
   ```python
   # This won't resolve statically:
   f = get_func()
   f(x)  # Callee is dynamic
   ```

3. **Check imports**: Ensure import is resolved correctly

### Debugging Summary Computation

```bash
# Trace summary computation
venv/bin/python -c "
from pyfromscratch.semantics.summaries import SummaryComputer
from pyfromscratch.cfg.call_graph import build_call_graph_from_file
from pathlib import Path

cg = build_call_graph_from_file(Path('test_file.py'))
computer = SummaryComputer(cg)

# Enable debug mode
import logging
logging.basicConfig(level=logging.DEBUG)

summaries = computer.compute_all()

for name, summary in summaries.items():
    print(f'{name}:')
    print(f'  param_to_return: {summary.param_to_return}')
    print(f'  returns_source: {summary.returns_source}')
"
```

### Common Interprocedural Issues

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Cross-file taint lost | Import not resolved | Check module resolver |
| Recursive function hangs | Fixpoint not converging | Add widening or iteration limit |
| Wrong summary | SCC order incorrect | Check topological sort |
| Missing entry point | Framework pattern not recognized | Add to entry point detector |
| Dynamic call ignored | Callee not resolvable | Use havoc fallback |

## End-to-End Interprocedural Example

```bash
# Full interprocedural analysis
venv/bin/python -c "
from pyfromscratch.semantics.interprocedural_taint import InterproceduralContext
from pathlib import Path

# Build context for project
ctx = InterproceduralContext.from_project(Path('.'))

print(f'Entry points: {ctx.entry_points}')
print(f'Reachable functions: {len(ctx.reachable_functions)}')
print(f'Summaries computed: {len(ctx.summaries)}')

# Run analysis from entry points
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugFinder
finder = InterproceduralBugFinder(ctx)
bugs = finder.find_all_bugs()

for bug in bugs:
    print(f'BUG: {bug.bug_type} at {bug.location}')
    print(f'  Taint path: {bug.taint_path}')
"
```

---

# Unknown calls as barrier-theoretic relations (must implement)

Model an unknown call `f` as a relation `R_f ⊆ In × Out` where the interface includes:

- argument values (and possibly shapes/types),
- heap footprint (what locations may be read/written/allocated),
- raised-exception behavior.

Soundness rule: your assumed `R_f` must be an **over-approximation** of true behavior. Refinement must preserve `Sem_f ⊆ R_f`.

Preferred implementation form:
- Use **relational summaries** with multiple guarded cases plus a required havoc fallback (see `ELEVATION_PLAN.md` / `python-barrier-certificate-theory.md` elevation plan section), rather than ad-hoc per-function logic in the VM.
- Expand library-specific summaries aggressively once the scaffold exists, because real Python programs are dominated by library calls.

Use DSE as an oracle to *witness* behaviors and to produce concrete repros, but do not use DSE failure to shrink `R_f` unless independently justified.

Track contracts in:
- code (a contract library file),
- and `State.json` under `progress.unknown_calls.contracts`.

---

# DSE refinement oracle (how to use it correctly)

Implement DSE to answer "can we actually realize this candidate trace?" and to produce human-usable repros.

Rules:

- If DSE **finds** inputs/executions matching a symbolic counterexample: you have a concrete reproducer; attach it to the bug report artifact.
- If DSE **fails** to find a witness within budget: do **not** conclude infeasible; keep the over‑approx contract/abstraction unless you have independent justification to narrow it.
- Use DSE failures to decide *where* to invest:
  - expand opcode semantics,
  - refine path condition modeling,
  - refine unknown-call contracts conservatively.

Always log DSE attempts (inputs tried, constraints, coverage) into `results/` and summarize in `State.json`.

---

# Evaluation loop (false negatives and false positives, RustFromScratch-style)

You must continuously test both:

- **False negatives**: BUG programs your analyzer misses.
- **False positives**: SAFE programs your analyzer flags.

Do this in increasing difficulty tiers:

1. **Micro-tests**: 5–20 line programs targeting one semantic corner (exceptions, stack, div, bounds).
2. **Synthetic realistic tests**: 50–200 line programs with plausible structure; label the "bug line"; include non-bugs.
3. **PyGoat comparison** (NEW): Run on intentionally vulnerable PyGoat app, compare to CodeQL, document gaps or what you determine are false positives on our part in `checkers_lacks.md`.
4. **Public repos**: clone curated Python repos; scan in batches; triage.

For every flagged issue in real code:

- Produce a model witness trace (symbolic path + concrete repro if possible).
- If you cannot produce a witness, do not claim BUG; keep it UNKNOWN or as a "suspicious site" (non-decisive).
- Fix false positives by improving semantics/contracts/proofs, not by adding text heuristics.
- When a BUG/UNKNOWN hinges on unknown library behavior (or you "can't reason" because a call is modeled as havoc), prefer adding/refining a library summary/contract for the specific call(s) involved (while preserving `Sem_f ⊆ R_f`), then rerun analysis.


**Write a report on any true positives in real OR synthetic repos within the document TRUE_POSITIVES{name of repo or 'synthetic'}.md, including what reasoning you used to make you conclude that it was indeed a true positive and not a false positive.**. **Note that this work will ultimately be judged by the false positive rate *as well as* the sheer number of true positives found, so take this task and the reporting seriously.**
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

1. Scaffold the Python package + CLI + tests (minimal).
2. Add library-specific semantics scaffolding: relational summaries (cases + required havoc fallback), and seed as many builtin/stdlib summaries as possible (sound over-approx only).
3. Implement a tiny concrete bytecode stepper for a trivial program.
4. Implement symbolic state + Z3 encoding for that same trivial program.
5. Implement the first unsafe predicate: `ASSERT_FAIL` as "uncaught AssertionError".
6. Make it find a concrete counterexample trace for `assert False` outside any handler.
7. Add NON‑BUG tests where `assert False` is caught/handled.
8. Add `DIV_ZERO` and `BOUNDS` unsafe predicates next (still pure Python semantics).
9. Ensure unknown-call fallback ("havoc with footprint") is present and cannot yield unsound SAFE claims; expand library summaries/contracts as needed to turn UNKNOWN into provable BUG/SAFE.
10. **Run PyGoat + CodeQL comparison** (Phase `PYGOAT_CODEQL_COMPARISON`) - before expanding to random public repos, validate against known-vulnerable app and document gaps AND FALSE POSITIVES from our checker in `checkers_lacks.md`.
11. Only then expand opcode coverage and add more bug classes.
12. Proceed to public repo evaluation.

---

# Quality bar (how you know you're not cheating)

For any detector/bug class, you must be able to answer, with code pointers:

- "What is the exact semantic unsafe region, in terms of the machine state?"
- "What is the exact transition relation you used?"
- "Where is the Z3 query that proves reachability / inductiveness?"
- "Where is the extracted witness trace, and how do we replay it concretely?"

If you cannot answer those, you are not doing the project—stop and fix the model.
