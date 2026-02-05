# Python Barrier Certificate Semantics: Core Concepts

Summary of key concepts from `python-barrier-certificate-theory.md` needed for implementation.

## 1. Target Execution Model

**Python 3.11 bytecode as an abstract machine** (not source-level AST analysis).

Why bytecode:
- Explicit program counter (pc) for reachability
- Explicit operand stack for evaluation order
- Explicit exception table for handler edges
- Closer to "executable semantics" than source

## 2. Machine State σ

The complete machine state includes:

```
σ = (Threads, Heap, Globals, Builtins, ImportState, IO, Time, Flags)

Per-thread:
  - Frame stack: [(locals, cells, globals, builtins, operand_stack, pc, exception_state), ...]
  - Current exception (if propagating)

Heap:
  - ObjId → Object mapping
  - Objects: None, bool, int, float, str, list, dict, tuple, user objects, ...
  - External resources/handles (for leak/UAF modeling)
```

Key: **Identity vs Value**
- Use ObjId for objects (to model aliasing)
- Use mathematical integers for Python ints (unless boundary operation)
- Tagged values for type confusion detection

## 3. Reachability as the Semantic Core

Safety = `Reach(S0, →) ∩ Unsafe = ∅`

Where:
- `S0` = initial states
- `→` = step relation (nondeterministic for unknown calls/IO/scheduling)
- `Unsafe` = union of unsafe predicates for each bug type
- `Reach` = least fixpoint of reachable states

**Bugs are reachability properties**, not syntactic patterns.

## 4. Barrier Certificates (Nondeterministic Case)

A barrier function B : S → ℝ proves safety if:

1. **Init**: ∀s ∈ S0. B(s) ≥ ε
2. **Unsafe**: ∀s ∈ U. B(s) ≤ -ε  
3. **Step (inductive)**: ∀s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0

This handles nondeterminism (unknown calls, IO) because inductiveness must hold for **all** successor states.

## 5. Exception Semantics (Critical for Python)

Many Python bugs are "unhandled exception" bugs (ASSERT_FAIL, PANIC, TYPE_CONFUSION, BOUNDS, etc.).

**Exception propagation is explicit control flow:**
- When an exception is raised, control transfers to the handler (if any)
- Handlers are in the exception table (3.11+): `[(start, end, target, depth)]`
- `finally` blocks always run (on return, raise, or normal exit)

**Unsafe predicate for uncaught exceptions:**
```
UnsafeAssert(σ) := (pc == pc_assert_fail) ∧ (__debug__ == True) ∧ (g_catch == 0)
```

Where `g_catch` is a guard bit that is 1 if there's a handler that will catch AssertionError.

## 6. Unknown Calls as Relations (§4.2-4.3)

Model unknown call `f` as a relation `R_f ⊆ In × Out`:

```
R_f ⊆ { (args, heap_in, exc_in) × (ret, heap_out, exc_out) }
```

**Soundness rule:** `Sem_f ⊆ R_f` (contract must **over-approximate** true behavior)

Start with "havoc" default:
- May return any value
- May raise any exception
- May mutate any reachable heap location

**DSE as refinement oracle (§4.3):**
- Use concolic execution to **validate** candidate counterexample traces
- If DSE realizes a trace: **real bug** (produce concrete repro)
- If DSE fails within budget: **cannot conclude infeasible**
  - Keep contract as-is (report UNKNOWN), or
  - Refine only with independently justified constraints (from source, from bounded SMT proof, from trusted spec)

**Never** use DSE failure to prove safety.

## 7. CFG + Exceptional Edges

Control flow graph must include:
- Normal edges (branches, jumps, calls, returns)
- **Exceptional edges** (from exception table)
- Handler matching (which exceptions caught by which handlers)

Without explicit exceptional edges, "unreachable" analysis is unsound.

## 8. Z3 Roles

1. **Path feasibility oracle**: Is this path condition satisfiable?
2. **Bounded model checking (BMC)**: Bug within k steps?
3. **Certificate checker**: Discharge barrier inductiveness conditions (boolean/discrete parts)

Hybrid approach: Z3 for reachability queries + SOS/numerical methods for polynomial barrier synthesis.

## 9. Interface Abstraction

Full Python state is infinite; analysis needs an **interface abstraction** α:

```
α : (exact Python machine states) → (interface states)
```

Interface state contains:
- Numeric values (ints, floats) or their abstract domains (intervals, octagons)
- Guard bits (g_catch, g_type_int, g_bounds_checked, ...)
- Program counter π
- Heap summary (lengths, types, aliasing classes)

Soundness: α must **over-approximate** (if α(s) is safe, then s is safe).
