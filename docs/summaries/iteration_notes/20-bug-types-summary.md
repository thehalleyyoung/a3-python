# 20 Bug Types from barrier-certificate-theory.tex

This is a summary of the 20 bug types defined in `barrier-certificate-theory.tex` §3933-3961 
("Summary: Complete Coverage of 20 Bug Types").

Each bug type has a barrier certificate formulation B(x,π,g) that satisfies:
- **Initial safety**: B(x₀, π_entry, 0) > 0
- **Unsafe exclusion**: B(x, π, g) < 0 for (x, π, g) ∈ U (unsafe region)
- **Inductive descent**: B(f_e(s)) ≤ B(s) for all transitions

## The 20 Bug Types

1. **INTEGER_OVERFLOW** - Arithmetic overflow/underflow
2. **DIV_ZERO** - Division by zero
3. **FP_DOMAIN** - Floating-point domain errors (sqrt of negative, log of non-positive)
4. **USE_AFTER_FREE** - Access to deallocated memory
5. **DOUBLE_FREE** - Freeing already freed memory
6. **MEMORY_LEAK** - Unbounded heap growth / unreachable retained memory
7. **UNINIT_MEMORY** - Reading uninitialized memory
8. **NULL_PTR** - Null pointer dereference
9. **BOUNDS** - Array/buffer out-of-bounds access
10. **DATA_RACE** - Concurrent unsynchronized access with ≥1 write
11. **DEADLOCK** - Circular wait on locks
12. **SEND_SYNC** - Thread-safety contract violation (Rust Send/Sync analogue)
13. **NON_TERMINATION** - Unbounded loops without ranking function
14. **PANIC** - Unhandled exception / crash
15. **ASSERT_FAIL** - Assertion failure that propagates out
16. **STACK_OVERFLOW** - Runaway recursion / stack exhaustion
17. **TYPE_CONFUSION** - Dynamic dispatch/type errors violating protocol
18. **ITERATOR_INVALID** - Collection mutation invalidation (e.g., dict size change during iteration)
19. **INFO_LEAK** - Taint / noninterference violation (secret → sink)
20. **TIMING_CHANNEL** - Secret-dependent timing side-channel

## Critical Anti-Cheating Rule

**NO PROOF = NO SAFETY GUARANTEE**

- A BUG report requires a **model-checked reachable trace** (counterexample witness)
- A SAFE report requires a **proof** (barrier certificate / inductive invariant)
- UNKNOWN is allowed (when neither proof nor counterexample is found)
- Never use:
  - Regex/pattern matching as the decider
  - Absence of counterexample as proof
  - Comments/docstrings/variable names as signals
  - Heuristics that don't ground in the transition system semantics
