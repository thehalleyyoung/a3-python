# Iteration 40: Increased Path Exploration Depth

## Motivation

Iteration 39's tier 1 public repo scan showed that exploration was averaging ~14 paths per file, which is likely hitting depth/path limits too early and missing reachable states. All results were UNKNOWN (no bugs found, no proofs synthesized).

## Changes

Increased path exploration parameters by 10x:
- `max_paths`: 50 → 500 (10x increase)
- `max_depth`: 500 → 2000 (4x increase)

Both the default `Analyzer` constructor and the `analyze_file()` function used for public repo evaluation were updated.

## Rationale

The low path count suggests we're hitting resource limits before exhausting the interesting state space. Real-world Python code often has deep call stacks and many control flow branches. Conservative limits were appropriate during early development, but now that all 20 bug types are implemented and validated, we need more aggressive exploration to find real bugs or generate meaningful SAFE proofs.

## Testing

All 530 tests pass (10 skipped, 13 xfailed, 12 xpassed). No regressions.

## Next Steps

1. Re-run tier 1 public repo scan with new depth parameters to measure impact
2. Track path exploration metrics (avg paths per file, avg depth reached)
3. If still limited, consider:
   - Smarter path prioritization (coverage-guided, loop unrolling heuristics)
   - Incrementally increasing limits based on file complexity
   - Caching/memoization of repeated subpaths

## Anti-cheating Check

This change is purely a resource allocation adjustment (exploration budget). It does not:
- Add heuristics or pattern matching
- Change unsafe predicates or semantics
- Alter the BUG/SAFE/UNKNOWN decision logic
- Bypass any formal verification steps

The same Z3-based symbolic execution and barrier synthesis machinery is used; we're just allowing it to explore more states before giving up.
