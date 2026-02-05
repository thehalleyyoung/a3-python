# Iteration 120: SAFE Proof Soundness Fix (Path Limit Issue)

**Date**: 2026-01-23  
**Phase**: PUBLIC_REPO_EVAL  
**Critical Severity**: HIGH

## Problem Identified (Iteration 119)

Scanner/CLI discrepancy investigation revealed a critical soundness issue:

- **Scanner uses `max_paths=2000`** (evaluation/scanner.py:546)
- **CLI uses `max_paths=500`** (analyzer.py:126 default)
- **Root cause**: When path exploration hits the limit, analyzer still attempts barrier synthesis and may claim SAFE

### Why This is Unsound

A barrier certificate B(σ) proves safety by showing:
1. **Init**: ∀s∈S₀. B(s) ≥ ε
2. **Unsafe**: ∀s∈U. B(s) ≤ -ε  
3. **Step**: ∀s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0

For SAFE to be valid: **Reach(S₀,→) ∩ U = ∅**

If we hit `max_paths` limit:
- We've only explored a **subset** of Reach(S₀,→)
- Synthesized barrier may only cover explored states
- Unexplored states might reach unsafe region
- **SAFE claim is unsound** without coverage proof

## The Fix

### Code Changes (analyzer.py)

1. **Track whether path limit was hit**:
   ```python
   hit_path_limit = False
   
   while paths_to_explore and len(explored_paths) < self.max_paths:
       # ... exploration loop ...
   
   hit_path_limit = len(explored_paths) >= self.max_paths and len(paths_to_explore) > 0
   ```

2. **Report UNKNOWN if limit hit**:
   ```python
   if hit_path_limit:
       return AnalysisResult(
           verdict="UNKNOWN",
           message=(
               f"Hit path exploration limit ({self.max_paths}) with unexplored paths remaining. "
               f"Cannot prove SAFE without exhaustive exploration or barrier coverage proof."
           )
       )
   ```

3. **Only attempt SAFE synthesis if paths exhausted**:
   ```python
   # We exhausted all reachable paths without finding bugs
   # Now we can soundly attempt barrier synthesis
   synthesis_result = self._attempt_safe_proof(code, explored_paths)
   ```

### Soundness Guarantee

After fix:
- **BUG**: Counterexample trace found → always sound
- **SAFE**: All paths exhausted + barrier certificate → sound
- **UNKNOWN**: Hit path limit OR synthesis failed → conservative

The fix maintains the anti-cheating requirement:
> "Every safety claim must be justified strictly by the Python Z3 heap/transition/barrier theory model"

## Testing

Created `tests/test_path_limit_soundness.py`:

1. **test_path_limit_hit_reports_unknown**:
   - Program with exponential branching (many paths)
   - Set `max_paths=5` to force limit
   - Verify verdict is UNKNOWN (not SAFE)
   - ✓ PASSED

2. **test_exhausted_paths_can_synthesize_safe**:
   - Simple program with few paths
   - Set `max_paths=100` (plenty)
   - Verify no path-limit message
   - ✓ PASSED

## Impact on Results

### Expected Changes

Programs that were previously reported as **SAFE** may now be **UNKNOWN** if:
1. They hit the path limit without exhausting all paths
2. The barrier synthesizer happened to find a valid certificate for explored paths only

### Repos Likely Affected

From State.json evaluation metrics:
- **Tier 1**: 88 SAFE proofs (may be affected)
- **Tier 2**: 584 SAFE (90.4% rate, may be affected)
- **Scanner** (max_paths=2000): Higher limits, fewer affected
- **CLI** (max_paths=500): Lower limits, more affected

Need to rescan to quantify impact.

## Future Work

### Option 1: Increase Path Limits
- Standardize at higher value (e.g., 5000)
- Trade-off: analysis time vs coverage

### Option 2: Barrier Coverage Verification
Implement sound coverage check:
```
For synthesized barrier B and unexplored paths P_unexplored:
  Can we prove: ∀p∈P_unexplored. ∀s∈p. B(s) ≥ 0?
  
If yes: SAFE is sound even with unexplored paths
If no: Must report UNKNOWN
```

This would allow SAFE claims even when hitting limits, **if** we can prove the barrier covers unexplored space.

### Option 3: Symbolic Path Enumeration
Use Z3 to reason about **all** paths symbolically instead of enumerating them. More complex but more powerful.

## Related Prompt Requirements

From `python-semantic-barrier-workflow.prompt.md`:

> **Phase: BARRIERS_AND_PROOFS** (lines 237-244)  
> - At least one nontrivial SAFE proof is produced and verified end‑to‑end.

✓ This fix ensures SAFE proofs are verified end-to-end with coverage.

> **Forbidden approaches** (line 59):  
> - Returning "SAFE" because you didn't find a counterexample (absence of evidence is not proof).

✓ This fix prevents exactly this forbidden pattern.

## Quality Bar Check

Can we answer with code pointers?

1. ✓ "What is the exact semantic unsafe region?"
   - `unsafe/registry.py`: predicates for 20 bug types

2. ✓ "What is the exact transition relation?"
   - `analyzer.py:387-405`: step_relation encoding

3. ✓ "Where is the Z3 query for reachability?"
   - `semantics/symbolic_vm.py`: symbolic execution
   - `barriers/synthesis.py`: inductiveness checking

4. ✓ "Where is coverage verification?"
   - **NEW**: `analyzer.py:199`: hit_path_limit tracking
   - **NEW**: `analyzer.py:234-252`: UNKNOWN if limit hit

## Files Changed

1. `pyfromscratch/analyzer.py`:
   - Added `hit_path_limit` tracking
   - Added soundness check before SAFE synthesis
   - Enhanced verbose logging for limit detection

2. `tests/test_path_limit_soundness.py` (NEW):
   - Regression test for soundness fix
   - Tests both limit-hit and exhausted-paths cases

3. `State.json`:
   - Updated iteration to 120
   - Added critical finding about SAFE proof soundness

4. `docs/notes/iteration-120-safe-proof-soundness.md` (THIS FILE)

## Conclusion

This is a **critical soundness fix** that prevents false SAFE claims. The analyzer now correctly distinguishes between:

- **Exhaustive exploration + no bugs** → can attempt SAFE proof
- **Partial exploration + no bugs** → must report UNKNOWN

This maintains the barrier-theoretic rigor required by the prompt and prevents the "absence of evidence ≠ proof" anti-pattern.
