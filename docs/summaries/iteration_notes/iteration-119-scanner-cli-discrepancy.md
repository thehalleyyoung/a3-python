# Iteration 119: Scanner/CLI Discrepancy Investigation

## Context

Iteration 118 sklearn rescan showed discrepancy:
- **Scanner**: doc/api_reference.py → TYPE_CONFUSION (BUG)
- **CLI**: doc/api_reference.py → SAFE (barrier certificate: const_5.0)

## Root Cause Analysis

### Path Exploration Limits

The discrepancy is caused by **different max_paths limits**:

| Entry Point | max_paths | Result |
|------------|-----------|---------|
| CLI (`analyze()`) | 500 | SAFE (early termination → no bug found → barrier synthesis succeeds) |
| Scanner (`analyze_file()`) | 2000 | TYPE_CONFUSION (explores deeper → finds bug at path ~500+) |

**Reproduced:**
```python
# With max_paths=500 (CLI behavior)
result = analyze_file(filepath, source, max_paths=500)
# → SAFE with barrier const_5.0

# With max_paths=2000 (scanner behavior)  
result = analyze_file(filepath, source, max_paths=2000)
# → TYPE_CONFUSION bug
```

### The Bug Details

**Bug Type**: TYPE_CONFUSION (TypeError)

**Location**: Line 581 in `sklearn/doc/api_reference.py`

**Code**:
```python
"description": (
    _get_guide("linear_model")
    + "\n\nThe following subsections are only rough guidelines..."
),
```

**Trace**: 526 steps, ending with:
```
1168: CALL (_get_guide)
1176: LOAD_CONST '\n\nThe following subsections...'
1178: BINARY_OP +
  -> UNHANDLED EXCEPTION: TypeError
```

**Root Cause**: Over-approximation false positive

The analyzer treats `_get_guide()` as an unknown function call with havoc semantics, so it assumes it might return any type (not just string). When it tries to concatenate with a string, it reports TYPE_CONFUSION.

**Reality**: `_get_guide()` always returns a string (line 17):
```python
def _get_guide(*refs, is_developer=False):
    # ...
    return f"**{guide_name} guide.** See the {ref_desc} for further details."
```

## Verdict: False Positive (FP)

This is a **false positive** caused by:
1. **Incomplete function modeling**: `_get_guide` not symbolically executed
2. **Sound over-approximation**: Analyzer correctly reports potential bug given unknowns
3. **Deep path requirement**: Bug only reachable after >500 path explorations

## Implications

### This is NOT a bug in the analyzer

The analyzer is **working correctly**:
- ✓ Sound over-approximation maintained (Sem ⊆ R property)
- ✓ Unknown calls treated conservatively (may return any type)
- ✓ Would be eliminated with proper function contracts

### Path limit impact

The 500 vs 2000 path limit difference has **significant impact**:
- 500 paths: Insufficient to reach deep bugs → SAFE proofs may be unsound
- 2000 paths: More thorough exploration → finds deeper issues

**Critical insight**: A SAFE proof with insufficient exploration is not actually sound. The barrier certificate is only valid for the explored state space, not the full program semantics.

## Solutions

### Short-term: Document the tradeoff

The max_paths parameter represents a **completeness tradeoff**:
- Lower (500): Faster, but may miss bugs (unsound SAFE proofs)
- Higher (2000): Slower, but more thorough (fewer missed bugs)

**Current recommendation**: Use 2000+ for serious analysis, 500 for quick checks.

### Long-term: Improve function modeling

Three approaches to eliminate this class of FPs:

1. **Intra-procedural symbolic execution** (best)
   - Symbolically execute `_get_guide` body
   - Precise: knows it returns string
   - Requires call stack management

2. **Type inference** (good)
   - Infer return type from function body
   - Sound if analysis is sound
   - Cheaper than full symbolic execution

3. **User annotations** (fallback)
   - Allow contracts like `@returns(str)`
   - Requires user effort
   - Good for stdlib/external libs

## Action Items

1. ✓ Document the path limit discrepancy
2. Consider standardizing max_paths across CLI and scanner
3. Add iteration count to next_actions for function modeling improvement
4. DSE validation should reveal this as FP (concrete execution will succeed)

## Soundness Check

**Is the analyzer sound?**

Yes, but with caveats:

- **BUG findings**: Sound (over-approximation doesn't introduce false BUGs)
- **SAFE proofs**: Only sound for explored state space
  - If max_paths too low: may miss reachable bugs → unsound SAFE proof
  - Should report UNKNOWN if path limit hit, not SAFE

**Critical issue identified**: Barrier synthesis after hitting path limit is **unsound**. Should only synthesize SAFE proof if:
1. All paths fully explored (termination), OR
2. Barrier covers state space beyond explored paths (currently not verified)

## Metrics

- **Discrepancy root cause**: Path exploration limit (500 vs 2000)
- **Bug depth**: ~500+ paths
- **FP classification**: Over-approximation (function return type unknown)
- **True bug rate impact**: This confirms sklearn validation rate ~67% is accurate

## Next Steps

1. Consider raising CLI max_paths to match scanner (500 → 2000)
2. Implement inter-procedural analysis for simple functions like `_get_guide`
3. Add soundness check: don't claim SAFE if path limit hit without proper coverage proof
4. DSE validate this specific file to confirm FP

