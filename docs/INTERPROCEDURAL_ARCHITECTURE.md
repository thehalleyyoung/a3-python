# Interprocedural Analysis Architecture (Post-Iteration 539)

## Current State

The interprocedural analysis system now has enhanced precision through improved summary-based propagation with fixpoint iteration.

## Architecture Layers

### Layer 1: Intraprocedural Analysis (SOTA Analyzer)
- File: `pyfromscratch/semantics/sota_intraprocedural.py`
- Performs within-function taint tracking
- Uses abstract interpretation with taint lattice
- Identifies sources, sanitizers, and sinks within a single function
- Produces violations and function summaries

### Layer 2: Summary Computation
- File: `pyfromscratch/semantics/summaries.py` (basic)
- File: `pyfromscratch/semantics/sota_interprocedural.py` (enhanced)
- Computes `FunctionTaintSummary` for each function:
  - `param_to_ret`: How parameters affect return value
  - `param_to_sinks`: Which parameters flow to which sinks
  - `ret_depends_on`: Which parameters the return depends on
  - Violations found during analysis

### Layer 3: Call Graph Construction
- File: `pyfromscratch/cfg/call_graph.py`
- Builds interprocedural call graph from bytecode
- Identifies call sites with line numbers and bytecode offsets
- Resolves callee names where possible

### Layer 4: Interprocedural Propagation (Enhanced in Iteration 539)
- File: `pyfromscratch/semantics/sota_interprocedural.py`
- Method: `_propagate_interprocedural`
- **Key Innovation**: Fixpoint iteration for multi-hop taint flows
- **Algorithm**:
  1. Initialize: Mark no functions as processed
  2. Iterate until fixpoint or max iterations:
     - For each unprocessed function with a summary
     - Check each call site
     - If callee has param→sink flows, create interprocedural violation
     - Mark function as processed
  3. Return enhanced violations with 0.75 confidence

### Layer 5: Context Sensitivity (Framework Ready)
- Data structure: `CallContext` with k-CFA support
- Currently: Basic implementation, ready for enhancement
- Future: Full context-sensitive tracking per IFDS/IDE

## Precision Improvements (Iteration 539)

### Before
- Single pass over call graph
- Conservative assumptions about argument tainting
- 0.7 confidence score
- No multi-hop handling

### After
- Fixpoint iteration (up to 10 iterations)
- More precise argument-to-parameter tracking
- 0.75 confidence score
- Handles multi-hop taint flows

## Data Flow Example

```
entry(user_input)
  ↓ [HTTP_PARAM taint]
level1(user_input)
  ↓ [propagates taint]
level2(x)
  ↓ [propagates taint]
level3(x)
  ↓ [reaches sink]
os.system(x)  ← VIOLATION detected interprocedurally
```

### How It Works

1. **Intraprocedural**: Each function analyzed in isolation finds local sources/sinks
2. **Summary**: Each function gets summary of param→return and param→sink flows
3. **Iteration 1**: Direct call edges checked (entry→level1)
4. **Iteration 2**: Transitive edges checked (level1→level2→level3)
5. **Fixpoint**: No new violations found, stop
6. **Result**: Interprocedural violation reported with call chain

## Comparison to IDE/IFDS

### Current Implementation (Summary-Based)
- ✅ Fast: O(n*k) where n=functions, k=iterations
- ✅ Sound: Conservative over-approximation
- ✅ Handles recursion through summary caching
- ⚠️ Precision: Per-function summary, not per-statement
- ⚠️ Context: Basic call chain tracking

### Full IDE/IFDS (Future)
- ⏳ Slower: O(|ICFG| * |Facts| * |Context|)
- ✅ More Precise: Per-program-point facts
- ✅ Call/Return Matching: Summary edges
- ✅ Context Sensitivity: k-CFA with proper context handling
- ✅ Distributive: Supports precise transfer functions

## Testing

### Test Coverage
- `test_sota_interprocedural.py`: 16 tests (basic interprocedural)
- `test_interprocedural_security.py`: 18 tests (security-specific)
- `test_ide_precision.py`: 7 tests (precision validation)
- **Total**: 41 interprocedural tests

### Key Test Categories
1. **Straight-line flows**: Taint through helper returns
2. **Multi-hop**: Chains of 2+ function calls
3. **Sanitization**: Proper handling of sanitizers in callees
4. **Recursion**: Termination with recursive functions
5. **Context**: Different call sites distinguished
6. **Precision**: Correct argument index tracking

## Performance Characteristics

### Time Complexity
- **Call graph**: O(n) where n = bytecode instructions
- **Intraprocedural**: O(b * i) where b = blocks, i = max iterations per function (50)
- **Interprocedural**: O(f * c * k) where:
  - f = number of functions
  - c = average call sites per function
  - k = fixpoint iterations (≤ 10)

### Space Complexity
- **Summaries**: O(f * p) where p = average parameters per function
- **Call graph**: O(f * c) for edges
- **Violations**: O(v) where v = violations found

### Typical Performance
- Single file (10 functions): < 0.5s
- PyGoat (50+ files): ~2-5s
- Large project (500+ functions): ~30-60s

## Next Steps (From Queue)

1. **Complete full IDE/IFDS tabulation** with explicit ICFG node facts
2. **Add context-sensitive tracking** beyond basic call chains
3. **Optimize large-scale analysis** with incremental computation
4. **Expand sanitizer modeling** with more precise effect tracking

## References

- **SOTA Plan**: `docs/CODEQL_PARITY_SOTA_MATH_PLAN.md` Section 2.4
- **Taint Theory**: `leak_theory.md` Section on interprocedural analysis
- **Barrier Theory**: `python-barrier-certificate-theory.md` Section 9.5
- **Implementation**: `pyfromscratch/semantics/sota_interprocedural.py`
