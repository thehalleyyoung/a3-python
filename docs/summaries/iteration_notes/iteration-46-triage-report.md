# Iteration 46: Public Repo BUG Triage Report

## Summary

Triaged 221 BUG findings from tier 1 public repos (click, flask, pytest, requests, rich).

**Key finding:** All 221 BUGs are PANIC errors caused by missing opcode implementations, NOT false positives in the semantic analysis.

## Breakdown by Repository

- **click**: 45 BUGs (90% of files)
- **flask**: 47 BUGs (94% of files)
- **pytest**: 50 BUGs (100% of files)
- **requests**: 30 BUGs (83% of files)
- **rich**: 49 BUGs (98% of files)

## Bug Type Distribution

- **PANIC**: 221 (100%)

All PANIC bugs are caused by encountering unsupported opcodes during symbolic execution.

## Missing Opcodes (Priority Order)

1. **IMPORT_FROM**: 196 occurrences (89%)
   - Used in almost every Python module that imports specific names
   - Example: `from click.parser import _OptionParser`
   - Critical for analyzing real Python code

2. **CALL_KW**: 8 occurrences (4%)
   - Calls with keyword arguments
   - Example: `func(x=1, y=2)`

3. **MAKE_CELL**: 8 occurrences (4%)
   - Creates cell objects for closures
   - Critical for analyzing nested functions with free variables

4. **BUILD_LIST**: 6 occurrences (3%)
   - List literal construction
   - Example: `[1, 2, 3]`

5. **BUILD_MAP**: 1 occurrence (<1%)
   - Dict literal construction
   - Example: `{'a': 1}`

6. **STORE_GLOBAL**: 1 occurrence (<1%)
   - Stores to global namespace

## Test Files vs Production Code

- Test files: 137 BUGs (62%)
- Production files: 84 BUGs (38%)

**Note**: Many test files intentionally trigger exceptional behavior. However, our PANIC findings are about analyzer limitations, not the code itself. We should still analyze test files to ensure semantic coverage, but may want to filter them from user-facing reports.

## False Positive Assessment

**Conclusion**: These are NOT false positives.

The analyzer correctly:
1. Encounters an opcode it hasn't implemented
2. Recognizes it cannot soundly analyze the code (unknown transition relation)
3. Reports PANIC (unhandled exception in the semantic model)

This aligns with the anti-cheating rule: we never pretend to understand code we haven't modeled semantically.

## False Negative Assessment

**Potential issue**: By failing early on unsupported opcodes, we may miss real bugs that would be reachable if we had complete opcode coverage.

However, reporting UNKNOWN for unsupported code is semantically correct. The false negatives will decrease as we implement more opcodes.

## Recommended Actions (Priority Order)

1. **Implement IMPORT_FROM** (blocks 89% of real-world analysis)
   - Semantics: Pop module object, push attribute from module
   - Z3 model: Attribute lookup on module object
   - Should be straightforward given existing LOAD_ATTR implementation

2. **Implement BUILD_LIST** (common data structure)
   - Semantics: Pop N values, create list object
   - Z3 model: Create heap object with list tag

3. **Implement BUILD_MAP** (common data structure)
   - Similar to BUILD_LIST but for dicts

4. **Implement MAKE_CELL** (closures are common)
   - Semantics: Create cell object for closure variable
   - Z3 model: Cell as wrapper around symbolic value

5. **Implement CALL_KW** (keyword args are very common)
   - Extension of existing CALL implementation
   - Need to handle keyword argument matching

6. **Implement STORE_GLOBAL** (rarely used in modern Python)

## Verification Strategy

For each implemented opcode:
1. Add concrete VM tests (differential against CPython)
2. Add symbolic tests (Z3 path exploration)
3. Add BUG/NON-BUG tests for relevant bug types
4. Re-scan tier 1 repos to measure impact

## Impact Prediction

Implementing IMPORT_FROM alone should enable analysis of ~196 more files, dramatically increasing the number of files we can analyze completely.

After implementing all 6 opcodes, we expect to successfully analyze most of the tier 1 repos end-to-end, revealing actual semantic bugs (DIV_ZERO, BOUNDS, etc.) rather than analyzer limitations.
